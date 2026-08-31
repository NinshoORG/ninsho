import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from 'node:crypto';
import { KeyError, type KeySet, type SigningKey } from '@ninsho/core';

/**
 * Ed25519 key material for the `paseto` strategy.
 *
 * ─── Why a key *set* and not a key ────────────────────────────────────────
 * The predecessor accepted exactly one keypair. Rotating it — after a
 * suspected compromise, or on any sane schedule — invalidated every
 * outstanding token at once, so in practice teams never rotated. A key that
 * cannot be rotated without an outage is a key that never gets rotated.
 *
 * A key set fixes that: the active key signs, every key in the set verifies.
 * Rotation is "mint a new key, move the old one to `previous`, deploy" and
 * causes no forced sign-outs. The old key is dropped once the longest access
 * token issued under it has expired.
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * ASN.1 DER prefixes for Ed25519, from RFC 8410.
 *
 * Node's key loaders want DER or PEM, but every PASETO implementation and test
 * vector exchanges raw 32-byte keys. Rather than push that conversion onto the
 * developer — the predecessor made people paste PKCS#8 DER hex into `.env` —
 * these prefixes let Ninsho accept the raw form and wrap it here.
 */
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const RAW_KEY_BYTES = 32;
/** PASETO exchanges secret keys as seed ‖ public key. */
const PASETO_SECRET_BYTES = 64;

/** A `kid` must be safe to place in a footer and to log. */
const KID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

function fromHex(value: string, field: string): Buffer {
  if (typeof value !== 'string' || value.length === 0) {
    throw new KeyError(`${field} must be a non-empty hex string`);
  }
  if (!/^[0-9a-fA-F]+$/.test(value) || value.length % 2 !== 0) {
    throw new KeyError(`${field} is not valid hex`);
  }
  return Buffer.from(value, 'hex');
}

/**
 * Loads an Ed25519 private key from hex.
 *
 * Accepts the raw 32-byte seed, the 64-byte PASETO form (seed ‖ public key),
 * or a PKCS#8 DER encoding — so keys from any PASETO implementation load
 * without conversion.
 */
export function loadPrivateKey(hex: string, field = 'privateKey'): KeyObject {
  const raw = fromHex(hex, field);

  let der: Buffer;
  if (raw.length === RAW_KEY_BYTES) {
    der = Buffer.concat([PKCS8_ED25519_PREFIX, raw]);
  } else if (raw.length === PASETO_SECRET_BYTES) {
    // Seed ‖ public. Only the seed is needed; Node derives the public half.
    der = Buffer.concat([PKCS8_ED25519_PREFIX, raw.subarray(0, RAW_KEY_BYTES)]);
  } else {
    der = raw;
  }

  let key: KeyObject;
  try {
    key = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  } catch (error) {
    throw new KeyError(
      `${field} could not be parsed as an Ed25519 private key`,
      error instanceof Error ? error.message : String(error),
    );
  }

  // A P-256 or RSA key would load successfully above and then fail deep inside
  // signing with something unhelpful. Reject it here, by name.
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new KeyError(
      `${field} is ${key.asymmetricKeyType ?? 'an unknown key type'}, but PASETO v4.public requires Ed25519`,
    );
  }
  return key;
}

/** Loads an Ed25519 public key from hex. Accepts the raw 32 bytes or SPKI DER. */
export function loadPublicKey(hex: string, field = 'publicKey'): KeyObject {
  const raw = fromHex(hex, field);
  const der =
    raw.length === RAW_KEY_BYTES ? Buffer.concat([SPKI_ED25519_PREFIX, raw]) : raw;

  let key: KeyObject;
  try {
    key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch (error) {
    throw new KeyError(
      `${field} could not be parsed as an Ed25519 public key`,
      error instanceof Error ? error.message : String(error),
    );
  }

  if (key.asymmetricKeyType !== 'ed25519') {
    throw new KeyError(
      `${field} is ${key.asymmetricKeyType ?? 'an unknown key type'}, but PASETO v4.public requires Ed25519`,
    );
  }
  return key;
}

/** Generates a fresh Ed25519 keypair as raw hex, ready for configuration. */
export function generateKeyPair(kid: string): SigningKey {
  if (!KID_PATTERN.test(kid)) {
    throw new KeyError(
      `kid must be 1-64 characters of [A-Za-z0-9._-]. Received: ${JSON.stringify(kid)}`,
    );
  }

  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    publicKeyEncoding: { type: 'spki', format: 'der' },
  });

  // Strip the DER prefixes so the output is the portable raw form.
  return {
    kid,
    privateKey: Buffer.from(privateKey).subarray(PKCS8_ED25519_PREFIX.length).toString('hex'),
    publicKey: Buffer.from(publicKey).subarray(SPKI_ED25519_PREFIX.length).toString('hex'),
  };
}

/**
 * A validated, loaded key set.
 *
 * Signs with the active key and verifies against any key it holds, which is
 * what makes rotation a non-event for users.
 */
export class KeyRing {
  readonly #signingKid: string;
  readonly #privateKey: KeyObject;
  readonly #publicKeys = new Map<string, KeyObject>();

  constructor(keySet: KeySet) {
    if (typeof keySet !== 'object' || keySet === null || keySet.active === undefined) {
      throw new KeyError('keys.active is required when strategy is "paseto"');
    }

    const active: SigningKey = keySet.active;
    KeyRing.#assertKid(active.kid, 'keys.active.kid');

    this.#signingKid = active.kid;
    this.#privateKey = loadPrivateKey(active.privateKey, 'keys.active.privateKey');
    this.#publicKeys.set(active.kid, loadPublicKey(active.publicKey, 'keys.active.publicKey'));

    for (const [index, previous] of (keySet.previous ?? []).entries()) {
      const field = `keys.previous[${index}]`;
      KeyRing.#assertKid(previous.kid, `${field}.kid`);

      // A duplicate kid would make key selection depend on array order — the
      // kind of ambiguity that turns a routine rotation into an outage.
      if (this.#publicKeys.has(previous.kid)) {
        throw new KeyError(
          `duplicate kid "${previous.kid}" in ${field}. Every key id must be unique.`,
        );
      }
      this.#publicKeys.set(previous.kid, loadPublicKey(previous.publicKey, `${field}.publicKey`));
    }
  }

  static #assertKid(kid: unknown, field: string): void {
    if (typeof kid !== 'string' || !KID_PATTERN.test(kid)) {
      throw new KeyError(
        `${field} must be 1-64 characters of [A-Za-z0-9._-]. Received: ${JSON.stringify(kid)}`,
      );
    }
  }

  /** The key id stamped into every token this process signs. */
  get signingKid(): string {
    return this.#signingKid;
  }

  /** The private key for signing. Only the active key ever signs. */
  get privateKey(): KeyObject {
    return this.#privateKey;
  }

  /** Every key id this ring will verify against, active first. */
  get verificationKids(): readonly string[] {
    return [...this.#publicKeys.keys()];
  }

  /**
   * Resolves a key id to its public key, or `null` when unknown.
   *
   * `null` must be treated as a verification failure. A retired key that has
   * been removed from the set is indistinguishable from one an attacker made
   * up, and neither should authenticate anything.
   */
  resolve(kid: string): KeyObject | null {
    if (typeof kid !== 'string') return null;
    return this.#publicKeys.get(kid) ?? null;
  }
}
