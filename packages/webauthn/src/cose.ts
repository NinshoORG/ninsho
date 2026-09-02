/**
 * COSE public keys — RFC 9052 §7, restricted to what WebAuthn registers.
 *
 * ─── The threat this file exists to close ─────────────────────────────────
 * A COSE key is a self-describing structure: it states its own type, its own
 * curve, and its own algorithm. All of it arrives from the browser during
 * registration. A verifier that takes those fields at face value and hands
 * them to a crypto library is running whatever algorithm the attacker named —
 * the same shape of mistake as JWT's `alg: none`, arriving through a different
 * encoding.
 *
 * So three rules hold here, in order:
 *
 *   1. The algorithm must be on an allowlist the *relying party* supplied.
 *      Never a denylist: a denylist is wrong the moment a new algorithm is
 *      registered.
 *   2. The key type must match the algorithm. An EC2 key labelled RS256 is
 *      refused rather than coerced, because interpreting a curve point as an
 *      RSA modulus is not a meaningful operation and nothing good follows from
 *      attempting it.
 *   3. Every structural parameter — curve, coordinate width, modulus size — is
 *      checked here rather than left to WebCrypto. WebCrypto's own validation
 *      is uneven: it rejects an off-curve P-256 point, but it will happily
 *      import a 512-bit RSA modulus, which is forgeable on a laptop. Verified
 *      by test, not assumed.
 * ──────────────────────────────────────────────────────────────────────────
 */

import type { webcrypto } from 'node:crypto';
import { decodeCbor, CborError, type CborValue } from './cbor.js';
import { derToRawSignature, DerError } from './der.js';

/** Raised for any COSE key this module will not accept. */
export class CoseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CoseError';
  }
}

/** COSE algorithm identifiers, IANA COSE Algorithms registry. */
export const ES256 = -7;
export const EdDSA = -8;
export const RS256 = -257;

export type CoseAlgorithm = typeof ES256 | typeof EdDSA | typeof RS256;

/**
 * What this package can verify.
 *
 * ES256 and EdDSA are the modern passkey algorithms. RS256 is here because
 * Windows Hello's TPM path still produces RSA keys, and refusing it would lock
 * out a large share of real users on a purity argument.
 *
 * Deliberately absent: ES256K, PS256, and the SHA-1 family. Nothing in the
 * WebAuthn ecosystem needs them, and each additional algorithm is another
 * import path to get right.
 */
export const SUPPORTED_ALGORITHMS: readonly CoseAlgorithm[] = [ES256, EdDSA, RS256];

/**
 * Recommended `pubKeyCredParams`, most preferred first.
 *
 * Order is a signal to the authenticator, not a constraint — it will pick what
 * it supports. Verification still enforces the allowlist regardless of what
 * comes back.
 */
export const DEFAULT_ALGORITHMS: readonly CoseAlgorithm[] = [ES256, EdDSA, RS256];

/** COSE key common parameters (RFC 9052 §7.1) and per-type parameters. */
const LABEL_KTY = 1;
const LABEL_ALG = 3;
const LABEL_CRV = -1;
const LABEL_X = -2;
const LABEL_Y = -3;
/** RSA reuses the negative labels for its own fields (RFC 8230 §4). */
const LABEL_RSA_N = -1;
const LABEL_RSA_E = -2;

const KTY_OKP = 1;
const KTY_EC2 = 2;
const KTY_RSA = 3;

const CRV_P256 = 1;
const CRV_ED25519 = 6;

/** P-256 field width. Coordinates are exactly this wide — see below. */
const P256_COORDINATE_BYTES = 32;
const ED25519_KEY_BYTES = 32;

/**
 * Smallest RSA modulus accepted, in bits.
 *
 * WebCrypto imports a 512-bit modulus without complaint (verified by test), and
 * a 512-bit RSA key is factorable with commodity hardware. NIST SP 800-57 and
 * every current guideline put the floor at 2048.
 */
const MIN_RSA_MODULUS_BITS = 2048;
const MAX_RSA_MODULUS_BITS = 8192;

/** A parsed, imported, verification-only public key. */
export interface CosePublicKey {
  readonly alg: CoseAlgorithm;
  readonly key: webcrypto.CryptoKey;
}

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/** Reads a label that must be present and must be a byte string. */
function requireBytes(map: Map<string | number, CborValue>, label: number, what: string): Uint8Array {
  const value = map.get(label);
  if (!(value instanceof Uint8Array)) {
    throw new CoseError(`COSE key is missing ${what}, or it is not a byte string`);
  }
  return value;
}

/** Reads a label that must be present and must be an integer. */
function requireInteger(map: Map<string | number, CborValue>, label: number, what: string): number {
  const value = map.get(label);
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new CoseError(`COSE key is missing ${what}, or it is not an integer`);
  }
  return value;
}

/**
 * Counts the significant bits of a big-endian unsigned integer.
 *
 * Leading zero bytes do not contribute: a 2048-bit modulus padded to 257 bytes
 * is still 2048 bits, and a 512-bit modulus padded to 256 bytes is still 512.
 * Measuring the buffer instead of the number is how an undersized key gets
 * waved through.
 */
function bitLength(bytes: Uint8Array): number {
  let index = 0;
  while (index < bytes.length && bytes[index] === 0) index += 1;
  if (index === bytes.length) return 0;

  const leading = bytes[index] as number;
  return (bytes.length - index - 1) * 8 + (32 - Math.clz32(leading));
}

/** A validated key, ready to import — or to hand to node:crypto as a JWK. */
export interface CoseKeyMaterial {
  readonly jwk: webcrypto.JsonWebKey;
  readonly params: webcrypto.EcKeyImportParams | webcrypto.RsaHashedImportParams | string;
}

function ec2Material(map: Map<string | number, CborValue>): CoseKeyMaterial {
  const crv = requireInteger(map, LABEL_CRV, 'a curve');
  if (crv !== CRV_P256) {
    throw new CoseError(`unsupported EC2 curve: ${crv} (only P-256 is accepted)`);
  }

  const x = requireBytes(map, LABEL_X, 'the x coordinate');
  const y = requireBytes(map, LABEL_Y, 'the y coordinate');

  // Exactly 32 bytes, not "at most". A short coordinate that some code
  // left-pads and other code does not gives the same key two encodings, and a
  // credential that has two encodings has two identities.
  if (x.length !== P256_COORDINATE_BYTES || y.length !== P256_COORDINATE_BYTES) {
    throw new CoseError(
      `P-256 coordinates must be exactly ${P256_COORDINATE_BYTES} bytes ` +
        `(got x=${x.length}, y=${y.length})`,
    );
  }

  // Whether the point is actually on the curve is checked by WebCrypto at
  // import. Verified by test rather than assumed.
  return {
    jwk: { kty: 'EC', crv: 'P-256', x: toBase64Url(x), y: toBase64Url(y) },
    params: { name: 'ECDSA', namedCurve: 'P-256' },
  };
}

function okpMaterial(map: Map<string | number, CborValue>): CoseKeyMaterial {
  const crv = requireInteger(map, LABEL_CRV, 'a curve');
  if (crv !== CRV_ED25519) {
    throw new CoseError(`unsupported OKP curve: ${crv} (only Ed25519 is accepted)`);
  }

  const x = requireBytes(map, LABEL_X, 'the public key');
  if (x.length !== ED25519_KEY_BYTES) {
    throw new CoseError(`an Ed25519 public key must be ${ED25519_KEY_BYTES} bytes, got ${x.length}`);
  }

  return { jwk: { kty: 'OKP', crv: 'Ed25519', x: toBase64Url(x) }, params: 'Ed25519' };
}

function rsaMaterial(map: Map<string | number, CborValue>): CoseKeyMaterial {
  const n = requireBytes(map, LABEL_RSA_N, 'the modulus');
  const e = requireBytes(map, LABEL_RSA_E, 'the exponent');

  const bits = bitLength(n);
  if (bits < MIN_RSA_MODULUS_BITS) {
    throw new CoseError(
      `RSA modulus of ${bits} bits is below the ${MIN_RSA_MODULUS_BITS}-bit minimum`,
    );
  }
  // An upper bound too: verification cost grows with the modulus, so an
  // enormous key is a cheap way to make the server do expensive work.
  if (bits > MAX_RSA_MODULUS_BITS) {
    throw new CoseError(`RSA modulus of ${bits} bits exceeds the ${MAX_RSA_MODULUS_BITS}-bit limit`);
  }

  // e = 1 makes the "signature" the message itself. Even exponents are not
  // valid RSA. Neither should reach a crypto library at all.
  const exponent = bitLength(e);
  if (exponent < 2 || (e[e.length - 1] as number) % 2 === 0) {
    throw new CoseError('invalid RSA public exponent');
  }
  if (exponent > 64) {
    throw new CoseError('implausibly large RSA public exponent');
  }

  return {
    jwk: { kty: 'RSA', n: toBase64Url(n), e: toBase64Url(e) },
    params: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
  };
}

/** A validated COSE key: its algorithm and the material to import it with. */
export interface ParsedCoseKey extends CoseKeyMaterial {
  readonly alg: CoseAlgorithm;
}

/**
 * Parses and validates a COSE public key without importing it.
 *
 * Split out from {@link importCoseKey} because attestation needs the same
 * validated key material as a JWK for `node:crypto`, and the imported
 * `CryptoKey` is deliberately non-extractable — so exporting it back out is
 * not possible, and duplicating the validation would be worse than sharing it.
 *
 * @param bytes    the `credentialPublicKey` from attested credential data.
 * @param allowed  algorithms the relying party accepts. An algorithm absent
 *                 from this list is refused even if this package supports it —
 *                 the decision is the relying party's, not this module's.
 */
export function parseCoseKey(
  bytes: Uint8Array,
  allowed: readonly CoseAlgorithm[] = DEFAULT_ALGORITHMS,
): ParsedCoseKey {
  if (allowed.length === 0) {
    // An empty allowlist can only ever reject, and a check that always fails
    // is nearly always a configuration mistake rather than an intention.
    throw new CoseError('no algorithms are allowed, so no key can be accepted');
  }

  let decoded: CborValue;
  try {
    decoded = decodeCbor(bytes);
  } catch (error) {
    // Re-typed so callers have one error class to catch for "this key is not
    // acceptable", rather than having to know the decoder's own type.
    throw new CoseError(
      `credential public key is not valid CBOR: ${
        error instanceof CborError ? error.message : 'unknown error'
      }`,
    );
  }

  if (!(decoded instanceof Map)) {
    throw new CoseError('credential public key is not a CBOR map');
  }

  const alg = requireInteger(decoded, LABEL_ALG, 'an algorithm');
  if (!allowed.includes(alg as CoseAlgorithm)) {
    throw new CoseError(`algorithm ${alg} is not accepted by this relying party`);
  }
  // Redundant with the check above for any sane allowlist, and kept anyway: it
  // means a caller who widens `allowed` cannot reach an import path that was
  // never written.
  if (!SUPPORTED_ALGORITHMS.includes(alg as CoseAlgorithm)) {
    throw new CoseError(`algorithm ${alg} is not supported`);
  }

  const kty = requireInteger(decoded, LABEL_KTY, 'a key type');

  // Rule 2: the key type must match the algorithm. Refusing the mismatch is
  // the difference between "this key is an EC2 key" and "the attacker told us
  // which code path to take".
  const expectedKty =
    alg === ES256 ? KTY_EC2 : alg === EdDSA ? KTY_OKP : KTY_RSA;
  if (kty !== expectedKty) {
    throw new CoseError(`key type ${kty} does not match algorithm ${alg}`);
  }

  const material =
    kty === KTY_EC2
      ? ec2Material(decoded)
      : kty === KTY_OKP
        ? okpMaterial(decoded)
        : rsaMaterial(decoded);

  return { alg: alg as CoseAlgorithm, ...material };
}

/**
 * Parses and imports a COSE public key as a verification-only `CryptoKey`.
 *
 * @param bytes    the `credentialPublicKey` from attested credential data.
 * @param allowed  algorithms the relying party accepts.
 */
export async function importCoseKey(
  bytes: Uint8Array,
  allowed: readonly CoseAlgorithm[] = DEFAULT_ALGORITHMS,
): Promise<CosePublicKey> {
  const { alg, jwk, params } = parseCoseKey(bytes, allowed);

  let key: webcrypto.CryptoKey;
  try {
    // Non-extractable and verify-only: nothing downstream has a reason to read
    // the key material back out.
    key = await crypto.subtle.importKey('jwk', jwk, params as webcrypto.EcKeyImportParams, false, [
      'verify',
    ]);
  } catch (error) {
    // WebCrypto's own refusals — an off-curve point, a malformed modulus —
    // arrive as DOMException or TypeError. They are still "this key is not
    // acceptable", so they get the same error class as everything else.
    throw new CoseError(
      `the public key could not be imported: ${(error as Error).message ?? 'unknown error'}`,
    );
  }

  return { alg, key };
}

/**
 * Verifies a WebAuthn assertion signature.
 *
 * The algorithm comes from the stored key, never from the request. That is the
 * whole point: an attacker who could choose the verification algorithm at
 * assertion time would simply choose one they can forge.
 */
export async function verifyCoseSignature(
  publicKey: CosePublicKey,
  signature: Uint8Array,
  data: Uint8Array,
): Promise<boolean> {
  switch (publicKey.alg) {
    case ES256: {
      // Authenticators emit DER; WebCrypto wants raw r||s. A malformed
      // encoding is a failed verification, not an exception — the caller asked
      // whether this signature is good, and the answer is no.
      let raw: Uint8Array;
      try {
        raw = derToRawSignature(signature, P256_COORDINATE_BYTES);
      } catch (error) {
        if (error instanceof DerError) return false;
        throw error;
      }
      return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey.key, raw, data);
    }

    case EdDSA:
      // Ed25519 signatures are raw and fixed-width. Checking the length first
      // keeps a malformed input from depending on library-specific behaviour.
      if (signature.length !== 64) return false;
      return crypto.subtle.verify('Ed25519', publicKey.key, signature, data);

    case RS256:
      return crypto.subtle.verify('RSASSA-PKCS1-v1_5', publicKey.key, signature, data);

    default: {
      // Unreachable while CoseAlgorithm stays a closed union — and it fails
      // closed rather than falling through if that ever changes.
      const unreachable: never = publicKey.alg;
      throw new CoseError(`unsupported algorithm: ${String(unreachable)}`);
    }
  }
}
