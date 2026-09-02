/**
 * Attestation statement verification — WebAuthn Level 3, §8.
 *
 * ─── What attestation actually buys you ───────────────────────────────────
 * A normal passkey ceremony proves someone controls a private key. Attestation
 * proves something else: that the key was generated inside a particular *piece
 * of hardware*, vouched for by a certificate chain the manufacturer signed.
 *
 * That is the difference between "a credential" and "a credential on an
 * approved YubiKey", which is the only way to enforce a policy like "company
 * laptops must authenticate with issued hardware".
 *
 * ─── Why trust anchors are mandatory, not optional ────────────────────────
 * The verification below could be run without any trust anchors. It would
 * check that the attestation signature is internally consistent and that the
 * certificate's AAGUID matches the authenticator data — and it would prove
 * nothing at all, because anyone can generate a self-signed CA and put any
 * AAGUID they like in a certificate they issued to themselves.
 *
 * A verifier that reports "attestation verified" in that situation is worse
 * than one with no attestation support: it manufactures confidence. So
 * `packed` attestation is accepted only when the relying party supplies the
 * roots it trusts. If you do not have roots, you do not have attestation, and
 * saying so is the honest answer.
 * ──────────────────────────────────────────────────────────────────────────
 */

import {
  X509Certificate,
  createPublicKey,
  verify as nodeVerify,
  type JsonWebKey as NodeJsonWebKey,
} from 'node:crypto';
import { findExtension, Asn1Error } from './asn1.js';
import { ES256, EdDSA, RS256, parseCoseKey, type CoseAlgorithm } from './cose.js';
import type { CborValue } from './cbor.js';

/** Raised for an attestation statement that will not be accepted. */
export class AttestationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AttestationError';
  }
}

/** What an accepted attestation established. */
export type AttestationType =
  /** No attestation was conveyed. The normal case for passkeys. */
  | 'none'
  /**
   * The credential key signed its own attestation. Proves nothing beyond what
   * the ceremony already proved — there is no manufacturer in the chain.
   */
  | 'self'
  /**
   * A manufacturer certificate chain, verified to a root the relying party
   * trusts. This is the one that means something.
   */
  | 'basic';

/** `id-fido-gen-ce-aaguid` — where FIDO puts the authenticator model id. */
export const FIDO_AAGUID_OID = '1.3.6.1.4.1.45724.1.1.4';

/** Formats this package can actually verify. */
export const VERIFIABLE_FORMATS: readonly string[] = ['none', 'packed'];

/** How deep an attestation chain may be, counting the leaf. */
const MAX_CHAIN_DEPTH = 6;

/** Longest x5c array accepted, before any parsing. */
const MAX_X5C_ENTRIES = 8;

export interface AttestationPolicy {
  /**
   * Formats to accept. Default `['none']`.
   *
   * Adding `'packed'` requires `trustAnchors`; see the note at the top of this
   * file for why that is not optional.
   */
  readonly formats?: readonly string[];
  /**
   * Root certificates, DER-encoded, that may terminate a chain.
   *
   * These are an operational artifact, not library content: which
   * manufacturers you trust is your decision, and it changes without this
   * package changing. FIDO publishes a metadata service that many relying
   * parties draw them from.
   */
  readonly trustAnchors?: readonly Uint8Array[];
  /**
   * AAGUIDs permitted, lowercase hex without separators.
   *
   * Setting this implies a trusted chain: an AAGUID that no manufacturer
   * vouched for is a number the client chose.
   */
  readonly allowedAaguids?: readonly string[];
  /**
   * Accept self-attestation. Default `false`.
   *
   * Off by default because it conveys no hardware provenance, and a relying
   * party that asked for attestation almost certainly wanted provenance.
   */
  readonly allowSelfAttestation?: boolean;
}

export interface AttestationResult {
  readonly format: string;
  readonly type: AttestationType;
  /**
   * Whether the AAGUID was vouched for by a trusted chain.
   *
   * `false` means the value in the authenticator data is self-asserted by the
   * client and must not be used for policy.
   */
  readonly aaguidVerified: boolean;
  /** Lowercase hex, from the authenticator data. */
  readonly aaguid: string;
  /** Subject of the leaf certificate, when there was one. */
  readonly attestationSubject: string | undefined;
}

export interface VerifyAttestationInput {
  readonly format: string;
  /** The decoded `attStmt` map. */
  readonly statement: Map<string | number, CborValue>;
  /** Raw authenticator data, as signed. */
  readonly authData: Uint8Array;
  readonly clientDataHash: Uint8Array;
  /** AAGUID from the attested credential data. */
  readonly aaguid: Uint8Array;
  /** The credential's COSE key, needed for self-attestation. */
  readonly credentialPublicKey: Uint8Array;
  /** The algorithm the credential key uses. */
  readonly credentialAlgorithm: CoseAlgorithm;
}

const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/**
 * Verifies a signature with a certificate's or credential's key.
 *
 * The digest comes from the COSE algorithm identifier, never from the
 * signature or the certificate — the same rule the rest of this package
 * follows, for the same reason.
 */
function verifySignature(
  alg: CoseAlgorithm,
  key: ReturnType<typeof createPublicKey>,
  data: Uint8Array,
  signature: Uint8Array,
): boolean {
  const keyType = key.asymmetricKeyType;

  // The key type must match the algorithm. Without this the digest and the
  // key could disagree, and what a library does then is not something to rely
  // on.
  const expected = alg === RS256 ? 'rsa' : alg === EdDSA ? 'ed25519' : 'ec';
  if (keyType !== expected) return false;

  try {
    // Ed25519 takes no separate digest; the others take SHA-256. ECDSA
    // signatures here are DER, which is what node:crypto expects.
    return alg === EdDSA
      ? nodeVerify(null, data, key, signature)
      : nodeVerify('sha256', data, key, signature);
  } catch {
    // A malformed signature is a failed verification, not an exception: the
    // caller asked whether this signature is good and the answer is no.
    return false;
  }
}

/** Reads the AAGUID a certificate claims, if it carries the FIDO extension. */
function certificateAaguid(certificate: Uint8Array): Uint8Array | undefined {
  let value: Uint8Array | undefined;
  try {
    value = findExtension(certificate, FIDO_AAGUID_OID);
  } catch (error) {
    throw new AttestationError(
      `attestation certificate could not be read: ${
        error instanceof Asn1Error ? error.message : 'unknown error'
      }`,
    );
  }
  if (value === undefined) return undefined;

  // The extension value wraps the AAGUID in its own OCTET STRING: tag 0x04,
  // length 0x10, then sixteen bytes.
  if (value.length !== 18 || value[0] !== 0x04 || value[1] !== 0x10) {
    throw new AttestationError('the AAGUID extension is not a 16-byte OCTET STRING');
  }
  return value.subarray(2);
}

/**
 * Walks from the leaf up to a trusted root.
 *
 * Each step must both verify cryptographically and name its issuer correctly,
 * and every certificate must be inside its validity window. Returns whether a
 * trust anchor was reached — never a partial result, because "the chain was
 * fine until it wasn't" is not a security answer.
 */
function chainReachesAnchor(chain: X509Certificate[], anchors: X509Certificate[]): boolean {
  const now = new Date();
  const valid = (cert: X509Certificate): boolean =>
    cert.validFromDate <= now && now <= cert.validToDate;

  let current: X509Certificate | undefined = chain[0];
  if (current === undefined || !valid(current)) return false;

  for (let depth = 0; depth < MAX_CHAIN_DEPTH; depth += 1) {
    const certificate: X509Certificate = current;

    // A trust anchor that issued this certificate ends the walk successfully.
    const anchor = anchors.find(
      (candidate) =>
        valid(candidate) && certificate.checkIssued(candidate) && certificate.verify(candidate.publicKey),
    );
    if (anchor !== undefined) return true;

    // Otherwise continue through an intermediate the client supplied. It must
    // be a CA, or anything could sign for anything.
    const issuer: X509Certificate | undefined = chain.find(
      (candidate) =>
        candidate !== certificate &&
        candidate.ca &&
        valid(candidate) &&
        certificate.checkIssued(candidate) &&
        certificate.verify(candidate.publicKey),
    );
    if (issuer === undefined) return false;

    current = issuer;
  }

  // Ran out of depth without reaching an anchor. A chain this long is not one
  // a real authenticator produces.
  return false;
}

/** Reads and validates the `x5c` array from an attestation statement. */
function readX5c(statement: Map<string | number, CborValue>): X509Certificate[] | undefined {
  const x5c = statement.get('x5c');
  if (x5c === undefined) return undefined;

  if (!Array.isArray(x5c) || x5c.length === 0) {
    throw new AttestationError('x5c is present but not a non-empty array');
  }
  if (x5c.length > MAX_X5C_ENTRIES) {
    throw new AttestationError(`x5c carries ${x5c.length} certificates, which is implausible`);
  }

  return x5c.map((entry) => {
    if (!(entry instanceof Uint8Array)) {
      throw new AttestationError('every x5c entry must be a byte string');
    }
    try {
      return new X509Certificate(Buffer.from(entry));
    } catch {
      throw new AttestationError('an x5c entry is not a valid certificate');
    }
  });
}

/**
 * Verifies an attestation statement against a relying party's policy.
 *
 * @throws {AttestationError} whenever the statement is not acceptable. There
 *   is no partial success: a caller receiving a result may treat every field
 *   in it as established.
 */
export async function verifyAttestation(
  input: VerifyAttestationInput,
  policy: AttestationPolicy = {},
): Promise<AttestationResult> {
  const formats = policy.formats ?? ['none'];
  const aaguidHex = toHex(input.aaguid);

  if (!formats.includes(input.format)) {
    throw new AttestationError(`attestation format ${input.format} is not accepted`);
  }
  if (!VERIFIABLE_FORMATS.includes(input.format)) {
    // Reached only if a caller allowlisted a format this package cannot check.
    // Refusing here means no arrangement of options produces an unverified
    // attestation reported as a verified one.
    throw new AttestationError(`attestation format ${input.format} cannot be verified`);
  }

  if (input.format === 'none') {
    if (input.statement.size > 0) {
      // §8.7: the statement for `none` must be empty. Data hiding in a field
      // nobody reads is data nobody is checking.
      throw new AttestationError('the none attestation statement must be empty');
    }
    if (policy.allowedAaguids !== undefined) {
      throw new AttestationError(
        'allowedAaguids requires attestation; the none format vouches for no AAGUID',
      );
    }
    return {
      format: 'none',
      type: 'none',
      aaguidVerified: false,
      aaguid: aaguidHex,
      attestationSubject: undefined,
    };
  }

  // ── packed ───────────────────────────────────────────────────────────────

  const alg = input.statement.get('alg');
  const sig = input.statement.get('sig');

  if (typeof alg !== 'number') {
    throw new AttestationError('the attestation statement has no algorithm');
  }
  if (!(sig instanceof Uint8Array) || sig.length === 0) {
    throw new AttestationError('the attestation statement has no signature');
  }
  if (![ES256, EdDSA, RS256].includes(alg as CoseAlgorithm)) {
    throw new AttestationError(`attestation algorithm ${alg} is not supported`);
  }

  // The signed bytes, per §8.2 step 2.
  const signedData = new Uint8Array(input.authData.length + input.clientDataHash.length);
  signedData.set(input.authData, 0);
  signedData.set(input.clientDataHash, input.authData.length);

  const chain = readX5c(input.statement);

  if (chain === undefined) {
    // Self-attestation: the credential key signed its own statement.
    if (policy.allowSelfAttestation !== true) {
      throw new AttestationError('self-attestation is not accepted');
    }
    if (alg !== input.credentialAlgorithm) {
      // §8.2 step 4: the algorithms must agree, or this is not the credential
      // key signing for itself.
      throw new AttestationError('self-attestation algorithm does not match the credential key');
    }
    if (policy.allowedAaguids !== undefined) {
      throw new AttestationError(
        'allowedAaguids cannot be enforced against self-attestation, which vouches for no AAGUID',
      );
    }

    const credentialKey = credentialKeyForNode(input.credentialPublicKey, alg as CoseAlgorithm);
    if (!verifySignature(alg as CoseAlgorithm, credentialKey, signedData, sig)) {
      throw new AttestationError('the self-attestation signature did not verify');
    }

    return {
      format: 'packed',
      type: 'self',
      // Self-attestation vouches for nothing, and saying otherwise here is
      // exactly the false confidence this module exists to avoid.
      aaguidVerified: false,
      aaguid: aaguidHex,
      attestationSubject: undefined,
    };
  }

  // Basic attestation.
  const anchors = policy.trustAnchors ?? [];
  if (anchors.length === 0) {
    throw new AttestationError(
      'packed attestation requires trustAnchors; without roots, a chain proves nothing',
    );
  }

  const leaf = chain[0] as X509Certificate;

  // §8.2.1: the attestation certificate must not be a CA. A CA certificate
  // presented as a leaf could sign for other authenticators too.
  if (leaf.ca) {
    throw new AttestationError('the attestation certificate must not be a CA certificate');
  }

  if (!verifySignature(alg as CoseAlgorithm, leaf.publicKey, signedData, sig)) {
    throw new AttestationError('the attestation signature did not verify');
  }

  // If the certificate names an AAGUID it must be the one in the authenticator
  // data. A mismatch means the statement was lifted from another device.
  const certAaguid = certificateAaguid(new Uint8Array(leaf.raw));
  if (certAaguid !== undefined && !bytesEqual(certAaguid, input.aaguid)) {
    throw new AttestationError('the certificate AAGUID does not match the authenticator data');
  }

  let anchorCertificates: X509Certificate[];
  try {
    anchorCertificates = anchors.map((der) => new X509Certificate(Buffer.from(der)));
  } catch {
    throw new AttestationError('a configured trust anchor is not a valid certificate');
  }

  if (!chainReachesAnchor(chain, anchorCertificates)) {
    throw new AttestationError('the attestation chain does not reach a trusted root');
  }

  // Only now is the AAGUID worth anything: a root the relying party trusts has
  // vouched for the device that holds this key.
  if (policy.allowedAaguids !== undefined && !policy.allowedAaguids.includes(aaguidHex)) {
    throw new AttestationError(`authenticator model ${aaguidHex} is not on the allowed list`);
  }

  return {
    format: 'packed',
    type: 'basic',
    aaguidVerified: true,
    aaguid: aaguidHex,
    attestationSubject: leaf.subject,
  };
}

/**
 * Reads a COSE credential key as a node KeyObject, for self-attestation.
 *
 * Goes through `parseCoseKey` rather than `importCoseKey` because the latter
 * produces a deliberately non-extractable `CryptoKey` — there is no route from
 * one back to a JWK, which is the point of it. `parseCoseKey` applies exactly
 * the same validation and stops one step earlier.
 */
function credentialKeyForNode(
  credentialPublicKey: Uint8Array,
  alg: CoseAlgorithm,
): ReturnType<typeof createPublicKey> {
  const { jwk } = parseCoseKey(credentialPublicKey, [alg]);
  try {
    return createPublicKey({ key: jwk as NodeJsonWebKey, format: 'jwk' });
  } catch {
    throw new AttestationError('the credential public key could not be read');
  }
}
