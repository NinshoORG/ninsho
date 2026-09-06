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
 * than one with no attestation support: it manufactures confidence. So every
 * format that carries a chain — which is every format but `none` — is accepted
 * only when the relying party supplies the roots it trusts. If you do not have
 * roots, you do not have attestation, and saying so is the honest answer.
 * ──────────────────────────────────────────────────────────────────────────
 */

import {
  X509Certificate,
  createPublicKey,
  verify as nodeVerify,
  type JsonWebKey as NodeJsonWebKey,
} from 'node:crypto';
import { findExtension, readTlv, encodeOid, Asn1Error } from './asn1.js';
import {
  ANDROID_KEY_ATTESTATION_OID,
  AndroidKeyError,
  parseKeyDescription,
  verifyAuthorizations,
} from './android-key.js';
import {
  SAFETYNET_HOSTNAME,
  SafetyNetError,
  parseSafetyNetResponse,
  verifySafetyNetVerdicts,
} from './safetynet.js';
import {
  TpmError,
  parseTpmAttest,
  parseTpmPublic,
  verifyAttestedName,
  verifyPublicKeyMatches,
} from './tpm.js';
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
export const VERIFIABLE_FORMATS: readonly string[] = [
  'none',
  'packed',
  'apple',
  'tpm',
  'fido-u2f',
  'android-key',
  'android-safetynet',
];

/** How deep an attestation chain may be, counting the leaf. */
const MAX_CHAIN_DEPTH = 6;

/** Longest x5c array accepted, before any parsing. */
const MAX_X5C_ENTRIES = 8;

export interface AttestationPolicy {
  /**
   * Formats to accept. Default `['none']`.
   *
   * Anything but `'none'` requires `trustAnchors`; see the note at the top of
   * this file for why that is not optional.
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
   * vouched for is a number the client chose. It cannot be combined with
   * `fido-u2f`, which conveys no AAGUID at all.
   */
  readonly allowedAaguids?: readonly string[];
  /**
   * Accept self-attestation. Default `false`.
   *
   * Off by default because it conveys no hardware provenance, and a relying
   * party that asked for attestation almost certainly wanted provenance.
   */
  readonly allowSelfAttestation?: boolean;
  /**
   * Read `android-key` authorizations from the software-enforced list as well
   * as the hardware-enforced one. Default `false`.
   *
   * WebAuthn §8.4 permits either. Off by default because a software-enforced
   * authorization list is the Android OS vouching for itself, and if the OS's
   * word were enough there would be no reason to be doing attestation. Turn it
   * on if emulators or devices without a TEE have to be able to register, and
   * know that what you get back is no longer a hardware claim.
   */
  readonly allowSoftwareEnforcedAndroidKey?: boolean;
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
  /**
   * The credential id from the attested credential data.
   *
   * `fido-u2f` signs over it explicitly, so it is not derivable from anything
   * else here.
   */
  readonly credentialId: Uint8Array;
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
export function verifySignature(
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
export function chainReachesAnchor(
  chain: X509Certificate[],
  anchors: X509Certificate[],
): boolean {
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
 * `id-apple-anonymous-attestation` — where Apple puts the ceremony nonce.
 *
 * The extension value is `SEQUENCE { [1] { OCTET STRING nonce } }`.
 */
const APPLE_NONCE_OID = '1.2.840.113635.100.8.2';

/**
 * Reads the nonce Apple embeds in the credential certificate.
 *
 * Parsed rather than pattern-matched: the nonce is the entire binding between
 * the certificate and this ceremony, so reading it out of the wrong place — or
 * accepting a structure that merely happens to contain the right bytes — would
 * make the check pass for a certificate issued for something else.
 */
function appleNonce(certificate: Uint8Array): Uint8Array {
  let extension: Uint8Array | undefined;
  try {
    extension = findExtension(certificate, APPLE_NONCE_OID);
  } catch (error) {
    throw new AttestationError(
      `credential certificate could not be read: ${
        error instanceof Asn1Error ? error.message : 'unknown error'
      }`,
    );
  }
  if (extension === undefined) {
    throw new AttestationError('the credential certificate carries no Apple nonce extension');
  }

  try {
    // SEQUENCE → [1] → OCTET STRING.
    const outer = readTlv(extension, 0);
    if (outer.tag !== 0x30) throw new Asn1Error('nonce extension is not a SEQUENCE');

    const context = readTlv(extension, outer.start);
    if (context.tag !== 0xa1) throw new Asn1Error('nonce extension has no [1] element');

    const octets = readTlv(extension, context.start);
    if (octets.tag !== 0x04) throw new Asn1Error('nonce is not an OCTET STRING');

    return extension.subarray(octets.start, octets.end);
  } catch (error) {
    throw new AttestationError(
      `the Apple nonce extension is malformed: ${
        error instanceof Asn1Error ? error.message : 'unknown error'
      }`,
    );
  }
}

/**
 * Verifies Apple Anonymous Attestation — WebAuthn §8.8.
 *
 * ─── Why this format has no signature field ───────────────────────────────
 * `packed` carries a signature over `authData || clientDataHash`, and checking
 * it is what ties the statement to the ceremony. Apple's format has no `sig`
 * at all, which looks alarming until you see what replaces it: the certificate
 * itself carries a nonce equal to `SHA-256(authData || clientDataHash)`, put
 * there by Apple when it issued the certificate for *this* ceremony.
 *
 * So the binding is the same strength and arrives differently. A certificate
 * from another ceremony carries another nonce and is refused; the relying
 * party still has to trust the chain, which is why anchors remain mandatory.
 *
 * The second check is the one easy to leave out: the certificate's public key
 * must be the credential's public key. Without it a valid Apple certificate
 * could be presented alongside a credential key an attacker controls.
 */
async function verifyAppleAttestation(
  input: VerifyAttestationInput,
  chain: X509Certificate[],
  anchors: X509Certificate[],
): Promise<void> {
  const credCert = chain[0] as X509Certificate;

  // §8.8 steps 2-3: the nonce is a hash of exactly what was signed elsewhere.
  const nonceToHash = new Uint8Array(input.authData.length + input.clientDataHash.length);
  nonceToHash.set(input.authData, 0);
  nonceToHash.set(input.clientDataHash, input.authData.length);
  const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', nonceToHash));

  // §8.8 step 4.
  if (!bytesEqual(appleNonce(new Uint8Array(credCert.raw)), expected)) {
    throw new AttestationError('the Apple attestation nonce does not match this ceremony');
  }

  // §8.8 step 5. Without this a genuine Apple certificate could be presented
  // beside a credential key the attacker holds, and everything else would
  // still check out.
  if (!certificateHoldsCredentialKey(credCert, input)) {
    throw new AttestationError(
      'the credential public key does not match the attestation certificate',
    );
  }

  if (!chainReachesAnchor(chain, anchors)) {
    throw new AttestationError('the attestation chain does not reach a trusted root');
  }
}

/** `extendedKeyUsage`. */
const EKU_OID = '2.5.29.37';

/** `tcg-kp-AIKCertificate` — the usage an attestation identity key must declare. */
const AIK_CERTIFICATE_OID = '2.23.133.8.3';

/**
 * Whether a certificate declares an extended key usage.
 *
 * The extension is a `SEQUENCE OF OID`, and the comparison is on encoded bytes
 * rather than on decoded strings — the same reasoning as `findExtension`, where
 * decoding introduces a second place for two implementations to disagree.
 */
function hasExtendedKeyUsage(certificate: Uint8Array, oid: string): boolean {
  let extension: Uint8Array | undefined;
  try {
    extension = findExtension(certificate, EKU_OID);
  } catch {
    return false;
  }
  if (extension === undefined) return false;

  const target = encodeOid(oid);
  try {
    const sequence = readTlv(extension, 0);
    if (sequence.tag !== 0x30) return false;

    let offset = sequence.start;
    while (offset < sequence.end) {
      const entry = readTlv(extension, offset);
      if (
        entry.tag === 0x06 &&
        entry.end - entry.start === target.length &&
        extension.subarray(entry.start, entry.end).every((b, i) => b === target[i])
      ) {
        return true;
      }
      offset = entry.next;
    }
  } catch {
    return false;
  }
  return false;
}

/**
 * The credential key as raw material, for comparison against `pubArea`.
 *
 * Goes through `parseCoseKey` so the same validation applies — an undersized
 * RSA modulus is refused here exactly as it is anywhere else.
 */
function credentialKeyMaterial(
  credentialPublicKey: Uint8Array,
  alg: CoseAlgorithm,
): { kty: string; n?: Uint8Array; e?: number; x?: Uint8Array; y?: Uint8Array } {
  const { jwk } = parseCoseKey(credentialPublicKey, [alg]);
  const decode = (value: string | undefined): Uint8Array | undefined =>
    value === undefined ? undefined : new Uint8Array(Buffer.from(value, 'base64url'));

  if (jwk.kty === 'RSA') {
    const exponentBytes = decode(jwk.e as string | undefined);
    let exponent: number | undefined;
    if (exponentBytes !== undefined) {
      exponent = 0;
      for (const byte of exponentBytes) exponent = exponent * 256 + byte;
    }
    return {
      kty: 'RSA',
      ...(decode(jwk.n as string | undefined) !== undefined && {
        n: decode(jwk.n as string | undefined) as Uint8Array,
      }),
      ...(exponent !== undefined && { e: exponent }),
    };
  }

  return {
    kty: 'EC',
    ...(decode(jwk.x as string | undefined) !== undefined && {
      x: decode(jwk.x as string | undefined) as Uint8Array,
    }),
    ...(decode(jwk.y as string | undefined) !== undefined && {
      y: decode(jwk.y as string | undefined) as Uint8Array,
    }),
  };
}

/**
 * The raw uncompressed P-256 point U2F signs over: `0x04 || x || y`.
 *
 * U2F predates COSE. The signature is over the key in the shape a U2F
 * authenticator had it in, so the COSE key has to be converted back rather
 * than hashed or re-encoded — a mismatch here would look like a bad signature
 * and be blamed on the wrong thing.
 */
function u2fPublicKey(credentialPublicKey: Uint8Array): Uint8Array {
  const { jwk } = parseCoseKey(credentialPublicKey, [ES256]);
  const x = Buffer.from((jwk.x as string | undefined) ?? '', 'base64url');
  const y = Buffer.from((jwk.y as string | undefined) ?? '', 'base64url');

  // §8.6 assumes P-256 throughout; a coordinate of any other length is not a
  // key this format can describe.
  if (x.length !== 32 || y.length !== 32) {
    throw new AttestationError('the credential key is not a P-256 point');
  }

  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(x, 1);
  out.set(y, 33);
  return out;
}

/**
 * Verifies FIDO U2F attestation — WebAuthn §8.6.
 *
 * ─── What this format is, and what it is not ──────────────────────────────
 * This is the shape a CTAP1 security key produces: the older YubiKeys and
 * everything else that shipped before CTAP2. The signature is over a flat
 * concatenation rather than over `authData`, and it names the credential
 * explicitly — `0x00 || rpIdHash || clientDataHash || credentialId ||
 * publicKeyU2F` — so the binding to this credential and this ceremony is
 * direct, with none of the indirection TPM attestation carries.
 *
 * What it does *not* carry is an AAGUID. U2F has no model identifier, and the
 * browser zeroes the field. So a verified U2F attestation proves the credential
 * lives on hardware a trusted manufacturer vouched for, and proves nothing
 * about *which model* — `aaguidVerified` stays false, and an `allowedAaguids`
 * policy can never be satisfied by this format. Reporting otherwise would put
 * a manufacturer's name behind sixteen zero bytes the client chose.
 * ──────────────────────────────────────────────────────────────────────────
 */
async function verifyU2fAttestation(
  input: VerifyAttestationInput,
  chain: X509Certificate[],
  anchors: X509Certificate[],
): Promise<void> {
  const sig = input.statement.get('sig');
  if (!(sig instanceof Uint8Array) || sig.length === 0) {
    throw new AttestationError('the u2f statement has no signature');
  }

  // §8.6 step 1: exactly one certificate. U2F has no intermediates in the
  // statement, and accepting a longer chain would mean accepting a leaf chosen
  // from a list the client supplied.
  if (chain.length !== 1) {
    throw new AttestationError(
      `u2f attestation carries ${chain.length} certificates; §8.6 permits exactly one`,
    );
  }

  const attCert = chain[0] as X509Certificate;

  // §8.6 step 2. The algorithm is fixed by the format, not chosen by the
  // statement — there is no `alg` field here to be talked out of.
  const details = attCert.publicKey.asymmetricKeyDetails;
  if (attCert.publicKey.asymmetricKeyType !== 'ec' || details?.namedCurve !== 'prime256v1') {
    throw new AttestationError('the u2f attestation certificate is not P-256');
  }
  if (input.credentialAlgorithm !== ES256) {
    throw new AttestationError('u2f credentials are P-256 only');
  }

  const publicKeyU2F = u2fPublicKey(input.credentialPublicKey);

  // §8.6 step 4. The leading zero byte is a reserved constant, not padding:
  // it is what stops this signature being replayed as a U2F *authentication*
  // response, which is signed over a different structure with a different
  // first byte.
  const rpIdHash = input.authData.subarray(0, 32);
  const verificationData = new Uint8Array(
    1 + rpIdHash.length + input.clientDataHash.length + input.credentialId.length + 65,
  );
  let offset = 0;
  verificationData[offset] = 0x00;
  offset += 1;
  verificationData.set(rpIdHash, offset);
  offset += rpIdHash.length;
  verificationData.set(input.clientDataHash, offset);
  offset += input.clientDataHash.length;
  verificationData.set(input.credentialId, offset);
  offset += input.credentialId.length;
  verificationData.set(publicKeyU2F, offset);

  if (!verifySignature(ES256, attCert.publicKey, verificationData, sig)) {
    throw new AttestationError('the u2f attestation signature did not verify');
  }

  if (!chainReachesAnchor(chain, anchors)) {
    throw new AttestationError('the attestation chain does not reach a trusted root');
  }
}

/**
 * Whether a certificate's subject public key is the credential's public key.
 *
 * The check `apple` and `android-key` both turn on. Without it a genuine
 * attestation certificate could be presented beside a credential key the
 * attacker generated, and every signature in sight would still verify.
 *
 * Compared as SPKI rather than field by field, so the two encodings have to
 * agree completely rather than in the parts a comparison remembered to look
 * at.
 */
function certificateHoldsCredentialKey(
  certificate: X509Certificate,
  input: VerifyAttestationInput,
): boolean {
  let credentialSpki: Buffer;
  try {
    const { jwk } = parseCoseKey(input.credentialPublicKey, [input.credentialAlgorithm]);
    credentialSpki = createPublicKey({ key: jwk as NodeJsonWebKey, format: 'jwk' }).export({
      type: 'spki',
      format: 'der',
    });
  } catch {
    throw new AttestationError('the credential public key could not be read');
  }

  const certificateSpki = certificate.publicKey.export({ type: 'spki', format: 'der' });
  return bytesEqual(new Uint8Array(credentialSpki), new Uint8Array(certificateSpki));
}

/**
 * Verifies Android Keystore attestation — WebAuthn §8.4.
 *
 * The signature is over the ceremony, as `packed`'s is, and the certificate
 * holds the credential key. What makes the format mean anything beyond a
 * self-signed chain is the extension Keystore writes into the certificate it
 * issues: see `android-key.ts` for what is read out of it and why the
 * hardware-enforced list is the default one to read.
 */
async function verifyAndroidKeyAttestation(
  input: VerifyAttestationInput,
  chain: X509Certificate[],
  anchors: X509Certificate[],
  alg: CoseAlgorithm,
  allowSoftwareEnforced: boolean,
): Promise<void> {
  const sig = input.statement.get('sig');
  if (!(sig instanceof Uint8Array) || sig.length === 0) {
    throw new AttestationError('the android-key statement has no signature');
  }

  const attCert = chain[0] as X509Certificate;

  // §8.4 step 2.
  const signedData = new Uint8Array(input.authData.length + input.clientDataHash.length);
  signedData.set(input.authData, 0);
  signedData.set(input.clientDataHash, input.authData.length);

  if (!verifySignature(alg, attCert.publicKey, signedData, sig)) {
    throw new AttestationError('the android-key attestation signature did not verify');
  }

  // §8.4 step 3.
  if (!certificateHoldsCredentialKey(attCert, input)) {
    throw new AttestationError(
      'the credential public key does not match the attestation certificate',
    );
  }

  // §8.4 steps 4-6, all of them read out of the Keystore extension.
  let extensionBytes: Uint8Array | undefined;
  try {
    extensionBytes = findExtension(new Uint8Array(attCert.raw), ANDROID_KEY_ATTESTATION_OID);
  } catch (error) {
    throw new AttestationError(
      `attestation certificate could not be read: ${
        error instanceof Asn1Error ? error.message : 'unknown error'
      }`,
    );
  }
  if (extensionBytes === undefined) {
    throw new AttestationError(
      'the attestation certificate carries no Android key attestation extension',
    );
  }

  let description;
  try {
    description = parseKeyDescription(extensionBytes);
    verifyAuthorizations(description, allowSoftwareEnforced);
  } catch (error) {
    throw new AttestationError(
      error instanceof AndroidKeyError
        ? error.message
        : 'the Android key description could not be read',
    );
  }

  // §8.4 step 4. The challenge is fixed when the key is *generated*, so a
  // certificate carrying this ceremony's client data hash is one Keystore
  // minted for this registration — which is what stops a certificate from an
  // earlier ceremony being presented here.
  if (!bytesEqual(description.attestationChallenge, input.clientDataHash)) {
    throw new AttestationError('the attestation challenge is not this ceremony’s client data hash');
  }

  if (!chainReachesAnchor(chain, anchors)) {
    throw new AttestationError('the attestation chain does not reach a trusted root');
  }
}

/**
 * Verifies TPM attestation — WebAuthn §8.3.
 *
 * A TPM does not sign the ceremony. It signs a statement about a key it
 * certifies, and the tie to the ceremony runs through two indirections that
 * both have to be checked: `extraData` binds the statement to this
 * registration, and `attested.name` binds it to a particular key. Verifying
 * one without the other leaves a genuine TPM signature vouching for something
 * it never attested to.
 */
async function verifyTpmAttestation(
  input: VerifyAttestationInput,
  chain: X509Certificate[],
  anchors: X509Certificate[],
  alg: CoseAlgorithm,
): Promise<void> {
  const statement = input.statement;

  const ver = statement.get('ver');
  const sig = statement.get('sig');
  const certInfo = statement.get('certInfo');
  const pubArea = statement.get('pubArea');

  if (ver !== '2.0') {
    throw new AttestationError(`unsupported TPM version: ${String(ver)}`);
  }
  if (!(sig instanceof Uint8Array) || sig.length === 0) {
    throw new AttestationError('the TPM statement has no signature');
  }
  if (!(certInfo instanceof Uint8Array) || !(pubArea instanceof Uint8Array)) {
    throw new AttestationError('the TPM statement is missing certInfo or pubArea');
  }

  // §8.3 step 2: the key the TPM certified must be the credential key.
  let parsedPublic;
  try {
    parsedPublic = parseTpmPublic(pubArea);
    verifyPublicKeyMatches(parsedPublic, credentialKeyMaterial(input.credentialPublicKey, alg));
  } catch (error) {
    // Either the TPM structure was malformed, or the credential key it claims
    // to certify was not acceptable. Both are "this attestation is not good".
    throw new AttestationError(
      error instanceof TpmError || error instanceof Error
        ? (error as Error).message
        : 'pubArea could not be read',
    );
  }

  // §8.3 steps 3-4.
  const attToBeSigned = new Uint8Array(input.authData.length + input.clientDataHash.length);
  attToBeSigned.set(input.authData, 0);
  attToBeSigned.set(input.clientDataHash, input.authData.length);

  let attest;
  try {
    attest = parseTpmAttest(certInfo);
  } catch (error) {
    throw new AttestationError(
      error instanceof TpmError ? error.message : 'certInfo could not be read',
    );
  }

  const expectedExtraData = new Uint8Array(await crypto.subtle.digest('SHA-256', attToBeSigned));
  if (!bytesEqual(attest.extraData, expectedExtraData)) {
    throw new AttestationError('certInfo.extraData does not hash this ceremony');
  }

  try {
    await verifyAttestedName(attest.attestedName, pubArea);
  } catch (error) {
    throw new AttestationError(
      error instanceof TpmError ? error.message : 'the attested name could not be checked',
    );
  }

  // §8.3 step 5: the signature is over certInfo, not over the ceremony.
  const aikCert = chain[0] as X509Certificate;
  if (!verifySignature(alg, aikCert.publicKey, certInfo, sig)) {
    throw new AttestationError('the TPM attestation signature did not verify');
  }

  // §8.3.1: what an attestation identity key certificate must look like.
  const aikRaw = new Uint8Array(aikCert.raw);
  if (aikCert.ca) {
    throw new AttestationError('the AIK certificate must not be a CA certificate');
  }
  // §8.3.1 requires an empty subject; the identity lives in the SAN so the
  // certificate does not become a device identifier. node reports an empty
  // distinguished name as `undefined` rather than '', and the empty case is
  // the *expected* one here — so this cannot take the declared type at its
  // word without turning every genuine TPM registration into a TypeError.
  const aikSubject = (aikCert.subject as string | undefined) ?? '';
  if (aikSubject.trim().length > 0) {
    throw new AttestationError('the AIK certificate subject must be empty');
  }
  if (!hasExtendedKeyUsage(aikRaw, AIK_CERTIFICATE_OID)) {
    throw new AttestationError(
      'the AIK certificate does not declare the tcg-kp-AIKCertificate extended key usage',
    );
  }

  if (!chainReachesAnchor(chain, anchors)) {
    throw new AttestationError('the attestation chain does not reach a trusted root');
  }
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

  // ── apple ────────────────────────────────────────────────────────────────
  // Handled before `packed`, because it carries no `alg` or `sig` and the
  // checks below would reject it for lacking fields it never has.

  if (input.format === 'apple') {
    const appleChain = readX5c(input.statement);
    if (appleChain === undefined) {
      throw new AttestationError('apple attestation requires an x5c chain');
    }

    const appleAnchors = policy.trustAnchors ?? [];
    if (appleAnchors.length === 0) {
      throw new AttestationError(
        'apple attestation requires trustAnchors; without roots, a chain proves nothing',
      );
    }

    let anchorCerts: X509Certificate[];
    try {
      anchorCerts = appleAnchors.map((der) => new X509Certificate(Buffer.from(der)));
    } catch {
      throw new AttestationError('a configured trust anchor is not a valid certificate');
    }

    await verifyAppleAttestation(input, appleChain, anchorCerts);

    if (policy.allowedAaguids !== undefined && !policy.allowedAaguids.includes(aaguidHex)) {
      throw new AttestationError(`authenticator model ${aaguidHex} is not on the allowed list`);
    }

    return {
      format: 'apple',
      // Apple issues these through an anonymization CA, so the chain vouches
      // for the platform rather than for an individual device — which is the
      // point: it attests without being a tracking identifier.
      type: 'basic',
      aaguidVerified: true,
      aaguid: aaguidHex,
      attestationSubject: (appleChain[0] as X509Certificate).subject,
    };
  }

  // ── tpm ──────────────────────────────────────────────────────────────────

  if (input.format === 'tpm') {
    const tpmAlg = input.statement.get('alg');
    if (typeof tpmAlg !== 'number' || ![ES256, RS256].includes(tpmAlg as CoseAlgorithm)) {
      throw new AttestationError(`unsupported TPM attestation algorithm: ${String(tpmAlg)}`);
    }

    const tpmChain = readX5c(input.statement);
    if (tpmChain === undefined) {
      throw new AttestationError('tpm attestation requires an x5c chain');
    }

    const tpmAnchors = policy.trustAnchors ?? [];
    if (tpmAnchors.length === 0) {
      throw new AttestationError(
        'tpm attestation requires trustAnchors; without roots, a chain proves nothing',
      );
    }

    let anchorCerts: X509Certificate[];
    try {
      anchorCerts = tpmAnchors.map((der) => new X509Certificate(Buffer.from(der)));
    } catch {
      throw new AttestationError('a configured trust anchor is not a valid certificate');
    }

    await verifyTpmAttestation(input, tpmChain, anchorCerts, tpmAlg as CoseAlgorithm);

    if (policy.allowedAaguids !== undefined && !policy.allowedAaguids.includes(aaguidHex)) {
      throw new AttestationError(`authenticator model ${aaguidHex} is not on the allowed list`);
    }

    return {
      format: 'tpm',
      type: 'basic',
      aaguidVerified: true,
      aaguid: aaguidHex,
      attestationSubject: (tpmChain[0] as X509Certificate).issuer,
    };
  }

  // ── android-safetynet ────────────────────────────────────────────────────
  // The chain of trust runs through Google rather than through the device, so
  // this branch checks a document Google composed rather than anything the
  // authenticator produced. See `safetynet.ts` for what that costs.

  if (input.format === 'android-safetynet') {
    const ver = input.statement.get('ver');
    if (typeof ver !== 'string' || ver.length === 0) {
      throw new AttestationError('the SafetyNet statement names no Play Services version');
    }

    const raw = input.statement.get('response');
    if (!(raw instanceof Uint8Array) || raw.length === 0) {
      throw new AttestationError('the SafetyNet statement carries no response');
    }

    const safetyNetAnchors = policy.trustAnchors ?? [];
    if (safetyNetAnchors.length === 0) {
      throw new AttestationError(
        'android-safetynet attestation requires trustAnchors; without roots, a chain proves nothing',
      );
    }

    let response;
    try {
      response = parseSafetyNetResponse(raw);
    } catch (error) {
      throw new AttestationError(
        error instanceof SafetyNetError ? error.message : 'the SafetyNet response could not be read',
      );
    }

    let chain: X509Certificate[];
    let anchorCerts: X509Certificate[];
    try {
      chain = response.certificates.map((der) => new X509Certificate(Buffer.from(der)));
    } catch {
      throw new AttestationError('the SafetyNet chain holds something that is not a certificate');
    }
    try {
      anchorCerts = safetyNetAnchors.map((der) => new X509Certificate(Buffer.from(der)));
    } catch {
      throw new AttestationError('a configured trust anchor is not a valid certificate');
    }

    const leaf = chain[0] as X509Certificate;

    // §8.5 step 3. The response is only Google's if Google's certificate signed
    // it, and Google's certificate is the one issued to this hostname.
    if (leaf.checkHost(SAFETYNET_HOSTNAME) === undefined) {
      throw new AttestationError(
        `the SafetyNet certificate is not issued to ${SAFETYNET_HOSTNAME}`,
      );
    }

    if (!verifySignature(RS256, leaf.publicKey, response.signingInput, response.signature)) {
      throw new AttestationError('the SafetyNet signature did not verify');
    }

    // §8.5 step 2. The nonce is the only thing tying Google's verdict about a
    // device to this registration.
    const attested = new Uint8Array(input.authData.length + input.clientDataHash.length);
    attested.set(input.authData, 0);
    attested.set(input.clientDataHash, input.authData.length);
    const expectedNonce = Buffer.from(
      await crypto.subtle.digest('SHA-256', attested),
    ).toString('base64');

    if (response.nonce !== expectedNonce) {
      throw new AttestationError('the SafetyNet nonce does not hash this ceremony');
    }

    try {
      verifySafetyNetVerdicts(response, Date.now());
    } catch (error) {
      throw new AttestationError(
        error instanceof SafetyNetError ? error.message : 'the SafetyNet verdicts could not be read',
      );
    }

    if (!chainReachesAnchor(chain, anchorCerts)) {
      throw new AttestationError('the attestation chain does not reach a trusted root');
    }

    // Nothing in the response names an authenticator model, so an AAGUID
    // allowlist cannot be applied to it — the same situation as `fido-u2f`,
    // and refused here for the same reason.
    if (policy.allowedAaguids !== undefined) {
      throw new AttestationError(
        'allowedAaguids cannot be enforced on android-safetynet; the format conveys no AAGUID',
      );
    }

    return {
      format: 'android-safetynet',
      type: 'basic',
      // Google vouched for the *device*, not for where the key lives and not
      // for which authenticator model produced it.
      aaguidVerified: false,
      aaguid: aaguidHex,
      attestationSubject: leaf.subject,
    };
  }

  // ── android-key ──────────────────────────────────────────────────────────

  if (input.format === 'android-key') {
    const androidAlg = input.statement.get('alg');
    if (typeof androidAlg !== 'number' || ![ES256, RS256].includes(androidAlg as CoseAlgorithm)) {
      throw new AttestationError(
        `unsupported android-key attestation algorithm: ${String(androidAlg)}`,
      );
    }

    const androidChain = readX5c(input.statement);
    if (androidChain === undefined) {
      throw new AttestationError('android-key attestation requires an x5c chain');
    }

    const androidAnchors = policy.trustAnchors ?? [];
    if (androidAnchors.length === 0) {
      throw new AttestationError(
        'android-key attestation requires trustAnchors; without roots, a chain proves nothing',
      );
    }

    let anchorCerts: X509Certificate[];
    try {
      anchorCerts = androidAnchors.map((der) => new X509Certificate(Buffer.from(der)));
    } catch {
      throw new AttestationError('a configured trust anchor is not a valid certificate');
    }

    await verifyAndroidKeyAttestation(
      input,
      androidChain,
      anchorCerts,
      androidAlg as CoseAlgorithm,
      policy.allowSoftwareEnforcedAndroidKey === true,
    );

    if (policy.allowedAaguids !== undefined && !policy.allowedAaguids.includes(aaguidHex)) {
      throw new AttestationError(`authenticator model ${aaguidHex} is not on the allowed list`);
    }

    return {
      format: 'android-key',
      type: 'basic',
      aaguidVerified: true,
      aaguid: aaguidHex,
      attestationSubject: (androidChain[0] as X509Certificate).subject,
    };
  }

  // ── fido-u2f ─────────────────────────────────────────────────────────────
  // Also handled before `packed`: the statement has no `alg`, because §8.6
  // fixes the algorithm rather than letting the statement name it.

  if (input.format === 'fido-u2f') {
    const u2fChain = readX5c(input.statement);
    if (u2fChain === undefined) {
      throw new AttestationError('u2f attestation requires an x5c chain');
    }

    const u2fAnchors = policy.trustAnchors ?? [];
    if (u2fAnchors.length === 0) {
      throw new AttestationError(
        'u2f attestation requires trustAnchors; without roots, a chain proves nothing',
      );
    }

    let anchorCerts: X509Certificate[];
    try {
      anchorCerts = u2fAnchors.map((der) => new X509Certificate(Buffer.from(der)));
    } catch {
      throw new AttestationError('a configured trust anchor is not a valid certificate');
    }

    await verifyU2fAttestation(input, u2fChain, anchorCerts);

    // U2F conveys no AAGUID — see `verifyU2fAttestation`. An allowlist cannot
    // be applied to sixteen zero bytes, and refusing here says so rather than
    // reporting a model mismatch the caller would misread.
    if (policy.allowedAaguids !== undefined) {
      throw new AttestationError(
        'allowedAaguids cannot be enforced on fido-u2f; the format conveys no AAGUID',
      );
    }

    return {
      format: 'fido-u2f',
      type: 'basic',
      // The chain vouches for the hardware, but there is no model identifier
      // for it to vouch for.
      aaguidVerified: false,
      aaguid: aaguidHex,
      attestationSubject: (u2fChain[0] as X509Certificate).subject,
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
