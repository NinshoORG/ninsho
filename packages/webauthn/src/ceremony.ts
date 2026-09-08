/**
 * Registration and authentication verification — WebAuthn Level 3, §7.1 and §7.2.
 *
 * ─── What is verified, and what is deliberately not ───────────────────────
 * These two functions are the security boundary of this package. Everything
 * they receive came from a browser, which means it came from whoever controls
 * that browser.
 *
 * Both ceremonies check, in order: the client data type (so a registration
 * response cannot be replayed as an authentication one), the challenge, the
 * origin, the RP ID hash, the user-presence flag, the backup-state invariant,
 * and — for authentication — the signature and the sign counter.
 *
 * Attestation is verified only on terms that mean something. `none` is the
 * default and conveys nothing, which is correct for passkeys — the browser
 * substitutes it whenever the relying party requests `none` conveyance.
 * Every other format WebAuthn defines — `packed`, `apple`, `tpm`, `fido-u2f`,
 * `android-key` and `android-safetynet` — is verified against certificate
 * roots the relying party supplies, and refused outright without them: a chain
 * checked against no trust anchor proves nothing, because anyone can self-sign
 * a CA and claim any AAGUID. A format this package does not know is refused
 * rather than parsed-and-ignored. See `attestation.ts`.
 * ──────────────────────────────────────────────────────────────────────────
 */

import { NinshoError, safeEqual } from '@ninshorg/core';
import { CborError, decodeCbor, type CborValue } from './cbor.js';
import { AuthDataError, parseAuthenticatorData, type ParsedAuthenticatorData } from './authdata.js';
import {
  CoseError,
  DEFAULT_ALGORITHMS,
  importCoseKey,
  verifyCoseSignature,
  type CoseAlgorithm,
} from './cose.js';
import {
  AttestationError,
  verifyAttestation,
  type AttestationPolicy,
  type AttestationType,
} from './attestation.js';

/** A ceremony failed to verify. Maps to 400. */
export class WebAuthnError extends NinshoError {
  readonly code = 'WEBAUTHN_VERIFICATION_FAILED';
  readonly status = 400;
  constructor(detail?: string) {
    // The specific failed check goes in `detail`, which never reaches a
    // client. Telling a caller *which* check failed is a free oracle for
    // probing what a relying party expects.
    super('Verification failed', detail);
  }
}

/** How strictly user verification is enforced. Mirrors the WebAuthn enum. */
export type UserVerificationRequirement = 'required' | 'preferred' | 'discouraged';

/** The subset of `clientDataJSON` that verification reads. */
export interface ClientData {
  readonly type: string;
  readonly challenge: string;
  readonly origin: string;
  readonly crossOrigin?: boolean;
  readonly topOrigin?: string;
}

const CREATE_TYPE = 'webauthn.create';
const GET_TYPE = 'webauthn.get';

/**
 * Largest `clientDataJSON` accepted.
 *
 * Real client data is a few hundred bytes. The bound stops an attacker making
 * the server parse a megabyte of JSON per request, which is free for them and
 * not for us.
 */
const MAX_CLIENT_DATA_BYTES = 8192;

const utf8 = new TextDecoder('utf-8', { fatal: true });

/** Canonical base64url for a byte string. */
function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/**
 * Re-encodes a base64url string canonically.
 *
 * A browser sends the challenge back as base64url of the bytes it was given,
 * but padding and alphabet variations exist in the wild. Normalising through
 * the bytes means the comparison is about the value, not its spelling —
 * without ever widening what counts as a match, since two different byte
 * strings still normalise differently.
 */
function canonicaliseBase64Url(value: string): string {
  return toBase64Url(new Uint8Array(Buffer.from(value, 'base64url')));
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/** Parses and structurally validates `clientDataJSON`. */
export function parseClientData(clientDataJSON: Uint8Array): ClientData {
  if (clientDataJSON.length === 0) {
    throw new WebAuthnError('clientDataJSON is empty');
  }
  if (clientDataJSON.length > MAX_CLIENT_DATA_BYTES) {
    throw new WebAuthnError(
      `clientDataJSON of ${clientDataJSON.length} bytes exceeds the ${MAX_CLIENT_DATA_BYTES}-byte limit`,
    );
  }

  let text: string;
  try {
    // Strict UTF-8. Silently substituting replacement characters would change
    // what the origin string says while still parsing as JSON.
    text = utf8.decode(clientDataJSON);
  } catch {
    throw new WebAuthnError('clientDataJSON is not valid UTF-8');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new WebAuthnError('clientDataJSON is not valid JSON');
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new WebAuthnError('clientDataJSON is not a JSON object');
  }

  const data = parsed as Record<string, unknown>;
  for (const field of ['type', 'challenge', 'origin'] as const) {
    if (typeof data[field] !== 'string') {
      throw new WebAuthnError(`clientDataJSON.${field} is missing or not a string`);
    }
  }
  if (data['crossOrigin'] !== undefined && typeof data['crossOrigin'] !== 'boolean') {
    throw new WebAuthnError('clientDataJSON.crossOrigin is not a boolean');
  }

  return {
    type: data['type'] as string,
    challenge: data['challenge'] as string,
    origin: data['origin'] as string,
    ...(data['crossOrigin'] !== undefined ? { crossOrigin: data['crossOrigin'] as boolean } : {}),
    ...(typeof data['topOrigin'] === 'string' ? { topOrigin: data['topOrigin'] } : {}),
  };
}

/**
 * The challenge a response carries, canonicalised.
 *
 * Lets a relying party look the challenge up in its store *before* verifying
 * anything else — which is the right order, because consumption is what makes
 * a replay fail, and it should not depend on the rest of the response being
 * well-formed.
 */
export function extractChallenge(clientDataJSON: Uint8Array): string {
  return canonicaliseBase64Url(parseClientData(clientDataJSON).challenge);
}

/** Expectations shared by both ceremonies. */
interface CommonExpectations {
  /** The RP ID the credential is scoped to, e.g. `example.com`. */
  readonly rpId: string;
  /** Exact origin(s) to accept, e.g. `https://example.com`. No wildcards. */
  readonly origin: string | readonly string[];
  /** The challenge that was issued, base64url. */
  readonly challenge: string;
  /** Default `'preferred'`, matching the WebAuthn API's own default. */
  readonly userVerification?: UserVerificationRequirement;
  /**
   * Whether to accept a ceremony performed in a cross-origin iframe.
   * Defaults to `false`: a credential ceremony the user may not have known
   * they were in is one they cannot meaningfully consent to.
   */
  readonly allowCrossOrigin?: boolean;
}

function normaliseOrigins(origin: string | readonly string[]): readonly string[] {
  const origins = typeof origin === 'string' ? [origin] : origin;
  if (origins.length === 0) {
    throw new WebAuthnError('no expected origin was configured');
  }
  return origins;
}

/**
 * The checks common to both ceremonies, in the order the spec gives them.
 *
 * Factored out so the two ceremonies cannot drift apart. A check that exists
 * in registration and was forgotten in authentication is the kind of asymmetry
 * that survives review precisely because both functions look correct on their
 * own.
 */
function verifyClientData(
  clientData: ClientData,
  expectedType: string,
  expectations: CommonExpectations,
): string {
  // The type binds a response to its ceremony. Without it, an assertion
  // collected at a sign-in page could be presented to a registration
  // endpoint — the two are otherwise the same shape.
  if (clientData.type !== expectedType) {
    throw new WebAuthnError(`clientData.type is ${clientData.type}, expected ${expectedType}`);
  }

  // Constant-time, though the challenge is a public value: the comparison
  // costs the same either way, and it removes the question.
  const presented = canonicaliseBase64Url(clientData.challenge);
  const expected = canonicaliseBase64Url(expectations.challenge);
  if (presented.length === 0 || !safeEqual(presented, expected)) {
    throw new WebAuthnError('challenge does not match the one issued');
  }

  // Exact string match against an allowlist. Substring or suffix matching is
  // how `https://example.com.attacker.net` gets accepted.
  const origins = normaliseOrigins(expectations.origin);
  if (!origins.includes(clientData.origin)) {
    throw new WebAuthnError(`origin ${clientData.origin} is not an expected origin`);
  }

  if (clientData.crossOrigin === true && expectations.allowCrossOrigin !== true) {
    throw new WebAuthnError('ceremony was performed in a cross-origin iframe');
  }

  return clientData.origin;
}

/** Checks the flags every ceremony requires. */
function verifyFlags(
  authData: ParsedAuthenticatorData,
  userVerification: UserVerificationRequirement,
): void {
  // Mandatory in both ceremonies (§7.1 step 16, §7.2 step 17). There is no
  // option to disable it, because the spec does not offer one.
  if (!authData.flags.userPresent) {
    throw new WebAuthnError('the user-presence flag is not set');
  }

  if (userVerification === 'required' && !authData.flags.userVerified) {
    throw new WebAuthnError('user verification was required but the flag is not set');
  }
}

async function verifyRpIdHash(authData: ParsedAuthenticatorData, rpId: string): Promise<void> {
  const expected = await sha256(new TextEncoder().encode(rpId));
  if (!bytesEqual(authData.rpIdHash, expected)) {
    // This is what stops a credential registered for one site being used at
    // another: the authenticator hashes the RP ID it was invoked with, and the
    // signature covers that hash.
    throw new WebAuthnError('the RP ID hash does not match the expected relying party');
  }
}

// ─── Registration ──────────────────────────────────────────────────────────

export interface RegistrationResponse {
  readonly clientDataJSON: Uint8Array;
  readonly attestationObject: Uint8Array;
}

export interface RegistrationExpectations extends CommonExpectations {
  /** Algorithms this relying party accepts. Defaults to ES256, EdDSA, RS256. */
  readonly allowedAlgorithms?: readonly CoseAlgorithm[];
  /**
   * Attestation policy. Defaults to accepting `none` only.
   *
   * Accepting `packed` additionally requires `trustAnchors`; see
   * `attestation.ts` for why a chain without roots proves nothing.
   */
  readonly attestation?: AttestationPolicy;
}

export interface VerifiedRegistration {
  readonly credentialId: Uint8Array;
  /** COSE-encoded public key. Store these bytes; they are re-imported later. */
  readonly credentialPublicKey: Uint8Array;
  readonly algorithm: CoseAlgorithm;
  readonly signCount: number;
  readonly aaguid: Uint8Array;
  readonly userVerified: boolean;
  readonly backupEligible: boolean;
  readonly backedUp: boolean;
  readonly attestationFormat: string;
  /** What the attestation established. `none` and `self` establish nothing. */
  readonly attestationType: AttestationType;
  /**
   * Whether a trusted chain vouched for the AAGUID.
   *
   * `false` means the AAGUID is self-asserted by the client and must not drive
   * policy — it is fine for display, and not for "is this approved hardware".
   */
  readonly aaguidVerified: boolean;
  /** Subject of the attestation certificate, when there was one. */
  readonly attestationSubject: string | undefined;
  readonly origin: string;
}

/** Reads `fmt`, `attStmt` and `authData` from an attestation object. */
function parseAttestationObject(bytes: Uint8Array): {
  fmt: string;
  authData: Uint8Array;
  attStmt: Map<string | number, CborValue>;
} {
  let decoded: CborValue;
  try {
    decoded = decodeCbor(bytes);
  } catch (error) {
    throw new WebAuthnError(
      `attestationObject is not valid CBOR: ${
        error instanceof CborError ? error.message : 'unknown error'
      }`,
    );
  }

  if (!(decoded instanceof Map)) {
    throw new WebAuthnError('attestationObject is not a CBOR map');
  }

  const fmt = decoded.get('fmt');
  const authData = decoded.get('authData');

  if (typeof fmt !== 'string') {
    throw new WebAuthnError('attestationObject.fmt is missing or not a string');
  }
  if (!(authData instanceof Uint8Array)) {
    throw new WebAuthnError('attestationObject.authData is missing or not a byte string');
  }
  const attStmt = decoded.get('attStmt');
  if (!(attStmt instanceof Map)) {
    throw new WebAuthnError('attestationObject.attStmt is missing or not a map');
  }

  return { fmt, authData, attStmt };
}

/** Verifies a registration response and returns what to store. */
export async function verifyRegistration(
  response: RegistrationResponse,
  expectations: RegistrationExpectations,
): Promise<VerifiedRegistration> {
  const clientData = parseClientData(response.clientDataJSON);
  const origin = verifyClientData(clientData, CREATE_TYPE, expectations);

  const { fmt, authData: authDataBytes, attStmt } = parseAttestationObject(
    response.attestationObject,
  );

  let authData: ParsedAuthenticatorData;
  try {
    authData = parseAuthenticatorData(authDataBytes);
  } catch (error) {
    throw new WebAuthnError(
      error instanceof AuthDataError ? error.message : 'authenticator data could not be parsed',
    );
  }

  await verifyRpIdHash(authData, expectations.rpId);
  verifyFlags(authData, expectations.userVerification ?? 'preferred');

  const attested = authData.attestedCredentialData;
  if (!attested) {
    // Without a credential there is nothing to register. The AT flag governs
    // whether the section is present, so this is a response that never carried
    // one rather than one that failed to parse.
    throw new WebAuthnError('registration response carries no attested credential data');
  }

  // Importing proves the key is structurally sound and on an allowed
  // algorithm. Doing it now means a key that could never verify a signature is
  // rejected at registration rather than at the user's next sign-in.
  let algorithm: CoseAlgorithm;
  try {
    const imported = await importCoseKey(
      attested.credentialPublicKey,
      expectations.allowedAlgorithms ?? DEFAULT_ALGORITHMS,
    );
    algorithm = imported.alg;
  } catch (error) {
    throw new WebAuthnError(
      error instanceof CoseError ? error.message : 'the credential public key was not acceptable',
    );
  }

  // Attestation last, because it needs the AAGUID and the credential key that
  // the steps above established. Everything it checks is about *provenance* —
  // the ceremony itself is already verified by this point.
  let attestation;
  try {
    attestation = await verifyAttestation(
      {
        format: fmt,
        statement: attStmt,
        authData: authData.raw,
        clientDataHash: await sha256(response.clientDataJSON),
        aaguid: attested.aaguid,
        credentialPublicKey: attested.credentialPublicKey,
        credentialId: attested.credentialId,
        credentialAlgorithm: algorithm,
      },
      expectations.attestation ?? {},
    );
  } catch (error) {
    throw new WebAuthnError(
      error instanceof AttestationError ? error.message : 'the attestation was not acceptable',
    );
  }

  return {
    // Copied out of the parent buffer. The subarrays share memory with the
    // response, and a caller storing them would be storing a view of bytes
    // they no longer control.
    credentialId: new Uint8Array(attested.credentialId),
    credentialPublicKey: new Uint8Array(attested.credentialPublicKey),
    algorithm,
    signCount: authData.signCount,
    aaguid: new Uint8Array(attested.aaguid),
    userVerified: authData.flags.userVerified,
    backupEligible: authData.flags.backupEligible,
    backedUp: authData.flags.backedUp,
    attestationFormat: fmt,
    attestationType: attestation.type,
    aaguidVerified: attestation.aaguidVerified,
    attestationSubject: attestation.attestationSubject,
    origin,
  };
}

// ─── Authentication ────────────────────────────────────────────────────────

/** What a relying party must have stored from registration. */
export interface StoredCredential {
  readonly credentialId: Uint8Array;
  /** The COSE bytes returned by `verifyRegistration`. */
  readonly publicKey: Uint8Array;
  /** The counter as of the last successful authentication. */
  readonly signCount: number;
  /** The user this credential belongs to, for the user-handle check. */
  readonly userId?: string;
}

export interface AuthenticationResponse {
  readonly clientDataJSON: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly signature: Uint8Array;
  /** Present for discoverable credentials. */
  readonly userHandle?: Uint8Array | undefined;
  /** The credential the browser used, from `PublicKeyCredential.rawId`. */
  readonly credentialId?: Uint8Array;
}

export interface AuthenticationExpectations extends CommonExpectations {
  /** The stored credential this assertion claims to be from. */
  readonly credential: StoredCredential;
  /** Algorithms accepted. Defaults to ES256, EdDSA, RS256. */
  readonly allowedAlgorithms?: readonly CoseAlgorithm[];
  /**
   * How to respond when the sign counter does not advance.
   *
   * A counter that goes backwards or stands still is the spec's signal that an
   * authenticator may have been cloned (§6.1.1). Default `'reject'`: the
   * signal exists to be acted on, and a library that only logs it has moved
   * the decision to a place nobody is looking.
   *
   * Authenticators that do not implement counters report 0 forever; that case
   * is not a clone signal and is never rejected.
   */
  readonly onCounterRegression?: 'reject' | 'allow';
}

export interface VerifiedAuthentication {
  readonly credentialId: Uint8Array;
  /** Persist this as the credential's new counter. */
  readonly newSignCount: number;
  /** Whether this authenticator implements a counter at all. */
  readonly counterSupported: boolean;
  readonly userVerified: boolean;
  readonly backupEligible: boolean;
  readonly backedUp: boolean;
  readonly origin: string;
  readonly userHandle: string | undefined;
}

/** Verifies an authentication assertion against a stored credential. */
export async function verifyAuthentication(
  response: AuthenticationResponse,
  expectations: AuthenticationExpectations,
): Promise<VerifiedAuthentication> {
  const { credential } = expectations;

  // If the browser told us which credential it used, it must be the one we
  // are checking against. Verifying a signature with the wrong stored key
  // would fail anyway; failing here says why.
  if (response.credentialId && !bytesEqual(response.credentialId, credential.credentialId)) {
    throw new WebAuthnError('the asserted credential id does not match the stored credential');
  }

  // A discoverable credential reports whose it is. If we know, they must
  // agree — otherwise an assertion from one account could be presented as
  // another's.
  let userHandle: string | undefined;
  if (response.userHandle !== undefined && response.userHandle.length > 0) {
    userHandle = utf8Decode(response.userHandle);
    if (credential.userId !== undefined && !safeEqual(userHandle, credential.userId)) {
      throw new WebAuthnError('the asserted user handle does not match the stored credential');
    }
  }

  const clientData = parseClientData(response.clientDataJSON);
  const origin = verifyClientData(clientData, GET_TYPE, expectations);

  let authData: ParsedAuthenticatorData;
  try {
    authData = parseAuthenticatorData(response.authenticatorData);
  } catch (error) {
    throw new WebAuthnError(
      error instanceof AuthDataError ? error.message : 'authenticator data could not be parsed',
    );
  }

  await verifyRpIdHash(authData, expectations.rpId);
  verifyFlags(authData, expectations.userVerification ?? 'preferred');

  // An assertion must not carry attested credential data: that belongs to
  // registration, and accepting it here would mean a sign-in could smuggle in
  // a new credential.
  if (authData.attestedCredentialData) {
    throw new WebAuthnError('an assertion must not carry attested credential data');
  }

  let publicKey;
  try {
    publicKey = await importCoseKey(
      credential.publicKey,
      expectations.allowedAlgorithms ?? DEFAULT_ALGORITHMS,
    );
  } catch (error) {
    // The stored key failed to import. That is the relying party's data, not
    // the client's, so it is a 500-shaped problem — but surfacing it as a
    // failed verification is still correct: this assertion cannot be trusted.
    throw new WebAuthnError(
      error instanceof CoseError
        ? `the stored public key could not be imported: ${error.message}`
        : 'the stored public key could not be imported',
    );
  }

  // The signed bytes, exactly as §7.2 step 20 defines them.
  const clientDataHash = await sha256(response.clientDataJSON);
  const signedData = new Uint8Array(authData.raw.length + clientDataHash.length);
  signedData.set(authData.raw, 0);
  signedData.set(clientDataHash, authData.raw.length);

  const valid = await verifyCoseSignature(publicKey, response.signature, signedData);
  if (!valid) {
    throw new WebAuthnError('the assertion signature did not verify');
  }

  // §6.1.1. Only meaningful when at least one of the two counters is non-zero:
  // an authenticator that does not implement counters reports 0 forever, and
  // treating that as a clone would break every passkey.
  const counterSupported = authData.signCount !== 0 || credential.signCount !== 0;
  if (counterSupported && authData.signCount <= credential.signCount) {
    if ((expectations.onCounterRegression ?? 'reject') === 'reject') {
      throw new WebAuthnError(
        `sign counter did not advance (stored ${credential.signCount}, ` +
          `presented ${authData.signCount}) — the authenticator may be cloned`,
      );
    }
  }

  return {
    credentialId: new Uint8Array(credential.credentialId),
    newSignCount: authData.signCount,
    counterSupported,
    userVerified: authData.flags.userVerified,
    backupEligible: authData.flags.backupEligible,
    backedUp: authData.flags.backedUp,
    origin,
    userHandle,
  };
}

function utf8Decode(bytes: Uint8Array): string {
  try {
    return utf8.decode(bytes);
  } catch {
    throw new WebAuthnError('the user handle is not valid UTF-8');
  }
}
