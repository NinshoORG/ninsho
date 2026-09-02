/**
 * @ninsho/webauthn — passkey registration and authentication verification.
 *
 * ─── Where this sits ──────────────────────────────────────────────────────
 * WebAuthn is credential *verification*: it establishes who someone is, and
 * stops there. Sessions, tokens, revocation and authorization are
 * `@ninsho/server`'s job. So this package produces a `Principal`, and you hand
 * that to `createSession()`:
 *
 *     const result = await webauthn.finishAuthentication(response, credential);
 *     const tokens = await auth.createSession(result.principal);
 *
 * Keeping the boundary there is what lets a passkey, a password and an OIDC
 * login all end at the same place, with one session implementation behind
 * them rather than three.
 *
 * The package has no third-party dependencies. It depends on `@ninsho/core`,
 * which has none either.
 * ──────────────────────────────────────────────────────────────────────────
 */

// ── The wired-up relying party — start here ─────────────────────────────────
export { WebAuthnServer } from './server.js';
export type {
  WebAuthnServerOptions,
  StartRegistrationInput,
  StartAuthenticationInput,
  FinishRegistrationResult,
  FinishAuthenticationResult,
} from './server.js';

// ── Ceremony verification, for callers managing their own challenges ────────
export {
  WebAuthnError,
  verifyRegistration,
  verifyAuthentication,
  parseClientData,
  extractChallenge,
} from './ceremony.js';
export type {
  UserVerificationRequirement,
  ClientData,
  RegistrationResponse,
  RegistrationExpectations,
  VerifiedRegistration,
  AuthenticationResponse,
  AuthenticationExpectations,
  VerifiedAuthentication,
  StoredCredential,
} from './ceremony.js';

// ── Challenges ──────────────────────────────────────────────────────────────
export { ChallengeManager, ChallengeError, ChallengeConfigurationError } from './challenge.js';
export type {
  ChallengeStore,
  ChallengeOptions,
  ChallengeContext,
  IssuedChallenge,
  CeremonyType,
} from './challenge.js';

// ── Ceremony options ────────────────────────────────────────────────────────
export { buildRegistrationOptions, buildAuthenticationOptions } from './options.js';
export type {
  RegistrationOptionsJSON,
  AuthenticationOptionsJSON,
  BuildRegistrationOptionsInput,
  BuildAuthenticationOptionsInput,
  CredentialDescriptorJSON,
  CredentialSummary,
  ResidentKeyRequirement,
  AuthenticatorAttachment,
  AuthenticatorTransport,
  AttestationConveyance,
} from './options.js';

// ── Attestation ─────────────────────────────────────────────────────────────
export { AttestationError, verifyAttestation, VERIFIABLE_FORMATS, FIDO_AAGUID_OID } from './attestation.js';
export type {
  AttestationPolicy,
  AttestationResult,
  AttestationType,
  VerifyAttestationInput,
} from './attestation.js';

export { Asn1Error, findExtension } from './asn1.js';

// ── COSE keys ───────────────────────────────────────────────────────────────
export {
  CoseError,
  ES256,
  EdDSA,
  RS256,
  SUPPORTED_ALGORITHMS,
  DEFAULT_ALGORITHMS,
  importCoseKey,
  parseCoseKey,
  verifyCoseSignature,
} from './cose.js';
export type { CoseAlgorithm, CosePublicKey, ParsedCoseKey, CoseKeyMaterial } from './cose.js';

// ── Lower-level parsers ─────────────────────────────────────────────────────
// Exported because a relying party inspecting a credential — reading the
// AAGUID to name the authenticator, say — should not have to reimplement the
// parsing to do it.
export { AuthDataError, parseAuthenticatorData } from './authdata.js';
export type {
  ParsedAuthenticatorData,
  AuthenticatorFlags,
  AttestedCredentialData,
} from './authdata.js';

export { CborError, decodeCbor, decodeCborPrefix } from './cbor.js';
export type { CborValue } from './cbor.js';

export { DerError, derToRawSignature } from './der.js';
