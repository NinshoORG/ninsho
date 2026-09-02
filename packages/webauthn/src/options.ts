/**
 * Ceremony options — the JSON a browser needs to start a ceremony.
 *
 * ─── Why these are typed rather than hand-built ───────────────────────────
 * The shapes below match the WebAuthn Level 3 JSON serialisation, so a browser
 * can pass them straight to `PublicKeyCredential.parseCreationOptionsFromJSON`
 * and `parseRequestOptionsFromJSON` without a translation layer.
 *
 * The options are not a security boundary — a client can ignore every one of
 * them, and verification never trusts what comes back. What they do is make
 * the *default* ceremony the right one: a relying party that hand-rolls this
 * JSON is one `userVerification` typo away from a policy it did not intend,
 * and nothing at verification time would tell it so.
 * ──────────────────────────────────────────────────────────────────────────
 */

import { DEFAULT_ALGORITHMS, type CoseAlgorithm } from './cose.js';
import type { UserVerificationRequirement } from './ceremony.js';

/**
 * How much attestation to ask the browser for.
 *
 * `none` is the default and the right answer for passkeys: the browser
 * replaces whatever the authenticator produced with an empty statement, so
 * nothing identifying the device reaches the relying party. Asking for
 * `direct` is only worthwhile when you have trust anchors to check the result
 * against — otherwise you have collected a statement nobody verifies.
 */
export type AttestationConveyance = 'none' | 'indirect' | 'direct' | 'enterprise';

/** How the credential should be stored on the authenticator. */
export type ResidentKeyRequirement = 'discouraged' | 'preferred' | 'required';

/** Platform (built into the device) or cross-platform (a roaming key). */
export type AuthenticatorAttachment = 'platform' | 'cross-platform';

/** How a credential can be reached. Passed through from registration. */
export type AuthenticatorTransport = 'usb' | 'nfc' | 'ble' | 'smart-card' | 'hybrid' | 'internal';

/** A credential named in `excludeCredentials` or `allowCredentials`. */
export interface CredentialDescriptorJSON {
  readonly type: 'public-key';
  /** base64url. */
  readonly id: string;
  readonly transports?: readonly AuthenticatorTransport[];
}

export interface RegistrationOptionsJSON {
  readonly rp: { readonly id: string; readonly name: string };
  readonly user: {
    /** base64url of the user handle. */
    readonly id: string;
    readonly name: string;
    readonly displayName: string;
  };
  /** base64url. */
  readonly challenge: string;
  readonly pubKeyCredParams: readonly { readonly type: 'public-key'; readonly alg: number }[];
  readonly timeout: number;
  readonly excludeCredentials: readonly CredentialDescriptorJSON[];
  readonly authenticatorSelection: {
    readonly residentKey: ResidentKeyRequirement;
    readonly requireResidentKey: boolean;
    readonly userVerification: UserVerificationRequirement;
    readonly authenticatorAttachment?: AuthenticatorAttachment;
  };
  readonly attestation: AttestationConveyance;
}

export interface AuthenticationOptionsJSON {
  /** base64url. */
  readonly challenge: string;
  readonly timeout: number;
  readonly rpId: string;
  readonly allowCredentials: readonly CredentialDescriptorJSON[];
  readonly userVerification: UserVerificationRequirement;
}

export interface CredentialSummary {
  readonly credentialId: Uint8Array;
  readonly transports?: readonly AuthenticatorTransport[];
}

const toBase64Url = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');

function toDescriptors(
  credentials: readonly CredentialSummary[],
): readonly CredentialDescriptorJSON[] {
  return credentials.map((credential) => ({
    type: 'public-key' as const,
    id: toBase64Url(credential.credentialId),
    ...(credential.transports ? { transports: credential.transports } : {}),
  }));
}

export interface BuildRegistrationOptionsInput {
  readonly rpId: string;
  readonly rpName: string;
  /** The user handle. Must not be an email or username — see below. */
  readonly userId: Uint8Array;
  readonly userName: string;
  readonly displayName?: string;
  /** base64url, from the challenge manager. */
  readonly challenge: string;
  readonly timeoutMs: number;
  readonly algorithms?: readonly CoseAlgorithm[];
  /**
   * Credentials the user already has.
   *
   * Passing them stops the authenticator creating a second credential for the
   * same account on the same device — which otherwise produces a user who has
   * two passkeys, uses whichever the browser offers, and cannot tell why one
   * of them stopped working.
   */
  readonly existingCredentials?: readonly CredentialSummary[];
  readonly residentKey?: ResidentKeyRequirement;
  readonly userVerification?: UserVerificationRequirement;
  readonly authenticatorAttachment?: AuthenticatorAttachment;
  /** Defaults to `'none'`. */
  readonly attestation?: AttestationConveyance;
}

export function buildRegistrationOptions(
  input: BuildRegistrationOptionsInput,
): RegistrationOptionsJSON {
  const residentKey = input.residentKey ?? 'preferred';

  return {
    rp: { id: input.rpId, name: input.rpName },
    user: {
      id: toBase64Url(input.userId),
      name: input.userName,
      displayName: input.displayName ?? input.userName,
    },
    challenge: input.challenge,
    pubKeyCredParams: (input.algorithms ?? DEFAULT_ALGORITHMS).map((alg) => ({
      type: 'public-key' as const,
      alg,
    })),
    timeout: input.timeoutMs,
    excludeCredentials: toDescriptors(input.existingCredentials ?? []),
    authenticatorSelection: {
      residentKey,
      // The deprecated boolean, kept in sync with `residentKey`. Older
      // authenticators read this one, and leaving them to disagree is how a
      // discoverable credential quietly stops being discoverable.
      requireResidentKey: residentKey === 'required',
      userVerification: input.userVerification ?? 'preferred',
      ...(input.authenticatorAttachment
        ? { authenticatorAttachment: input.authenticatorAttachment }
        : {}),
    },
    // Defaults to `none`. A relying party that has configured trust anchors
    // asks for `direct` instead — requesting attestation you cannot check
    // would collect a statement nobody verifies.
    attestation: input.attestation ?? 'none',
  };
}

export interface BuildAuthenticationOptionsInput {
  readonly rpId: string;
  /** base64url, from the challenge manager. */
  readonly challenge: string;
  readonly timeoutMs: number;
  /**
   * Credentials the user may sign in with.
   *
   * Leave empty for a usernameless flow, where the authenticator offers
   * whatever discoverable credentials it holds for this relying party.
   */
  readonly allowCredentials?: readonly CredentialSummary[];
  readonly userVerification?: UserVerificationRequirement;
}

export function buildAuthenticationOptions(
  input: BuildAuthenticationOptionsInput,
): AuthenticationOptionsJSON {
  return {
    challenge: input.challenge,
    timeout: input.timeoutMs,
    rpId: input.rpId,
    allowCredentials: toDescriptors(input.allowCredentials ?? []),
    userVerification: input.userVerification ?? 'preferred',
  };
}
