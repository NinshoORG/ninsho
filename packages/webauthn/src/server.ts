/**
 * The wired-up relying party.
 *
 * ─── Why this layer exists ────────────────────────────────────────────────
 * `verifyRegistration` and `verifyAuthentication` take an *expected* challenge
 * and leave storing and consuming it to the caller. That is the right seam for
 * a team with its own session infrastructure, and the wrong first experience
 * for everyone else: it makes the single most important step — consuming the
 * challenge exactly once — a thing you have to remember to do.
 *
 * This class remembers it. `finish*` extracts the challenge from the response,
 * consumes it atomically, and only then verifies. Getting that order wrong in
 * either direction is a real vulnerability, so it is written once here rather
 * than in every application.
 *
 * Consume-before-verify is deliberate. A failed verification still burns the
 * challenge, so an attacker cannot grind attempts against one value; the
 * legitimate user simply starts a new ceremony.
 * ──────────────────────────────────────────────────────────────────────────
 */

import type { Principal } from '@ninsho/core';
import {
  ChallengeManager,
  type ChallengeStore,
  type CeremonyType,
  type ChallengeContext,
} from './challenge.js';
import {
  WebAuthnError,
  extractChallenge,
  verifyAuthentication,
  verifyRegistration,
  type AuthenticationResponse,
  type RegistrationResponse,
  type StoredCredential,
  type UserVerificationRequirement,
  type VerifiedAuthentication,
  type VerifiedRegistration,
} from './ceremony.js';
import type { CoseAlgorithm } from './cose.js';
import type { AttestationPolicy } from './attestation.js';
import {
  buildAuthenticationOptions,
  buildRegistrationOptions,
  type AuthenticationOptionsJSON,
  type AuthenticatorAttachment,
  type CredentialSummary,
  type RegistrationOptionsJSON,
  type ResidentKeyRequirement,
} from './options.js';

export interface WebAuthnServerOptions {
  /**
   * The RP ID: a registrable domain suffix of the origin, e.g. `example.com`.
   * Credentials are scoped to it, so it cannot be changed without invalidating
   * every credential already registered.
   */
  readonly rpId: string;
  /** Human-readable name, shown by the authenticator during a ceremony. */
  readonly rpName: string;
  /** Exact origin(s) to accept. No wildcards — see `ceremony.ts`. */
  readonly origin: string | readonly string[];
  /** Where challenges live. A `NinshoStore` satisfies this. */
  readonly store: ChallengeStore;
  /** Ceremony timeout in milliseconds, and the challenge lifetime. Default 300000. */
  readonly timeoutMs?: number;
  readonly algorithms?: readonly CoseAlgorithm[];
  readonly userVerification?: UserVerificationRequirement;
  readonly residentKey?: ResidentKeyRequirement;
  readonly authenticatorAttachment?: AuthenticatorAttachment;
  readonly allowCrossOrigin?: boolean;
  readonly onCounterRegression?: 'reject' | 'allow';
  /**
   * Attestation policy. Defaults to accepting `none` only.
   *
   * Supplying one that accepts `packed` also changes what the browser is asked
   * for: the ceremony requests `direct` conveyance, because a browser asked
   * for `none` replaces the statement and there would be nothing to verify.
   */
  readonly attestation?: AttestationPolicy;
  /** Key prefix for the challenge store. */
  readonly keyPrefix?: string;
}

export interface StartRegistrationInput {
  /** Stable, opaque user id. */
  readonly userId: string;
  /** The account name the authenticator displays, e.g. an email. */
  readonly userName: string;
  readonly displayName?: string;
  /** Credentials this user already has, so a duplicate is not created. */
  readonly existingCredentials?: readonly CredentialSummary[];
  readonly userVerification?: UserVerificationRequirement;
}

export interface StartAuthenticationInput {
  /** Omit for a usernameless flow. */
  readonly userId?: string;
  readonly allowCredentials?: readonly CredentialSummary[];
  readonly userVerification?: UserVerificationRequirement;
}

export interface FinishRegistrationResult extends VerifiedRegistration {
  /** The user the challenge was issued for. */
  readonly userId: string;
}

export interface FinishAuthenticationResult extends VerifiedAuthentication {
  /** A principal ready for `createSession()`. Roles and scopes are yours to fill. */
  readonly principal: Principal;
}

const DEFAULT_TIMEOUT_MS = 300_000;

export class WebAuthnServer {
  readonly #options: WebAuthnServerOptions;
  readonly #challenges: ChallengeManager;
  readonly #timeoutMs: number;

  constructor(options: WebAuthnServerOptions) {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

    this.#options = options;
    this.#timeoutMs = timeoutMs;
    // One number governs both, so a ceremony cannot outlive the challenge it
    // depends on — a timeout longer than the challenge TTL produces users who
    // are told to try again after doing everything right.
    this.#challenges = new ChallengeManager(options.store, {
      ttlSeconds: Math.ceil(timeoutMs / 1000),
      ...(options.keyPrefix ? { keyPrefix: options.keyPrefix } : {}),
    });
  }

  /** The challenge manager, for callers that want it directly. */
  get challenges(): ChallengeManager {
    return this.#challenges;
  }

  async startRegistration(input: StartRegistrationInput): Promise<RegistrationOptionsJSON> {
    const { challenge } = await this.#challenges.issue('registration', input.userId);

    // Asking for attestation only makes sense when it will be checked, so the
    // conveyance follows the policy rather than being configured separately —
    // two settings that must agree are two settings that will not.
    const wantsAttestation = (this.#options.attestation?.formats ?? ['none']).some(
      (format) => format !== 'none',
    );

    return buildRegistrationOptions({
      rpId: this.#options.rpId,
      rpName: this.#options.rpName,
      // The user handle is the opaque id, never the email or username: it is
      // stored on the authenticator and may be shown by password managers, and
      // WebAuthn §14.6.1 is explicit that it must not contain personally
      // identifying information.
      userId: new TextEncoder().encode(input.userId),
      userName: input.userName,
      challenge,
      timeoutMs: this.#timeoutMs,
      ...(input.displayName !== undefined ? { displayName: input.displayName } : {}),
      ...(this.#options.algorithms ? { algorithms: this.#options.algorithms } : {}),
      ...(input.existingCredentials ? { existingCredentials: input.existingCredentials } : {}),
      ...(this.#options.residentKey ? { residentKey: this.#options.residentKey } : {}),
      ...(this.#options.authenticatorAttachment
        ? { authenticatorAttachment: this.#options.authenticatorAttachment }
        : {}),
      userVerification:
        input.userVerification ?? this.#options.userVerification ?? 'preferred',
      attestation: wantsAttestation ? 'direct' : 'none',
    });
  }

  async startAuthentication(
    input: StartAuthenticationInput = {},
  ): Promise<AuthenticationOptionsJSON> {
    const { challenge } = await this.#challenges.issue('authentication', input.userId);

    return buildAuthenticationOptions({
      rpId: this.#options.rpId,
      challenge,
      timeoutMs: this.#timeoutMs,
      ...(input.allowCredentials ? { allowCredentials: input.allowCredentials } : {}),
      userVerification:
        input.userVerification ?? this.#options.userVerification ?? 'preferred',
    });
  }

  /**
   * Consumes the challenge a response carries, then hands back its context.
   *
   * Extraction happens before anything else is trusted, and consumption before
   * anything is verified — a response that fails verification must not leave a
   * live challenge behind.
   */
  async #consume(type: CeremonyType, clientDataJSON: Uint8Array): Promise<ChallengeContext> {
    const challenge = extractChallenge(clientDataJSON);
    return this.#challenges.consume(type, challenge);
  }

  /**
   * Verifies a registration response.
   *
   * @param expectedUserId when given, the challenge must have been issued for
   *   this user. Pass it whenever the request is already authenticated — it
   *   stops one user's ceremony being completed against another's account.
   */
  async finishRegistration(
    response: RegistrationResponse,
    expectedUserId?: string,
  ): Promise<FinishRegistrationResult> {
    const context = await this.#consume('registration', response.clientDataJSON);

    if (context.userId === undefined) {
      throw new WebAuthnError('the registration challenge was not issued for a user');
    }
    if (expectedUserId !== undefined && context.userId !== expectedUserId) {
      throw new WebAuthnError('the challenge was issued for a different user');
    }

    const verified = await verifyRegistration(response, {
      rpId: this.#options.rpId,
      origin: this.#options.origin,
      challenge: extractChallenge(response.clientDataJSON),
      ...(this.#options.algorithms ? { allowedAlgorithms: this.#options.algorithms } : {}),
      ...(this.#options.allowCrossOrigin !== undefined
        ? { allowCrossOrigin: this.#options.allowCrossOrigin }
        : {}),
      ...(this.#options.attestation ? { attestation: this.#options.attestation } : {}),
      userVerification: this.#options.userVerification ?? 'preferred',
    });

    return { ...verified, userId: context.userId };
  }

  /**
   * Verifies an authentication assertion against a stored credential.
   *
   * The caller looks the credential up — by `response.credentialId` for a
   * usernameless flow, or by the session's user otherwise. Credential storage
   * belongs in the application's own database, alongside the user it
   * identifies.
   */
  async finishAuthentication(
    response: AuthenticationResponse,
    credential: StoredCredential,
  ): Promise<FinishAuthenticationResult> {
    const context = await this.#consume('authentication', response.clientDataJSON);

    // When the challenge was issued for a known user, the credential presented
    // must be that user's. Without this, a challenge issued for one account
    // could be completed with another account's credential.
    if (
      context.userId !== undefined &&
      credential.userId !== undefined &&
      context.userId !== credential.userId
    ) {
      throw new WebAuthnError('the credential does not belong to the user the challenge was for');
    }

    const verified = await verifyAuthentication(response, {
      rpId: this.#options.rpId,
      origin: this.#options.origin,
      challenge: extractChallenge(response.clientDataJSON),
      credential,
      ...(this.#options.algorithms ? { allowedAlgorithms: this.#options.algorithms } : {}),
      ...(this.#options.allowCrossOrigin !== undefined
        ? { allowCrossOrigin: this.#options.allowCrossOrigin }
        : {}),
      ...(this.#options.onCounterRegression
        ? { onCounterRegression: this.#options.onCounterRegression }
        : {}),
      userVerification: this.#options.userVerification ?? 'preferred',
    });

    const userId = credential.userId ?? context.userId ?? verified.userHandle;
    if (userId === undefined) {
      // Nothing identified the user: no stored owner, no challenge context, no
      // user handle. Guessing would be worse than refusing.
      throw new WebAuthnError('the assertion did not identify a user');
    }

    return {
      ...verified,
      // Roles and scopes are the application's to decide; WebAuthn proves who,
      // not what they may do.
      principal: { userId, roles: [], scopes: [] },
    };
  }
}
