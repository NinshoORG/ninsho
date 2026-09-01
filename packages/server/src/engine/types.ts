import type { AuthContext, Principal, TokenStrategy } from '@ninsho/core';

/** What the caller supplies to mint an access token. */
export interface IssueAccessTokenInput {
  /** Identity and authorization data to bind into the token. */
  readonly principal: Principal;
  /**
   * The session this token belongs to. Constant across refreshes, so
   * terminating a session kills every access token issued under it.
   */
  readonly sessionId: string;
  /**
   * RFC 7638 thumbprint of the client's DPoP key, under `binding: 'dpop'`.
   *
   * Setting it makes the issued token proof-of-possession rather than bearer:
   * every later presentation must carry a proof signed by the matching private
   * key.
   */
  readonly confirmationKey?: string;
}

/** A freshly minted access token. */
export interface IssuedAccessToken {
  /**
   * The credential to hand to the client.
   * SECURITY: never log this value, and never place it in a URL.
   */
  readonly token: string;
  /** Identifier for this token, safe to log and to use for revocation. */
  readonly tokenId: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

/**
 * The seam between the two token strategies.
 *
 * Everything above this interface — middleware, session management,
 * authorization — is strategy-agnostic. That is what lets one API serve both a
 * solo developer's single application (`opaque`, no keys, native revocation)
 * and a team's several services (`paseto`, locally verifiable, audience-scoped)
 * without the two growing separate call paths.
 *
 * ─── Contract every implementation must honour ────────────────────────────
 * `verify()` either returns a fully valid {@link AuthContext} or throws. It
 * must never return a context for a credential that is expired, revoked,
 * structurally malformed, or whose validity it could not establish. In
 * particular, a store or transport failure must propagate as a thrown error
 * rather than being read as "not revoked" — deciding what an outage means is
 * the caller's job, governed by the configured failure mode, and an engine
 * that swallows the error takes that decision away.
 *
 * Errors must come from the `@ninsho/core` taxonomy so the transport layer can
 * map them to a status without inspecting messages.
 * ──────────────────────────────────────────────────────────────────────────
 */
/** Options for a single verification. */
export interface VerifyOptions {
  /**
   * Skip the revocation lookup and accept the token on its other merits.
   *
   * Only meaningful for an engine whose {@link TokenEngine.canVerifyWithoutStore}
   * is `true`. It exists so that a deployment configured `onStoreError: 'open'`
   * can keep serving during a store outage, and it is honoured **only** on that
   * path — never as a routine optimisation.
   *
   * SECURITY: setting this accepts tokens that may have been revoked. It is a
   * deliberate availability trade-off and every use emits a
   * `store.unavailable` audit event.
   */
  readonly skipRevocationCheck?: boolean;

  /**
   * Thumbprint of the key that signed the DPoP proof accompanying this request.
   *
   * The engine compares it against the token's own binding. A token bound to a
   * key and presented **without** this is refused — the binding must fail
   * closed, or enabling DPoP would silently weaken to bearer semantics the
   * moment a caller forgot to pass the proof through.
   */
  readonly confirmationKey?: string;
}

export interface TokenEngine {
  /** Which strategy this engine implements. Surfaces on `AuthContext.strategy`. */
  readonly strategy: TokenStrategy;

  /**
   * Whether this engine can establish identity without reaching the store.
   *
   * This is the asymmetry that governs what `onStoreError: 'open'` can mean:
   *
   *   - `paseto` → `true`. The signature is verified locally, so a store
   *     outage costs only the revocation check. Failing open is a coherent
   *     (if weakened) posture.
   *
   *   - `opaque` → `false`. The store *is* the identity; without it there is
   *     no way to learn who the caller is. Failing open would mean admitting
   *     an unauthenticated request, so it is not offered — the request is
   *     refused regardless of configuration.
   */
  readonly canVerifyWithoutStore: boolean;

  /** Mints an access token. */
  issue(input: IssueAccessTokenInput): Promise<IssuedAccessToken>;

  /**
   * Validates a raw access token.
   * @throws {TokenInvalidError} Malformed, unknown, or failing verification.
   * @throws {TokenExpiredError} Past its expiry.
   * @throws {TokenRevokedError} Explicitly revoked before expiry.
   * @throws {StoreUnavailableError} The store could not be reached. Callers
   *   decide what that means via the configured failure mode; the engine never
   *   silently reads an outage as "not revoked".
   */
  verify(token: string, options?: VerifyOptions): Promise<AuthContext>;

  /**
   * Revokes a single access token by its id. Idempotent — revoking an unknown
   * or already-revoked token succeeds silently, because the caller's intent
   * ("this token must not work") is satisfied either way.
   */
  revoke(tokenId: string): Promise<void>;

  /**
   * Revokes every access token issued under a session. Idempotent.
   * Used by logout and by refresh-token reuse detection in Phase 3.
   */
  revokeSession(sessionId: string): Promise<void>;
}
