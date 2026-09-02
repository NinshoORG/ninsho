/**
 * Store key namespace.
 *
 * Every key is versioned (`ninsho:v1:`) so a future schema change can run
 * alongside the current one instead of colliding with it. Bumping to `v2`
 * makes old records invisible rather than misread, which is the safer failure:
 * a session that silently disappears forces a re-login, whereas a record
 * parsed under the wrong schema could produce a valid-looking context with
 * wrong claims.
 *
 * The prefix also keeps Ninsho's keys distinguishable in a Redis instance
 * shared with application data.
 */

const NS = 'ninsho:v1';

export const KEYS = {
  /**
   * Opaque access token record, keyed by `hashToken(rawToken)`.
   * The raw token is never a key and never a value, so read access to the
   * store yields no usable credential.
   * TTL: the access token's remaining lifetime.
   */
  accessToken: (tokenHash: string): string => `${NS}:at:${tokenHash}`,

  /**
   * Reverse index from a token id to its hash, so a token can be revoked
   * given only `req.auth.tokenId` — the raw token is not available at logout.
   * TTL: matches the access token record.
   */
  accessTokenId: (tokenId: string): string => `${NS}:atid:${tokenId}`,

  /**
   * Set of access-token hashes belonging to one session.
   * Lets a session be terminated without scanning the keyspace.
   * TTL: refreshed on every add; outlives the longest access token in it.
   */
  sessionTokens: (sessionId: string): string => `${NS}:sess:${sessionId}:at`,

  /**
   * Live refresh token record, keyed by `hashToken(rawToken)`.
   * Consumed atomically on rotation via `store.take()`, so exactly one of any
   * number of concurrent callers can rotate it.
   * TTL: the refresh token's remaining lifetime.
   */
  refreshToken: (tokenHash: string): string => `${NS}:rt:${tokenHash}`,

  /**
   * Tombstone proving a refresh token was once real and has been rotated.
   *
   * This is what makes reuse *detectable* rather than merely rejected.
   * Without it, a replayed token and a fabricated one look identical, and the
   * strongest signal of credential theft an auth system can observe is thrown
   * away — which is exactly what the predecessor did.
   *
   * TTL: the family's remaining lifetime, so a replay stays detectable for as
   * long as the stolen token would plausibly be used.
   *
   * SECURITY: holds the principal but never a raw token.
   */
  refreshConsumed: (tokenHash: string): string => `${NS}:rtc:${tokenHash}`,

  /**
   * Grace mapping from a just-rotated token to its raw replacement, so a
   * parallel browser tab that raced and lost receives the replacement instead
   * of a spurious logout.
   *
   * SECURITY: this is the one place a raw token is stored, and it is a
   * deliberate, bounded trade-off — the receiving tab needs the raw value to
   * set its cookie. TTL is the grace period (30s by default), not the refresh
   * lifetime. The predecessor made the same trade but is worth contrasting:
   * scoping this key to the grace window rather than the token lifetime keeps
   * raw-token exposure to seconds instead of days.
   */
  refreshGrace: (tokenHash: string): string => `${NS}:rtg:${tokenHash}`,

  /**
   * Set of refresh token hashes belonging to one session (the family).
   * Read when a family must be revoked wholesale on reuse detection.
   */
  sessionRefresh: (sessionId: string): string => `${NS}:sess:${sessionId}:rt`,

  /**
   * Metadata about a session, for listing a user's active sessions.
   * TTL: the session's remaining lifetime.
   */
  sessionMeta: (sessionId: string): string => `${NS}:sess:${sessionId}:meta`,

  /**
   * Positive marker that a session has been terminated.
   *
   * ─── Why enumeration alone is not enough ────────────────────────────────
   * Revocation used to work purely by reading the family index and deleting
   * what it found. That loses a race: a rotation that adds its replacement to
   * the index *after* revocation has read it leaves a record nothing points
   * to. The index is then deleted, so no later revocation can find the orphan
   * either, and a refresh token survives a completed logout for its full
   * lifetime.
   *
   * This marker is written *before* the index is read, and consulted by
   * refresh, so the outcome no longer depends on which operation touched the
   * index first.
   *
   * TTL: the refresh lifetime — the longest anything in the family can live.
   * ────────────────────────────────────────────────────────────────────────
   */
  sessionRevoked: (sessionId: string): string => `${NS}:sess:${sessionId}:dead`,

  /**
   * Set of session ids belonging to a user, for "sign out everywhere".
   */
  userSessions: (userId: string): string => `${NS}:user:${userId}:sess`,

  /**
   * Denylist entry for a revoked PASETO token id. Phase 4.
   * Only the paseto strategy needs this: an opaque token is revoked by
   * deleting its record, so absence is revocation and no denylist exists.
   * TTL: the token's remaining lifetime, so the entry expires exactly when
   * the token it blocks would have expired anyway.
   */
  revoked: (tokenId: string): string => `${NS}:rev:${tokenId}`,

  /**
   * Seen DPoP proof identifier, for single-use enforcement.
   *
   * Namespaced by key thumbprint as well as `jti` so one client cannot burn
   * another's identifiers by guessing them.
   *
   * TTL: the proof acceptance window plus clock tolerance — long enough that a
   * proof is remembered for as long as it would still be accepted, and no
   * longer, so the set stays bounded.
   */
  dpopProof: (jkt: string, jti: string): string => `${NS}:dpop:${jkt}:${jti}`,

  /**
   * A single-use token — password reset, email verification, magic link.
   *
   * Keyed by `hashToken(rawToken)`, so a store read yields nothing usable: the
   * raw value exists only in the email that carried it.
   *
   * The purpose is part of the key rather than a field compared afterwards. A
   * password-reset token presented to an email-verification endpoint is
   * therefore not *rejected*, it is simply absent — and a check that cannot be
   * skipped is better than one that must be remembered.
   *
   * TTL: the token's remaining lifetime.
   */
  oneTimeToken: (purpose: string, tokenHash: string): string =>
    `${NS}:ott:${purpose}:${tokenHash}`,

  /**
   * Set of outstanding single-use token hashes for one subject and purpose.
   *
   * Read when issuing a replacement, so requesting a second password-reset
   * email invalidates the first — OWASP's guidance, and what stops an old link
   * sitting in an inbox from working indefinitely.
   */
  oneTimeTokenSubject: (purpose: string, subject: string): string =>
    `${NS}:ott:${purpose}:sub:${subject}`,

  /**
   * Rate-limit counter for one bucket in one time window.
   *
   * The window index is part of the key rather than being enforced by TTL.
   * That is what makes the counter safe to touch repeatedly: refreshing the
   * expiry delays cleanup but cannot extend a window, because a new window is
   * a different key.
   */
  rateLimit: (bucket: string, windowIndex: number): string =>
    `${NS}:rl:${bucket}:${windowIndex}`,
} as const;
