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
