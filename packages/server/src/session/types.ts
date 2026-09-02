import type { Principal } from '@ninsho/core';

/**
 * Tombstone left behind when a refresh token is rotated.
 *
 * Its existence is what distinguishes "this token was real and has been used"
 * from "this token was never real". That distinction is the whole of reuse
 * detection: without it, a replayed token and a fabricated one produce the
 * same 401 and the strongest available signal of credential theft is
 * discarded.
 *
 * SECURITY: never holds a raw token. The raw replacement lives in a separate
 * key with a much shorter TTL — see `KEYS.refreshGrace`.
 */
export interface ConsumedRefreshRecord {
  /** Family to revoke if this token is presented again outside the grace window. */
  readonly sessionId: string;
  /** Which rotation produced this tombstone. Reported in the reuse event. */
  readonly generation: number;
  /** When the rotation happened. */
  readonly rotatedAt: string;
  /**
   * Carried so the grace path can mint an access token without a second
   * lookup. Identical to the family's principal — rotation never changes it.
   */
  readonly principal: Principal;
  /**
   * The family's authentication time, carried for the same reason as the
   * principal — the grace path mints a token and must not reset it. A parallel
   * tab racing a refresh is not a new authentication.
   */
  readonly authenticatedAt: string;
  /**
   * The family's DPoP binding, carried so the grace path enforces it too.
   *
   * Without it, replaying a bound token inside the grace window would hand
   * back a live credential without any proof-of-possession check — a way
   * around the binding rather than an exception to it.
   */
  readonly confirmationKey?: string;
}

/** Options for starting a session. */
export interface CreateSessionOptions {
  /**
   * RFC 7638 thumbprint of the client's DPoP key, under `binding: 'dpop'`.
   * Binds both the access token and the refresh family to that key.
   */
  readonly confirmationKey?: string;
}

/** Options for redeeming a refresh token. */
export interface RefreshSessionOptions {
  /**
   * Thumbprint of the key that signed the proof accompanying this request.
   * Must match the family's binding; a bound family presented without one is
   * refused.
   */
  readonly confirmationKey?: string;
}

/** Value stored under `KEYS.refreshGrace`, for a tab that lost a rotation race. */
export interface GraceRecord {
  /**
   * The raw replacement token.
   * SECURITY: the only raw token Ninsho stores, held for the grace period
   * only (30s by default) because the receiving tab needs the literal value
   * to set its cookie.
   */
  readonly token: string;
  readonly expiresAt: string;
}

/** Metadata about a live session, for listing a user's active sessions. */
export interface SessionMeta {
  readonly sessionId: string;
  readonly userId: string;
  readonly createdAt: string;
  readonly lastUsedAt: string;
  /** Hard ceiling on the session, fixed at creation. */
  readonly expiresAt: string;
  readonly generation: number;
}

/**
 * A session as reported to an application, e.g. for a "your active sessions"
 * screen. Contains no credential material.
 */
export interface SessionSummary {
  readonly sessionId: string;
  readonly createdAt: string;
  readonly lastUsedAt: string;
  readonly expiresAt: string;
  /** How many times this session has been refreshed. */
  readonly generation: number;
  /** True when this is the session that made the current request. */
  readonly current: boolean;
}

/** Why a session was terminated. Surfaces in the audit log. */
export type RevocationReason =
  | 'logout'
  | 'logout_all'
  | 'reuse_detected'
  /**
   * The password changed, so every existing session must end.
   *
   * Distinguished from `administrative` because it is the one an incident
   * review looks for: whoever forced a reset may already hold a session, and a
   * password change that left those alive accomplished nothing.
   */
  | 'credential_changed'
  | 'administrative';
