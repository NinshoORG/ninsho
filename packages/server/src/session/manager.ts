import {
  RefreshInvalidError,
  RefreshReuseError,
  type AuditSink,
  type Principal,
  type RefreshRecord,
  type TokenPair,
  generateId,
  generateToken,
  hashToken,
  isExpired,
  isoIn,
  isoToMs,
  nowIso,
  secondsUntil,
} from '@ninsho/core';
import type { NinshoStore } from '../store/types.js';
import type { TokenEngine } from '../engine/types.js';
import { KEYS } from '../keys.js';
import type {
  ConsumedRefreshRecord,
  GraceRecord,
  RevocationReason,
  SessionMeta,
  SessionSummary,
} from './types.js';

/**
 * How many times a caller that lost a rotation race re-checks for the
 * winner's tombstone, and how long it pauses between attempts. Together these
 * bound the extra latency an unrecognised refresh token can cost.
 */
const TOMBSTONE_RETRIES = 3;
const TOMBSTONE_RETRY_MS = 5;

export interface SessionManagerOptions {
  readonly refreshTokenTtl: number;
  readonly refreshGraceSeconds: number;
  readonly clockToleranceSeconds: number;
  readonly audit: AuditSink;
}

/**
 * Sessions, refresh-token rotation, and reuse detection.
 *
 * ─── The security property this class exists to provide ───────────────────
 * Rotation alone is not theft protection. If a stolen refresh token is
 * redeemed by an attacker before the legitimate client's next refresh, the
 * attacker holds a valid rotating chain and the victim simply sees one failed
 * refresh, shrugs, and signs in again. Nothing is revoked and no alarm fires.
 * That was the predecessor's behaviour, and it discards the single strongest
 * compromise signal an authentication system can observe.
 *
 * RFC 9700 §4.14.2 and OAuth 2.1 require the opposite: presenting a refresh
 * token that has already been rotated must invalidate the **entire family**,
 * because exactly one of the two parties holding that token is an attacker and
 * there is no way to tell which. Ending the session is the only safe response —
 * it costs the legitimate user one sign-in and costs the attacker everything.
 *
 * Ninsho implements that, and emits `refresh.reuse_detected` so the host
 * application can notify the user or raise an alert.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * ─── How rotation stays race-free ─────────────────────────────────────────
 * Rotation begins with `store.take()` on the live record — an atomic
 * read-and-delete. Of any number of concurrent callers presenting the same
 * token, exactly one receives the record and rotates; every other caller sees
 * `null` and falls through to the grace path. No lock, no Lua script, and no
 * window in which two callers both mint a replacement.
 *
 * The grace window then distinguishes a browser's second tab (which raced and
 * lost microseconds ago) from an attacker replaying a token minutes later.
 * That distinction is heuristic, and the window length is the trade-off knob:
 * see `refreshGraceSeconds`.
 * ──────────────────────────────────────────────────────────────────────────
 */
export class SessionManager {
  readonly #store: NinshoStore;
  readonly #engine: TokenEngine;
  readonly #options: SessionManagerOptions;

  constructor(store: NinshoStore, engine: TokenEngine, options: SessionManagerOptions) {
    this.#store = store;
    this.#engine = engine;
    this.#options = options;
  }

  /**
   * Starts a session: mints a refresh token and a first access token.
   *
   * Call this only after the caller's identity has been established. Ninsho
   * does not verify credentials — passwords, WebAuthn and federated login are
   * the application's concern, and conflating the two is how auth libraries
   * end up dictating a user model.
   */
  async create(principal: Principal): Promise<TokenPair> {
    const sessionId = generateId();
    const now = nowIso();
    // Fixed here and never extended, so rotation cannot grant a session
    // unlimited life.
    const familyExpiresAt = isoIn(this.#options.refreshTokenTtl);

    const refreshToken = await this.#writeRefreshToken({
      sessionId,
      principal,
      issuedAt: now,
      expiresAt: familyExpiresAt,
      familyExpiresAt,
      generation: 0,
    });

    const meta: SessionMeta = {
      sessionId,
      userId: principal.userId,
      createdAt: now,
      lastUsedAt: now,
      expiresAt: familyExpiresAt,
      generation: 0,
    };
    const familyTtl = secondsUntil(familyExpiresAt);
    await this.#store.set(KEYS.sessionMeta(sessionId), JSON.stringify(meta), familyTtl);
    await this.#store.sAdd(KEYS.userSessions(principal.userId), sessionId, familyTtl);

    const access = await this.#engine.issue({ principal, sessionId });

    this.#options.audit.emit({
      type: 'session.created',
      at: now,
      userId: principal.userId,
      sessionId,
      tokenId: access.tokenId,
    });

    return {
      accessToken: access.token,
      refreshToken,
      accessExpiresAt: access.expiresAt,
      refreshExpiresAt: familyExpiresAt,
      sessionId,
    };
  }

  /**
   * Exchanges a refresh token for a new pair, rotating the refresh token.
   *
   * @throws {RefreshInvalidError} Unknown, malformed, or expired token — and
   *   for a token whose family has already been terminated. Carries no
   *   information about which of those it was.
   * @throws {RefreshReuseError} The token was already rotated and the grace
   *   window has passed. The family is revoked before this throws.
   */
  async refresh(rawToken: string): Promise<TokenPair> {
    if (typeof rawToken !== 'string' || rawToken.length === 0) {
      throw new RefreshInvalidError('empty or non-string refresh token');
    }

    const hash = hashToken(rawToken);

    // Atomic. Exactly one concurrent caller can win this.
    const liveRaw = await this.#store.take(KEYS.refreshToken(hash));

    if (liveRaw !== null) {
      return this.#rotate(hash, liveRaw);
    }

    // Either this caller lost the race, or the token is stale, forged, or
    // being replayed. Only the tombstone can tell those apart.
    return this.#resolveNonLive(hash);
  }

  /** Ends one session: its refresh family and all its access tokens. */
  async revoke(sessionId: string, reason: RevocationReason = 'logout'): Promise<void> {
    await this.#revokeFamily(sessionId, reason);
  }

  /**
   * Ends every session for a user. The response to a password change, a
   * suspected compromise, or a "sign out everywhere" button.
   */
  async revokeAllForUser(
    userId: string,
    reason: RevocationReason = 'logout_all',
  ): Promise<void> {
    const sessionIds = await this.#store.sMembers(KEYS.userSessions(userId));

    for (const sessionId of sessionIds) {
      await this.#revokeFamily(sessionId, reason, { skipUserIndex: true });
    }

    await this.#store.delete(KEYS.userSessions(userId));

    this.#options.audit.emit({
      type: 'session.revoked_all',
      at: nowIso(),
      userId,
      reason,
    });
  }

  /**
   * Lists a user's live sessions, for an account-security screen.
   * Contains no credential material — session ids only.
   *
   * Expired entries are pruned as they are encountered, so the user's index
   * does not accumulate dead sessions for the life of the account.
   */
  async listSessions(userId: string, currentSessionId?: string): Promise<SessionSummary[]> {
    const sessionIds = await this.#store.sMembers(KEYS.userSessions(userId));
    const summaries: SessionSummary[] = [];
    const stale: string[] = [];

    for (const sessionId of sessionIds) {
      const raw = await this.#store.get(KEYS.sessionMeta(sessionId));
      if (raw === null) {
        stale.push(sessionId);
        continue;
      }
      const meta = this.#parseMeta(raw);
      if (meta === null || isExpired(meta.expiresAt)) {
        stale.push(sessionId);
        continue;
      }

      summaries.push({
        sessionId: meta.sessionId,
        createdAt: meta.createdAt,
        lastUsedAt: meta.lastUsedAt,
        expiresAt: meta.expiresAt,
        generation: meta.generation,
        current: currentSessionId !== undefined && meta.sessionId === currentSessionId,
      });
    }

    if (stale.length > 0) {
      await this.#store.sRemove(KEYS.userSessions(userId), ...stale);
    }

    return summaries;
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  /** Writes a refresh record and indexes it under its family. */
  async #writeRefreshToken(record: RefreshRecord): Promise<string> {
    const rawToken = generateToken();
    const hash = hashToken(rawToken);
    const ttl = secondsUntil(record.expiresAt);

    await this.#store.set(KEYS.refreshToken(hash), JSON.stringify(record), ttl);
    // Indexed so the family can be revoked wholesale without scanning.
    // Outlives the token slightly so the index never expires beneath a live
    // member — a revocation that silently missed a token would be worse than
    // one that failed loudly.
    await this.#store.sAdd(
      KEYS.sessionRefresh(record.sessionId),
      hash,
      secondsUntil(record.familyExpiresAt) + 60,
    );

    return rawToken;
  }

  /** The winning path: this caller consumed the live record and rotates it. */
  async #rotate(oldHash: string, recordJson: string): Promise<TokenPair> {
    const record = this.#parseRefreshRecord(recordJson);
    if (record === null) {
      // Unparseable. The token is gone (take() removed it) and there is no
      // trustworthy family id to act on, so fail without revoking anything.
      throw new RefreshInvalidError('stored refresh record is malformed');
    }

    const { sessionId, principal } = record;

    // The session may have been terminated between this token being issued and
    // being presented. The marker is authoritative where the family index is
    // not: revocation writes it before enumerating, so a logout that raced a
    // rotation is still visible here.
    if (await this.#store.exists(KEYS.sessionRevoked(sessionId))) {
      throw new RefreshInvalidError(`session ${sessionId} has been revoked`);
    }

    // A token past its own expiry, or past the family ceiling, is dead. This
    // is not reuse — nothing is revoked beyond the token already consumed.
    if (
      isExpired(record.expiresAt, this.#options.clockToleranceSeconds) ||
      isExpired(record.familyExpiresAt, this.#options.clockToleranceSeconds)
    ) {
      await this.#revokeFamily(sessionId, 'administrative', { silent: true });
      throw new RefreshInvalidError(`refresh token for session ${sessionId} expired`);
    }

    const now = nowIso();
    const generation = record.generation + 1;

    // The new token expires at the sooner of a full TTL from now and the
    // family ceiling — rotation extends the token, never the session.
    const proposed = isoIn(this.#options.refreshTokenTtl);
    const expiresAt =
      isoToMs(proposed) < isoToMs(record.familyExpiresAt) ? proposed : record.familyExpiresAt;

    const newToken = await this.#writeRefreshToken({
      sessionId,
      principal,
      issuedAt: now,
      expiresAt,
      familyExpiresAt: record.familyExpiresAt,
      generation,
    });

    // ─── Write order below is load-bearing ────────────────────────────────
    // The tombstone is the last thing written, because a caller that lost the
    // race treats "tombstone present, grace absent" as reuse and revokes the
    // family. Publishing the tombstone first would open a window in which a
    // legitimate parallel tab sees exactly that and destroys a healthy
    // session. Grace first, tombstone second, so the tombstone's presence
    // guarantees grace is already visible.
    // ──────────────────────────────────────────────────────────────────────

    // Grace mapping, so a parallel tab that lost the race adopts this
    // replacement rather than being signed out. Short-lived by design: this
    // is the only raw token Ninsho ever stores.
    if (this.#options.refreshGraceSeconds > 0) {
      const grace: GraceRecord = { token: newToken, expiresAt };
      await this.#store.set(
        KEYS.refreshGrace(oldHash),
        JSON.stringify(grace),
        this.#options.refreshGraceSeconds,
      );
    }

    // Tombstone: proves this token was real, so a later replay is recognised
    // as reuse rather than dismissed as garbage. Lives as long as the family,
    // and doubles as the signal that this rotation has completed.
    const consumed: ConsumedRefreshRecord = {
      sessionId,
      generation: record.generation,
      rotatedAt: now,
      principal,
    };
    await this.#store.set(
      KEYS.refreshConsumed(oldHash),
      JSON.stringify(consumed),
      secondsUntil(record.familyExpiresAt),
    );

    // Re-check after publishing. A revocation that began between the check
    // above and this point has, by now, written its marker — so this is where
    // that interleaving is caught. Without it, the replacement record would
    // survive a completed logout with nothing left pointing at it.
    if (await this.#store.exists(KEYS.sessionRevoked(sessionId))) {
      await this.#store.delete(
        KEYS.refreshToken(hashToken(newToken)),
        KEYS.refreshGrace(oldHash),
      );
      throw new RefreshInvalidError(
        `session ${sessionId} was revoked during rotation`,
      );
    }

    await this.#touchMeta(sessionId, generation);

    const access = await this.#engine.issue({ principal, sessionId });

    this.#options.audit.emit({
      type: 'session.refreshed',
      at: now,
      userId: principal.userId,
      sessionId,
      tokenId: access.tokenId,
    });

    return {
      accessToken: access.token,
      refreshToken: newToken,
      accessExpiresAt: access.expiresAt,
      refreshExpiresAt: expiresAt,
      sessionId,
    };
  }

  /**
   * The token was not live. Decide between "never existed", "lost a race", and
   * "being replayed".
   */
  async #resolveNonLive(hash: string): Promise<TokenPair> {
    const consumedRaw = await this.#awaitTombstone(hash);

    if (consumedRaw === null) {
      // No tombstone: forged, long expired, or belonging to a family that was
      // already revoked. There is no family to act on, and revoking on an
      // unrecognised token would hand an attacker a denial-of-service — submit
      // garbage, log someone out.
      throw new RefreshInvalidError('no record for presented refresh token');
    }

    const consumed = this.#parseConsumed(consumedRaw);
    if (consumed === null) {
      throw new RefreshInvalidError('consumed refresh record is malformed');
    }

    const graceRaw = await this.#store.get(KEYS.refreshGrace(hash));
    if (graceRaw !== null) {
      const grace = this.#parseGrace(graceRaw);
      if (grace !== null) {
        return this.#adoptReplacement(consumed, grace);
      }
    }

    // Tombstoned, and past the grace window. One of the two parties holding
    // this token is an attacker, and there is no way to tell which — so the
    // session ends for both.
    await this.#revokeFamily(consumed.sessionId, 'reuse_detected');

    this.#options.audit.emit({
      type: 'refresh.reuse_detected',
      at: nowIso(),
      userId: consumed.principal.userId,
      sessionId: consumed.sessionId,
      reason: `replayed generation ${consumed.generation}`,
    });

    throw new RefreshReuseError(
      `refresh token for session ${consumed.sessionId} replayed after rotation`,
    );
  }

  /**
   * Reads the tombstone, briefly tolerating a rotation that is still in flight.
   *
   * `take()` makes the *consumption* of a token atomic, but publishing the
   * tombstone that follows it is a second round trip. A caller that lost the
   * race by microseconds can arrive in between and see neither a live record
   * nor a tombstone — and reporting a failure there would sign out a
   * legitimate parallel tab, which is precisely what the grace window exists
   * to prevent.
   *
   * The wait is bounded and tiny: the winner needs only a couple of store
   * writes. A genuinely unknown token pays this cost once and is then
   * rejected, so the ceiling on wasted work per bogus request is a few
   * milliseconds.
   *
   * Skipped entirely when the grace window is disabled — `refreshGraceSeconds:
   * 0` means "tolerate nothing", and waiting to be lenient would contradict it.
   */
  async #awaitTombstone(hash: string): Promise<string | null> {
    const key = KEYS.refreshConsumed(hash);

    const first = await this.#store.get(key);
    if (first !== null || this.#options.refreshGraceSeconds <= 0) {
      return first;
    }

    for (let attempt = 0; attempt < TOMBSTONE_RETRIES; attempt += 1) {
      await new Promise((resolve) => {
        setTimeout(resolve, TOMBSTONE_RETRY_MS);
      });
      const retried = await this.#store.get(key);
      if (retried !== null) return retried;
    }

    return null;
  }

  /**
   * Grace path: another tab rotated moments ago. Hand this caller the same
   * replacement token and a fresh access token, so both tabs converge on one
   * chain instead of one of them being signed out.
   */
  async #adoptReplacement(
    consumed: ConsumedRefreshRecord,
    grace: GraceRecord,
  ): Promise<TokenPair> {
    // A grace mapping can outlive the revocation that should have removed it,
    // for the same reason a rotation's output can: both are written outside
    // the index that revocation enumerates.
    if (await this.#store.exists(KEYS.sessionRevoked(consumed.sessionId))) {
      throw new RefreshInvalidError(`session ${consumed.sessionId} has been revoked`);
    }

    const access = await this.#engine.issue({
      principal: consumed.principal,
      sessionId: consumed.sessionId,
    });

    this.#options.audit.emit({
      type: 'session.refreshed',
      at: nowIso(),
      userId: consumed.principal.userId,
      sessionId: consumed.sessionId,
      tokenId: access.tokenId,
      reason: 'grace_window',
    });

    return {
      accessToken: access.token,
      refreshToken: grace.token,
      accessExpiresAt: access.expiresAt,
      refreshExpiresAt: grace.expiresAt,
      sessionId: consumed.sessionId,
    };
  }

  /**
   * Terminates a family: every refresh token, every tombstone, every grace
   * mapping, the session metadata, and — via the engine — every access token
   * issued under it.
   *
   * Tombstones are deleted deliberately. Keeping them would make every stale
   * tab belonging to a legitimately ended session raise a reuse alarm, and an
   * alert channel full of false positives is one nobody reads.
   */
  async #revokeFamily(
    sessionId: string,
    reason: RevocationReason,
    options: { skipUserIndex?: boolean; silent?: boolean } = {},
  ): Promise<void> {
    // Written before anything is read. Ordering is the whole point: a rotation
    // running concurrently will observe this marker even if its own record
    // reaches the index too late to be enumerated below.
    await this.#store.set(
      KEYS.sessionRevoked(sessionId),
      '1',
      this.#options.refreshTokenTtl,
    );

    const metaRaw = await this.#store.get(KEYS.sessionMeta(sessionId));
    const meta = metaRaw === null ? null : this.#parseMeta(metaRaw);

    const hashes = await this.#store.sMembers(KEYS.sessionRefresh(sessionId));
    if (hashes.length > 0) {
      await this.#store.delete(
        ...hashes.map((h) => KEYS.refreshToken(h)),
        ...hashes.map((h) => KEYS.refreshConsumed(h)),
        ...hashes.map((h) => KEYS.refreshGrace(h)),
      );
    }

    await this.#store.delete(KEYS.sessionRefresh(sessionId), KEYS.sessionMeta(sessionId));

    // Access tokens are the engine's to revoke — the session layer stays
    // strategy-agnostic.
    await this.#engine.revokeSession(sessionId);

    if (meta !== null && options.skipUserIndex !== true) {
      await this.#store.sRemove(KEYS.userSessions(meta.userId), sessionId);
    }

    if (options.silent !== true) {
      this.#options.audit.emit({
        type: 'session.revoked',
        at: nowIso(),
        ...(meta !== null && { userId: meta.userId }),
        sessionId,
        reason,
      });
    }
  }

  /** Records that a session was used, for the sessions list. Best-effort. */
  async #touchMeta(sessionId: string, generation: number): Promise<void> {
    const raw = await this.#store.get(KEYS.sessionMeta(sessionId));
    if (raw === null) return;
    const meta = this.#parseMeta(raw);
    if (meta === null) return;

    const updated: SessionMeta = { ...meta, lastUsedAt: nowIso(), generation };
    await this.#store.set(
      KEYS.sessionMeta(sessionId),
      JSON.stringify(updated),
      secondsUntil(meta.expiresAt),
    );
  }

  // ── Parsing ───────────────────────────────────────────────────────────────
  // Every stored value is re-validated on read. A record can be malformed
  // because a schema changed, because something else wrote the key, or because
  // it was truncated — none of which is a reason to renew a session.

  #parseJson(raw: string): Record<string, unknown> | null {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return null;
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  }

  #parsePrincipal(value: unknown): Principal | null {
    if (typeof value !== 'object' || value === null) return null;
    const p = value as Record<string, unknown>;
    if (typeof p['userId'] !== 'string' || p['userId'].length === 0) return null;

    const roles = p['roles'];
    const scopes = p['scopes'];
    if (!Array.isArray(roles) || !roles.every((x) => typeof x === 'string')) return null;
    if (!Array.isArray(scopes) || !scopes.every((x) => typeof x === 'string')) return null;

    const tenant = p['tenant'];
    if (tenant !== undefined && typeof tenant !== 'string') return null;

    return {
      userId: p['userId'],
      roles: roles as string[],
      scopes: scopes as string[],
      ...(tenant !== undefined && { tenant }),
    };
  }

  #parseRefreshRecord(raw: string): RefreshRecord | null {
    const r = this.#parseJson(raw);
    if (r === null) return null;

    if (
      typeof r['sessionId'] !== 'string' ||
      typeof r['issuedAt'] !== 'string' ||
      typeof r['expiresAt'] !== 'string' ||
      typeof r['familyExpiresAt'] !== 'string' ||
      typeof r['generation'] !== 'number' ||
      !Number.isInteger(r['generation']) ||
      r['generation'] < 0
    ) {
      return null;
    }

    const principal = this.#parsePrincipal(r['principal']);
    if (principal === null) return null;

    return {
      sessionId: r['sessionId'],
      principal,
      issuedAt: r['issuedAt'],
      expiresAt: r['expiresAt'],
      familyExpiresAt: r['familyExpiresAt'],
      generation: r['generation'],
    };
  }

  #parseConsumed(raw: string): ConsumedRefreshRecord | null {
    const r = this.#parseJson(raw);
    if (r === null) return null;

    if (
      typeof r['sessionId'] !== 'string' ||
      typeof r['rotatedAt'] !== 'string' ||
      typeof r['generation'] !== 'number'
    ) {
      return null;
    }

    const principal = this.#parsePrincipal(r['principal']);
    if (principal === null) return null;

    return {
      sessionId: r['sessionId'],
      generation: r['generation'],
      rotatedAt: r['rotatedAt'],
      principal,
    };
  }

  #parseGrace(raw: string): GraceRecord | null {
    const r = this.#parseJson(raw);
    if (r === null) return null;
    if (typeof r['token'] !== 'string' || r['token'].length === 0) return null;
    if (typeof r['expiresAt'] !== 'string') return null;
    return { token: r['token'], expiresAt: r['expiresAt'] };
  }

  #parseMeta(raw: string): SessionMeta | null {
    const r = this.#parseJson(raw);
    if (r === null) return null;

    if (
      typeof r['sessionId'] !== 'string' ||
      typeof r['userId'] !== 'string' ||
      typeof r['createdAt'] !== 'string' ||
      typeof r['lastUsedAt'] !== 'string' ||
      typeof r['expiresAt'] !== 'string' ||
      typeof r['generation'] !== 'number'
    ) {
      return null;
    }

    return {
      sessionId: r['sessionId'],
      userId: r['userId'],
      createdAt: r['createdAt'],
      lastUsedAt: r['lastUsedAt'],
      expiresAt: r['expiresAt'],
      generation: r['generation'],
    };
  }
}
