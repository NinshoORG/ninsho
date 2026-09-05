import {
  RefreshInvalidError,
  RefreshReuseError,
  type AuditSink,
  type ClientSignals,
  type Principal,
  type RefreshRecord,
  type SecuritySignals,
  type TokenPair,
  generateId,
  generateToken,
  hashSignal,
  hashToken,
  isExpired,
  isoFrom,
  isoIn,
  isoToMs,
  nowIso,
  secondsUntil,
} from '@ninsho/core';
import type { NinshoStore } from '../store/types.js';
import type { TokenEngine } from '../engine/types.js';
import { KEYS } from '../keys.js';
import { mapConcurrent } from '../internal/concurrent.js';
import type {
  CreateSessionOptions,
  RefreshSessionOptions,
  ConsumedRefreshRecord,
  GraceRecord,
  RevocationReason,
  SessionMeta,
  SessionSummary,
} from './types.js';

/**
 * Backoff for a caller that lost a rotation race and is waiting for the
 * winner's tombstone to appear.
 *
 * ─── Why these numbers, and why they changed ──────────────────────────────
 * This was a flat 3 x 5ms. That was tuned against `MemoryStore`, where the
 * winner's follow-up writes complete inside a single tick, and it is far too
 * tight for a store that lives across a socket.
 *
 * Measured against a local Redis, a rotation race takes 14ms at the median
 * with two callers and 45-85ms with forty. Under the old 15ms ceiling, losers
 * gave up before the winner had published, and reported `no record for
 * presented refresh token` — a spurious sign-out for a parallel tab, which is
 * the precise failure the grace window exists to prevent. At a concurrency of
 * 100 it happened in a quarter of attempts.
 *
 * Exponential steps totalling ~126ms fix that without slowing the common case:
 * the loop returns the moment the tombstone appears, so a typical loser waits
 * one or two steps.
 *
 * The cost is paid only by a token that never had a tombstone — genuinely
 * unknown or forged — which occupies a request for up to ~126ms before being
 * refused. A token whose family was *deliberately* revoked is answered at once
 * from the marker revocation leaves (`KEYS.refreshRevoked`), because otherwise
 * every tab still open after a sign-out-everywhere would pay this, and that is
 * a routine event rather than a suspect one. What remains is a bounded
 * amplification on unrecognised input, and the refresh endpoint should be
 * rate-limited regardless; `auth.rateLimit()` is there for it.
 * ──────────────────────────────────────────────────────────────────────────
 */
const TOMBSTONE_BACKOFF_MS = [2, 4, 8, 16, 32, 64] as const;

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
/**
 * Hashes raw client signals for storage.
 *
 * Truncated hashes, never the raw values: an IP address is personal data, and
 * a store that never held one cannot leak one. Nothing branches on the result
 * — these are trivially forged — so hashing costs nothing that matters and
 * makes the privacy property structural rather than a caller's responsibility.
 */
function hashSignals(signals: ClientSignals | undefined): SecuritySignals | undefined {
  if (signals === undefined) return undefined;

  const hashed: { userAgentHash?: string; ipHash?: string } = {};
  if (typeof signals.userAgent === 'string' && signals.userAgent.length > 0) {
    hashed.userAgentHash = hashSignal(signals.userAgent);
  }
  if (typeof signals.ip === 'string' && signals.ip.length > 0) {
    hashed.ipHash = hashSignal(signals.ip);
  }
  return hashed.userAgentHash === undefined && hashed.ipHash === undefined ? undefined : hashed;
}

/**
 * Compares recorded signals against those of the current request.
 *
 * `unknown` when either side is missing — the honest answer, rather than
 * treating an absent signal as a match and reporting confidence that was never
 * established.
 */
function compareSignals(
  recorded: SecuritySignals | undefined,
  presented: SecuritySignals | undefined,
): 'same' | 'different' | 'unknown' {
  if (recorded === undefined || presented === undefined) return 'unknown';

  const fields = ['userAgentHash', 'ipHash'] as const;
  let compared = 0;

  for (const field of fields) {
    const a = recorded[field];
    const b = presented[field];
    if (a === undefined || b === undefined) continue;
    compared += 1;
    if (a !== b) return 'different';
  }

  return compared === 0 ? 'unknown' : 'same';
}

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
  async create(principal: Principal, options: CreateSessionOptions = {}): Promise<TokenPair> {
    const sessionId = generateId();
    const startedAt = Date.now();
    const now = isoFrom(startedAt);
    // Fixed here and never extended, so rotation cannot grant a session
    // unlimited life. Derived from the same instant as `now`.
    const familyExpiresAt = isoFrom(startedAt, this.#options.refreshTokenTtl);

    const refreshToken = await this.#writeRefreshToken({
      sessionId,
      principal,
      issuedAt: now,
      // The session is being created, so this *is* the authentication. Every
      // later rotation carries this value forward unchanged.
      authenticatedAt: now,
      expiresAt: familyExpiresAt,
      familyExpiresAt,
      generation: 0,
      ...(options.confirmationKey !== undefined && {
        confirmationKey: options.confirmationKey,
      }),
    });

    const signals = hashSignals(options.signals);
    const meta: SessionMeta = {
      sessionId,
      userId: principal.userId,
      createdAt: now,
      lastUsedAt: now,
      expiresAt: familyExpiresAt,
      generation: 0,
      ...(signals !== undefined && { signals }),
    };
    const familyTtl = secondsUntil(familyExpiresAt);
    await this.#store.set(KEYS.sessionMeta(sessionId), JSON.stringify(meta), familyTtl);
    await this.#store.sAdd(KEYS.userSessions(principal.userId), sessionId, familyTtl);

    const access = await this.#engine.issue({
      principal,
      sessionId,
      authenticatedAt: now,
      ...(options.confirmationKey !== undefined && {
        confirmationKey: options.confirmationKey,
      }),
    });

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
  async refresh(
    rawToken: string,
    options: RefreshSessionOptions = {},
  ): Promise<TokenPair> {
    if (typeof rawToken !== 'string' || rawToken.length === 0) {
      throw new RefreshInvalidError('empty or non-string refresh token');
    }

    const hash = hashToken(rawToken);

    // ─── The binding is checked before the token is consumed ───────────────
    // `take()` is destructive, so checking the DPoP binding after it would let
    // an attacker holding a stolen refresh token — but not the key — destroy
    // the session simply by presenting it. The token would be consumed, the
    // rotation would then fail, and the legitimate client's next refresh would
    // find nothing. A denial of service handed to exactly the party the
    // binding is meant to shut out.
    //
    // Peeking first costs one extra round trip on the refresh path, which runs
    // once per token lifetime rather than per request. It is not a
    // time-of-check problem: a token's binding is fixed at issuance, so a
    // binding that matches now still matches at `take()`. Losing the race to
    // another caller in between simply falls through to the grace path, which
    // is the behaviour that path exists for.
    // ──────────────────────────────────────────────────────────────────────
    const peeked = await this.#store.get(KEYS.refreshToken(hash));
    if (peeked !== null) {
      const record = this.#parseRefreshRecord(peeked);
      if (record !== null && record.confirmationKey !== undefined) {
        if (options.confirmationKey === undefined) {
          throw new RefreshInvalidError(
            `refresh token for session ${record.sessionId} is DPoP-bound but no proof was presented`,
          );
        }
        if (options.confirmationKey !== record.confirmationKey) {
          throw new RefreshInvalidError(
            `refresh token for session ${record.sessionId} is bound to a different key`,
          );
        }
      }
    }

    // Atomic. Exactly one concurrent caller can win this.
    const liveRaw = await this.#store.take(KEYS.refreshToken(hash));

    if (liveRaw !== null) {
      return this.#rotate(hash, liveRaw, options.confirmationKey);
    }

    // Either this caller lost the race, or the token is stale, forged, or
    // being replayed. Only the tombstone can tell those apart.
    return this.#resolveNonLive(hash, options.confirmationKey, hashSignals(options.signals));
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

    // Bounded parallelism. Serially this was one round trip at a time — around
    // 4,500 for a user with 500 sessions, which is seconds against a real
    // store. This is the operation invoked during an incident, so it needs to
    // finish.
    //
    // Failures are swallowed per session rather than propagated: one corrupt
    // record must not abandon the remaining sessions half-revoked, which would
    // leave the caller believing they had signed out everywhere when they had
    // not. Each failure is still recorded.
    const failures = await mapConcurrent(sessionIds, async (sessionId) => {
      try {
        await this.#revokeFamily(sessionId, reason, { skipUserIndex: true });
        return null;
      } catch (error) {
        return { sessionId, error };
      }
    });

    await this.#store.delete(KEYS.userSessions(userId));

    for (const failure of failures) {
      if (failure === null) continue;
      this.#options.audit.emit({
        type: 'session.revoked',
        at: nowIso(),
        userId,
        sessionId: failure.sessionId,
        reason: 'revocation_failed',
      });
    }

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

    // Bounded parallelism: one round trip per session, and a user with many
    // devices should not wait for them in series.
    const loaded = await mapConcurrent(sessionIds, async (sessionId) => {
      const raw = await this.#store.get(KEYS.sessionMeta(sessionId));
      return { sessionId, meta: raw === null ? null : this.#parseMeta(raw) };
    });

    const summaries: SessionSummary[] = [];
    const stale: string[] = [];

    for (const { sessionId, meta } of loaded) {
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
        ...(meta.signals !== undefined && { signals: meta.signals }),
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
  async #rotate(
    oldHash: string,
    recordJson: string,
    presentedKey: string | undefined,
  ): Promise<TokenPair> {
    const record = this.#parseRefreshRecord(recordJson);
    if (record === null) {
      // Unparseable. The token is gone (take() removed it) and there is no
      // trustworthy family id to act on, so fail without revoking anything.
      throw new RefreshInvalidError('stored refresh record is malformed');
    }

    const { sessionId, principal } = record;

    // RFC 9449 section 5: a refresh token bound to a key must only be
    // redeemable by the holder of that key. Without this the longest-lived
    // credential in the system would be the one piece with no
    // proof-of-possession, and stealing it would still hand an attacker an
    // indefinite session.
    //
    // `refresh()` has already rejected a mismatch before consuming the token.
    // This is the backstop for any future caller that reaches #rotate by
    // another path — a check this cheap is worth keeping in both places.
    if (record.confirmationKey !== undefined) {
      if (presentedKey === undefined) {
        throw new RefreshInvalidError(
          `refresh token for session ${sessionId} is DPoP-bound but no proof was presented`,
        );
      }
      if (presentedKey !== record.confirmationKey) {
        throw new RefreshInvalidError(
          `refresh token for session ${sessionId} is bound to a different key`,
        );
      }
    }

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
      // Deliberately the original, not `now`. A refresh proves possession of a
      // token, not that the user is present — resetting this would let a
      // session stay "freshly authenticated" forever and quietly defeat every
      // step-up check built on it.
      authenticatedAt: record.authenticatedAt,
      expiresAt,
      familyExpiresAt: record.familyExpiresAt,
      generation,
      ...(record.confirmationKey !== undefined && {
        confirmationKey: record.confirmationKey,
      }),
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
      authenticatedAt: record.authenticatedAt,
      ...(record.confirmationKey !== undefined && {
        confirmationKey: record.confirmationKey,
      }),
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

    const access = await this.#engine.issue({
      principal,
      sessionId,
      authenticatedAt: record.authenticatedAt,
      ...(record.confirmationKey !== undefined && {
        confirmationKey: record.confirmationKey,
      }),
    });

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
  async #resolveNonLive(
    hash: string,
    presentedKey: string | undefined,
    presentedSignals: SecuritySignals | undefined,
  ): Promise<TokenPair> {
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
        return this.#adoptReplacement(consumed, grace, presentedKey);
      }
    }

    // Read before revoking: revocation deletes the metadata this compares
    // against, and losing the signal would make the alarm less useful at
    // exactly the moment it matters.
    const signalMatch = compareSignals(await this.#readSignals(consumed.sessionId), presentedSignals);

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
      // The difference between an alarm and an actionable one: a replay from a
      // different client is close to certain theft, while one from the same
      // client is more often a retry in the application's own code.
      signalMatch,
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
   * The wait is bounded and returns the instant the tombstone appears, so a
   * caller that genuinely lost a race usually pauses once or twice. A
   * genuinely unknown token pays the full backoff before being rejected; a
   * token from a revoked family is refused immediately, since a family that
   * was deliberately ended has no rotation in flight to wait for — see
   * `TOMBSTONE_BACKOFF_MS` for the measurements behind the numbers.
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

    // Nothing is in flight to wait for if the family was deliberately ended,
    // and a signed-out tab retrying is a routine event rather than a suspect
    // one. Answering it here keeps the backoff for the case it was written
    // for — a token that might still be mid-rotation — instead of charging it
    // to every stale tab after a sign-out.
    if (await this.#store.exists(KEYS.refreshRevoked(hash))) {
      throw new RefreshInvalidError('the session for this refresh token has been revoked');
    }

    for (const delayMs of TOMBSTONE_BACKOFF_MS) {
      await new Promise((resolve) => {
        setTimeout(resolve, delayMs);
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
    presentedKey: string | undefined,
  ): Promise<TokenPair> {
    // The grace path hands back a live credential, so it must enforce the same
    // binding the rotation path does. Otherwise replaying a bound token inside
    // the grace window would be a way around proof-of-possession.
    if (consumed.confirmationKey !== undefined && presentedKey !== consumed.confirmationKey) {
      throw new RefreshInvalidError(
        `refresh token for session ${consumed.sessionId} is bound to a different key`,
      );
    }

    // A grace mapping can outlive the revocation that should have removed it,
    // for the same reason a rotation's output can: both are written outside
    // the index that revocation enumerates.
    if (await this.#store.exists(KEYS.sessionRevoked(consumed.sessionId))) {
      throw new RefreshInvalidError(`session ${consumed.sessionId} has been revoked`);
    }

    const access = await this.#engine.issue({
      principal: consumed.principal,
      sessionId: consumed.sessionId,
      authenticatedAt: consumed.authenticatedAt,
      ...(consumed.confirmationKey !== undefined && {
        confirmationKey: consumed.confirmationKey,
      }),
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
      // Written before the deletes, for the same reason the session marker is:
      // a token presented mid-revocation should find the marker rather than an
      // empty keyspace. See `KEYS.refreshRevoked` for what it costs and buys.
      await Promise.all(
        hashes.map((h) =>
          this.#store.set(KEYS.refreshRevoked(h), '1', this.#options.refreshTokenTtl),
        ),
      );
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

  /**
   * Reads the signals recorded when a session started.
   *
   * Best-effort: a session whose metadata has already expired reports nothing,
   * and `compareSignals` treats that as `unknown` rather than as a match.
   */
  async #readSignals(sessionId: string): Promise<SecuritySignals | undefined> {
    const raw = await this.#store.get(KEYS.sessionMeta(sessionId));
    if (raw === null) return undefined;
    return this.#parseMeta(raw)?.signals;
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

    const confirmationKey = r['confirmationKey'];
    if (confirmationKey !== undefined && typeof confirmationKey !== 'string') return null;

    // Fail closed rather than defaulting to `issuedAt`: a record that cannot
    // say when the user authenticated cannot support a step-up decision.
    if (typeof r['authenticatedAt'] !== 'string') return null;

    return {
      sessionId: r['sessionId'],
      principal,
      issuedAt: r['issuedAt'],
      authenticatedAt: r['authenticatedAt'],
      expiresAt: r['expiresAt'],
      familyExpiresAt: r['familyExpiresAt'],
      generation: r['generation'],
      ...(confirmationKey !== undefined && { confirmationKey }),
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

    const consumedKey = r['confirmationKey'];
    if (consumedKey !== undefined && typeof consumedKey !== 'string') return null;

    // Fail closed, as elsewhere: a tombstone that cannot say when the user
    // authenticated cannot mint a token that answers a step-up check.
    if (typeof r['authenticatedAt'] !== 'string') return null;

    return {
      sessionId: r['sessionId'],
      generation: r['generation'],
      rotatedAt: r['rotatedAt'],
      principal,
      authenticatedAt: r['authenticatedAt'],
      ...(consumedKey !== undefined && { confirmationKey: consumedKey }),
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

    // Signals are optional and are read defensively: a malformed one is
    // dropped rather than failing the whole record, because they are an audit
    // aid and losing a session over one would be the wrong trade.
    const raw_signals = r['signals'];
    let signals: SecuritySignals | undefined;
    if (typeof raw_signals === 'object' && raw_signals !== null && !Array.isArray(raw_signals)) {
      const candidate = raw_signals as Record<string, unknown>;
      const picked: { userAgentHash?: string; ipHash?: string } = {};
      if (typeof candidate['userAgentHash'] === 'string') {
        picked.userAgentHash = candidate['userAgentHash'];
      }
      if (typeof candidate['ipHash'] === 'string') picked.ipHash = candidate['ipHash'];
      if (picked.userAgentHash !== undefined || picked.ipHash !== undefined) signals = picked;
    }

    return {
      sessionId: r['sessionId'],
      userId: r['userId'],
      createdAt: r['createdAt'],
      lastUsedAt: r['lastUsedAt'],
      expiresAt: r['expiresAt'],
      generation: r['generation'],
      ...(signals !== undefined && { signals }),
    };
  }
}
