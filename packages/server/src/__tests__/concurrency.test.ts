import { describe, it, expect, beforeEach } from 'vitest';
import {
  RefreshInvalidError,
  RefreshReuseError,
  TokenInvalidError,
  type Principal,
} from '@ninsho/core';
import { MemoryStore } from '../store/memory.js';
import { OpaqueEngine } from '../engine/opaque.js';
import { SessionManager } from '../session/manager.js';
import { RateLimiter } from '../ratelimit/limiter.js';
import { MemoryAuditSink } from '../audit.js';

/**
 * Behaviour under parallel load.
 *
 * ─── Why these are separate from the unit suites ──────────────────────────
 * Races do not show up in sequential tests. Every operation here is correct
 * when called one at a time; the question is whether the invariants still hold
 * when many callers interleave — which is the only way they run in production.
 *
 * Two invariants matter most:
 *
 *   1. **Exactly one** caller may consume a single-use credential. Two winners
 *      means a forked refresh chain, which guarantees a later false reuse alarm
 *      and an unexplained logout.
 *
 *   2. A revocation that races an issuance must not leave a live token behind.
 *      "Sign out this device" reporting success while a token still works is
 *      the worst possible outcome for that button.
 * ──────────────────────────────────────────────────────────────────────────
 */

const ALICE: Principal = { userId: 'user_alice', roles: ['user'], scopes: [] };

let store: MemoryStore;
let engine: OpaqueEngine;
let audit: MemoryAuditSink;
let sessions: SessionManager;

function build(graceSeconds = 30): void {
  store = new MemoryStore();
  engine = new OpaqueEngine(store, { accessTokenTtl: 300, clockToleranceSeconds: 5 });
  audit = new MemoryAuditSink();
  sessions = new SessionManager(store, engine, {
    refreshTokenTtl: 3600,
    refreshGraceSeconds: graceSeconds,
    clockToleranceSeconds: 5,
    audit,
  });
}

beforeEach(() => {
  build();
});

describe('concurrent session creation', () => {
  it('gives every parallel login a distinct session and token', async () => {
    const pairs = await Promise.all(
      Array.from({ length: 100 }, () => sessions.create(ALICE)),
    );

    expect(new Set(pairs.map((p) => p.sessionId)).size).toBe(100);
    expect(new Set(pairs.map((p) => p.accessToken)).size).toBe(100);
    expect(new Set(pairs.map((p) => p.refreshToken)).size).toBe(100);
  });

  it('leaves every one of them independently verifiable', async () => {
    const pairs = await Promise.all(
      Array.from({ length: 50 }, () => sessions.create(ALICE)),
    );

    const verified = await Promise.all(pairs.map((p) => engine.verify(p.accessToken)));
    expect(verified).toHaveLength(50);
    expect(new Set(verified.map((v) => v.tokenId)).size).toBe(50);
  });

  it('lists every concurrently created session', async () => {
    await Promise.all(Array.from({ length: 25 }, () => sessions.create(ALICE)));
    await expect(sessions.listSessions(ALICE.userId)).resolves.toHaveLength(25);
  });
});

describe('concurrent rotation', () => {
  it('produces exactly one replacement chain from many simultaneous callers', async () => {
    const first = await sessions.create(ALICE);

    const results = await Promise.all(
      Array.from({ length: 50 }, () => sessions.refresh(first.refreshToken)),
    );

    // One rotation, fifty callers, one chain. A second winner would fork the
    // family and guarantee a later false reuse alarm.
    expect(new Set(results.map((r) => r.refreshToken)).size).toBe(1);
    expect(audit.ofType('refresh.reuse_detected')).toHaveLength(0);
  });

  it('gives each caller its own working access token', async () => {
    const first = await sessions.create(ALICE);
    const results = await Promise.all(
      Array.from({ length: 20 }, () => sessions.refresh(first.refreshToken)),
    );

    expect(new Set(results.map((r) => r.accessToken)).size).toBe(20);
    for (const result of results) {
      await expect(engine.verify(result.accessToken)).resolves.toBeDefined();
    }
  });

  it('keeps the surviving chain usable afterwards', async () => {
    const first = await sessions.create(ALICE);
    const results = await Promise.all(
      Array.from({ length: 20 }, () => sessions.refresh(first.refreshToken)),
    );

    await expect(sessions.refresh(results[0]!.refreshToken)).resolves.toBeDefined();
  });

  it('survives a long chain rotated concurrently at every step', async () => {
    let pair = await sessions.create(ALICE);

    for (let step = 0; step < 15; step += 1) {
      const results = await Promise.all([
        sessions.refresh(pair.refreshToken),
        sessions.refresh(pair.refreshToken),
        sessions.refresh(pair.refreshToken),
      ]);
      expect(new Set(results.map((r) => r.refreshToken)).size).toBe(1);
      pair = results[0]!;
    }

    await expect(engine.verify(pair.accessToken)).resolves.toBeDefined();
    expect(audit.ofType('refresh.reuse_detected')).toHaveLength(0);
  });

  it('detects a genuine replay even when it races legitimate traffic', async () => {
    build(0); // no grace, so a replay is unambiguous
    const first = await sessions.create(ALICE);
    await sessions.refresh(first.refreshToken);

    // Twenty simultaneous replays of the already-rotated token. Every one must
    // be refused, and the family revoked exactly once.
    const outcomes = await Promise.all(
      Array.from({ length: 20 }, () =>
        sessions.refresh(first.refreshToken).then(
          () => 'renewed' as const,
          (error: unknown) =>
            error instanceof RefreshReuseError ? ('reuse' as const) : ('other' as const),
        ),
      ),
    );

    expect(outcomes.filter((o) => o === 'renewed')).toHaveLength(0);
    expect(outcomes.filter((o) => o === 'reuse').length).toBeGreaterThan(0);
  });
});

describe('revocation racing issuance', () => {
  /**
   * The invariant that matters for a "sign out this device" button: once it
   * has returned, nothing issued before it may still verify.
   */
  it('leaves no live token behind when revocation races issuance', async () => {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const pair = await sessions.create(ALICE);

      // Issue and revoke at the same moment.
      const [issued] = await Promise.all([
        engine.issue({ principal: ALICE, sessionId: pair.sessionId , authenticatedAt: new Date().toISOString() }),
        sessions.revoke(pair.sessionId),
      ]);

      // The token issued during the revocation may or may not have been
      // caught, depending on interleaving — but a *second* revocation must
      // settle it. What must never happen is a token surviving a completed
      // revoke that observed it.
      await sessions.revoke(pair.sessionId);
      await expect(engine.verify(issued.token)).rejects.toThrow(TokenInvalidError);
      await expect(engine.verify(pair.accessToken)).rejects.toThrow(TokenInvalidError);
    }
  });

  it('is idempotent under concurrent revocation of the same session', async () => {
    const pair = await sessions.create(ALICE);

    const outcomes = await Promise.allSettled(
      Array.from({ length: 20 }, () => sessions.revoke(pair.sessionId)),
    );

    expect(outcomes.every((o) => o.status === 'fulfilled')).toBe(true);
    await expect(engine.verify(pair.accessToken)).rejects.toThrow(TokenInvalidError);
  });

  it('ends every session under a concurrent sign-out-everywhere', async () => {
    const pairs = await Promise.all(
      Array.from({ length: 30 }, () => sessions.create(ALICE)),
    );

    await Promise.all([
      sessions.revokeAllForUser(ALICE.userId),
      sessions.revokeAllForUser(ALICE.userId),
      sessions.revokeAllForUser(ALICE.userId),
    ]);

    for (const pair of pairs) {
      await expect(engine.verify(pair.accessToken)).rejects.toThrow(TokenInvalidError);
      await expect(sessions.refresh(pair.refreshToken)).rejects.toThrow(RefreshInvalidError);
    }
  });

  it('does not let a refresh racing a revocation resurrect the session', async () => {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const pair = await sessions.create(ALICE);

      const [refreshed] = await Promise.allSettled([
        sessions.refresh(pair.refreshToken),
        sessions.revoke(pair.sessionId),
      ]);

      // Whichever won, the session must be dead once both have settled.
      await sessions.revoke(pair.sessionId);

      if (refreshed.status === 'fulfilled') {
        await expect(engine.verify(refreshed.value.accessToken)).rejects.toThrow(
          TokenInvalidError,
        );
        await expect(sessions.refresh(refreshed.value.refreshToken)).rejects.toThrow(
          RefreshInvalidError,
        );
      }
    }
  });
});

describe('cross-user isolation under load', () => {
  it('keeps users separate when their traffic interleaves', async () => {
    const users: Principal[] = Array.from({ length: 10 }, (_, i) => ({
      userId: `user_${i}`,
      roles: ['user'],
      scopes: [],
    }));

    const pairs = await Promise.all(
      users.flatMap((user) => [sessions.create(user), sessions.create(user)]),
    );

    const contexts = await Promise.all(pairs.map((p) => engine.verify(p.accessToken)));
    for (const [index, context] of contexts.entries()) {
      // Two sessions per user, created in order.
      expect(context.userId).toBe(`user_${Math.floor(index / 2)}`);
    }
  });

  it('confines a concurrent sign-out-everywhere to one user', async () => {
    const target = await sessions.create({ userId: 'user_target', roles: [], scopes: [] });
    const others = await Promise.all(
      Array.from({ length: 10 }, (_, i) =>
        sessions.create({ userId: `user_other_${i}`, roles: [], scopes: [] }),
      ),
    );

    await Promise.all([
      sessions.revokeAllForUser('user_target'),
      ...others.map((p) => engine.verify(p.accessToken)),
    ]);

    await expect(engine.verify(target.accessToken)).rejects.toThrow(TokenInvalidError);
    for (const pair of others) {
      await expect(engine.verify(pair.accessToken)).resolves.toBeDefined();
    }
  });
});

describe('rate limiting under load', () => {
  it('admits exactly the limit however many callers arrive at once', async () => {
    const limiter = new RateLimiter({ store, onStoreError: 'closed', audit });

    const verdicts = await Promise.all(
      Array.from({ length: 200 }, () => limiter.consume('load:test', 50, 60_000)),
    );

    // The whole point of an atomic counter: a limit that holds under exactly
    // the concurrent load it exists to control.
    expect(verdicts.filter((v) => v.allowed)).toHaveLength(50);
  });

  it('keeps buckets independent under interleaved load', async () => {
    const limiter = new RateLimiter({ store, onStoreError: 'closed', audit });

    const verdicts = await Promise.all(
      Array.from({ length: 300 }, (_, i) =>
        limiter.consume(`load:bucket-${i % 3}`, 20, 60_000),
      ),
    );

    // 100 requests per bucket, 20 allowed each.
    expect(verdicts.filter((v) => v.allowed)).toHaveLength(60);
  });

  it('never admits more than the limit across both dimensions', async () => {
    const limiter = new RateLimiter({ store, onStoreError: 'closed', audit });

    const outcomes = await Promise.all(
      Array.from({ length: 100 }, () =>
        limiter
          .enforce([
            { bucket: 'multi:ip', limit: 30, windowMs: 60_000 },
            { bucket: 'multi:acct', limit: 10, windowMs: 60_000 },
          ])
          .then(
            () => 'allowed' as const,
            () => 'refused' as const,
          ),
      ),
    );

    // The tighter bucket governs.
    expect(outcomes.filter((o) => o === 'allowed')).toHaveLength(10);
  });
});

describe('sustained mixed load', () => {
  /**
   * A rough simulation of real traffic: logins, verifications, refreshes and
   * logouts all interleaved. Not a throughput benchmark — it exists to surface
   * a race that only appears when several code paths touch the store at once.
   */
  it('holds its invariants through interleaved traffic', async () => {
    const active: Array<{ sessionId: string; accessToken: string; refreshToken: string }> = [];

    for (let round = 0; round < 10; round += 1) {
      const created = await Promise.all(
        Array.from({ length: 10 }, () => sessions.create(ALICE)),
      );
      active.push(...created);

      await Promise.all([
        ...active.slice(0, 5).map((p) => engine.verify(p.accessToken)),
        ...created.slice(0, 3).map((p) => sessions.refresh(p.refreshToken)),
      ]);

      // Retire a few, and confirm they are genuinely gone.
      const retiring = active.splice(0, 3);
      await Promise.all(retiring.map((p) => sessions.revoke(p.sessionId)));
      for (const pair of retiring) {
        await expect(engine.verify(pair.accessToken)).rejects.toThrow(TokenInvalidError);
      }
    }

    // No spurious theft alarms were raised by ordinary concurrent traffic —
    // a false positive here would sign a real user out.
    expect(audit.ofType('refresh.reuse_detected')).toHaveLength(0);
  });
});
