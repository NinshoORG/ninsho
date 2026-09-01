import { describe, it, expect } from 'vitest';
import { MemoryStore } from '../store/memory.js';
import { OpaqueEngine } from '../engine/opaque.js';
import { SessionManager } from '../session/manager.js';
import { MemoryAuditSink } from '../audit.js';
import { mapConcurrent, DEFAULT_CONCURRENCY } from '../internal/concurrent.js';
import type { NinshoStore } from '../store/types.js';
import type { Principal } from '@ninsho/core';

describe('mapConcurrent', () => {
  it('returns results in input order regardless of completion order', async () => {
    const input = [50, 10, 30, 5, 20];
    const results = await mapConcurrent(input, async (ms) => {
      await new Promise((r) => setTimeout(r, ms));
      return ms;
    });
    expect(results).toEqual(input);
  });

  it('handles an empty list', async () => {
    await expect(mapConcurrent([], async () => 1)).resolves.toEqual([]);
  });

  it('passes the index to the worker', async () => {
    const seen = await mapConcurrent(['a', 'b', 'c'], async (item, index) => `${index}:${item}`);
    expect(seen).toEqual(['0:a', '1:b', '2:c']);
  });

  /**
   * The property the whole helper exists for. Unbounded `Promise.all` over a
   * user's sessions would issue that many commands at once and starve every
   * other request on the process.
   */
  it('never exceeds the concurrency limit', async () => {
    let inFlight = 0;
    let peak = 0;

    await mapConcurrent(
      Array.from({ length: 200 }, (_, i) => i),
      async () => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        await new Promise((r) => setTimeout(r, 1));
        inFlight -= 1;
      },
      8,
    );

    expect(peak).toBeLessThanOrEqual(8);
    expect(peak).toBeGreaterThan(1);
  });

  /**
   * Parallelism is asserted by observing overlap rather than by measuring
   * elapsed time. A wall-clock assertion here passes in isolation and fails
   * under load — which is exactly when the whole suite runs — so it would be a
   * flaky test dressed up as a performance guarantee. Overlap is the property
   * that actually matters, and it is deterministic.
   */
  it('actually runs in parallel rather than serially', async () => {
    const events: Array<'start' | 'end'> = [];

    await mapConcurrent(
      Array.from({ length: 40 }, (_, i) => i),
      async () => {
        events.push('start');
        await new Promise((r) => setTimeout(r, 1));
        events.push('end');
      },
      10,
    );

    // Serial execution produces a strict start,end,start,end… alternation.
    // Any two consecutive starts prove two tasks were in flight at once.
    const overlapped = events.some(
      (event, index) => event === 'start' && events[index + 1] === 'start',
    );
    expect(overlapped).toBe(true);
    expect(events.filter((e) => e === 'end')).toHaveLength(40);
  });

  it('does not spawn more runners than there are items', async () => {
    let peak = 0;
    let inFlight = 0;
    await mapConcurrent(
      [1, 2],
      async () => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        await new Promise((r) => setTimeout(r, 5));
        inFlight -= 1;
      },
      100,
    );
    expect(peak).toBeLessThanOrEqual(2);
  });

  it('treats a limit below one as one', async () => {
    const results = await mapConcurrent([1, 2, 3], async (n) => n * 2, 0);
    expect(results).toEqual([2, 4, 6]);
  });

  it('propagates a rejection', async () => {
    await expect(
      mapConcurrent([1, 2, 3], async (n) => {
        if (n === 2) throw new Error('boom');
        return n;
      }),
    ).rejects.toThrow('boom');
  });

  it('uses a sane default pool size', () => {
    expect(DEFAULT_CONCURRENCY).toBeGreaterThan(1);
    expect(DEFAULT_CONCURRENCY).toBeLessThanOrEqual(32);
  });
});

/**
 * ─── Scale regression ─────────────────────────────────────────────────────
 * `revokeAllForUser` and `listSessions` used to walk their sessions serially:
 * one store round trip at a time, ~4,500 of them for a user with 500 sessions,
 * which is seconds against a real store. "Sign out everywhere" is what gets
 * invoked during an incident, and one that slow risks timing out partway and
 * leaving sessions live.
 *
 * These tests assert the shape of the fix — parallel, but bounded — rather
 * than a wall-clock number, which would be flaky on shared CI hardware.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('session operations at scale', () => {
  const ALICE: Principal = { userId: 'user_heavy', roles: ['user'], scopes: [] };

  /** Wraps a store to observe round trips and peak concurrency. */
  function instrument(inner: MemoryStore): {
    store: NinshoStore;
    peak: () => number;
    reset: () => void;
  } {
    let inFlight = 0;
    let peak = 0;

    const wrap =
      <A extends unknown[], R>(fn: (...args: A) => Promise<R>) =>
      async (...args: A): Promise<R> => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        try {
          return await fn.apply(inner, args);
        } finally {
          inFlight -= 1;
        }
      };

    const store = {
      get: wrap(inner.get),
      set: wrap(inner.set),
      setIfAbsent: wrap(inner.setIfAbsent),
      take: wrap(inner.take),
      increment: wrap(inner.increment),
      delete: wrap(inner.delete),
      exists: wrap(inner.exists),
      sAdd: wrap(inner.sAdd),
      sRemove: wrap(inner.sRemove),
      sMembers: wrap(inner.sMembers),
      ping: wrap(inner.ping),
      close: wrap(inner.close),
    } as unknown as NinshoStore;

    return {
      store,
      peak: () => peak,
      reset: () => {
        peak = 0;
      },
    };
  }

  async function setup(sessionCount: number): Promise<{
    sessions: SessionManager;
    engine: OpaqueEngine;
    audit: MemoryAuditSink;
    peak: () => number;
    reset: () => void;
    inner: MemoryStore;
  }> {
    const inner = new MemoryStore();
    const { store, peak, reset } = instrument(inner);
    const engine = new OpaqueEngine(store, { accessTokenTtl: 300, clockToleranceSeconds: 5 });
    const audit = new MemoryAuditSink();
    const sessions = new SessionManager(store, engine, {
      refreshTokenTtl: 604_800,
      refreshGraceSeconds: 30,
      clockToleranceSeconds: 5,
      audit,
    });

    for (let i = 0; i < sessionCount; i += 1) await sessions.create(ALICE);
    reset();

    return { sessions, engine, audit, peak, reset, inner };
  }

  it('revokes many sessions in parallel rather than one at a time', async () => {
    const { sessions, peak, inner } = await setup(60);
    await sessions.revokeAllForUser(ALICE.userId);

    expect(peak()).toBeGreaterThan(1);
    await inner.close();
  });

  it('bounds the fan-out so a large user cannot exhaust the connection pool', async () => {
    const { sessions, peak, inner } = await setup(200);
    await sessions.revokeAllForUser(ALICE.userId);

    // Each session's revocation issues several commands, so the ceiling is a
    // small multiple of the pool rather than the pool exactly. What matters is
    // that it does not scale with the number of sessions.
    expect(peak()).toBeLessThan(DEFAULT_CONCURRENCY * 4);
    await inner.close();
  });

  it('lists many sessions in parallel', async () => {
    const { sessions, peak, inner } = await setup(60);
    await sessions.listSessions(ALICE.userId);

    expect(peak()).toBeGreaterThan(1);
    expect(peak()).toBeLessThanOrEqual(DEFAULT_CONCURRENCY);
    await inner.close();
  });

  it('still revokes every session', async () => {
    const { sessions, engine, inner } = await setup(0);
    const pairs = await Promise.all(
      Array.from({ length: 40 }, () => sessions.create(ALICE)),
    );

    await sessions.revokeAllForUser(ALICE.userId);

    for (const pair of pairs) {
      await expect(engine.verify(pair.accessToken)).rejects.toThrow();
      await expect(sessions.refresh(pair.refreshToken)).rejects.toThrow();
    }
    await inner.close();
  });

  /**
   * One corrupt session must not abandon the rest half-revoked, which would
   * leave the caller believing they had signed out everywhere when they had
   * not.
   */
  it('completes the sweep even when one session fails to revoke', async () => {
    const inner = new MemoryStore();
    const engine = new OpaqueEngine(inner, { accessTokenTtl: 300, clockToleranceSeconds: 5 });
    const audit = new MemoryAuditSink();
    const sessions = new SessionManager(inner, engine, {
      refreshTokenTtl: 604_800,
      refreshGraceSeconds: 30,
      clockToleranceSeconds: 5,
      audit,
    });

    const pairs = await Promise.all(
      Array.from({ length: 10 }, () => sessions.create(ALICE)),
    );

    // Make exactly one session's revocation throw.
    const doomed = pairs[3]!.sessionId;
    const originalSMembers = inner.sMembers.bind(inner);
    inner.sMembers = async (key: string): Promise<readonly string[]> => {
      if (key.includes(doomed)) throw new Error('store blew up for this session');
      return originalSMembers(key);
    };

    await expect(sessions.revokeAllForUser(ALICE.userId)).resolves.toBeUndefined();

    inner.sMembers = originalSMembers;

    // Every other session is gone, and the failure was recorded rather than
    // swallowed silently.
    for (const [index, pair] of pairs.entries()) {
      if (index === 3) continue;
      await expect(engine.verify(pair.accessToken)).rejects.toThrow();
    }
    expect(
      audit.ofType('session.revoked').some((e) => e.reason === 'revocation_failed'),
    ).toBe(true);

    await inner.close();
  });
});
