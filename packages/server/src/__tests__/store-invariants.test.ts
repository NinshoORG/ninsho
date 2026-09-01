import { describe, it, expect, afterEach } from 'vitest';
import {
  RefreshInvalidError,
  RefreshReuseError,
  StoreUnavailableError,
  TokenInvalidError,
  generateId,
  type Principal,
} from '@ninsho/core';
import { MemoryStore } from '../store/memory.js';
import { RedisStore } from '../store/redis.js';
import { OpaqueEngine } from '../engine/opaque.js';
import { SessionManager } from '../session/manager.js';
import { RateLimiter } from '../ratelimit/limiter.js';
import { DpopReplayGuard } from '../dpop/replay.js';
import { MemoryAuditSink } from '../audit.js';
import type { NinshoStore } from '../store/types.js';

/**
 * The security invariants, run against every store implementation.
 *
 * ─── Why this suite exists separately ─────────────────────────────────────
 * `store.contract.test.ts` proves the two stores agree about primitives — that
 * `take` is atomic, what a non-positive TTL does. This suite proves the
 * *engine* invariants that are built on those primitives still hold when the
 * store is a real database over a socket rather than a Map in the same
 * process.
 *
 * That distinction matters more than it looks. Against `MemoryStore` every
 * operation completes synchronously inside one tick, so an interleaving that
 * production hits constantly may be unreachable locally. Redis adds real
 * latency, real concurrency, and a real network boundary between the check and
 * the act — which is exactly where a rotation can slip past a revocation.
 *
 * Every invariant here has a matching unit test that runs against
 * `MemoryStore` alone. The point of repeating them is not coverage; it is that
 * "passes locally" should mean "would pass in production", and the only way to
 * know is to run them somewhere that behaves like production.
 *
 * Redis participates only when `REDIS_URL` is set, and is skipped visibly
 * otherwise. There is no mock: a double that merely resembles Redis would
 * defeat the entire purpose.
 * ──────────────────────────────────────────────────────────────────────────
 */

const REDIS_URL = process.env['REDIS_URL'];

interface Candidate {
  readonly name: string;
  readonly create: () => NinshoStore;
}

const candidates: Candidate[] = [{ name: 'MemoryStore', create: () => new MemoryStore() }];

if (REDIS_URL !== undefined && REDIS_URL.length > 0) {
  candidates.push({ name: 'RedisStore', create: () => new RedisStore(REDIS_URL) });
} else {
  describe.skip('Engine invariants against RedisStore (set REDIS_URL to run)', () => {
    it('is skipped without a live Redis', () => {
      expect(true).toBe(true);
    });
  });
}

/** Unique per test, so a shared Redis cannot leak state between runs. */
const principal = (): Principal => ({
  userId: `user_${generateId()}`,
  roles: ['user'],
  scopes: [],
});

const openStores: NinshoStore[] = [];

afterEach(async () => {
  // Redis connections are real sockets; leaking them across a suite eventually
  // exhausts the connection limit and produces failures that look like bugs in
  // whatever test happened to run last.
  await Promise.all(openStores.splice(0).map((store) => store.close()));
});

interface Harness {
  readonly store: NinshoStore;
  readonly sessions: SessionManager;
  readonly engine: OpaqueEngine;
  readonly audit: MemoryAuditSink;
}

function build(candidate: Candidate, graceSeconds = 30): Harness {
  const store = candidate.create();
  openStores.push(store);

  const engine = new OpaqueEngine(store, { accessTokenTtl: 300, clockToleranceSeconds: 5 });
  const audit = new MemoryAuditSink();
  const sessions = new SessionManager(store, engine, {
    refreshTokenTtl: 3600,
    refreshGraceSeconds: graceSeconds,
    clockToleranceSeconds: 5,
    audit,
  });

  return { store, sessions, engine, audit };
}

for (const candidate of candidates) {
  describe(`engine invariants — ${candidate.name}`, () => {
    /**
     * The invariant everything else rests on. Two winners means a forked
     * refresh chain, which guarantees a later false reuse alarm and an
     * unexplained logout for a user who did nothing wrong.
     */
    describe('single-use refresh consumption', () => {
      it('produces exactly one replacement chain from 40 concurrent callers', async () => {
        // With a grace window every caller succeeds — that is what stops a
        // parallel-tab page load looking like theft. The invariant is not
        // "one winner" but "one chain": all forty must receive the *same*
        // replacement, because a second distinct token forks the family and
        // guarantees a later false reuse alarm.
        const { sessions, audit } = build(candidate);
        const pair = await sessions.create(principal());

        const results = await Promise.all(
          Array.from({ length: 40 }, () => sessions.refresh(pair.refreshToken)),
        );

        expect(new Set(results.map((r) => r.refreshToken)).size).toBe(1);
        expect(audit.events.filter((e) => e.type === 'refresh.reuse_detected')).toHaveLength(0);
      });

      it('lets exactly one of 40 concurrent refreshes win with no grace window', async () => {
        // Without grace there is no adoption, so the atomicity of `take` is
        // visible directly: one caller consumes the token and the rest find it
        // gone.
        const { sessions } = build(candidate, 0);
        const pair = await sessions.create(principal());

        const results = await Promise.allSettled(
          Array.from({ length: 40 }, () => sessions.refresh(pair.refreshToken)),
        );

        expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      });

      it('never issues the same replacement token twice', async () => {
        // A duplicate would mean two callers walked away believing they held
        // distinct credentials.
        const { sessions } = build(candidate);
        const pairs = await Promise.all(
          Array.from({ length: 25 }, () => sessions.create(principal())),
        );

        const refreshed = await Promise.all(pairs.map((p) => sessions.refresh(p.refreshToken)));
        const tokens = new Set(refreshed.map((p) => p.refreshToken));
        expect(tokens.size).toBe(25);
      });

      it('keeps the winner usable and the losers dead', async () => {
        const { sessions } = build(candidate, 0);
        const pair = await sessions.create(principal());

        const results = await Promise.allSettled(
          Array.from({ length: 10 }, () => sessions.refresh(pair.refreshToken)),
        );
        const winner = results.find((r) => r.status === 'fulfilled');
        if (winner?.status !== 'fulfilled') throw new Error('expected a winner');

        // The winner's replacement must itself be usable — a rotation that
        // consumes the old token without producing a working new one strands
        // the session.
        await expect(sessions.refresh(winner.value.refreshToken)).resolves.toBeTruthy();
      });
    });

    /**
     * RFC 9700 §4.14.2. A rotated token presented again is the strongest
     * signal of theft an authentication system can observe, and the response
     * is to end the family rather than to reject one request.
     */
    describe('refresh reuse detection', () => {
      it('revokes the whole family when a rotated token is replayed', async () => {
        const { sessions, engine } = build(candidate, 0);
        const pair = await sessions.create(principal());

        const rotated = await sessions.refresh(pair.refreshToken);

        // The thief replays the original.
        await expect(sessions.refresh(pair.refreshToken)).rejects.toBeInstanceOf(RefreshReuseError);

        // Both parties are now locked out, which is the intended outcome: the
        // legitimate user re-authenticates, the thief gets nothing.
        await expect(sessions.refresh(rotated.refreshToken)).rejects.toBeInstanceOf(
          RefreshInvalidError,
        );
        await expect(engine.verify(rotated.accessToken)).rejects.toBeInstanceOf(TokenInvalidError);
      });

      it('raises an alarm rather than only a 401', async () => {
        const { sessions, audit } = build(candidate, 0);
        const pair = await sessions.create(principal());
        await sessions.refresh(pair.refreshToken);
        await sessions.refresh(pair.refreshToken).catch(() => undefined);

        expect(audit.events.some((e) => e.type === 'refresh.reuse_detected')).toBe(true);
      });

      it('does not revoke anything when an unrecognised token is presented', async () => {
        // Otherwise anyone could end any session by posting garbage.
        const { sessions } = build(candidate);
        const pair = await sessions.create(principal());

        await expect(sessions.refresh('not-a-real-token')).rejects.toBeInstanceOf(
          RefreshInvalidError,
        );
        await expect(sessions.refresh(pair.refreshToken)).resolves.toBeTruthy();
      });
    });

    /**
     * The regression that motivated the session tombstone.
     *
     * Revocation used to enumerate the family index; a rotation completing
     * after that read added its replacement to an index that was then deleted,
     * orphaning a live refresh token no later revocation could find. It
     * survived a completed logout for the full refresh lifetime.
     *
     * Against MemoryStore the window is a single tick. Against Redis it is a
     * real round trip, which is why running this here is worth more than
     * running it there.
     */
    describe('revocation racing rotation', () => {
      it('leaves no usable token when logout races a refresh', async () => {
        for (let attempt = 0; attempt < 12; attempt += 1) {
          const { sessions, engine } = build(candidate);
          const pair = await sessions.create(principal());
          const context = await engine.verify(pair.accessToken);

          // Fire both without awaiting either, so they interleave.
          const [refreshed] = await Promise.allSettled([
            sessions.refresh(pair.refreshToken),
            sessions.revoke(context.sessionId, 'logout'),
          ]);

          // Whether or not the rotation won, nothing it produced may still work.
          if (refreshed.status === 'fulfilled') {
            await expect(
              sessions.refresh(refreshed.value.refreshToken),
              `attempt ${attempt}: a refresh token survived logout`,
            ).rejects.toThrow();
            await expect(
              engine.verify(refreshed.value.accessToken),
              `attempt ${attempt}: an access token survived logout`,
            ).rejects.toThrow();
          }

          await expect(sessions.refresh(pair.refreshToken)).rejects.toThrow();
          await Promise.all(openStores.splice(0).map((s) => s.close()));
        }
      });

      it('leaves no usable token when sign-out-everywhere races a refresh', async () => {
        for (let attempt = 0; attempt < 8; attempt += 1) {
          const { sessions, engine } = build(candidate);
          const who = principal();
          const pairs = await Promise.all(
            Array.from({ length: 5 }, () => sessions.create(who)),
          );

          const [, ...rotations] = await Promise.allSettled([
            sessions.revokeAllForUser(who.userId, 'logout_all'),
            ...pairs.map((p) => sessions.refresh(p.refreshToken)),
          ]);

          for (const rotation of rotations) {
            if (rotation.status === 'fulfilled') {
              await expect(
                engine.verify(rotation.value.accessToken),
                `attempt ${attempt}: a token survived sign-out-everywhere`,
              ).rejects.toThrow();
            }
          }
          await Promise.all(openStores.splice(0).map((s) => s.close()));
        }
      });
    });

    /**
     * A parallel-tab load fires several refreshes at once. Without a grace
     * window the losers look like theft, and a normal page load ends the
     * session.
     */
    describe('the grace window', () => {
      it('does not raise a reuse alarm for a token rotated moments ago', async () => {
        const { sessions, audit } = build(candidate, 30);
        const pair = await sessions.create(principal());

        await sessions.refresh(pair.refreshToken);
        // The same token again, inside the grace window.
        await sessions.refresh(pair.refreshToken).catch(() => undefined);

        expect(audit.events.some((e) => e.type === 'refresh.reuse_detected')).toBe(false);
      });
    });

    /**
     * `setIfAbsent` is what makes a captured DPoP proof unusable twice. A
     * get-then-set would let both replays through — the exact race an attacker
     * would aim for.
     */
    describe('DPoP proof replay', () => {
      it('lets exactly one of 30 concurrent claims on a jti win', async () => {
        const { store } = build(candidate);
        const guard = new DpopReplayGuard(store, 'closed', 60);
        const jkt = generateId();
        const jti = generateId();

        const claims = await Promise.all(
          Array.from({ length: 30 }, () => guard.claim(jkt, jti)),
        );

        expect(claims.filter(Boolean)).toHaveLength(1);
      });

      it('namespaces by key thumbprint, so one client cannot burn another’s', async () => {
        const { store } = build(candidate);
        const guard = new DpopReplayGuard(store, 'closed', 60);
        const jti = generateId();

        expect(await guard.claim(generateId(), jti)).toBe(true);
        // A different key, the same jti — must still be its first use.
        expect(await guard.claim(generateId(), jti)).toBe(true);
      });
    });

    /**
     * A rate limit that is only approximately enforced under concurrency is
     * not a rate limit; the concurrency is the attack.
     */
    describe('rate limiting under concurrency', () => {
      it('admits exactly the configured number of concurrent requests', async () => {
        const { store, audit } = build(candidate);
        const limiter = new RateLimiter({ store, onStoreError: 'closed', audit });
        const bucket = `login:ip:${generateId()}`;

        const verdicts = await Promise.all(
          Array.from({ length: 50 }, () => limiter.consume(bucket, 10, 60_000)),
        );

        expect(verdicts.filter((v) => v.allowed)).toHaveLength(10);
      });

      it('keeps separate buckets independent', async () => {
        const { store, audit } = build(candidate);
        const limiter = new RateLimiter({ store, onStoreError: 'closed', audit });
        const a = `login:ip:${generateId()}`;
        const b = `login:ip:${generateId()}`;

        await Promise.all(Array.from({ length: 10 }, () => limiter.consume(a, 5, 60_000)));
        const verdict = await limiter.consume(b, 5, 60_000);

        expect(verdict.allowed).toBe(true);
      });
    });

    /**
     * Sign-out-everywhere fans out across every session a user has. The
     * bounded-parallelism helper exists so this does not become one round trip
     * per session; against a real socket that difference is the whole latency
     * budget.
     */
    describe('sign-out-everywhere at scale', () => {
      it('revokes 40 sessions and leaves none alive', async () => {
        const { sessions, engine } = build(candidate);
        const who = principal();
        const pairs = await Promise.all(
          Array.from({ length: 40 }, () => sessions.create(who)),
        );

        await sessions.revokeAllForUser(who.userId, 'logout_all');

        const survivors = await Promise.all(
          pairs.map((p) => engine.verify(p.accessToken).then(() => true, () => false)),
        );
        expect(survivors.filter(Boolean)).toHaveLength(0);
        expect(await sessions.listSessions(who.userId)).toHaveLength(0);
      });

      it('lists only the sessions belonging to the user asked about', async () => {
        // A cross-user leak here would be a listing endpoint that enumerates
        // other people's devices.
        const { sessions } = build(candidate);
        const alice = principal();
        const bob = principal();

        await Promise.all([
          sessions.create(alice),
          sessions.create(alice),
          sessions.create(bob),
        ]);

        expect(await sessions.listSessions(alice.userId)).toHaveLength(2);
        expect(await sessions.listSessions(bob.userId)).toHaveLength(1);
      });
    });
  });
}

/**
 * Only meaningful against a real store: a Map in the same process cannot be
 * unreachable, so fail-closed behaviour has no way to be exercised there.
 */
describe.runIf(REDIS_URL !== undefined && REDIS_URL.length > 0)(
  'fail-closed when Redis is unreachable',
  () => {
    /** A port nothing is listening on. */
    const DEAD_URL = 'redis://127.0.0.1:6390';

    it('rejects rather than admitting a request it could not check', async () => {
      const store = new RedisStore(DEAD_URL);
      openStores.push(store);
      const audit = new MemoryAuditSink();
      const limiter = new RateLimiter({ store, onStoreError: 'closed', audit });

      // The whole point of fail-closed: an unreachable store must not read as
      // "under the limit".
      await expect(limiter.consume(`login:${generateId()}`, 5, 60_000)).rejects.toBeInstanceOf(
        StoreUnavailableError,
      );
    });

    it('refuses a DPoP proof it cannot check for replay', async () => {
      const store = new RedisStore(DEAD_URL);
      openStores.push(store);
      const guard = new DpopReplayGuard(store, 'closed', 60);

      await expect(guard.claim(generateId(), generateId())).rejects.toBeInstanceOf(
        StoreUnavailableError,
      );
    });

    it('reports an unreachable store as unhealthy rather than throwing', async () => {
      // `ping` is the liveness probe; it answers false so a health endpoint can
      // return 503 instead of a stack trace.
      const store = new RedisStore(DEAD_URL);
      openStores.push(store);

      expect(await store.ping()).toBe(false);
    });
  },
);
