import { afterEach, describe, expect, it, vi } from 'vitest';
import { generateId, RefreshInvalidError, RefreshReuseError } from '@ninshorg/core';
import { MemoryStore } from '../store/memory.js';
import { RedisStore } from '../store/redis.js';
import type { NinshoStore } from '../store/types.js';
import { OpaqueEngine } from '../engine/opaque.js';
import { PasetoEngine } from '../engine/paseto.js';
import { KeyRing, generateKeyPair } from '../keys/keyring.js';
import { SessionManager } from '../session/manager.js';
import { MemoryAuditSink } from '../audit.js';

function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => { release = resolve; });
  return { promise, release };
}
const stores: NinshoStore[] = [];
afterEach(async () => { vi.restoreAllMocks(); await Promise.all(stores.splice(0).map(s => s.close())); });
const candidates = [{ name: 'memory', create: (): NinshoStore => new MemoryStore() }];
const redisUrl = process.env['REDIS_URL'];
if (redisUrl) candidates.push({ name: 'redis', create: () => new RedisStore(redisUrl) });

for (const candidate of candidates) {
  for (const strategy of ['opaque', 'paseto'] as const) {
    describe(`${candidate.name} / ${strategy} review regressions`, () => {
      function build() {
        const store = candidate.create(); stores.push(store);
        const engine = strategy === 'opaque'
          ? new OpaqueEngine(store, { accessTokenTtl: 300, clockToleranceSeconds: 0 })
          : new PasetoEngine(store, new KeyRing({ active: generateKeyPair('review') }), {
              accessTokenTtl: 300, clockToleranceSeconds: 0, issuer: 'review', audience: 'review',
            });
        const audit = new MemoryAuditSink();
        const sessions = new SessionManager(store, engine, {
          refreshTokenTtl: 3600, refreshGraceSeconds: 0, clockToleranceSeconds: 0, audit,
        });
        const user = { userId: generateId(), roles: ['user'], scopes: [] };
        return { engine, sessions, user, audit };
      }
      for (const revokeAll of [false, true]) {
        it(`refuses initial credentials issued after completed ${revokeAll ? 'logout-all' : 'device logout'}`, async () => {
          // REGRESSION: create indexed a session, then issued access after revocation had enumerated it.
          const { engine, sessions, user, audit } = build();
          const entered = gate(), resume = gate();
          const issue = engine.issue.bind(engine);
          let lateToken = '';
          vi.spyOn(engine, 'issue').mockImplementation(async (input) => {
            entered.release(); await resume.promise;
            const issued = await issue(input); lateToken = issued.token; return issued;
          });
          const pending = sessions.create(user);
          const result = pending.then(value => ({ value, error: undefined }), error => ({ value: undefined, error }));
          await entered.promise;
          const indexed = await sessions.listSessions(user.userId);
          expect(indexed).toHaveLength(1);
          if (revokeAll) await sessions.revokeAllForUser(user.userId);
          else await sessions.revoke(indexed[0]!.sessionId);
          resume.release();
          expect((await result).error).toBeInstanceOf(RefreshInvalidError);
          await expect(engine.verify(lateToken)).rejects.toThrow();
          expect(await sessions.listSessions(user.userId)).toHaveLength(0);
          expect(audit.ofType('session.created')).toHaveLength(0);
        });
      }
      it.each([undefined, 'wrong-key'])('does not let a thief without the bound key revoke a rotated family (%s)', async (key) => {
        // REGRESSION: the tombstone path checked reuse before sender binding.
        const { engine, sessions, user } = build();
        const first = await sessions.create(user, { confirmationKey: 'owner-key' });
        const next = await sessions.refresh(first.refreshToken, { confirmationKey: 'owner-key' });
        await expect(sessions.refresh(first.refreshToken, key === undefined ? {} : { confirmationKey: key }))
          .rejects.toBeInstanceOf(RefreshInvalidError);
        await expect(engine.verify(next.accessToken, { confirmationKey: 'owner-key' })).resolves.toBeDefined();
        await expect(sessions.refresh(first.refreshToken, { confirmationKey: 'owner-key' }))
          .rejects.toBeInstanceOf(RefreshReuseError);
        await expect(engine.verify(next.accessToken, { confirmationKey: 'owner-key' })).rejects.toThrow();
      });
    });
  }
}
