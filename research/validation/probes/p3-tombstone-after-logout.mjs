// Probe P3 — a logout that races a rotation can leave a tombstone behind, and
// a stale tab presenting the old token then raises a theft alarm.
//
// `#revokeFamily` deletes every tombstone (`rtc:*`) precisely so that stale
// tabs of a deliberately ended session do not raise `refresh.reuse_detected`
// (manager.ts, comment above #revokeFamily). `#rotate` writes the tombstone
// *after* its first revocation check. If revocation runs entirely inside that
// gap, revocation deletes nothing (the tombstone does not exist yet), then the
// rotation writes it, then the re-check throws — but never removes the
// tombstone it just published. The next presentation of the old token finds
// it before the `rtx:` revoked marker is consulted, takes the reuse path, and
// emits `refresh.reuse_detected` with RefreshReuseError.
//
// Expected (documented) behaviour: RefreshInvalidError and no reuse alarm.
//
// Run: [REDIS_URL=redis://localhost:6379] node research/validation/probes/p3-tombstone-after-logout.mjs
// Requires: npm run build.

import {
  SessionManager, OpaqueEngine, PasetoEngine, KeyRing, generateKeyPair,
  MemoryStore, RedisStore, KEYS,
} from '../../../packages/server/dist/index.js';

const gate = () => { let release; const promise = new Promise((r) => { release = r; }); return { promise, release }; };
const user = { userId: `u_${Date.now()}`, roles: ['user'], scopes: [] };

async function trial(storeName, strategy) {
  const inner = storeName === 'redis' ? new RedisStore(process.env.REDIS_URL) : new MemoryStore();
  const entered = gate(); const resume = gate();
  let armed = false;
  // Pause the rotation exactly at its tombstone write. Every other call passes through.
  const store = new Proxy(inner, {
    get(target, prop) {
      const value = Reflect.get(target, prop, target);
      if (prop !== 'set' || typeof value !== 'function') return typeof value === 'function' ? value.bind(target) : value;
      return async (key, ...rest) => {
        if (armed && key.startsWith('ninsho:v1:rtc:')) { armed = false; entered.release(); await resume.promise; }
        return value.call(target, key, ...rest);
      };
    },
  });
  const engine = strategy === 'opaque'
    ? new OpaqueEngine(store, { accessTokenTtl: 300, clockToleranceSeconds: 0 })
    : new PasetoEngine(store, new KeyRing({ active: generateKeyPair('p3') }), {
        accessTokenTtl: 300, clockToleranceSeconds: 0, issuer: 'p3', audience: 'p3' });
  const events = [];
  const sessions = new SessionManager(store, engine, {
    refreshTokenTtl: 3600, refreshGraceSeconds: 30, clockToleranceSeconds: 0,
    audit: { emit: (e) => events.push(e) },
  });

  const first = await sessions.create(user);
  armed = true;
  const rotating = sessions.refresh(first.refreshToken).then(() => 'rotated', (e) => e.constructor.name);
  await entered.promise;
  await sessions.revoke(first.sessionId);          // logout completes inside the gap
  resume.release();
  const rotationOutcome = await rotating;

  const leftover = await inner.exists(KEYS.refreshConsumed(
    (await import('../../../packages/core/dist/index.js')).hashToken(first.refreshToken)));
  const stale = await sessions.refresh(first.refreshToken).then(() => 'ACCEPTED', (e) => e.constructor.name);
  const alarms = events.filter((e) => e.type === 'refresh.reuse_detected').length;
  await inner.close();
  return { store: storeName, strategy, rotationOutcome, tombstoneLeftAfterLogout: leftover, staleTabOutcome: stale, reuseAlarms: alarms };
}

const rows = [];
for (const s of ['memory', ...(process.env.REDIS_URL ? ['redis'] : [])]) {
  for (const strat of ['opaque', 'paseto']) rows.push(await trial(s, strat));
}
console.table(rows);
const reproduced = rows.some((r) => r.reuseAlarms > 0 && r.staleTabOutcome === 'RefreshReuseError');
console.log(reproduced ? 'RESULT: REPRODUCED (false theft alarm after a completed logout)' : 'RESULT: NOT REPRODUCED');
