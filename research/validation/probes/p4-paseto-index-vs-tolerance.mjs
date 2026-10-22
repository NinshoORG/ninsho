// Probe P4 — PASETO session index can expire before a token stops verifying.
//
// PasetoEngine.verify() accepts a token until exp + clockToleranceSeconds.
// PasetoEngine.issue() indexes the token id under the session with a TTL of
// accessTokenTtl + 60. resolveConfig() permits clockToleranceSeconds up to
// accessTokenTtl. With tolerance > 60 s there is a window in which the token
// still verifies but the index revokeSession() enumerates has already expired,
// so revoking the session writes no denylist entry for it.
//
// Uses the public Ninsho facade and real Redis, in real time (~2.5 minutes).
// Run: REDIS_URL=redis://localhost:6379 node research/validation/probes/p4-paseto-index-vs-tolerance.mjs
// Requires: npm run build.

import { Ninsho, RedisStore, generateKeyPair } from '../../../packages/server/dist/index.js';

const TTL = 70;        // accessTokenTtl
const TOL = 70;        // clockToleranceSeconds (accepted by config: TOL <= TTL)
const sleep = (s) => new Promise((r) => setTimeout(r, s * 1000));

const store = new RedisStore(process.env.REDIS_URL ?? 'redis://localhost:6379');
const auth = new Ninsho({
  store, strategy: 'paseto', issuer: 'p4', audience: 'p4',
  keys: { active: generateKeyPair('p4') },
  accessTokenTtl: TTL, clockToleranceSeconds: TOL,
  audit: { emit: () => {} },
});

const pair = await auth.createSession({ userId: `u_${Date.now()}`, roles: [], scopes: [] });
const t0 = Date.now();
const elapsed = () => ((Date.now() - t0) / 1000).toFixed(1);

// Control: revoking a fresh session must kill the token.
const control = await auth.createSession({ userId: `c_${Date.now()}`, roles: [], scopes: [] });
await auth.revokeSession(control.sessionId);
const controlOutcome = await auth.engine.verify(control.accessToken).then(() => 'ACCEPTED', (e) => e.constructor.name);
console.log(`[t=${elapsed()}s] control: revoke fresh session → verify = ${controlOutcome}`);

// Wait past index expiry (TTL + 60 + margin) but inside exp + TOL.
const waitUntil = TTL + 60 + 4;
console.log(`[t=${elapsed()}s] waiting until t=${waitUntil}s (index TTL ${TTL + 60}s, token acceptable until ${TTL + TOL}s)…`);
await sleep(waitUntil - (Date.now() - t0) / 1000);

const before = await auth.engine.verify(pair.accessToken).then(() => 'ACCEPTED', (e) => e.constructor.name);
await auth.revokeSession(pair.sessionId);
const after = await auth.engine.verify(pair.accessToken).then(() => 'ACCEPTED', (e) => e.constructor.name);
console.log(`[t=${elapsed()}s] before revokeSession: ${before}; after revokeSession: ${after}`);
console.log(after === 'ACCEPTED' && controlOutcome !== 'ACCEPTED'
  ? `RESULT: REPRODUCED (revoked session's token still verifies for up to ${TOL - 60}s)`
  : 'RESULT: NOT REPRODUCED');
await auth.close();
