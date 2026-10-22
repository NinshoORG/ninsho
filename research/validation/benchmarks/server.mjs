// Protected-request server, one configuration per process.
//
// Forked by http-bench.mjs so the load generator never shares an event loop
// with the server it is measuring. Every configuration serves the same route
// with the same Express 5 app shape and the same JSON body; only the
// authentication middleware differs.
//
//   node server.mjs <config> <redisUrl> <poolSize>
//
// On listen it sends { port, pool, preflight } over IPC. `pool` holds valid
// tokens for the load; `preflight` holds the tokens the security preflight
// presents (revoked, tampered, wrong audience).

import { randomUUID } from 'node:crypto';
import express from 'express';
import { buildJwt, buildNinsho, foreignPaseto, principal } from './lib/configs.mjs';

const [config, redisUrl, poolArg] = process.argv.slice(2);
const POOL = Number(poolArg ?? 64);

// A fixed, realistic response: ten small order records (~1.3 KB of JSON).
const ORDERS = Array.from({ length: 10 }, (_, i) => ({
  id: `ord_${String(i + 1).padStart(6, '0')}`, status: i % 3 === 0 ? 'shipped' : 'processing',
  totalCents: 1999 + i * 250, currency: 'INR', items: (i % 4) + 1, placedAt: '2026-10-01T10:00:00.000Z',
}));

const tamper = (t) => {
  const i = Math.floor(t.length / 2);
  return t.slice(0, i) + (t[i] === 'A' ? 'B' : 'A') + t.slice(i + 1);
};

let middleware = null;
const pool = [];
const preflight = {};
let close = async () => {};

if (config === 'ninsho-opaque' || config === 'ninsho-paseto') {
  const { auth, keyPair } = buildNinsho(config === 'ninsho-paseto' ? 'paseto' : 'opaque', redisUrl);
  middleware = auth.verify();
  for (let i = 0; i < POOL; i += 1) pool.push((await auth.createSession(principal(i))).accessToken);
  const revoked = await auth.createSession(principal(POOL + 1));
  await auth.revokeSession(revoked.sessionId);
  preflight.revoked = revoked.accessToken;
  preflight.tampered = tamper(pool[0]);
  if (keyPair !== null) preflight.wrongAudience = await foreignPaseto(auth.store, keyPair);
  close = () => auth.close();
} else if (config === 'jwt-redis' || config === 'jwt-stateless') {
  const jwt = await buildJwt(redisUrl, { revocation: config === 'jwt-redis' });
  middleware = jwt.middleware();
  for (let i = 0; i < POOL; i += 1) pool.push(await jwt.sign(principal(i).userId));
  const revoked = await jwt.sign(principal(POOL + 1).userId);
  if (config === 'jwt-redis') await jwt.revoke(revoked);
  // The stateless baseline has nowhere to record a revocation; the token is
  // presented anyway so the preflight shows what that means.
  preflight.revoked = revoked;
  preflight.tampered = tamper(pool[0]);
  preflight.wrongAudience = await jwt.sign(principal(9999).userId, { audience: 'another-api' });
  close = () => jwt.close();
} else if (config === 'no-auth') {
  middleware = (req, _res, next) => { req.auth = { userId: principal(0).userId }; next(); };
  pool.push(randomUUID());
} else {
  throw new Error(`unknown configuration ${config}`);
}

const app = express();
app.disable('x-powered-by');
app.disable('etag');
app.get('/api/orders', middleware, (req, res) => {
  res.json({ userId: req.auth.userId, orders: ORDERS });
});

const server = app.listen(0, '127.0.0.1', () => {
  process.send({ port: server.address().port, pool, preflight });
});
server.keepAliveTimeout = 65_000;

process.on('message', async (message) => {
  if (message === 'stop') {
    server.close();
    await close();
    process.exit(0);
  }
});
