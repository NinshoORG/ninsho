// Probe P2 — what a per-IP rate-limit bucket is keyed on.
//
// (a) IPv6: `clientIp` keys each full /128 address separately. A single host
//     that controls a /64 (the normal residential/cloud allocation) can rotate
//     source addresses and receive a fresh per-IP allowance for each one.
// (b) `trustProxy: false` is documented as "take the peer address only,
//     ignoring forwarding headers", but `peerAddress()` prefers `req.ip` over
//     `req.socket.remoteAddress`. Under Express with `app.set('trust proxy',
//     true)`, `req.ip` is already derived from X-Forwarded-For, so rotating
//     that header rotates the bucket. Demonstrated over real HTTP.
//
// Neither case affects the per-account bucket, which is the documented
// defence against distributed stuffing.
//
// Run: node research/validation/probes/p2-ratelimit-address-keying.mjs
// Requires: npm run build. Uses the workspace's Express 5 and MemoryStore.

import express from 'express';
import { Ninsho, MemoryStore, clientIp } from '../../../packages/server/dist/index.js';

// ── (a) IPv6 keying ─────────────────────────────────────────────────────────
const sameSlash64 = ['2001:db8:1:2::1', '2001:db8:1:2::2', '2001:db8:1:2:ffff::9'];
const keys = sameSlash64.map((ip) => clientIp({ headers: {}, ip }, false));
console.log('(a) IPv6 addresses in one /64 →', keys);
console.log(`(a) distinct buckets: ${new Set(keys).size}/${keys.length}`,
  new Set(keys).size === keys.length ? '— REPRODUCED (no prefix aggregation)' : '— not reproduced');

// ── (b) trustProxy:false under Express `trust proxy` ────────────────────────
async function run(expressTrustProxy) {
  const auth = new Ninsho({ store: new MemoryStore() });
  const app = express();
  if (expressTrustProxy) app.set('trust proxy', true);
  app.post('/login',
    auth.rateLimit({ action: 'login', perIp: { limit: 3, windowMs: 60_000 }, trustProxy: false }),
    (_req, res) => res.json({ ok: true }));
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const { port } = server.address();
  const statuses = [];
  for (let i = 0; i < 10; i += 1) {
    const res = await fetch(`http://127.0.0.1:${port}/login`, {
      method: 'POST', headers: { 'x-forwarded-for': `198.51.100.${i + 1}` },
    });
    statuses.push(res.status);
  }
  server.close();
  await auth.close();
  return statuses;
}

const off = await run(false);
const on = await run(true);
console.log(`(b) Express trust proxy OFF, 10 requests rotating XFF, limit 3 → ${off.join(',')}`);
console.log(`(b) Express trust proxy ON,  10 requests rotating XFF, limit 3 → ${on.join(',')}`);
const bypass = on.filter((s) => s === 200).length > 3 && off.filter((s) => s === 429).length > 0;
console.log(bypass ? '(b) RESULT: REPRODUCED (trustProxy:false still honours XFF via req.ip)' : '(b) RESULT: NOT REPRODUCED');
