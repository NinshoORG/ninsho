// Comparison 1 — verification cost, in-process, no HTTP.
//
// Times one verification at a time (concurrency 1) so each sample is the cost
// of the checks themselves plus, where the configuration performs one, a
// single store round trip. Store round trips are also measured on their own so
// the two components can be separated.
//
// Usage: node verify-cost.mjs [--trials 5] [--iterations 3000] [--warmup 500] [--out <dir>]
// Env:   REDIS_URL (default redis://localhost:6379)

import { mkdirSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { Redis } from 'ioredis';
import { RedisStore } from '../../../packages/server/dist/index.js';
import { buildJwt, buildNinsho, principal } from './lib/configs.mjs';
import { describe, shuffle } from './lib/stats.mjs';

let REDIS_URL = process.env.REDIS_URL ?? 'redis://localhost:6379';
let ITER = 3000;
let WARMUP = 500;

/** Each operation: what it is, which checks it performs, and whether it is comparable. */
async function buildOperations() {
  const rawRedis = new Redis(REDIS_URL, { enableOfflineQueue: false, lazyConnect: true });
  await rawRedis.connect();
  const store = new RedisStore(REDIS_URL);

  const opaque = buildNinsho('opaque', REDIS_URL).auth;
  const paseto = buildNinsho('paseto', REDIS_URL).auth;
  const opaqueMem = buildNinsho('opaque', REDIS_URL, { memory: true }).auth;
  const jwtR = await buildJwt(REDIS_URL, { revocation: true });
  const jwtS = await buildJwt(REDIS_URL, { revocation: false });

  // Tokens are re-minted before every timed operation (see `mint`): one trial
  // can outlast the 300 s access-token lifetime on a slow machine, and an
  // expired token would turn the measurement into a stream of refusals.
  let o, p, om, jr, js;
  const mint = async () => {
    o = await opaque.createSession(principal(1));
    p = await paseto.createSession(principal(2));
    om = await opaqueMem.createSession(principal(3));
    jr = await jwtR.sign(principal(4).userId);
    js = await jwtS.sign(principal(5).userId);
  };
  await mint();

  const ops = [
    { id: 'store.ioredis.get', group: 'store-lookup', checks: 'One Redis GET via ioredis (absent key).', run: () => rawRedis.get('bench:absent') },
    { id: 'store.ioredis.exists', group: 'store-lookup', checks: 'One Redis EXISTS via ioredis (absent key).', run: () => rawRedis.exists('bench:absent') },
    { id: 'store.ninsho.get', group: 'store-lookup', checks: 'RedisStore.get (ioredis GET behind Ninsho’s store wrapper).', run: () => store.get('bench:absent') },
    { id: 'store.ninsho.exists', group: 'store-lookup', checks: 'RedisStore.exists (ioredis EXISTS behind Ninsho’s store wrapper).', run: () => store.exists('bench:absent') },
    { id: 'verify.ninsho-opaque.redis', group: 'comparable', checks: 'SHA-256 + Redis GET + record parse + expiry + binding.', run: () => opaque.engine.verify(o.accessToken) },
    { id: 'verify.ninsho-paseto.redis', group: 'comparable', checks: 'Ed25519 PASETO + claims + Redis EXISTS denylist.', run: () => paseto.engine.verify(p.accessToken) },
    { id: 'verify.jwt-redis.redis', group: 'comparable', checks: 'jose EdDSA JWT + claims + Redis EXISTS denylist.', run: () => jwtR.verify(jr) },
    { id: 'verify.ninsho-paseto.no-revocation', group: 'reference', checks: 'Ed25519 PASETO + claims; revocation check skipped (skipRevocationCheck). NOT the default path.', run: () => paseto.engine.verify(p.accessToken, { skipRevocationCheck: true }) },
    { id: 'verify.jwt-stateless', group: 'reference', checks: 'jose EdDSA JWT + claims; no revocation check.', run: () => jwtS.verify(js) },
    { id: 'verify.ninsho-opaque.memory', group: 'reference', checks: 'Opaque verify against in-process MemoryStore (CPU cost without a network hop).', run: () => opaqueMem.engine.verify(om.accessToken) },
  ];

  const close = async () => {
    rawRedis.disconnect();
    await Promise.all([store.close(), opaque.close(), paseto.close(), opaqueMem.close(), jwtR.close(), jwtS.close()]);
  };
  return { ops, close, mint };
}

async function timeOp(run) {
  for (let i = 0; i < WARMUP; i += 1) await run();
  const samples = new Float64Array(ITER);
  for (let i = 0; i < ITER; i += 1) {
    const t = process.hrtime.bigint();
    await run();
    samples[i] = Number(process.hrtime.bigint() - t) / 1e6;
  }
  return samples;
}

export async function runVerifyCost({ outDir, trials = 5, iterations = 3000, warmup = 500, seed = 20261021, redisUrl = REDIS_URL }) {
  REDIS_URL = redisUrl; ITER = iterations; WARMUP = warmup;
  mkdirSync(path.join(outDir, 'raw'), { recursive: true });
  const { ops, close, mint } = await buildOperations();
  // Preflight: every operation must succeed before it is timed. A verifier
  // that throws would otherwise be measured as a fast failure.
  for (const op of ops) await op.run();

  const rows = [];
  for (let trial = 1; trial <= trials; trial += 1) {
    const order = shuffle(ops, seed + trial);
    for (const op of order) {
      await mint();
      const samples = await timeOp(op.run);
      const stats = describe(samples);
      const row = { comparison: 'verify-cost', trial, id: op.id, group: op.group, iterations: ITER, warmup: WARMUP,
        opsPerSec: 1000 / stats.meanMs, ...stats };
      rows.push(row);
      writeFileSync(path.join(outDir, 'raw', `verify-cost.t${trial}.${op.id}.json.gz`),
        gzipSync(JSON.stringify({ ...row, unit: 'ms', samples: Array.from(samples) })));
      console.log(`[verify-cost] trial ${trial} ${op.id.padEnd(36)} p50=${stats.p50Ms.toFixed(3)}ms p99=${stats.p99Ms.toFixed(3)}ms`);
    }
  }
  await close();
  const meta = Object.fromEntries(ops.map((op) => [op.id, { group: op.group, checks: op.checks }]));
  writeFileSync(path.join(outDir, 'verify-cost.trials.json'), JSON.stringify({ meta, rows }, null, 2));
  return { meta, rows };
}

if (process.argv[1]?.endsWith('verify-cost.mjs')) {
  const { values: a } = parseArgs({ options: {
    trials: { type: 'string', default: '5' }, iterations: { type: 'string', default: '3000' },
    warmup: { type: 'string', default: '500' }, out: { type: 'string' }, seed: { type: 'string', default: '20261021' },
  } });
  await runVerifyCost({
    outDir: a.out ?? path.resolve('results', `verify-cost-${Date.now()}`),
    trials: Number(a.trials), iterations: Number(a.iterations), warmup: Number(a.warmup), seed: Number(a.seed),
  });
}
