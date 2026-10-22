// Comparison 2 — comparable protected requests over real HTTP.
//
// For each trial, configurations are run in a recorded, shuffled order. Each
// configuration gets a fresh server process; a security preflight proves the
// verifier refuses what it should before any timing starts; then each
// concurrency level is warmed up and measured for a fixed duration with a
// closed-loop load generator (N workers, each with one request in flight over
// a keep-alive connection).
//
// Usage: node http-bench.mjs [--trials 5] [--duration 10] [--warmup 3] [--levels 1,8,32] [--out <dir>]
// Env:   REDIS_URL (default redis://localhost:6379)

import { fork } from 'node:child_process';
import http from 'node:http';
import { mkdirSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { CHECKS, COMPARABLE, CONFIG_NAMES } from './lib/configs.mjs';
import { describe, shuffle } from './lib/stats.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));

/** What each configuration must answer in the preflight. `null` = not applicable. */
const EXPECT = {
  'ninsho-opaque': { valid: 200, missing: 401, tampered: 401, revoked: 401, wrongAudience: null },
  'ninsho-paseto': { valid: 200, missing: 401, tampered: 401, revoked: 401, wrongAudience: 401 },
  'jwt-redis': { valid: 200, missing: 401, tampered: 401, revoked: 401, wrongAudience: 401 },
  // Accepting the revoked token is the expected — and disclosed — behaviour.
  'jwt-stateless': { valid: 200, missing: 401, tampered: 401, revoked: 200, wrongAudience: 401 },
  'no-auth': { valid: 200, missing: 200, tampered: null, revoked: null, wrongAudience: null },
};

function startServer(config, redisUrl, poolSize) {
  return new Promise((resolve, reject) => {
    const child = fork(path.join(here, 'server.mjs'), [config, redisUrl, String(poolSize)], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] });
    child.once('message', (m) => resolve({ child, ...m }));
    child.once('exit', (code) => reject(new Error(`${config} server exited early (${code})`)));
  });
}

function stopServer(child) {
  return new Promise((resolve) => { child.once('exit', resolve); child.send('stop'); });
}

function request(agent, port, token) {
  return new Promise((resolve, reject) => {
    const headers = token === undefined ? {} : { authorization: `Bearer ${token}` };
    const started = process.hrtime.bigint();
    const req = http.request({ host: '127.0.0.1', port, path: '/api/orders', method: 'GET', agent, headers }, (res) => {
      let bytes = 0;
      res.on('data', (c) => { bytes += c.length; });
      res.on('end', () => resolve({ status: res.statusCode, ms: Number(process.hrtime.bigint() - started) / 1e6, bytes }));
    });
    req.on('error', reject);
    req.end();
  });
}

async function preflight(config, port, pool, tokens) {
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  const answers = {};
  answers.valid = (await request(agent, port, pool[0])).status;
  answers.missing = (await request(agent, port, undefined)).status;
  for (const k of ['tampered', 'revoked', 'wrongAudience']) {
    answers[k] = tokens[k] === undefined ? null : (await request(agent, port, tokens[k])).status;
  }
  agent.destroy();
  const expected = EXPECT[config];
  const mismatches = Object.keys(expected).filter((k) => expected[k] !== null && answers[k] !== expected[k]);
  return { config, answers, expected, passed: mismatches.length === 0, mismatches };
}

async function load(port, pool, concurrency, seconds) {
  const agent = new http.Agent({ keepAlive: true, maxSockets: concurrency });
  const latencies = [];
  const statuses = {};
  let bytes = 0;
  let next = 0;
  const deadline = performance.now() + seconds * 1000;
  const started = performance.now();
  const worker = async () => {
    while (performance.now() < deadline) {
      const token = pool[next++ % pool.length];
      const r = await request(agent, port, token);
      latencies.push(r.ms);
      statuses[r.status] = (statuses[r.status] ?? 0) + 1;
      bytes += r.bytes;
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  const elapsed = (performance.now() - started) / 1000;
  agent.destroy();
  return { latencies, statuses, elapsedSeconds: elapsed, bytes };
}

export async function runHttpBench({ outDir, trials = 5, duration = 10, warmup = 3, levels = [1, 8, 32], seed = 20261021, poolSize = 64, redisUrl }) {
  mkdirSync(path.join(outDir, 'raw'), { recursive: true });
  const rows = [];
  const preflights = [];
  for (let trial = 1; trial <= trials; trial += 1) {
    const order = shuffle(CONFIG_NAMES, seed + trial);
    console.log(`[http] trial ${trial} order: ${order.join(', ')}`);
    for (const config of order) {
      const { child, port, pool, preflight: tokens } = await startServer(config, redisUrl, poolSize);
      try {
        const pf = await preflight(config, port, pool, tokens);
        preflights.push({ trial, ...pf });
        if (!pf.passed && COMPARABLE.includes(config)) {
          throw new Error(`preflight failed for ${config}: ${JSON.stringify(pf)} — refusing to time a verifier that does not refuse what it should`);
        }
        for (const c of levels) {
          await load(port, pool, c, warmup);
          const m = await load(port, pool, c, duration);
          const ok = m.statuses[200] ?? 0;
          const stats = describe(m.latencies);
          const row = {
            comparison: 'http', trial, config, concurrency: c, durationSeconds: m.elapsedSeconds, warmupSeconds: warmup,
            requests: m.latencies.length, ok, nonOk: m.latencies.length - ok, statuses: m.statuses,
            throughputRps: ok / m.elapsedSeconds, meanBytes: m.bytes / m.latencies.length, ...stats,
          };
          rows.push(row);
          writeFileSync(path.join(outDir, 'raw', `http.t${trial}.${config}.c${c}.json.gz`),
            gzipSync(JSON.stringify({ ...row, unit: 'ms', latencies: m.latencies })));
          console.log(`[http] t${trial} ${config.padEnd(14)} c=${String(c).padStart(2)} rps=${row.throughputRps.toFixed(0).padStart(5)} p50=${stats.p50Ms.toFixed(2)} p95=${stats.p95Ms.toFixed(2)} p99=${stats.p99Ms.toFixed(2)} non200=${row.nonOk}`);
        }
      } finally {
        await stopServer(child);
      }
    }
  }
  writeFileSync(path.join(outDir, 'http.trials.json'), JSON.stringify({ checks: CHECKS, expected: EXPECT, preflights, rows }, null, 2));
  return { preflights, rows };
}

if (process.argv[1]?.endsWith('http-bench.mjs')) {
  const { values: a } = parseArgs({ options: {
    trials: { type: 'string', default: '5' }, duration: { type: 'string', default: '10' },
    warmup: { type: 'string', default: '3' }, levels: { type: 'string', default: '1,8,32' },
    out: { type: 'string' }, seed: { type: 'string', default: '20261021' },
  } });
  await runHttpBench({
    outDir: a.out ?? path.resolve('results', `http-${Date.now()}`),
    trials: Number(a.trials), duration: Number(a.duration), warmup: Number(a.warmup),
    levels: a.levels.split(',').map(Number), seed: Number(a.seed),
    redisUrl: process.env.REDIS_URL ?? 'redis://localhost:6379',
  });
}
