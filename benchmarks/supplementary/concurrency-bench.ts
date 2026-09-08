/**
 * Concurrency benchmark — measures throughput degradation under parallel load.
 *
 *   npm run build
 *   node --experimental-strip-types benchmarks/supplementary/concurrency-bench.ts
 *   REDIS_URL=redis://localhost:6379 node --experimental-strip-types benchmarks/supplementary/concurrency-bench.ts
 */

import {
  MemoryStore,
  RedisStore,
  OpaqueEngine,
  generateKeyPair,
  PasetoEngine,
  KeyRing,
  type NinshoStore,
  type Principal,
} from '../../packages/server/dist/index.js';

const PRINCIPAL: Principal = {
  userId: 'usr_conc',
  roles: ['user'],
  scopes: ['orders:read'],
};
const AUTHENTICATED_AT = new Date().toISOString();

interface ConcurrencyResult {
  readonly concurrency: number;
  readonly operation: string;
  readonly totalOps: number;
  readonly durationMs: number;
  readonly throughputOpsPerSec: number;
  readonly meanMs: number;
  readonly p50Ms: number;
  readonly p95Ms: number;
  readonly p99Ms: number;
}

async function measureConcurrent(
  name: string,
  operation: () => Promise<unknown>,
  concurrency: number,
  totalOps: number,
): Promise<ConcurrencyResult> {
  // Warm up
  for (let i = 0; i < Math.min(20, totalOps / 10); i++) await operation();

  const samples: number[] = [];
  let completed = 0;
  const startTime = performance.now();

  // Worker function: each worker takes work from a shared counter
  async function worker(): Promise<void> {
    while (completed < totalOps) {
      completed++;
      const s = performance.now();
      await operation();
      samples.push(performance.now() - s);
    }
  }

  const workers = Array.from({ length: concurrency }, () => worker());
  await Promise.all(workers);
  const durationMs = performance.now() - startTime;

  samples.sort((a, b) => a - b);
  const mean = samples.reduce((s, v) => s + v, 0) / samples.length;

  return {
    concurrency,
    operation: name,
    totalOps: samples.length,
    durationMs,
    throughputOpsPerSec: Math.round((samples.length / durationMs) * 1000),
    meanMs: mean,
    p50Ms: samples[Math.floor(samples.length * 0.50)] ?? 0,
    p95Ms: samples[Math.floor(samples.length * 0.95)] ?? 0,
    p99Ms: samples[Math.floor(samples.length * 0.99)] ?? 0,
  };
}

function reportConcurrency(title: string, results: ConcurrencyResult[]): void {
  console.log(`\n${title}`);
  console.log('─'.repeat(100));
  console.log(
    'operation'.padEnd(28) +
    'conc'.padStart(6) +
    'ops'.padStart(8) +
    'total ms'.padStart(10) +
    'ops/sec'.padStart(10) +
    'mean'.padStart(10) +
    'p50'.padStart(10) +
    'p95'.padStart(10) +
    'p99'.padStart(10)
  );
  console.log('─'.repeat(100));
  for (const r of results) {
    console.log(
      r.operation.padEnd(28) +
      String(r.concurrency).padStart(6) +
      String(r.totalOps).padStart(8) +
      `${r.durationMs.toFixed(0)}`.padStart(10) +
      r.throughputOpsPerSec.toLocaleString().padStart(10) +
      `${r.meanMs.toFixed(3)}ms`.padStart(10) +
      `${r.p50Ms.toFixed(3)}ms`.padStart(10) +
      `${r.p95Ms.toFixed(3)}ms`.padStart(10) +
      `${r.p99Ms.toFixed(3)}ms`.padStart(10)
    );
  }
}

async function runConcurrencySuite(store: NinshoStore, label: string): Promise<ConcurrencyResult[]> {
  const concurrencyLevels = [1, 10, 25, 50, 100];
  const opsPerLevel = 500;
  const results: ConcurrencyResult[] = [];

  // --- Opaque verify ---
  const opaque = new OpaqueEngine(store, { accessTokenTtl: 300, clockToleranceSeconds: 5 });
  const opaqueToken = (
    await opaque.issue({
      principal: PRINCIPAL,
      sessionId: 'sess_conc',
      authenticatedAt: AUTHENTICATED_AT,
    })
  ).token;

  for (const c of concurrencyLevels) {
    results.push(
      await measureConcurrent('opaque: verify', () => opaque.verify(opaqueToken), c, opsPerLevel)
    );
  }

  // --- PASETO verify ---
  const keys = new KeyRing({ active: generateKeyPair('bench-conc') });
  const paseto = new PasetoEngine(store, keys, {
    accessTokenTtl: 300,
    clockToleranceSeconds: 5,
    issuer: 'https://bench.test',
    audience: 'bench-api',
  });
  const pasetoToken = (
    await paseto.issue({
      principal: PRINCIPAL,
      sessionId: 'sess_conc_p',
      authenticatedAt: AUTHENTICATED_AT,
    })
  ).token;

  for (const c of concurrencyLevels) {
    results.push(
      await measureConcurrent('paseto: verify', () => paseto.verify(pasetoToken), c, opsPerLevel)
    );
  }

  reportConcurrency(label, results);
  return results;
}

async function main(): Promise<void> {
  console.log(`Ninsho concurrency benchmark — Node ${process.version}`);
  const allResults: ConcurrencyResult[] = [];

  const memory = new MemoryStore();
  allResults.push(...await runConcurrencySuite(memory, 'Concurrency — MemoryStore'));
  await memory.close();

  const redisUrl = process.env['REDIS_URL'];
  if (redisUrl) {
    const redis = new RedisStore(redisUrl);
    allResults.push(...await runConcurrencySuite(redis, 'Concurrency — RedisStore'));
    await redis.close();
  } else {
    console.log('\nSet REDIS_URL to also measure against Redis.');
  }

  console.log('\n---JSON_START---');
  console.log(JSON.stringify(allResults, null, 2));
  console.log('---JSON_END---');
}

await main();
