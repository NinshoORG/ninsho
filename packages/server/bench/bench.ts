/**
 * Performance benchmarks for the operations on the request hot path.
 *
 *   npm run build
 *   npm run bench --workspace @ninsho/server
 *   REDIS_URL=redis://localhost:6379 npm run bench --workspace @ninsho/server
 *
 * Measures the built output rather than the source, so the numbers describe
 * what actually ships — including whatever the bundler did to it.
 *
 * ─── What these numbers are, and are not ──────────────────────────────────
 * Against MemoryStore these measure *library overhead* — serialization,
 * hashing, signing, claim validation — with store latency near zero. That is
 * the useful number for answering "what does Ninsho itself cost?", and it is
 * deliberately not a throughput figure for a deployed system.
 *
 * Against Redis they measure the same work plus real network round trips,
 * which is what production actually pays. Expect the Redis numbers to be
 * dominated by latency rather than by anything in this codebase.
 *
 * The point of measuring at all is to know where the cost is before optimising
 * anything, and to notice if a security fix later makes the hot path
 * dramatically worse.
 * ──────────────────────────────────────────────────────────────────────────
 */

import {
  MemoryStore,
  RedisStore,
  OpaqueEngine,
  PasetoEngine,
  KeyRing,
  SessionManager,
  RateLimiter,
  NullAuditSink,
  generateKeyPair,
  type NinshoStore,
  type Principal,
} from '../dist/index.js';

const PRINCIPAL: Principal = {
  userId: 'usr_bench',
  roles: ['user'],
  scopes: ['orders:read'],
};

interface Result {
  readonly name: string;
  readonly opsPerSecond: number;
  readonly meanMs: number;
  readonly p95Ms: number;
  readonly p99Ms: number;
}

/**
 * Times an operation, discarding a warm-up pass so JIT compilation and lazy
 * initialisation are not counted as steady-state cost.
 */
async function measure(
  name: string,
  operation: () => Promise<unknown>,
  iterations: number,
): Promise<Result> {
  const warmup = Math.min(50, Math.floor(iterations / 10));
  for (let i = 0; i < warmup; i += 1) await operation();

  const samples: number[] = new Array(iterations);
  for (let i = 0; i < iterations; i += 1) {
    const started = performance.now();
    await operation();
    samples[i] = performance.now() - started;
  }

  samples.sort((a, b) => a - b);
  const total = samples.reduce((sum, value) => sum + value, 0);
  const mean = total / iterations;

  return {
    name,
    opsPerSecond: Math.round(1000 / mean),
    meanMs: mean,
    p95Ms: samples[Math.floor(iterations * 0.95)] ?? 0,
    // p99 matters more than the mean for an auth endpoint: it is the tail that
    // shows up as user-visible slowness under load.
    p99Ms: samples[Math.floor(iterations * 0.99)] ?? 0,
  };
}

function report(title: string, results: readonly Result[]): void {
  console.log(`\n${title}`);
  console.log('─'.repeat(78));
  console.log(
    `${'operation'.padEnd(34)}${'ops/sec'.padStart(12)}${'mean'.padStart(11)}${'p95'.padStart(11)}${'p99'.padStart(10)}`,
  );
  console.log('─'.repeat(78));
  for (const r of results) {
    console.log(
      r.name.padEnd(34) +
        r.opsPerSecond.toLocaleString().padStart(12) +
        `${r.meanMs.toFixed(3)}ms`.padStart(11) +
        `${r.p95Ms.toFixed(3)}ms`.padStart(11) +
        `${r.p99Ms.toFixed(3)}ms`.padStart(10),
    );
  }
}

async function runSuite(store: NinshoStore, label: string, iterations: number): Promise<void> {
  const audit = new NullAuditSink();
  const results: Result[] = [];

  // ── Opaque strategy ───────────────────────────────────────────────────────
  const opaque = new OpaqueEngine(store, { accessTokenTtl: 300, clockToleranceSeconds: 5 });

  results.push(
    await measure(
      'opaque: issue',
      () => opaque.issue({ principal: PRINCIPAL, sessionId: 'sess_bench' }),
      iterations,
    ),
  );

  const opaqueToken = (await opaque.issue({ principal: PRINCIPAL, sessionId: 'sess_verify' })).token;
  results.push(
    await measure('opaque: verify (hot path)', () => opaque.verify(opaqueToken), iterations),
  );

  // ── PASETO strategy ───────────────────────────────────────────────────────
  const keys = new KeyRing({ active: generateKeyPair('bench') });
  const paseto = new PasetoEngine(store, keys, {
    accessTokenTtl: 300,
    clockToleranceSeconds: 5,
    issuer: 'https://bench.test',
    audience: 'bench-api',
  });

  results.push(
    await measure(
      'paseto: issue (Ed25519 sign)',
      () => paseto.issue({ principal: PRINCIPAL, sessionId: 'sess_bench' }),
      iterations,
    ),
  );

  const pasetoToken = (await paseto.issue({ principal: PRINCIPAL, sessionId: 'sess_verify' })).token;
  results.push(
    await measure('paseto: verify (Ed25519)', () => paseto.verify(pasetoToken), iterations),
  );

  // Isolates the signature check from the denylist round trip, which is the
  // number that tells you what statelessness actually buys.
  results.push(
    await measure(
      'paseto: verify (no store check)',
      () => paseto.verify(pasetoToken, { skipRevocationCheck: true }),
      iterations,
    ),
  );

  // ── Sessions ──────────────────────────────────────────────────────────────
  const sessions = new SessionManager(store, opaque, {
    refreshTokenTtl: 604_800,
    refreshGraceSeconds: 30,
    clockToleranceSeconds: 5,
    audit,
  });

  results.push(
    await measure('session: create', () => sessions.create(PRINCIPAL), Math.floor(iterations / 2)),
  );

  // Rotation consumes its input, so each iteration needs a fresh token. The
  // chain is pre-built to keep that setup out of the measurement.
  const rotationCount = Math.floor(iterations / 4);
  const chain: string[] = [];
  for (let i = 0; i < rotationCount + 60; i += 1) {
    chain.push((await sessions.create(PRINCIPAL)).refreshToken);
  }
  let chainIndex = 0;
  results.push(
    await measure(
      'session: refresh (rotation)',
      () => sessions.refresh(chain[chainIndex++] as string),
      rotationCount,
    ),
  );

  // ── Rate limiting ─────────────────────────────────────────────────────────
  const limiter = new RateLimiter({ store, onStoreError: 'closed', audit });
  let bucket = 0;
  results.push(
    await measure(
      'ratelimit: consume (2 buckets)',
      () =>
        limiter.consumeAll([
          { bucket: `bench:ip:${bucket++ % 1000}`, limit: 1_000_000, windowMs: 900_000 },
          { bucket: `bench:acct:${bucket % 1000}`, limit: 1_000_000, windowMs: 900_000 },
        ]),
      iterations,
    ),
  );

  report(label, results);
}

async function main(): Promise<void> {
  const iterations = Number.parseInt(process.env['ITERATIONS'] ?? '2000', 10);
  console.log(`Ninsho benchmarks — node ${process.version}, ${iterations} iterations`);

  const memory = new MemoryStore();
  await runSuite(memory, 'MemoryStore — library overhead only', iterations);
  await memory.close();

  const redisUrl = process.env['REDIS_URL'];
  if (redisUrl === undefined) {
    console.log('\nSet REDIS_URL to also measure against a real store.');
    console.log('The Redis figures are dominated by network latency, not by this code.');
    return;
  }

  const redis = new RedisStore(redisUrl);
  // Fewer iterations: each one is a real round trip.
  await runSuite(redis, 'RedisStore — including network round trips', Math.min(iterations, 500));
  await redis.close();
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
