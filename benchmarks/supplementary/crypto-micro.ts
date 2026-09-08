/**
 * Microbenchmarks for isolated cryptographic primitives.
 *
 *   npm run build
 *   node --experimental-strip-types benchmarks/supplementary/crypto-micro.ts
 *   ITERATIONS=5000 node --experimental-strip-types benchmarks/supplementary/crypto-micro.ts
 *
 * Measures raw cryptographic and identifier generation primitives from Ninsho
 * without storage, network, or framework overhead.
 */

import {
  generateKeyPair,
  loadPrivateKey,
  loadPublicKey,
  signV4Public,
  verifyV4Public,
} from '../../packages/server/dist/index.js';
import {
  generateId,
  generateToken,
  hashToken,
} from '../../packages/core/dist/index.js';

interface Result {
  readonly name: string;
  readonly opsPerSecond: number;
  readonly meanMs: number;
  readonly p50Ms: number;
  readonly p95Ms: number;
  readonly p99Ms: number;
  readonly minMs: number;
  readonly maxMs: number;
  readonly stddevMs: number;
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
  const variance = samples.reduce((sum, value) => sum + (value - mean) ** 2, 0) / iterations;
  const stddev = Math.sqrt(variance);

  return {
    name,
    opsPerSecond: Math.round(1000 / mean),
    meanMs: mean,
    p50Ms: samples[Math.floor(iterations * 0.5)] ?? 0,
    p95Ms: samples[Math.floor(iterations * 0.95)] ?? 0,
    p99Ms: samples[Math.floor(iterations * 0.99)] ?? 0,
    minMs: samples[0] ?? 0,
    maxMs: samples[samples.length - 1] ?? 0,
    stddevMs: stddev,
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

async function main(): Promise<void> {
  const iterations = Number.parseInt(process.env['ITERATIONS'] ?? '2000', 10);
  console.log(`Ninsho crypto microbenchmarks — Node ${process.version}, ${iterations} iterations`);

  const results: Result[] = [];

  // 1. generateToken (CSPRNG 256-bit)
  results.push(
    await measure('generateToken (CSPRNG 256-bit)', async () => generateToken(), iterations),
  );

  // 2. hashToken (SHA-256)
  const token = generateToken();
  results.push(
    await measure('hashToken (SHA-256)', async () => hashToken(token), iterations),
  );

  // 3. generateId (random ID)
  results.push(
    await measure('generateId (random ID)', async () => generateId(), iterations),
  );

  // 4. signV4Public (Ed25519 sign)
  const rawKeys = generateKeyPair('bench-crypto');
  const keys = {
    kid: rawKeys.kid,
    privateKey: typeof rawKeys.privateKey === 'string' ? loadPrivateKey(rawKeys.privateKey) : rawKeys.privateKey,
    publicKey: typeof rawKeys.publicKey === 'string' ? loadPublicKey(rawKeys.publicKey) : rawKeys.publicKey,
  };
  const payload = JSON.stringify({ sub: 'user', iat: Date.now() });

  results.push(
    await measure(
      'signV4Public (Ed25519 sign)',
      async () => signV4Public(payload, keys.privateKey),
      iterations,
    ),
  );

  // 5. verifyV4Public (Ed25519 verify)
  const signedToken = signV4Public(payload, keys.privateKey);
  results.push(
    await measure(
      'verifyV4Public (Ed25519 verify)',
      async () => verifyV4Public(signedToken, keys.publicKey),
      iterations,
    ),
  );

  // 6. signV4Public + verifyV4Public (round trip)
  results.push(
    await measure(
      'signV4Public + verifyV4Public (round trip)',
      async () => {
        const t = signV4Public(payload, keys.privateKey);
        verifyV4Public(t, keys.publicKey);
      },
      iterations,
    ),
  );

  report(`Cryptographic primitives — ${iterations} iterations`, results);

  console.log('\n---JSON_START---');
  console.log(JSON.stringify(results, null, 2));
  console.log('---JSON_END---');
}

await main();
