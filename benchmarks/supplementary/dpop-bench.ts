/**
 * DPoP proof-of-possession benchmarks.
 *
 *   npm run build
 *   node --experimental-strip-types benchmarks/supplementary/dpop-bench.ts
 */

import { randomUUID } from 'node:crypto';
import {
  generateDpopKeyPair,
  createDpopProof,
  verifyDpopProof,
  accessTokenHash,
  jwkThumbprint,
} from '../../packages/server/dist/index.js';
import { generateToken } from '../../packages/core/dist/index.js';

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

  return {
    name,
    opsPerSecond: Math.round(1000 / mean),
    meanMs: mean,
    p50Ms: samples[Math.floor(iterations * 0.5)] ?? 0,
    p95Ms: samples[Math.floor(iterations * 0.95)] ?? 0,
    p99Ms: samples[Math.floor(iterations * 0.99)] ?? 0,
    minMs: samples[0] ?? 0,
    maxMs: samples[samples.length - 1] ?? 0,
    stddevMs: Math.sqrt(variance),
  };
}

function report(title: string, results: readonly Result[]): void {
  console.log(`\n${title}`);
  console.log('─'.repeat(90));
  console.log(
    'operation'.padEnd(34) +
    'ops/sec'.padStart(12) +
    'mean'.padStart(11) +
    'p50'.padStart(11) +
    'p95'.padStart(11) +
    'p99'.padStart(10)
  );
  console.log('─'.repeat(90));
  for (const r of results) {
    console.log(
      r.name.padEnd(34) +
        r.opsPerSecond.toLocaleString().padStart(12) +
        `${r.meanMs.toFixed(3)}ms`.padStart(11) +
        `${r.p50Ms.toFixed(3)}ms`.padStart(11) +
        `${r.p95Ms.toFixed(3)}ms`.padStart(11) +
        `${r.p99Ms.toFixed(3)}ms`.padStart(10),
    );
  }
}

async function main(): Promise<void> {
  const iterations = Number.parseInt(process.env['ITERATIONS'] ?? '1000', 10);
  console.log(`Ninsho DPoP benchmarks — Node ${process.version}, ${iterations} iterations`);

  const results: Result[] = [];

  // 1. Key pair generation
  results.push(
    await measure('generateDpopKeyPair (ES256)', async () => generateDpopKeyPair('ES256'), iterations)
  );
  results.push(
    await measure('generateDpopKeyPair (EdDSA)', async () => generateDpopKeyPair('EdDSA'), iterations)
  );

  // 2. Proof creation
  const es256Key = generateDpopKeyPair('ES256');
  const ed25519Key = generateDpopKeyPair('EdDSA');

  results.push(
    await measure(
      'createDpopProof (ES256)',
      async () => createDpopProof(es256Key, { method: 'POST', url: 'https://example.com/api/data' }),
      iterations,
    )
  );
  results.push(
    await measure(
      'createDpopProof (EdDSA)',
      async () => createDpopProof(ed25519Key, { method: 'POST', url: 'https://example.com/api/data' }),
      iterations,
    )
  );

  // 3. Proof verification — pre-generate proofs (each needs unique jti)
  const es256Proofs: string[] = [];
  const ed25519Proofs: string[] = [];
  const proofCount = iterations + 60;
  for (let i = 0; i < proofCount; i++) {
    es256Proofs.push(createDpopProof(es256Key, {
      method: 'POST',
      url: 'https://example.com/api/data',
      jti: randomUUID(),
    }));
    ed25519Proofs.push(createDpopProof(ed25519Key, {
      method: 'POST',
      url: 'https://example.com/api/data',
      jti: randomUUID(),
    }));
  }

  let es256Idx = 0;
  results.push(
    await measure(
      'verifyDpopProof (ES256)',
      async () => {
        const proof = es256Proofs[es256Idx++ % es256Proofs.length]!;
        return verifyDpopProof(proof, {
          method: 'POST',
          url: 'https://example.com/api/data',
          // Both are REQUIRED by `VerifyProofOptions`, and omitting them does
          // not merely default — `undefined * 1000` is NaN, every comparison
          // against NaN is false, and the "issued in the future" and "proof is
          // too old" checks silently never fire. The benchmark was measuring a
          // verification with two of its checks disabled.
          //
          // These are the library's own defaults, so the figures below are the
          // cost of the path a deployment actually runs.
          maxAgeSeconds: 60,
          clockToleranceSeconds: 5,
        });
      },
      iterations,
    )
  );

  let ed25519Idx = 0;
  results.push(
    await measure(
      'verifyDpopProof (EdDSA)',
      async () => {
        const proof = ed25519Proofs[ed25519Idx++ % ed25519Proofs.length]!;
        return verifyDpopProof(proof, {
          method: 'POST',
          url: 'https://example.com/api/data',
          // Both are REQUIRED by `VerifyProofOptions`, and omitting them does
          // not merely default — `undefined * 1000` is NaN, every comparison
          // against NaN is false, and the "issued in the future" and "proof is
          // too old" checks silently never fire. The benchmark was measuring a
          // verification with two of its checks disabled.
          //
          // These are the library's own defaults, so the figures below are the
          // cost of the path a deployment actually runs.
          maxAgeSeconds: 60,
          clockToleranceSeconds: 5,
        });
      },
      iterations,
    )
  );

  // 4. Utility operations
  results.push(
    await measure('jwkThumbprint (ES256)', async () => jwkThumbprint(es256Key.publicJwk), iterations)
  );

  const sampleToken = generateToken();
  results.push(
    await measure('accessTokenHash', async () => accessTokenHash(sampleToken), iterations)
  );

  report(`DPoP operations — ${iterations} iterations`, results);

  console.log('\n---JSON_START---');
  console.log(JSON.stringify(results, null, 2));
  console.log('---JSON_END---');
}

await main();
