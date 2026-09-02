/**
 * Performance benchmarks for the WebAuthn hot paths.
 *
 *   npm run build --workspace @ninsho/webauthn
 *   npm run bench --workspace @ninsho/webauthn
 *
 * Measures the built output rather than the source, so the numbers describe
 * what actually ships.
 *
 * ─── What is being measured, and why it matters less than it looks ────────
 * A WebAuthn ceremony happens at sign-in, not on every request. So unlike
 * `opaque: verify` — which runs on every authenticated call — these costs are
 * paid once per session and are dominated in practice by the user's finger
 * touching a sensor.
 *
 * They are still worth knowing for two reasons. Attestation adds certificate
 * chain verification to registration, and it is fair to ask what that costs
 * before turning it on. And a parser on an attacker-reachable path is worth
 * measuring so an unauthenticated caller cannot make the server do expensive
 * work cheaply.
 * ──────────────────────────────────────────────────────────────────────────
 */

import {
  importCoseKey,
  decodeCbor,
  verifyRegistration,
  verifyAuthentication,
  ES256,
  EdDSA,
  RS256,
  type CoseAlgorithm,
} from '../dist/index.js';
import { VirtualAuthenticator, createChain } from '../dist/testing.js';

const RP_ID = 'example.com';
const ORIGIN = 'https://example.com';

const b64u = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');

const challenge = (): Uint8Array => {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
};

interface Result {
  readonly name: string;
  readonly opsPerSecond: number;
  readonly meanMs: number;
  readonly p95Ms: number;
  readonly p99Ms: number;
}

/** Times an operation, discarding a warm-up pass so JIT is not counted. */
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
  const mean = samples.reduce((sum, value) => sum + value, 0) / iterations;

  return {
    name,
    opsPerSecond: Math.round(1000 / mean),
    meanMs: mean,
    p95Ms: samples[Math.floor(iterations * 0.95)] ?? 0,
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

async function main(): Promise<void> {
  const iterations = Number(process.env['BENCH_ITERATIONS'] ?? 500);
  const results: Result[] = [];

  // ── Assertion verification, per algorithm ───────────────────────────────
  // The operation a returning user pays for. Pre-built outside the timer so
  // the measurement covers verification rather than the authenticator.
  for (const [label, alg] of [
    ['ES256', ES256],
    ['EdDSA', EdDSA],
    ['RS256', RS256],
  ] as const) {
    const device = await VirtualAuthenticator.create(alg as CoseAlgorithm);
    const regChallenge = challenge();
    const registration = await verifyRegistration(
      await device.register({ challenge: regChallenge, origin: ORIGIN, rpId: RP_ID }),
      { rpId: RP_ID, origin: ORIGIN, challenge: b64u(regChallenge) },
    );

    const credential = {
      credentialId: registration.credentialId,
      publicKey: registration.credentialPublicKey,
      signCount: 0,
    };

    // Counter regression would reject a replayed assertion, so each iteration
    // needs its own — built ahead of time, outside the measurement.
    const assertions = await Promise.all(
      Array.from({ length: iterations + 60 }, async (_, i) => {
        const c = challenge();
        return {
          challenge: c,
          assertion: await device.authenticate({
            challenge: c,
            origin: ORIGIN,
            rpId: RP_ID,
            signCount: i + 1,
          }),
        };
      }),
    );

    let index = 0;
    results.push(
      await measure(
        `authenticate: verify (${label})`,
        async () => {
          const next = assertions[index++ % assertions.length];
          if (!next) return;
          return verifyAuthentication(next.assertion, {
            rpId: RP_ID,
            origin: ORIGIN,
            challenge: b64u(next.challenge),
            credential,
            onCounterRegression: 'allow',
          });
        },
        iterations,
      ),
    );
  }

  // ── Registration, with and without attestation ──────────────────────────
  const device = await VirtualAuthenticator.create();
  const chain = createChain({ aaguid: device.aaguid });

  const plain = await Promise.all(
    Array.from({ length: iterations + 60 }, async () => {
      const c = challenge();
      return { c, response: await device.register({ challenge: c, origin: ORIGIN, rpId: RP_ID }) };
    }),
  );
  let plainIndex = 0;
  results.push(
    await measure(
      'register: verify (none)',
      async () => {
        const next = plain[plainIndex++ % plain.length];
        if (!next) return;
        return verifyRegistration(next.response, {
          rpId: RP_ID,
          origin: ORIGIN,
          challenge: b64u(next.c),
        });
      },
      iterations,
    ),
  );

  const attested = await Promise.all(
    Array.from({ length: iterations + 60 }, async () => {
      const c = challenge();
      return {
        c,
        response: await device.register({
          challenge: c,
          origin: ORIGIN,
          rpId: RP_ID,
          attestationChain: chain,
        }),
      };
    }),
  );
  let attestedIndex = 0;
  results.push(
    await measure(
      'register: verify (packed + chain)',
      async () => {
        const next = attested[attestedIndex++ % attested.length];
        if (!next) return;
        return verifyRegistration(next.response, {
          rpId: RP_ID,
          origin: ORIGIN,
          challenge: b64u(next.c),
          attestation: { formats: ['packed'], trustAnchors: [chain.root.der] },
        });
      },
      iterations,
    ),
  );

  // ── Primitives on the attacker-reachable path ───────────────────────────
  const coseKey = await device.coseKey();
  results.push(
    await measure('cose: importCoseKey', async () => importCoseKey(coseKey), iterations),
  );
  results.push(
    await measure('cbor: decode (COSE key)', async () => decodeCbor(coseKey), iterations),
  );

  report(`WebAuthn — ${iterations} iterations, Node ${process.version}`, results);
  console.log(
    '\nCeremonies happen once per sign-in, not per request. Compare with\n' +
      '`opaque: verify` in PERFORMANCE.md, which runs on every authenticated call.',
  );
}

await main();
