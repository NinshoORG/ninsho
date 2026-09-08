/**
 * End-to-end Express HTTP benchmarks.
 *
 * Starts the Express example application in-process and measures real HTTP
 * request latencies for:
 *   - Unauthenticated baseline (`GET /health`)
 *   - Authenticated endpoint (`GET /me`)
 *   - Full login→access→refresh→logout flow
 *
 *   npm run build
 *   node --experimental-strip-types benchmarks/supplementary/express-e2e-bench.ts
 */

import http from 'node:http';
import { createApp } from '../../examples/express-api/src/app.ts';
import { MemoryStore } from '../../packages/server/dist/index.js';

interface Result {
  readonly name: string;
  readonly opsPerSecond: number;
  readonly meanMs: number;
  readonly p50Ms: number;
  readonly p95Ms: number;
  readonly p99Ms: number;
  readonly minMs: number;
  readonly maxMs: number;
}

async function measure(
  name: string,
  operation: () => Promise<unknown>,
  iterations: number,
): Promise<Result> {
  const warmup = Math.min(30, Math.floor(iterations / 10));
  for (let i = 0; i < warmup; i += 1) await operation();

  const samples: number[] = new Array(iterations);
  for (let i = 0; i < iterations; i += 1) {
    const started = performance.now();
    await operation();
    samples[i] = performance.now() - started;
  }

  samples.sort((a, b) => a - b);
  const mean = samples.reduce((s, v) => s + v, 0) / iterations;

  return {
    name,
    opsPerSecond: Math.round(1000 / mean),
    meanMs: mean,
    p50Ms: samples[Math.floor(iterations * 0.50)] ?? 0,
    p95Ms: samples[Math.floor(iterations * 0.95)] ?? 0,
    p99Ms: samples[Math.floor(iterations * 0.99)] ?? 0,
    minMs: samples[0] ?? 0,
    maxMs: samples[samples.length - 1] ?? 0,
  };
}

function report(title: string, results: readonly Result[]): void {
  console.log(`\n${title}`);
  console.log('─'.repeat(90));
  console.log(
    'operation'.padEnd(32) +
    'ops/sec'.padStart(10) +
    'mean'.padStart(11) +
    'p50'.padStart(11) +
    'p95'.padStart(11) +
    'p99'.padStart(11)
  );
  console.log('─'.repeat(90));
  for (const r of results) {
    console.log(
      r.name.padEnd(32) +
      r.opsPerSecond.toLocaleString().padStart(10) +
      `${r.meanMs.toFixed(3)}ms`.padStart(11) +
      `${r.p50Ms.toFixed(3)}ms`.padStart(11) +
      `${r.p95Ms.toFixed(3)}ms`.padStart(11) +
      `${r.p99Ms.toFixed(3)}ms`.padStart(11)
    );
  }
}

function httpRequest(
  baseUrl: string,
  method: string,
  path: string,
  headers: Record<string, string> = {},
  body?: string,
): Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const req = http.request(url, { method, headers: { ...headers, ...(body ? { 'content-type': 'application/json' } : {}) } }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode ?? 0,
        body: Buffer.concat(chunks).toString('utf8'),
        headers: res.headers,
      }));
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function main(): Promise<void> {
  const iterations = Number(process.env['ITERATIONS'] ?? '500');
  console.log(`Express E2E benchmark — Node ${process.version}, ${iterations} iterations`);

  const store = new MemoryStore();
  const { app } = createApp({ store, secureCookies: false });
  const server = http.createServer(app);

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address() as { port: number };
  const baseUrl = `http://127.0.0.1:${addr.port}`;

  const results: Result[] = [];

  // --- Register a user for authenticated tests ---
  const email = `bench-${Date.now()}@test.com`;
  const password = 'benchmarkpassword123';
  await httpRequest(baseUrl, 'POST', '/auth/register', {}, JSON.stringify({ email, password }));

  // --- Login to get an access token ---
  const loginRes = await httpRequest(baseUrl, 'POST', '/auth/login', {}, JSON.stringify({ email, password }));
  const loginData = JSON.parse(loginRes.body);
  const accessToken: string = loginData.accessToken;

  // 1. Unauthenticated baseline
  results.push(
    await measure('GET /health (unauthed)', () => httpRequest(baseUrl, 'GET', '/health'), iterations)
  );

  // 2. Authenticated endpoint
  results.push(
    await measure(
      'GET /me (authed, opaque)',
      () => httpRequest(baseUrl, 'GET', '/me', { authorization: `Bearer ${accessToken}` }),
      iterations,
    )
  );

  // 3. Login flow (register + login, excluding password hashing since it re-uses existing)
  // Actually, measure just login (credential verification + session creation)
  // Need unique emails to avoid rate limiting
  let loginCounter = 0;
  // Pre-register accounts
  const loginCount = Math.min(iterations, 200);
  const loginEmails: string[] = [];
  for (let i = 0; i < loginCount + 40; i++) {
    const e = `benchlogin-${Date.now()}-${i}@test.com`;
    await httpRequest(baseUrl, 'POST', '/auth/register', {}, JSON.stringify({ email: e, password }));
    loginEmails.push(e);
  }

  results.push(
    await measure(
      'POST /auth/login (full)',
      async () => {
        const e = loginEmails[loginCounter++ % loginEmails.length]!;
        await httpRequest(baseUrl, 'POST', '/auth/login', {}, JSON.stringify({ email: e, password }));
      },
      loginCount,
    )
  );

  report(`Express E2E — MemoryStore, ${iterations} iterations`, results);

  console.log('\n---JSON_START---');
  console.log(JSON.stringify(results, null, 2));
  console.log('---JSON_END---');

  server.close();
  await store.close();
}

await main();
