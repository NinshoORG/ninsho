// One command: capture the environment, run both comparisons, summarise.
//
//   cd research/validation/benchmarks
//   npm ci                                   # installs the pinned jose
//   REDIS_URL=redis://localhost:6379 node run.mjs           # full run
//   REDIS_URL=redis://localhost:6379 node run.mjs --standard   # ~6 min; used for the blackbook
//   REDIS_URL=redis://localhost:6379 node run.mjs --quick   # smoke test, not for reporting
//
// Requires `npm run build` at the repository root first: Ninsho is imported
// from packages/server/dist, the code a consumer installs.

import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { captureEnvironment } from './lib/env.mjs';
import { runVerifyCost } from './verify-cost.mjs';
import { runHttpBench } from './http-bench.mjs';
import { summarize } from './summarize.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const { values: a } = parseArgs({ options: {
  quick: { type: 'boolean', default: false },
  standard: { type: 'boolean', default: false },
  out: { type: 'string' },
  'skip-verify-cost': { type: 'boolean', default: false },
  'skip-http': { type: 'boolean', default: false },
} });

const redisUrl = process.env.REDIS_URL ?? 'redis://localhost:6379';
const settings = a.standard
  ? { mode: 'standard', verifyCost: { trials: 3, iterations: 1000, warmup: 200 }, http: { trials: 3, duration: 5, warmup: 2, levels: [1, 16] } }
  : a.quick
  ? { mode: 'quick', verifyCost: { trials: 2, iterations: 300, warmup: 50 }, http: { trials: 2, duration: 2, warmup: 1, levels: [1, 8] } }
  : { mode: 'full', verifyCost: { trials: 5, iterations: 3000, warmup: 500 }, http: { trials: 5, duration: 10, warmup: 3, levels: [1, 8, 32] } };
settings.seed = 20261021;
settings.poolSize = 64;

const env = await captureEnvironment(redisUrl);
if (env.redis.error) {
  console.error(`Redis is not reachable at ${redisUrl}: ${env.redis.error}`);
  console.error('Start one with: docker run -d --rm -p 6379:6379 --name ninsho-redis redis:7-alpine');
  process.exit(1);
}

const stamp = new Date().toISOString().replace(/[:.]/g, '-');
const outDir = a.out ?? path.join(here, 'results', `${stamp}-${(env.git.commit ?? 'nogit').slice(0, 7)}-${settings.mode}`);
mkdirSync(outDir, { recursive: true });
writeFileSync(path.join(outDir, 'env.json'), JSON.stringify({ ...env, settings }, null, 2));
console.log(`run directory: ${outDir}`);

if (!a['skip-verify-cost']) await runVerifyCost({ outDir, redisUrl, seed: settings.seed, ...settings.verifyCost });
if (!a['skip-http']) await runHttpBench({ outDir, redisUrl, seed: settings.seed, poolSize: settings.poolSize, ...settings.http });
summarize(outDir);
console.log(`summary: ${path.join(outDir, 'summary.md')}`);
