import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runThreeDemos } from './three-demos.mjs';

test('viva HTTP demonstrations: shared Redis, DPoP and resource ownership', {
  skip: !process.env.REDIS_URL && 'REDIS_URL required; no memory substitute',
  timeout: 30000,
}, async () => {
  const results = await runThreeDemos(process.env.REDIS_URL, () => {});
  assert.equal(results.length, 10);
  assert.deepEqual(results.map(result => result.actual), [200, 200, 204, 401, 401, 401, 200, 401, 200, 403]);
});
