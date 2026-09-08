import { describe, it, expect, afterEach } from 'vitest';
import { ConfigurationError } from '@ninshorg/core';
import { MemoryStore } from '../store/memory.js';

const ORIGINAL_NODE_ENV = process.env['NODE_ENV'];

afterEach(() => {
  if (ORIGINAL_NODE_ENV === undefined) {
    delete process.env['NODE_ENV'];
  } else {
    process.env['NODE_ENV'] = ORIGINAL_NODE_ENV;
  }
});

/**
 * REGRESSION — audit finding C2.
 *
 * The predecessor selected an in-memory test double whenever
 * `USE_REDIS_MOCK=true` was set, from inside the Redis client's constructor,
 * and shipped that double in its published bundle. In production it silently
 * replaced revocation, session state and rate limiting with a per-process fake
 * while the API kept returning 200.
 *
 * Ninsho's in-memory store is safe for two reasons, and both are asserted here:
 * it must be named explicitly in application code, and it refuses to exist in
 * production at all.
 */
describe('MemoryStore production guard', () => {
  it('refuses to construct under NODE_ENV=production', () => {
    process.env['NODE_ENV'] = 'production';
    expect(() => new MemoryStore()).toThrow(ConfigurationError);
  });

  it('explains why, and names the alternative', () => {
    process.env['NODE_ENV'] = 'production';
    expect(() => new MemoryStore()).toThrow(/RedisStore|your own NinshoStore/);
  });

  it('has no opt-out flag — the constructor takes no arguments', () => {
    // A `{ allowInProduction: true }` escape hatch would reintroduce exactly
    // the failure mode this guard exists to prevent. A deployment that really
    // wants in-memory state can implement NinshoStore itself, which is
    // explicit and obviously not a test double.
    expect(MemoryStore.length).toBe(0);
  });

  it.each(['development', 'test', 'staging', undefined])(
    'constructs when NODE_ENV is %s',
    (env) => {
      if (env === undefined) delete process.env['NODE_ENV'];
      else process.env['NODE_ENV'] = env;
      expect(() => new MemoryStore()).not.toThrow();
    },
  );
});

describe('MemoryStore lifecycle', () => {
  it('reclaims expired entries on sweep', async () => {
    const store = new MemoryStore();
    await store.set('a', '1', 1);
    await store.set('b', '2', 60);
    expect(store.size()).toBe(2);

    await new Promise((r) => {
      setTimeout(r, 1200);
    });

    expect(store.size()).toBe(1);
    await store.close();
  });

  it('does not keep the process alive with a timer', () => {
    // A setInterval sweep would hold the event loop open after the host
    // application had finished its work — an unpleasant thing to inherit from
    // a library. Eviction is lazy instead.
    const before = process.getActiveResourcesInfo().length;
    const store = new MemoryStore();
    expect(process.getActiveResourcesInfo().length).toBe(before);
    void store.close();
  });

  it('rejects use after close rather than silently returning empty results', async () => {
    const store = new MemoryStore();
    await store.set('k', 'v');
    await store.close();

    // Returning null here would look identical to "revoked" to a caller,
    // turning a programming error into a silent authentication failure.
    await expect(store.get('k')).rejects.toThrow(/closed/);
  });

  it('reports a closed store as not alive', async () => {
    const store = new MemoryStore();
    await expect(store.ping()).resolves.toBe(true);
    await store.close();
    await expect(store.ping()).resolves.toBe(false);
  });

  it('tolerates being closed twice', async () => {
    const store = new MemoryStore();
    await store.close();
    await expect(store.close()).resolves.toBeUndefined();
  });
});
