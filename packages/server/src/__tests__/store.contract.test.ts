import { describe, it, expect, beforeEach, afterAll } from 'vitest';
import { MemoryStore } from '../store/memory.js';
import { RedisStore } from '../store/redis.js';
import type { NinshoStore } from '../store/types.js';

/**
 * One contract suite, executed against every NinshoStore implementation.
 *
 * The point is that the implementations cannot drift apart. `MemoryStore` is
 * what most people will develop against and what the test suite runs on by
 * default; `RedisStore` is what runs in production. If those two disagree
 * about — say — whether a non-positive TTL stores or deletes, then local tests
 * stop predicting production behaviour, which is exactly the kind of gap that
 * hides a revocation bug until it matters.
 *
 * RedisStore participates only when REDIS_URL is set. It is skipped, visibly,
 * otherwise. There is deliberately no mock Redis: substituting a test double
 * for the store is the failure this project was rebuilt to avoid, and a mock
 * that merely resembles Redis would defeat the purpose of a contract suite.
 */

const REDIS_URL = process.env['REDIS_URL'];

interface Candidate {
  readonly name: string;
  readonly create: () => NinshoStore;
}

const candidates: Candidate[] = [{ name: 'MemoryStore', create: () => new MemoryStore() }];

if (REDIS_URL !== undefined && REDIS_URL.length > 0) {
  candidates.push({ name: 'RedisStore', create: () => new RedisStore(REDIS_URL) });
} else {
  describe.skip('RedisStore contract (set REDIS_URL to run)', () => {
    it('is skipped without a live Redis', () => {
      expect(true).toBe(true);
    });
  });
}

/** Unique per run so a shared Redis does not leak state between runs. */
const RUN = `test:${Date.now()}:${Math.random().toString(36).slice(2)}`;
let counter = 0;
const k = (name: string): string => `${RUN}:${(counter += 1)}:${name}`;

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => {
    setTimeout(resolve, ms);
  });

describe.each(candidates)('NinshoStore contract — $name', ({ create }) => {
  let store: NinshoStore;
  const opened: NinshoStore[] = [];

  beforeEach(() => {
    store = create();
    opened.push(store);
  });

  afterAll(async () => {
    await Promise.all(opened.map((s) => s.close()));
  });

  describe('get / set', () => {
    it('round-trips a value', async () => {
      const key = k('roundtrip');
      await store.set(key, 'value-1');
      await expect(store.get(key)).resolves.toBe('value-1');
    });

    it('returns null for an absent key', async () => {
      await expect(store.get(k('absent'))).resolves.toBeNull();
    });

    it('overwrites an existing value', async () => {
      const key = k('overwrite');
      await store.set(key, 'first');
      await store.set(key, 'second');
      await expect(store.get(key)).resolves.toBe('second');
    });

    it('preserves values that look like JSON, and empty strings', async () => {
      const key = k('shapes');
      await store.set(key, '{"a":1}');
      await expect(store.get(key)).resolves.toBe('{"a":1}');
      await store.set(key, '');
      await expect(store.get(key)).resolves.toBe('');
    });
  });

  describe('TTL', () => {
    it('keeps a value alive within its TTL', async () => {
      const key = k('ttl-alive');
      await store.set(key, 'v', 60);
      await expect(store.get(key)).resolves.toBe('v');
    });

    it('expires a value after its TTL', async () => {
      const key = k('ttl-expire');
      await store.set(key, 'v', 1);
      await expect(store.get(key)).resolves.toBe('v');
      await sleep(1200);
      await expect(store.get(key)).resolves.toBeNull();
    });

    /**
     * A revocation entry is written with a TTL equal to the credential's
     * remaining life. That number can arrive as zero or negative when the
     * credential has already expired. Storing it without expiry would leave
     * the key in the store forever; every implementation must delete instead.
     */
    it.each([0, -1, -3600])('treats a TTL of %d as already expired', async (ttl) => {
      const key = k(`ttl-nonpositive-${ttl}`);
      await store.set(key, 'should-not-persist', ttl);
      await expect(store.get(key)).resolves.toBeNull();
      await expect(store.exists(key)).resolves.toBe(false);
    });

    it('does not resurrect a key when a non-positive TTL overwrites a live one', async () => {
      const key = k('ttl-overwrite-expired');
      await store.set(key, 'live', 60);
      await store.set(key, 'dead', -1);
      await expect(store.get(key)).resolves.toBeNull();
    });
  });

  describe('exists', () => {
    it('reports presence and absence', async () => {
      const key = k('exists');
      await expect(store.exists(key)).resolves.toBe(false);
      await store.set(key, 'v');
      await expect(store.exists(key)).resolves.toBe(true);
    });

    it('reports false once expired', async () => {
      const key = k('exists-expired');
      await store.set(key, 'v', 1);
      await sleep(1200);
      await expect(store.exists(key)).resolves.toBe(false);
    });
  });

  describe('delete', () => {
    it('removes a key', async () => {
      const key = k('delete');
      await store.set(key, 'v');
      await store.delete(key);
      await expect(store.get(key)).resolves.toBeNull();
    });

    it('removes several keys at once', async () => {
      const a = k('del-a');
      const b = k('del-b');
      await store.set(a, '1');
      await store.set(b, '2');
      await store.delete(a, b);
      await expect(store.get(a)).resolves.toBeNull();
      await expect(store.get(b)).resolves.toBeNull();
    });

    it('ignores absent keys and an empty argument list', async () => {
      await expect(store.delete(k('never-existed'))).resolves.toBeUndefined();
      await expect(store.delete()).resolves.toBeUndefined();
    });
  });

  describe('setIfAbsent', () => {
    it('stores and reports true when the key is free', async () => {
      const key = k('sia-free');
      await expect(store.setIfAbsent(key, 'first', 60)).resolves.toBe(true);
      await expect(store.get(key)).resolves.toBe('first');
    });

    it('reports false and leaves the existing value alone', async () => {
      const key = k('sia-taken');
      await store.setIfAbsent(key, 'first', 60);
      await expect(store.setIfAbsent(key, 'second', 60)).resolves.toBe(false);
      await expect(store.get(key)).resolves.toBe('first');
    });

    /**
     * The atomicity that matters: exactly one concurrent caller may win.
     * This is the primitive that keeps refresh-token rotation from issuing
     * two replacements for one presented token.
     */
    it('lets exactly one of many concurrent callers win', async () => {
      const key = k('sia-race');
      const results = await Promise.all(
        Array.from({ length: 25 }, (_, i) => store.setIfAbsent(key, `writer-${i}`, 60)),
      );
      expect(results.filter(Boolean)).toHaveLength(1);

      const stored = await store.get(key);
      const winnerIndex = results.indexOf(true);
      expect(stored).toBe(`writer-${winnerIndex}`);
    });

    it('succeeds again once the key has expired', async () => {
      const key = k('sia-after-expiry');
      await store.setIfAbsent(key, 'first', 1);
      await sleep(1200);
      await expect(store.setIfAbsent(key, 'second', 60)).resolves.toBe(true);
    });

    it('refuses a non-positive TTL rather than storing without expiry', async () => {
      const key = k('sia-nonpositive');
      await expect(store.setIfAbsent(key, 'v', 0)).resolves.toBe(false);
      await expect(store.exists(key)).resolves.toBe(false);
    });
  });

  describe('take', () => {
    it('returns the value and removes the key', async () => {
      const key = k('take');
      await store.set(key, 'once');
      await expect(store.take(key)).resolves.toBe('once');
      await expect(store.get(key)).resolves.toBeNull();
    });

    it('returns null for an absent key', async () => {
      await expect(store.take(k('take-absent'))).resolves.toBeNull();
    });

    /**
     * Single-use consumption must be race-free: of many concurrent takers,
     * exactly one may observe the value. A GET-then-DEL implementation fails
     * this, which is why the contract requires an atomic operation.
     */
    it('yields the value to exactly one of many concurrent takers', async () => {
      const key = k('take-race');
      await store.set(key, 'single-use');

      const results = await Promise.all(
        Array.from({ length: 25 }, () => store.take(key)),
      );
      expect(results.filter((r) => r === 'single-use')).toHaveLength(1);
      expect(results.filter((r) => r === null)).toHaveLength(24);
    });
  });

  describe('increment', () => {
    it('starts at 1 and counts up', async () => {
      const key = k('incr');
      await expect(store.increment(key, 60)).resolves.toBe(1);
      await expect(store.increment(key, 60)).resolves.toBe(2);
      await expect(store.increment(key, 60)).resolves.toBe(3);
    });

    it('keeps counters independent', async () => {
      const a = k('incr-a');
      const b = k('incr-b');
      await store.increment(a, 60);
      await store.increment(a, 60);
      await expect(store.increment(b, 60)).resolves.toBe(1);
    });

    /**
     * The property a rate limit depends on. Without atomicity, concurrent
     * requests receive duplicate counts and the limit becomes a suggestion
     * under exactly the load it exists to control.
     */
    it('gives every concurrent caller a distinct value', async () => {
      const key = k('incr-race');
      const results = await Promise.all(
        Array.from({ length: 50 }, () => store.increment(key, 60)),
      );
      expect(new Set(results).size).toBe(50);
      expect(Math.max(...results)).toBe(50);
    });

    it('expires the counter after its TTL', async () => {
      const key = k('incr-ttl');
      await store.increment(key, 1);
      await store.increment(key, 1);
      await sleep(1200);
      await expect(store.increment(key, 60)).resolves.toBe(1);
    });

    it('refuses a non-positive TTL rather than storing a counter forever', async () => {
      const key = k('incr-nonpositive');
      await expect(store.increment(key, 0)).resolves.toBe(0);
      await expect(store.exists(key)).resolves.toBe(false);
    });

    it('is readable through get, so a previous window can be weighted', async () => {
      const key = k('incr-read');
      await store.increment(key, 60);
      await store.increment(key, 60);
      await expect(store.get(key)).resolves.toBe('2');
    });
  });

  describe('sets', () => {
    it('adds and lists members', async () => {
      const key = k('set-add');
      await store.sAdd(key, 'a', 60);
      await store.sAdd(key, 'b', 60);
      const members = await store.sMembers(key);
      expect([...members].sort()).toEqual(['a', 'b']);
    });

    it('treats members as a set, not a list', async () => {
      const key = k('set-dupe');
      await store.sAdd(key, 'a', 60);
      await store.sAdd(key, 'a', 60);
      await expect(store.sMembers(key)).resolves.toHaveLength(1);
    });

    it('returns an empty array for an absent set', async () => {
      await expect(store.sMembers(k('set-absent'))).resolves.toEqual([]);
    });

    it('removes members', async () => {
      const key = k('set-remove');
      await store.sAdd(key, 'a', 60);
      await store.sAdd(key, 'b', 60);
      await store.sRemove(key, 'a');
      await expect(store.sMembers(key)).resolves.toEqual(['b']);
    });

    it('removes several members at once and ignores unknown ones', async () => {
      const key = k('set-remove-many');
      await store.sAdd(key, 'a', 60);
      await store.sAdd(key, 'b', 60);
      await store.sAdd(key, 'c', 60);
      await store.sRemove(key, 'a', 'b', 'not-a-member');
      await expect(store.sMembers(key)).resolves.toEqual(['c']);
    });

    it('ignores an empty removal list', async () => {
      const key = k('set-remove-none');
      await store.sAdd(key, 'a', 60);
      await expect(store.sRemove(key)).resolves.toBeUndefined();
      await expect(store.sMembers(key)).resolves.toEqual(['a']);
    });

    it('reports an emptied set as empty', async () => {
      const key = k('set-emptied');
      await store.sAdd(key, 'only', 60);
      await store.sRemove(key, 'only');
      await expect(store.sMembers(key)).resolves.toEqual([]);
    });

    it('expires the whole set after its TTL', async () => {
      const key = k('set-ttl');
      await store.sAdd(key, 'a', 1);
      await expect(store.sMembers(key)).resolves.toEqual(['a']);
      await sleep(1200);
      await expect(store.sMembers(key)).resolves.toEqual([]);
    });

    /**
     * An access token's hash is added to its session's set on every issue. If
     * adding did not refresh the set's expiry, a long-lived session would lose
     * its index partway through and `revokeSession` would silently miss
     * tokens — a revocation that reports success while leaving tokens live.
     */
    it('extends the set TTL on each add, so an active set does not expire early', async () => {
      const key = k('set-ttl-refresh');
      await store.sAdd(key, 'first', 1);
      await sleep(600);
      await store.sAdd(key, 'second', 5);
      await sleep(700);

      const members = await store.sMembers(key);
      expect([...members].sort()).toEqual(['first', 'second']);
    });

    it('deletes a set through delete()', async () => {
      const key = k('set-delete');
      await store.sAdd(key, 'a', 60);
      await store.delete(key);
      await expect(store.sMembers(key)).resolves.toEqual([]);
    });
  });

  describe('ping', () => {
    it('reports a live store', async () => {
      await expect(store.ping()).resolves.toBe(true);
    });
  });

  describe('key isolation', () => {
    it('keeps distinct keys independent', async () => {
      const a = k('iso-a');
      const b = k('iso-b');
      await store.set(a, 'value-a');
      await store.set(b, 'value-b');
      await store.delete(a);
      await expect(store.get(b)).resolves.toBe('value-b');
    });

    it('treats value and set namespaces as one keyspace, as Redis does', async () => {
      // Documenting shared-keyspace semantics: callers must not reuse a key
      // for both a value and a set. KEYS in keys.ts gives each its own prefix.
      const key = k('iso-mixed');
      await store.set(key, 'a-value');
      await expect(store.get(key)).resolves.toBe('a-value');
    });
  });
});
