import { describe, it, expect, vi, afterEach } from 'vitest';
import { MemoryStore } from '@ninsho/server';
import {
  ChallengeConfigurationError,
  ChallengeError,
  ChallengeManager,
  type ChallengeStore,
} from './challenge.js';

/**
 * A store that records calls and can be told to misbehave.
 *
 * MemoryStore covers the honest case; this covers the cases a correct store
 * never produces, which are exactly the ones the defensive checks exist for.
 */
class FakeStore implements ChallengeStore {
  readonly entries = new Map<string, string>();
  takeCalls: string[] = [];
  /** When set, `take` returns this instead of what was stored. */
  forcedTakeResult: string | null | undefined;
  /** When true, `setIfAbsent` reports the key already existed. */
  reportCollision = false;
  /** When true, expiry is ignored — a store that does not honour TTLs. */
  ignoreTtl = false;

  async setIfAbsent(key: string, value: string): Promise<boolean> {
    if (this.reportCollision) return false;
    if (this.entries.has(key)) return false;
    this.entries.set(key, value);
    return true;
  }

  async take(key: string): Promise<string | null> {
    this.takeCalls.push(key);
    // The delete happens on the forced path too: a fake that returns a value
    // without consuming it is not modelling `take`, and a test resting on that
    // difference would be testing the fake.
    if (!this.ignoreTtl) this.entries.delete(key);
    if (this.forcedTakeResult !== undefined) return this.forcedTakeResult;
    return this.entries.get(key) ?? null;
  }

  /** Replaces every stored record, leaving the keys intact. */
  corrupt(value: string): void {
    for (const key of this.entries.keys()) this.entries.set(key, value);
  }
}

/**
 * Captures a rejection so the assertion can look at `detail`.
 *
 * `message` is a fixed constant by design — the reason a challenge failed
 * lives in `detail`, which never reaches a client. Asserting on `message`
 * would test the wrong field and pass for the wrong reason.
 */
async function rejection(promise: Promise<unknown>): Promise<ChallengeError> {
  try {
    await promise;
  } catch (error) {
    return error as ChallengeError;
  }
  throw new Error('expected the promise to reject');
}

afterEach(() => {
  vi.useRealTimers();
});

describe('issuing', () => {
  it('produces an unpredictable base64url challenge', async () => {
    const manager = new ChallengeManager(new MemoryStore());
    const seen = new Set<string>();

    for (let i = 0; i < 200; i += 1) {
      const { challenge } = await manager.issue('registration', 'user-1');
      expect(challenge).toMatch(/^[A-Za-z0-9_-]+$/);
      // 32 bytes of base64url is 43 characters with no padding.
      expect(challenge).toHaveLength(43);
      expect(seen.has(challenge)).toBe(false);
      seen.add(challenge);
    }
  });

  it('honours a configured challenge size', async () => {
    const manager = new ChallengeManager(new MemoryStore(), { challengeBytes: 64 });
    const { challenge } = await manager.issue('authentication');
    expect(Buffer.from(challenge, 'base64url')).toHaveLength(64);
  });

  it('records the expiry it promised', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));

    const manager = new ChallengeManager(new MemoryStore(), { ttlSeconds: 120 });
    const issued = await manager.issue('registration', 'user-1');
    expect(issued.expiresAt).toBe('2026-01-01T00:02:00.000Z');
  });

  it('carries the user id through to consumption', async () => {
    const manager = new ChallengeManager(new MemoryStore());
    const { challenge } = await manager.issue('registration', 'user-42');
    const context = await manager.consume('registration', challenge);

    expect(context.userId).toBe('user-42');
    expect(context.type).toBe('registration');
  });

  it('allows a challenge with no user, for usernameless sign-in', async () => {
    // A discoverable-credential flow does not know who is signing in until the
    // authenticator answers.
    const manager = new ChallengeManager(new MemoryStore());
    const { challenge } = await manager.issue('authentication');
    const context = await manager.consume('authentication', challenge);
    // Serialising drops an undefined field, so the key is absent on read
    // rather than present-and-undefined.
    expect(context.userId).toBeUndefined();
    expect(context.type).toBe('authentication');
  });

  it('refuses to reuse a value the store says already exists', async () => {
    // Only reachable if the random source has failed, in which case carrying
    // on is the worst available option.
    const store = new FakeStore();
    store.reportCollision = true;
    const manager = new ChallengeManager(store);

    await expect(manager.issue('registration', 'u')).rejects.toThrow(/random source is suspect/);
  });
});

describe('single use', () => {
  it('accepts a challenge once', async () => {
    const manager = new ChallengeManager(new MemoryStore());
    const { challenge } = await manager.issue('authentication', 'user-1');

    await expect(manager.consume('authentication', challenge)).resolves.toBeTruthy();
    await expect(manager.consume('authentication', challenge)).rejects.toThrow(ChallengeError);
  });

  it('lets exactly one of many concurrent attempts win', async () => {
    // The property that makes replay impossible rather than merely unlikely.
    // A read-then-delete implementation passes the sequential test above and
    // fails this one.
    const manager = new ChallengeManager(new MemoryStore());
    const { challenge } = await manager.issue('authentication', 'user-1');

    const results = await Promise.allSettled(
      Array.from({ length: 32 }, () => manager.consume('authentication', challenge)),
    );

    const fulfilled = results.filter((r) => r.status === 'fulfilled');
    expect(fulfilled).toHaveLength(1);
    expect(results.filter((r) => r.status === 'rejected')).toHaveLength(31);
  });

  it('consumes the challenge even when validation then fails', async () => {
    // Otherwise a malformed record would leave a live challenge behind for a
    // second attempt — a retry loop that never runs out of tries.
    const store = new FakeStore();
    const manager = new ChallengeManager(store);
    const { challenge } = await manager.issue('registration', 'u');

    // Corrupt the record in place rather than forcing the return value, so
    // `take` still behaves like `take` and the deletion is the real one.
    store.corrupt('not json');
    await expect(manager.consume('registration', challenge)).rejects.toThrow(ChallengeError);

    // Gone: take() ran before the JSON parse, so a bad record leaves no live
    // challenge behind for a second attempt.
    expect(store.entries.size).toBe(0);
    expect((await rejection(manager.consume('registration', challenge))).detail).toMatch(
      /not found/,
    );
  });
});

describe('ceremony scoping', () => {
  it('will not consume a registration challenge as an authentication one', async () => {
    // The separation is structural: the ceremony type is part of the key, so
    // the challenge is not merely rejected, it is not there.
    const manager = new ChallengeManager(new MemoryStore());
    const { challenge } = await manager.issue('registration', 'user-1');

    await expect(manager.consume('authentication', challenge)).rejects.toThrow(ChallengeError);
    // And it is still available for its own ceremony — the failed attempt
    // consumed nothing.
    await expect(manager.consume('registration', challenge)).resolves.toBeTruthy();
  });

  it('will not consume an authentication challenge as a registration one', async () => {
    const manager = new ChallengeManager(new MemoryStore());
    const { challenge } = await manager.issue('authentication', 'user-1');

    await expect(manager.consume('registration', challenge)).rejects.toThrow(ChallengeError);
    await expect(manager.consume('authentication', challenge)).resolves.toBeTruthy();
  });

  it('puts the ceremony type in the storage key', async () => {
    const store = new FakeStore();
    const manager = new ChallengeManager(store);
    const { challenge } = await manager.issue('registration', 'u');

    await manager.consume('registration', challenge).catch(() => undefined);
    expect(store.takeCalls[0]).toContain(':registration:');
  });

  it('still refuses a type mismatch if the key ever stops carrying the type', async () => {
    // The redundant field check. It cannot fire today; it exists so that a
    // future refactor moving the type out of the key does not silently remove
    // the separation.
    const store = new FakeStore();
    const manager = new ChallengeManager(store);
    const { challenge } = await manager.issue('authentication', 'u');

    store.forcedTakeResult = JSON.stringify({
      type: 'registration',
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });

    expect((await rejection(manager.consume('authentication', challenge))).detail).toMatch(
      /issued for registration/,
    );
  });
});

describe('expiry', () => {
  it('refuses a challenge past its lifetime', async () => {
    vi.useFakeTimers();
    const manager = new ChallengeManager(new MemoryStore(), { ttlSeconds: 60 });
    const { challenge } = await manager.issue('authentication', 'u');

    vi.advanceTimersByTime(61_000);
    await expect(manager.consume('authentication', challenge)).rejects.toThrow(ChallengeError);
  });

  it('accepts a challenge just inside its lifetime', async () => {
    vi.useFakeTimers();
    const manager = new ChallengeManager(new MemoryStore(), { ttlSeconds: 60 });
    const { challenge } = await manager.issue('authentication', 'u');

    vi.advanceTimersByTime(59_000);
    await expect(manager.consume('authentication', challenge)).resolves.toBeTruthy();
  });

  it('refuses an expired challenge even from a store that ignores TTLs', async () => {
    // Defence in depth: the guarantee rests on the recorded timestamp, not on
    // a backend expiring things promptly.
    vi.useFakeTimers();
    const store = new FakeStore();
    store.ignoreTtl = true;
    const manager = new ChallengeManager(store, { ttlSeconds: 60 });
    const { challenge } = await manager.issue('authentication', 'u');

    vi.advanceTimersByTime(120_000);
    expect((await rejection(manager.consume('authentication', challenge))).detail).toMatch(
      /had expired/,
    );
  });

  it.each([
    ['a missing expiry', { type: 'authentication', issuedAt: 'x' }],
    ['an unparseable expiry', { type: 'authentication', expiresAt: 'not a date' }],
    ['a numeric expiry', { type: 'authentication', expiresAt: 12345 }],
  ])('fails closed on %s', async (_label, record) => {
    // A timestamp that cannot be read is not evidence that a challenge is
    // live.
    const store = new FakeStore();
    const manager = new ChallengeManager(store);
    const { challenge } = await manager.issue('authentication', 'u');

    store.forcedTakeResult = JSON.stringify(record);
    expect((await rejection(manager.consume('authentication', challenge))).detail).toMatch(
      /expired/,
    );
  });
});

describe('hostile input', () => {
  it.each([
    ['an empty string', ''],
    ['a challenge that was never issued', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
    ['a near-miss of a real challenge', 'x'],
  ])('refuses %s', async (_label, value) => {
    const manager = new ChallengeManager(new MemoryStore());
    await expect(manager.consume('authentication', value)).rejects.toThrow(ChallengeError);
  });

  it('refuses an implausibly long challenge before hashing it', async () => {
    const manager = new ChallengeManager(new MemoryStore());
    expect((await rejection(manager.consume('authentication', 'a'.repeat(513)))).detail).toMatch(
      /implausible/,
    );
  });

  it('never lets a caller-supplied string reach the store unhashed', async () => {
    // Keeps the keyspace free of caller-controlled bytes and bounds the key
    // length whatever arrives.
    const store = new FakeStore();
    const manager = new ChallengeManager(store);

    await manager.consume('authentication', 'injected:key:parts').catch(() => undefined);
    expect(store.takeCalls[0]).not.toContain('injected');
  });

  it('rejects a truncated or mutated challenge', async () => {
    const manager = new ChallengeManager(new MemoryStore());
    const { challenge } = await manager.issue('authentication', 'u');

    await expect(manager.consume('authentication', challenge.slice(0, -1))).rejects.toThrow(
      ChallengeError,
    );
    const mutated = `${challenge.slice(0, -1)}${challenge.endsWith('A') ? 'B' : 'A'}`;
    await expect(manager.consume('authentication', mutated)).rejects.toThrow(ChallengeError);
    // The real one still works — the failed attempts consumed nothing.
    await expect(manager.consume('authentication', challenge)).resolves.toBeTruthy();
  });

  it('reports every failure as a ChallengeError carrying a 400', async () => {
    const manager = new ChallengeManager(new MemoryStore());
    try {
      await manager.consume('authentication', 'nope');
      expect.unreachable('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(ChallengeError);
      expect((error as ChallengeError).status).toBe(400);
      expect((error as ChallengeError).code).toBe('WEBAUTHN_CHALLENGE_INVALID');
    }
  });

  it('never puts the reason in the client-facing body', async () => {
    // The distinction between "expired", "already used" and "never issued" is
    // three different hints to an attacker and the same answer to a client.
    const manager = new ChallengeManager(new MemoryStore());
    const { challenge } = await manager.issue('authentication', 'u');
    await manager.consume('authentication', challenge);

    const bodies: string[] = [];
    for (const value of [challenge, 'never-issued']) {
      await manager.consume('authentication', value).catch((error: ChallengeError) => {
        bodies.push(JSON.stringify(error.toResponse()));
      });
    }

    expect(bodies).toHaveLength(2);
    expect(bodies[0]).toBe(bodies[1]);
    expect(bodies[0]).not.toMatch(/expired|consumed|found/i);
  });
});

describe('configuration', () => {
  it.each([
    ['zero', 0],
    ['negative', -1],
    ['fractional', 1.5],
    ['beyond an hour', 3601],
  ])('refuses a %s ttl', (_label, ttlSeconds) => {
    expect(() => new ChallengeManager(new MemoryStore(), { ttlSeconds })).toThrow(
      ChallengeConfigurationError,
    );
  });

  it('refuses fewer than 16 random bytes', () => {
    // WebAuthn §13.4.3 sets the floor at 16.
    expect(() => new ChallengeManager(new MemoryStore(), { challengeBytes: 15 })).toThrow(
      /at least 16/,
    );
  });

  it('accepts the spec minimum', () => {
    expect(() => new ChallengeManager(new MemoryStore(), { challengeBytes: 16 })).not.toThrow();
  });

  it('fails at construction rather than at first use', () => {
    // A misconfiguration that only surfaces under load is one that reaches
    // production.
    expect(() => new ChallengeManager(new MemoryStore(), { ttlSeconds: 0 })).toThrow();
  });

  it('isolates deployments that share a store', async () => {
    const store = new MemoryStore();
    const a = new ChallengeManager(store, { keyPrefix: 'app-a' });
    const b = new ChallengeManager(store, { keyPrefix: 'app-b' });

    const { challenge } = await a.issue('authentication', 'u');
    await expect(b.consume('authentication', challenge)).rejects.toThrow(ChallengeError);
    await expect(a.consume('authentication', challenge)).resolves.toBeTruthy();
  });
});

describe('store compatibility', () => {
  it('works with NinshoStore from @ninsho/server without an adapter', async () => {
    // The structural-typing claim, as a test rather than an assertion in a
    // comment: MemoryStore is a NinshoStore, and it is passed here with no
    // wrapper at all.
    const store: ChallengeStore = new MemoryStore();
    const manager = new ChallengeManager(store);

    const { challenge } = await manager.issue('registration', 'user-1');
    await expect(manager.consume('registration', challenge)).resolves.toMatchObject({
      userId: 'user-1',
      type: 'registration',
    });
  });
});
