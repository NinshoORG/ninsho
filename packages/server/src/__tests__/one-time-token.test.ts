import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { hashToken } from '@ninsho/core';
import { MemoryStore } from '../store/memory.js';
import { MemoryAuditSink } from '../audit.js';
import {
  OneTimeTokenConfigurationError,
  OneTimeTokenError,
  OneTimeTokenManager,
} from '../tokens/one-time.js';
import { KEYS } from '../keys.js';

/**
 * Single-use tokens.
 *
 * ─── What these tests are really checking ─────────────────────────────────
 * Every way of botching a password reset is a full account takeover, so each
 * group below corresponds to one of them: a token stored in plaintext, a token
 * that works twice, a token that outlives its usefulness, a reset token
 * accepted by a weaker flow, and an old link that keeps working after a new
 * one was requested.
 *
 * The point is not that the happy path works. It is that each of those routes
 * is closed by construction rather than by remembering to close it.
 * ──────────────────────────────────────────────────────────────────────────
 */

let store: MemoryStore;
let audit: MemoryAuditSink;
let tokens: OneTimeTokenManager;

beforeEach(() => {
  store = new MemoryStore();
  audit = new MemoryAuditSink();
  tokens = new OneTimeTokenManager({ store, audit });
});

afterEach(async () => {
  vi.useRealTimers();
  await store.close();
});

const reset = (subject = 'user_alice') =>
  tokens.issue({ purpose: 'password-reset', subject });

describe('the happy path', () => {
  it('issues a token and returns the subject on consumption', async () => {
    const issued = await reset();
    const claim = await tokens.consume('password-reset', issued.token);

    expect(claim.subject).toBe('user_alice');
    expect(claim.purpose).toBe('password-reset');
  });

  it('produces an unguessable, URL-safe token', async () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i += 1) {
      const { token } = await tokens.issue({ purpose: 'p', subject: `u${i}` });
      // 32 bytes of base64url is 43 characters, and safe in a query string
      // without escaping.
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(seen.has(token)).toBe(false);
      seen.add(token);
    }
  });

  it('carries metadata through to consumption', async () => {
    // The shape a change-email flow needs: the new address is decided when the
    // link is sent, not when it is clicked.
    const issued = await tokens.issue({
      purpose: 'email-change',
      subject: 'user_alice',
      metadata: { newEmail: 'ada@example.test' },
    });

    const claim = await tokens.consume('email-change', issued.token);
    expect(claim.metadata['newEmail']).toBe('ada@example.test');
  });

  it('records the issue and the redemption as audit events', async () => {
    // A spike of these aimed at one account is a takeover attempt, and a spike
    // across many is email flooding — neither is visible without the events.
    const issued = await reset();
    await tokens.consume('password-reset', issued.token);

    expect(audit.events.map((e) => e.type)).toEqual(
      expect.arrayContaining(['onetime.issued', 'onetime.consumed']),
    );
  });
});

/** A database read must not be an account takeover. */
describe('the raw token never reaches the store', () => {
  it('stores the hash, not the value', async () => {
    const issued = await reset();

    // The record exists under the hash…
    const record = await store.get(KEYS.oneTimeToken('password-reset', hashToken(issued.token)));
    expect(record).not.toBeNull();

    // …and the raw value appears nowhere in the store at all.
    const key = KEYS.oneTimeToken('password-reset', issued.token);
    expect(await store.get(key)).toBeNull();
    expect(record).not.toContain(issued.token);
  });

  it('keeps the raw token out of the generation counter too', async () => {
    // The counter holds a number and nothing else — there is no per-subject
    // index of token hashes any more, and so nothing to leak from one.
    await reset();
    const counter = await store.get(KEYS.oneTimeTokenGeneration('password-reset', 'user_alice'));

    expect(counter).toMatch(/^\d+$/);
  });
});

/** A forwarded email must not be an account takeover. */
describe('single use', () => {
  it('accepts a token exactly once', async () => {
    const issued = await reset();

    await expect(tokens.consume('password-reset', issued.token)).resolves.toBeTruthy();
    await expect(tokens.consume('password-reset', issued.token)).rejects.toBeInstanceOf(
      OneTimeTokenError,
    );
  });

  it('lets exactly one of many simultaneous clicks win', async () => {
    // Two people opening the same link at the same moment. A read-then-delete
    // implementation passes the sequential test above and fails this one.
    const issued = await reset();

    const results = await Promise.allSettled(
      Array.from({ length: 24 }, () => tokens.consume('password-reset', issued.token)),
    );

    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
  });

  it('consumes the token even when validation then fails', async () => {
    // Otherwise a malformed record leaves a live token behind, and the retry
    // loop never runs out of attempts.
    const issued = await reset();
    await store.set(
      KEYS.oneTimeToken('password-reset', hashToken(issued.token)),
      'not json',
      900,
    );

    await expect(tokens.consume('password-reset', issued.token)).rejects.toBeInstanceOf(
      OneTimeTokenError,
    );
    // Gone: `take` ran before the parse.
    await expect(tokens.consume('password-reset', issued.token)).rejects.toBeInstanceOf(
      OneTimeTokenError,
    );
    expect(
      await store.get(KEYS.oneTimeToken('password-reset', hashToken(issued.token))),
    ).toBeNull();
  });
});

/** An old inbox must not be an account takeover. */
describe('expiry', () => {
  it('refuses a token past its lifetime', async () => {
    vi.useFakeTimers();
    const issued = await tokens.issue({ purpose: 'p', subject: 'u', ttlSeconds: 60 });

    vi.advanceTimersByTime(61_000);
    await expect(tokens.consume('p', issued.token)).rejects.toBeInstanceOf(OneTimeTokenError);
  });

  it('accepts one just inside its lifetime', async () => {
    vi.useFakeTimers();
    const issued = await tokens.issue({ purpose: 'p', subject: 'u', ttlSeconds: 60 });

    vi.advanceTimersByTime(59_000);
    await expect(tokens.consume('p', issued.token)).resolves.toBeTruthy();
  });

  it('defaults to fifteen minutes', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));

    const issued = await reset();
    expect(issued.expiresAt).toBe('2026-01-01T00:15:00.000Z');
  });

  it('refuses an expired record even from a store that ignores TTLs', async () => {
    // Defence in depth: the guarantee rests on the recorded timestamp, not on
    // a backend expiring things promptly.
    const issued = await reset();
    const key = KEYS.oneTimeToken('password-reset', hashToken(issued.token));
    const record = JSON.parse((await store.get(key)) as string) as Record<string, unknown>;

    await store.set(
      key,
      JSON.stringify({ ...record, expiresAt: new Date(Date.now() - 1000).toISOString() }),
      900,
    );

    await expect(tokens.consume('password-reset', issued.token)).rejects.toBeInstanceOf(
      OneTimeTokenError,
    );
  });

  it.each([
    ['a missing expiry', { purpose: 'password-reset', subject: 'u' }],
    ['an unparseable expiry', { purpose: 'password-reset', subject: 'u', expiresAt: 'soon' }],
    ['a missing subject', { purpose: 'password-reset', expiresAt: '2099-01-01T00:00:00.000Z' }],
  ])('fails closed on %s', async (_label, record) => {
    const issued = await reset();
    await store.set(
      KEYS.oneTimeToken('password-reset', hashToken(issued.token)),
      JSON.stringify(record),
      900,
    );

    await expect(tokens.consume('password-reset', issued.token)).rejects.toBeInstanceOf(
      OneTimeTokenError,
    );
  });
});

/** A weaker flow must not become an entry point to a stronger one. */
describe('purpose scoping', () => {
  it('will not accept a reset token at a verification endpoint', async () => {
    const issued = await tokens.issue({ purpose: 'password-reset', subject: 'u' });

    await expect(tokens.consume('email-verification', issued.token)).rejects.toBeInstanceOf(
      OneTimeTokenError,
    );
    // And the token is untouched — the failed attempt consumed nothing.
    await expect(tokens.consume('password-reset', issued.token)).resolves.toBeTruthy();
  });

  it('puts the purpose in the storage key', async () => {
    // Structural, not a comparison: a token for another purpose is not
    // rejected, it is simply absent. A check can be forgotten in a refactor; a
    // key that does not exist cannot be.
    const issued = await reset();
    expect(
      await store.get(KEYS.oneTimeToken('password-reset', hashToken(issued.token))),
    ).not.toBeNull();
    expect(
      await store.get(KEYS.oneTimeToken('email-verification', hashToken(issued.token))),
    ).toBeNull();
  });

  it('keeps two purposes for the same subject independent', async () => {
    const a = await tokens.issue({ purpose: 'password-reset', subject: 'u' });
    const b = await tokens.issue({ purpose: 'email-verification', subject: 'u' });

    await expect(tokens.consume('password-reset', a.token)).resolves.toBeTruthy();
    // Issuing the second must not have disturbed the first, and vice versa.
    await expect(tokens.consume('email-verification', b.token)).resolves.toBeTruthy();
  });
});

/** An old link must stop working once a new one is requested. */
describe('invalidating previous tokens', () => {
  it('kills the earlier token when a new one is issued', async () => {
    const first = await reset();
    const second = await reset();

    await expect(tokens.consume('password-reset', first.token)).rejects.toBeInstanceOf(
      OneTimeTokenError,
    );
    await expect(tokens.consume('password-reset', second.token)).resolves.toBeTruthy();
  });

  it('leaves exactly one token valid when two issues race', async () => {
    // REGRESSION (found by adversarial review)
    // Invalidation used to sweep a per-subject index: two concurrent issues
    // each read the index before the other wrote, so neither saw the other's
    // token and *both* stayed valid — 80 of 80 across 40 measured races. The
    // documented guarantee simply did not hold under concurrency.
    //
    // An atomic counter fixes it: the two issues receive distinct generations
    // and the older token no longer matches.
    for (let round = 0; round < 25; round += 1) {
      const store2 = new MemoryStore();
      const isolated = new OneTimeTokenManager({ store: store2, audit });

      const pair = await Promise.all([
        isolated.issue({ purpose: 'password-reset', subject: 'u' }),
        isolated.issue({ purpose: 'password-reset', subject: 'u' }),
      ]);

      const results = await Promise.allSettled(
        pair.map((one) => isolated.consume('password-reset', one.token)),
      );
      expect(
        results.filter((r) => r.status === 'fulfilled'),
        `round ${round}: both tokens survived the race`,
      ).toHaveLength(1);

      await store2.close();
    }
  });

  it('leaves other subjects alone', async () => {
    const alice = await reset('user_alice');
    await reset('user_bob');

    await expect(tokens.consume('password-reset', alice.token)).resolves.toBeTruthy();
  });

  it('can be turned off when a flow genuinely needs several outstanding', async () => {
    const many = new OneTimeTokenManager({ store, audit }, { invalidatePrevious: false });
    const first = await many.issue({ purpose: 'invite', subject: 'u' });
    const second = await many.issue({ purpose: 'invite', subject: 'u' });

    await expect(many.consume('invite', first.token)).resolves.toBeTruthy();
    await expect(many.consume('invite', second.token)).resolves.toBeTruthy();
  });

  it('revokes every outstanding token on request', async () => {
    const many = new OneTimeTokenManager({ store, audit }, { invalidatePrevious: false });
    const issued = await Promise.all(
      Array.from({ length: 5 }, () => many.issue({ purpose: 'invite', subject: 'u' })),
    );

    await many.revokeAllFor('invite', 'u');
    for (const one of issued) {
      await expect(many.consume('invite', one.token)).rejects.toBeInstanceOf(OneTimeTokenError);
    }
  });

  it('is a no-op for a subject with nothing outstanding', async () => {
    await expect(tokens.revokeAllFor('password-reset', 'nobody')).resolves.toBeUndefined();
  });
});

describe('hostile input', () => {
  it.each([
    ['an empty string', ''],
    ['a token that was never issued', 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
    ['a near miss', 'x'],
  ])('refuses %s', async (_label, value) => {
    await expect(tokens.consume('password-reset', value)).rejects.toBeInstanceOf(
      OneTimeTokenError,
    );
  });

  it('refuses an implausibly long token before hashing it', async () => {
    await expect(tokens.consume('password-reset', 'a'.repeat(513))).rejects.toBeInstanceOf(
      OneTimeTokenError,
    );
  });

  it('rejects a truncated or mutated token, leaving the real one usable', async () => {
    const issued = await reset();

    await expect(
      tokens.consume('password-reset', issued.token.slice(0, -1)),
    ).rejects.toBeInstanceOf(OneTimeTokenError);
    await expect(tokens.consume('password-reset', issued.token)).resolves.toBeTruthy();
  });

  it.each([
    ['an empty purpose', ''],
    ['a purpose with a separator', 'password:reset'],
    ['a purpose with a wildcard', 'reset*'],
    ['a purpose with whitespace', 'password reset'],
  ])('refuses %s', async (_label, purpose) => {
    // The purpose becomes part of a store key; a separator in it could make
    // two different purposes collide.
    await expect(tokens.issue({ purpose, subject: 'u' })).rejects.toBeInstanceOf(
      OneTimeTokenConfigurationError,
    );
  });

  it('refuses an empty subject', async () => {
    await expect(
      tokens.issue({ purpose: 'password-reset', subject: '' }),
    ).rejects.toBeInstanceOf(OneTimeTokenConfigurationError);
  });
});

describe('the client-facing error', () => {
  it('says the same thing whatever went wrong', async () => {
    // "Expired", "already used" and "never existed" are three hints to an
    // attacker probing which reset links were real, and one answer to a user.
    const used = await reset();
    await tokens.consume('password-reset', used.token);

    const bodies: string[] = [];
    for (const value of [used.token, 'never-issued']) {
      await tokens.consume('password-reset', value).catch((error: OneTimeTokenError) => {
        bodies.push(JSON.stringify(error.toResponse()));
      });
    }

    expect(bodies).toHaveLength(2);
    expect(bodies[0]).toBe(bodies[1]);
    expect(bodies[0]).not.toMatch(/expired|used|found/i);
  });

  it('carries a 400 and a stable code', async () => {
    try {
      await tokens.consume('password-reset', 'nope');
      expect.unreachable('should have thrown');
    } catch (error) {
      expect((error as OneTimeTokenError).status).toBe(400);
      expect((error as OneTimeTokenError).code).toBe('ONE_TIME_TOKEN_INVALID');
    }
  });

  it('keeps the reason server-side', async () => {
    const error = await tokens
      .consume('password-reset', 'nope')
      .catch((e: OneTimeTokenError) => e);

    expect((error as OneTimeTokenError).detail).toMatch(/not found/);
  });
});

describe('configuration', () => {
  it.each([
    ['zero', 0],
    ['negative', -1],
    ['fractional', 1.5],
    ['beyond a week', 60 * 60 * 24 * 7 + 1],
  ])('refuses a %s default ttl', (_label, defaultTtlSeconds) => {
    expect(() => new OneTimeTokenManager({ store, audit }, { defaultTtlSeconds })).toThrow(
      OneTimeTokenConfigurationError,
    );
  });

  it('refuses fewer than 16 random bytes', () => {
    expect(() => new OneTimeTokenManager({ store, audit }, { tokenBytes: 15 })).toThrow(
      /at least 16/,
    );
  });

  it('honours a configured token size', async () => {
    const big = new OneTimeTokenManager({ store, audit }, { tokenBytes: 64 });
    const { token } = await big.issue({ purpose: 'p', subject: 'u' });
    expect(Buffer.from(token, 'base64url')).toHaveLength(64);
  });

  it('refuses an out-of-range per-issue ttl', async () => {
    await expect(
      tokens.issue({ purpose: 'p', subject: 'u', ttlSeconds: 0 }),
    ).rejects.toBeInstanceOf(OneTimeTokenConfigurationError);
  });
});
