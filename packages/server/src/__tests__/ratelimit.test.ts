import { describe, it, expect, beforeEach } from 'vitest';
import { ConfigurationError, RateLimitError, StoreUnavailableError } from '@ninsho/core';
import { MemoryStore } from '../store/memory.js';
import { MemoryAuditSink } from '../audit.js';
import { RateLimiter } from '../ratelimit/limiter.js';
import { assertTrustProxy, clientIp } from '../ratelimit/client-ip.js';
import { createRateLimit } from '../ratelimit/middleware.js';
import type { HttpRequest, HttpResponse, Middleware } from '../http/types.js';

let store: MemoryStore;
let audit: MemoryAuditSink;
let limiter: RateLimiter;

beforeEach(() => {
  store = new MemoryStore();
  audit = new MemoryAuditSink();
  limiter = new RateLimiter({ store, onStoreError: 'closed', audit });
});

/**
 * ─── Audit finding H5, first half ─────────────────────────────────────────
 * The predecessor keyed on `req.ip` with no proxy guidance, which breaks the
 * limiter in both directions depending on deployment. There is no safe
 * default, so Ninsho refuses to guess.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('trustProxy validation', () => {
  it.each([
    ['false', false],
    ['zero', 0],
    ['a positive integer', 2],
    ["'all'", 'all'],
  ])('accepts %s', (_label, value) => {
    expect(() => assertTrustProxy(value)).not.toThrow();
  });

  it.each([
    ['undefined — the dangerous default', undefined],
    ['true', true],
    ['a negative count', -1],
    ['a fractional count', 1.5],
    ['a string number', '2'],
    ['null', null],
  ])('rejects %s', (_label, value) => {
    expect(() => assertTrustProxy(value)).toThrow(ConfigurationError);
  });

  it('explains both failure directions, so the choice can be made correctly', () => {
    expect(() => assertTrustProxy(undefined)).toThrow(/locks out every user|rotating an X-Forwarded-For/);
  });
});

describe('client address resolution', () => {
  const req = (headers: Record<string, string>, ip = '10.0.0.1'): HttpRequest =>
    ({ headers, ip }) as unknown as HttpRequest;

  it('uses the peer address when proxies are not trusted', () => {
    expect(clientIp(req({ 'x-forwarded-for': '1.2.3.4' }), false)).toBe('10.0.0.1');
  });

  /**
   * The bypass the audit called out: with proxies untrusted, a forged header
   * must not create a fresh bucket.
   */
  it('ignores a forged header entirely when proxies are not trusted', () => {
    const a = clientIp(req({ 'x-forwarded-for': 'attacker-1' }), false);
    const b = clientIp(req({ 'x-forwarded-for': 'attacker-2' }), false);
    expect(a).toBe(b);
  });

  it('counts hops from the trusted end of the chain', () => {
    // client, proxy-a, proxy-b — one trusted proxy means the client is the
    // second entry from the right.
    const r = req({ 'x-forwarded-for': '1.2.3.4, 5.6.7.8, 9.9.9.9' });
    expect(clientIp(r, 1)).toBe('5.6.7.8');
    expect(clientIp(r, 2)).toBe('1.2.3.4');
  });

  /**
   * Entries an attacker prepends sit on the *left*. Counting from the right is
   * what puts them out of reach.
   */
  it('does not let prepended entries shift the resolved address', () => {
    const honest = req({ 'x-forwarded-for': '5.6.7.8, 9.9.9.9' });
    const spoofed = req({ 'x-forwarded-for': 'evil-1, evil-2, 5.6.7.8, 9.9.9.9' });
    expect(clientIp(spoofed, 1)).toBe(clientIp(honest, 1));
  });

  it('falls back to the peer address when the chain is shorter than configured', () => {
    // The request did not traverse the expected path; reaching for an
    // attacker-supplied entry would be worse than using the peer.
    expect(clientIp(req({ 'x-forwarded-for': '1.2.3.4' }), 3)).toBe('10.0.0.1');
  });

  it("takes the leftmost entry under 'all'", () => {
    expect(clientIp(req({ 'x-forwarded-for': '1.2.3.4, 5.6.7.8' }), 'all')).toBe('1.2.3.4');
  });

  it('folds IPv6-mapped IPv4 so one client cannot occupy two buckets', () => {
    const mapped = ({ headers: {}, ip: '::ffff:1.2.3.4' }) as unknown as HttpRequest;
    const plain = ({ headers: {}, ip: '1.2.3.4' }) as unknown as HttpRequest;
    expect(clientIp(mapped, false)).toBe(clientIp(plain, false));
  });

  it('strips a port so the same client shares one bucket', () => {
    const withPort = ({ headers: {}, ip: '1.2.3.4:51234' }) as unknown as HttpRequest;
    expect(clientIp(withPort, false)).toBe('1.2.3.4');
  });

  it('degrades to one shared bucket rather than none when no address is available', () => {
    expect(clientIp({ headers: {} } as HttpRequest, false)).toBe('unknown');
  });

  it('reads the peer address from socket.remoteAddress when ip is absent', () => {
    const r = ({ headers: {}, socket: { remoteAddress: '7.7.7.7' } }) as unknown as HttpRequest;
    expect(clientIp(r, false)).toBe('7.7.7.7');
  });
});

describe('sliding window counter', () => {
  it('allows requests up to the limit', async () => {
    for (let i = 0; i < 5; i += 1) {
      const verdict = await limiter.consume('test-a', 5, 60_000);
      expect(verdict.allowed).toBe(true);
    }
  });

  it('refuses the request past the limit', async () => {
    for (let i = 0; i < 5; i += 1) await limiter.consume('test-b', 5, 60_000);
    expect((await limiter.consume('test-b', 5, 60_000)).allowed).toBe(false);
  });

  it('reports remaining allowance', async () => {
    expect((await limiter.consume('test-c', 5, 60_000)).remaining).toBe(4);
    expect((await limiter.consume('test-c', 5, 60_000)).remaining).toBe(3);
  });

  it('supplies a positive retryAfter when refusing', async () => {
    for (let i = 0; i < 3; i += 1) await limiter.consume('test-d', 2, 60_000);
    const verdict = await limiter.consume('test-d', 2, 60_000);
    expect(verdict.allowed).toBe(false);
    expect(verdict.retryAfter).toBeGreaterThan(0);
  });

  it('keeps buckets independent', async () => {
    for (let i = 0; i < 5; i += 1) await limiter.consume('bucket-x', 5, 60_000);
    expect((await limiter.consume('bucket-x', 5, 60_000)).allowed).toBe(false);
    expect((await limiter.consume('bucket-y', 5, 60_000)).allowed).toBe(true);
  });

  it('lets a short window expire and allow traffic again', async () => {
    for (let i = 0; i < 3; i += 1) await limiter.consume('test-e', 2, 500);
    expect((await limiter.consume('test-e', 2, 500)).allowed).toBe(false);

    await new Promise((r) => {
      setTimeout(r, 1100);
    });
    expect((await limiter.consume('test-e', 2, 500)).allowed).toBe(true);
  });

  /**
   * The reason for a sliding window rather than a fixed one: a fixed window
   * permits 2× the limit across a boundary, and a login endpoint is exactly
   * where that doubling is aimed.
   */
  it('does not permit a double burst across a window boundary', async () => {
    const windowMs = 1000;
    const limit = 5;
    const bucket = 'boundary-test';

    // Fill the current window right before it rolls over.
    const msIntoWindow = Date.now() % windowMs;
    await new Promise((r) => {
      setTimeout(r, Math.max(0, windowMs - msIntoWindow - 120));
    });
    for (let i = 0; i < limit; i += 1) await limiter.consume(bucket, limit, windowMs);

    // Cross into the next window and try to spend the allowance again.
    await new Promise((r) => {
      setTimeout(r, 200);
    });

    const verdict = await limiter.consume(bucket, limit, windowMs);
    // The previous window is still weighted in, so the burst is refused.
    expect(verdict.allowed).toBe(false);
  });

  it('counts concurrent requests exactly once each', async () => {
    // An atomic increment is what makes a limit hold under the concurrent load
    // it exists to control.
    const results = await Promise.all(
      Array.from({ length: 30 }, () => limiter.consume('concurrent', 10, 60_000)),
    );
    expect(results.filter((v) => v.allowed)).toHaveLength(10);
  });
});

describe('multiple buckets', () => {
  it('refuses when any bucket refuses', async () => {
    for (let i = 0; i < 5; i += 1) await limiter.consume('multi:ip', 5, 60_000);

    const verdict = await limiter.consumeAll([
      { bucket: 'multi:ip', limit: 5, windowMs: 60_000 },
      { bucket: 'multi:acct', limit: 100, windowMs: 60_000 },
    ]);
    expect(verdict.allowed).toBe(false);
  });

  /**
   * Otherwise an attacker could keep their per-account counter low by making
   * sure the per-IP counter trips first.
   */
  it('consumes every bucket even when one has already refused', async () => {
    for (let i = 0; i < 6; i += 1) await limiter.consume('drain:ip', 5, 60_000);

    await limiter.consumeAll([
      { bucket: 'drain:ip', limit: 5, windowMs: 60_000 },
      { bucket: 'drain:acct', limit: 100, windowMs: 60_000 },
    ]);

    // The account bucket advanced despite the IP bucket already refusing.
    expect((await limiter.consume('drain:acct', 100, 60_000)).remaining).toBeLessThan(99);
  });

  it('throws RateLimitError from enforce, carrying retryAfter', async () => {
    for (let i = 0; i < 3; i += 1) await limiter.consume('enforce', 2, 60_000);
    await expect(
      limiter.enforce([{ bucket: 'enforce', limit: 2, windowMs: 60_000 }]),
    ).rejects.toThrow(RateLimitError);
  });
});

/**
 * ─── Audit finding H5, second half ────────────────────────────────────────
 * The predecessor's limiter failed open unconditionally with no way to change
 * it, so a Redis blip silently removed brute-force protection from login.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('store outage', () => {
  function brokenStore(): MemoryStore {
    const broken = new MemoryStore();
    broken.increment = async (): Promise<never> => {
      throw new Error('ECONNREFUSED');
    };
    return broken;
  }

  it('refuses when fail-closed', async () => {
    const failing = new RateLimiter({
      store: brokenStore(),
      onStoreError: 'closed',
      audit,
    });
    await expect(failing.consume('x', 5, 60_000)).rejects.toThrow(StoreUnavailableError);
  });

  it('allows when explicitly configured fail-open', async () => {
    const failing = new RateLimiter({ store: brokenStore(), onStoreError: 'open', audit });
    expect((await failing.consume('x', 5, 60_000)).allowed).toBe(true);
  });

  it('records either outcome, so a gap in enforcement is reconstructible', async () => {
    const failing = new RateLimiter({ store: brokenStore(), onStoreError: 'open', audit });
    await failing.consume('x', 5, 60_000);

    const events = audit.ofType('store.unavailable');
    expect(events).toHaveLength(1);
    expect(events[0]?.reason).toBe('rate_limit_skipped');
  });
});

// ── Middleware ──────────────────────────────────────────────────────────────

class FakeResponse implements HttpResponse {
  statusCode: number | undefined;
  body: unknown;
  readonly headers = new Map<string, string | number>();
  status(code: number): HttpResponse {
    this.statusCode = code;
    return this;
  }
  json(body: unknown): unknown {
    this.body = body;
    return body;
  }
  setHeader(name: string, value: string | number): unknown {
    this.headers.set(name, value);
    return this;
  }
}

async function run(mw: Middleware, req: HttpRequest): Promise<{
  res: FakeResponse;
  nextCalled: boolean;
}> {
  const res = new FakeResponse();
  let nextCalled = false;

  await new Promise<void>((resolve) => {
    let settled = false;
    const done = (): void => {
      if (!settled) {
        settled = true;
        resolve();
      }
    };
    const originalJson = res.json.bind(res);
    res.json = (body: unknown): unknown => {
      const out = originalJson(body);
      done();
      return out;
    };
    void Promise.resolve(
      mw(req, res, () => {
        nextCalled = true;
        done();
      }),
    ).then(() => setTimeout(done, 20));
  });

  return { res, nextCalled };
}

describe('rateLimit middleware', () => {
  const loginRequest = (ip: string, email?: string): HttpRequest =>
    ({ headers: {}, ip, body: email === undefined ? {} : { email } }) as unknown as HttpRequest;

  const mw = (): Middleware =>
    createRateLimit(limiter, audit, {
      action: 'login',
      perIp: { limit: 20, windowMs: 900_000 },
      perAccount: { limit: 3, windowMs: 900_000 },
      identify: (req) => (req.body as { email?: string } | undefined)?.email,
      trustProxy: false,
    });

  it('allows traffic under the limit', async () => {
    const result = await run(mw(), loginRequest('1.1.1.1', 'a@x.test'));
    expect(result.nextCalled).toBe(true);
  });

  it('responds 429 with Retry-After once the limit is exceeded', async () => {
    const limit = mw();
    for (let i = 0; i < 4; i += 1) await run(limit, loginRequest('1.1.1.1', 'a@x.test'));

    const result = await run(limit, loginRequest('1.1.1.1', 'a@x.test'));
    expect(result.res.statusCode).toBe(429);
    expect(result.res.headers.get('Retry-After')).toBeGreaterThan(0);
  });

  /**
   * The attack the per-account bucket exists for. A botnet spreads attempts so
   * no single address approaches the per-IP limit, while one victim account
   * absorbs thousands of guesses. A per-IP limit alone never notices.
   */
  it('stops distributed credential stuffing against one account', async () => {
    const limit = mw();
    // Each attempt from a different address — every per-IP bucket stays at 1.
    for (let i = 0; i < 3; i += 1) {
      await run(limit, loginRequest(`10.0.0.${i}`, 'victim@x.test'));
    }

    const result = await run(limit, loginRequest('10.0.0.99', 'victim@x.test'));
    expect(result.res.statusCode).toBe(429);
  });

  it('does not punish other accounts from the same address', async () => {
    const limit = mw();
    for (let i = 0; i < 4; i += 1) await run(limit, loginRequest('1.1.1.1', 'victim@x.test'));

    // Shared NAT: a colleague behind the same address is unaffected while the
    // per-IP allowance remains.
    const result = await run(limit, loginRequest('1.1.1.1', 'colleague@x.test'));
    expect(result.nextCalled).toBe(true);
  });

  it('treats capitalisation variants as one account', async () => {
    const limit = mw();
    for (const email of ['a@x.test', 'A@X.test', ' a@x.TEST ']) {
      await run(limit, loginRequest('1.1.1.1', email));
    }
    const result = await run(limit, loginRequest('1.1.1.1', 'a@x.test'));
    expect(result.res.statusCode).toBe(429);
  });

  it('still applies the per-IP limit when no identifier is supplied', async () => {
    const limit = createRateLimit(limiter, audit, {
      action: 'anon',
      perIp: { limit: 2, windowMs: 900_000 },
      perAccount: { limit: 3, windowMs: 900_000 },
      identify: (req) => (req.body as { email?: string } | undefined)?.email,
      trustProxy: false,
    });

    // Omitting the field must not be an escape from limiting.
    for (let i = 0; i < 3; i += 1) await run(limit, loginRequest('2.2.2.2'));
    const result = await run(limit, loginRequest('2.2.2.2'));
    expect(result.res.statusCode).toBe(429);
  });

  it('records the refusal', async () => {
    const limit = mw();
    for (let i = 0; i < 5; i += 1) await run(limit, loginRequest('1.1.1.1', 'a@x.test'));
    expect(audit.ofType('ratelimit.exceeded').length).toBeGreaterThan(0);
  });

  it('keeps unrelated actions in separate namespaces', async () => {
    const login = createRateLimit(limiter, audit, {
      action: 'login',
      perIp: { limit: 2, windowMs: 900_000 },
      trustProxy: false,
    });
    const search = createRateLimit(limiter, audit, {
      action: 'search',
      perIp: { limit: 2, windowMs: 900_000 },
      trustProxy: false,
    });

    for (let i = 0; i < 3; i += 1) await run(login, loginRequest('3.3.3.3'));
    expect((await run(login, loginRequest('3.3.3.3'))).res.statusCode).toBe(429);
    // Traffic to a busy route must not exhaust the allowance for sign-in.
    expect((await run(search, loginRequest('3.3.3.3'))).nextCalled).toBe(true);
  });

  it('refuses to be constructed with perAccount but no identify', () => {
    expect(() =>
      createRateLimit(limiter, audit, {
        action: 'x',
        perIp: { limit: 5, windowMs: 1000 },
        perAccount: { limit: 5, windowMs: 1000 },
        trustProxy: false,
      }),
    ).toThrow(/also needs identify/);
  });

  it('never echoes the account identifier back to the client', async () => {
    const limit = mw();
    for (let i = 0; i < 5; i += 1) await run(limit, loginRequest('1.1.1.1', 'secret@x.test'));
    const result = await run(limit, loginRequest('1.1.1.1', 'secret@x.test'));
    expect(JSON.stringify(result.res.body)).not.toContain('secret@x.test');
  });
});
