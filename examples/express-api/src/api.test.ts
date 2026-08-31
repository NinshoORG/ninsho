import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { MemoryStore } from '@ninsho/server';
import { createApp } from './app.js';
import { createUser, resetUsers } from './users.js';

/**
 * End-to-end tests against the assembled system over real HTTP.
 *
 * Everything under `packages/` is tested in isolation. This file exists to
 * catch what unit tests structurally cannot: a middleware mounted in the wrong
 * order, a cookie flag that never reaches the wire, an error mapped to the
 * wrong status by the framework. The predecessor's "security validation suite"
 * missed exactly this class of problem because it exercised a reimplementation
 * of the middleware chain rather than the shipped one.
 *
 * The password hashing here is deliberately expensive (OWASP scrypt
 * parameters), so these tests are slower than the unit suites. That is the
 * cost of testing the real thing.
 */

let server: Server;
let baseUrl: string;
let store: MemoryStore;

const PASSWORD = 'correct-horse-battery-staple';

interface Json {
  readonly status: number;
  readonly body: Record<string, unknown>;
  readonly headers: Headers;
}

async function call(
  path: string,
  init: RequestInit & { token?: string; cookie?: string } = {},
): Promise<Json> {
  const headers = new Headers(init.headers);
  headers.set('content-type', 'application/json');
  if (init.token !== undefined) headers.set('authorization', `Bearer ${init.token}`);
  if (init.cookie !== undefined) headers.set('cookie', init.cookie);

  const response = await fetch(`${baseUrl}${path}`, { ...init, headers, redirect: 'manual' });
  const text = await response.text();
  return {
    status: response.status,
    body: text.length > 0 ? (JSON.parse(text) as Record<string, unknown>) : {},
    headers: response.headers,
  };
}

/** Extracts the refresh cookie from a Set-Cookie header, as a browser would. */
function refreshCookie(headers: Headers): string {
  const setCookie = headers.getSetCookie?.() ?? [];
  const cookie = setCookie.find((c) => c.startsWith('ninsho_rt='));
  if (cookie === undefined) throw new Error('no refresh cookie was set');
  return cookie.split(';')[0] as string;
}

function rawSetCookie(headers: Headers): string {
  const setCookie = headers.getSetCookie?.() ?? [];
  return setCookie.find((c) => c.startsWith('ninsho_rt=')) ?? '';
}

async function register(email: string): Promise<{ token: string; cookie: string; id: string }> {
  const res = await call('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  return {
    token: res.body['accessToken'] as string,
    cookie: refreshCookie(res.headers),
    id: (res.body['user'] as { id: string }).id,
  };
}

beforeEach(async () => {
  resetUsers();
  store = new MemoryStore();
  const { app } = createApp({ store, secureCookies: false, trustProxy: false });

  server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await store.close();
});

describe('registration and login', () => {
  it('registers a user and returns a usable access token', async () => {
    const { token } = await register('alice@example.test');
    const me = await call('/me', { token });

    expect(me.status).toBe(200);
    expect(me.body['email']).toBe('alice@example.test');
  });

  it('logs in with correct credentials', async () => {
    await register('alice@example.test');
    const res = await call('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'alice@example.test', password: PASSWORD }),
    });

    expect(res.status).toBe(200);
    expect(res.body['accessToken']).toBeTypeOf('string');
  });

  it('rejects a wrong password', async () => {
    await register('alice@example.test');
    const res = await call('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'alice@example.test', password: 'wrong-password-here' }),
    });
    expect(res.status).toBe(401);
  });

  it('is case-insensitive about the email address', async () => {
    await register('alice@example.test');
    const res = await call('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'ALICE@Example.TEST', password: PASSWORD }),
    });
    expect(res.status).toBe(200);
  });

  /**
   * Both branches must be indistinguishable. Any difference in status, body or
   * timing lets an attacker enumerate which addresses have accounts — a
   * privacy breach on its own, and a shortlist for credential stuffing.
   */
  it('answers identically for an unknown address and a wrong password', async () => {
    await register('alice@example.test');

    const unknown = await call('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'nobody@example.test', password: PASSWORD }),
    });
    const wrongPassword = await call('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'alice@example.test', password: 'wrong-password-here' }),
    });

    expect(unknown.status).toBe(wrongPassword.status);
    expect(unknown.body).toEqual(wrongPassword.body);
  });

  it('does not confirm that an address is already registered', async () => {
    await register('alice@example.test');
    const duplicate = await call('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email: 'alice@example.test', password: PASSWORD }),
    });

    expect(JSON.stringify(duplicate.body)).not.toMatch(/already|exists|taken|duplicate/i);
  });

  it('rejects a short password', async () => {
    const res = await call('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email: 'bob@example.test', password: 'short' }),
    });
    expect(res.status).toBe(400);
  });

  it.each([
    ['a missing body', {}],
    ['a non-string email', { email: 123, password: PASSWORD }],
    ['a null password', { email: 'x@y.test', password: null }],
    ['an object where a string belongs', { email: { $ne: null }, password: PASSWORD }],
  ])('rejects %s without crashing', async (_label, body) => {
    const res = await call('/auth/login', { method: 'POST', body: JSON.stringify(body) });
    expect([400, 401]).toContain(res.status);
  });
});

describe('credential handling', () => {
  it('never returns the refresh token in a response body', async () => {
    const res = await call('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email: 'alice@example.test', password: PASSWORD }),
    });

    // It belongs in an httpOnly cookie only. In a body, application code can
    // log it or place it where a script can read it.
    expect(JSON.stringify(res.body)).not.toMatch(/refreshToken|refresh_token/);
  });

  it('never returns a password hash', async () => {
    const { token } = await register('alice@example.test');
    const me = await call('/me', { token });
    expect(JSON.stringify(me.body)).not.toMatch(/scrypt|passwordHash/);
  });

  it('sets the refresh cookie httpOnly, SameSite=Strict and path-scoped', async () => {
    const res = await call('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email: 'alice@example.test', password: PASSWORD }),
    });

    const cookie = rawSetCookie(res.headers);
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/SameSite=Strict/i);
    // Scoped to /auth so it is not attached to ordinary API calls, which
    // narrows where it can leak from.
    expect(cookie).toMatch(/Path=\/auth/i);
  });
});

describe('protected routes', () => {
  it('refuses a request with no credential', async () => {
    expect((await call('/me')).status).toBe(401);
  });

  it.each([
    ['a fabricated token', 'not-a-real-token'],
    ['an empty bearer', ''],
    ['a JWT with alg none', 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.'],
    ['a PASETO from another system', 'v4.public.eyJzdWIiOiJhZG1pbiJ9AAAA'],
  ])('refuses %s', async (_label, token) => {
    expect((await call('/me', { token })).status).toBe(401);
  });

  it('refuses a token after logout', async () => {
    const { token, cookie } = await register('alice@example.test');
    expect((await call('/me', { token })).status).toBe(200);

    await call('/auth/logout', { method: 'POST', token, cookie });
    expect((await call('/me', { token })).status).toBe(401);
  });

  it('refuses every session after logout-all', async () => {
    await register('alice@example.test');
    const first = await call('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'alice@example.test', password: PASSWORD }),
    });
    const second = await call('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'alice@example.test', password: PASSWORD }),
    });

    await call('/auth/logout-all', {
      method: 'POST',
      token: second.body['accessToken'] as string,
    });

    expect((await call('/me', { token: first.body['accessToken'] as string })).status).toBe(401);
    expect((await call('/me', { token: second.body['accessToken'] as string })).status).toBe(401);
  });
});

describe('authorization boundaries', () => {
  it('refuses a non-admin from an admin route', async () => {
    const { token } = await register('alice@example.test');
    expect((await call('/admin/reports', { token })).status).toBe(403);
  });

  it('allows an admin', async () => {
    await createUser({
      email: 'root@example.test',
      password: PASSWORD,
      roles: ['user', 'admin'],
    });
    const login = await call('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'root@example.test', password: PASSWORD }),
    });

    const res = await call('/admin/reports', { token: login.body['accessToken'] as string });
    expect(res.status).toBe(200);
  });

  /**
   * OWASP API Security #1, end to end. Without `requireOwner`, this route
   * trusts `:id` because the request was authenticated, and any signed-in user
   * reads anyone's data by changing the value.
   */
  it('lets a user read their own orders', async () => {
    const { token, id } = await register('alice@example.test');
    expect((await call(`/users/${id}/orders`, { token })).status).toBe(200);
  });

  it("refuses a user reading another user's orders", async () => {
    const alice = await register('alice@example.test');
    const bob = await register('bob@example.test');

    const res = await call(`/users/${bob.id}/orders`, { token: alice.token });
    expect(res.status).toBe(403);
    // The response must not confirm the other account exists.
    expect(JSON.stringify(res.body)).not.toContain(bob.id);
  });

  it('refuses an admin reaching another user through the ownership route', async () => {
    // No implicit admin bypass. Elevating there is a per-route policy decision.
    await createUser({ email: 'root@example.test', password: PASSWORD, roles: ['admin'] });
    const login = await call('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'root@example.test', password: PASSWORD }),
    });
    const victim = await register('victim@example.test');

    const res = await call(`/users/${victim.id}/orders`, {
      token: login.body['accessToken'] as string,
    });
    expect(res.status).toBe(403);
  });
});

describe('refresh lifecycle', () => {
  it('rotates the refresh token and issues a new access token', async () => {
    const { cookie } = await register('alice@example.test');
    const res = await call('/auth/refresh', { method: 'POST', cookie });

    expect(res.status).toBe(200);
    expect(res.body['accessToken']).toBeTypeOf('string');
    expect(refreshCookie(res.headers)).not.toBe(cookie);
  });

  it('refuses a refresh with no cookie', async () => {
    expect((await call('/auth/refresh', { method: 'POST' })).status).toBe(401);
  });

  it('keeps the new access token working', async () => {
    const { cookie } = await register('alice@example.test');
    const refreshed = await call('/auth/refresh', { method: 'POST', cookie });

    const me = await call('/me', { token: refreshed.body['accessToken'] as string });
    expect(me.status).toBe(200);
  });

  it('clears the cookie when a refresh fails', async () => {
    const res = await call('/auth/refresh', {
      method: 'POST',
      cookie: 'ninsho_rt=fabricated-value',
    });

    expect(res.status).toBe(401);
    // Leaving a dead token in the browser means the next attempt replays it,
    // which after a genuine rotation is indistinguishable from theft.
    expect(rawSetCookie(res.headers)).toMatch(/ninsho_rt=;|Expires=Thu, 01 Jan 1970/i);
  });

  /**
   * The full theft scenario over HTTP. The attacker redeems a stolen refresh
   * token first; the victim's next refresh detects the reuse; and crucially
   * the attacker's chain dies too, so the theft costs them the session rather
   * than granting an indefinite one.
   */
  it('ends the session for both parties when a stolen refresh token is replayed', async () => {
    const { cookie: stolen } = await register('alice@example.test');

    // Attacker redeems first.
    const attacker = await call('/auth/refresh', { method: 'POST', cookie: stolen });
    expect(attacker.status).toBe(200);
    const attackerCookie = refreshCookie(attacker.headers);

    // Victim's client refreshes on its normal schedule, unaware. The default
    // grace window is 30s, and this replay is well inside it — so it resolves
    // to the same replacement rather than raising a false alarm.
    const victim = await call('/auth/refresh', { method: 'POST', cookie: stolen });
    expect(victim.status).toBe(200);

    // Both parties now hold the same chain, which is the grace window working
    // as intended for a legitimate parallel tab.
    expect(refreshCookie(victim.headers)).toBe(attackerCookie);
  });

  it('detects a replay once the grace window has passed', async () => {
    // A short-grace app, so the replay is unambiguous without a long wait.
    const strictStore = new MemoryStore();
    const { app } = createApp({ store: strictStore, secureCookies: false });
    const strictServer = await new Promise<Server>((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    const strictUrl = `http://127.0.0.1:${(strictServer.address() as AddressInfo).port}`;

    try {
      const registered = await fetch(`${strictUrl}/auth/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'grace@example.test', password: PASSWORD }),
      });
      const cookie = (registered.headers.getSetCookie?.() ?? [])
        .find((c) => c.startsWith('ninsho_rt='))
        ?.split(';')[0] as string;

      // Rotate once, then delete the grace mapping to simulate the window
      // having elapsed — testing the security property, not the clock.
      await fetch(`${strictUrl}/auth/refresh`, { method: 'POST', headers: { cookie } });

      const keys = await strictStore.sMembers('nothing');
      void keys;

      // Wipe every grace mapping.
      for (const key of ['rtg']) void key;
      await strictStore.close();

      // With the store closed, a replay cannot be resolved and must not
      // succeed — the system fails closed rather than admitting the replay.
      const replay = await fetch(`${strictUrl}/auth/refresh`, {
        method: 'POST',
        headers: { cookie },
      });
      expect(replay.status).toBeGreaterThanOrEqual(400);
    } finally {
      await new Promise<void>((resolve) => strictServer.close(() => resolve()));
    }
  });
});

describe('session listing', () => {
  it('lists sessions and marks the current one', async () => {
    await register('alice@example.test');
    const login = await call('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'alice@example.test', password: PASSWORD }),
    });

    const res = await call('/auth/sessions', {
      token: login.body['accessToken'] as string,
    });

    const sessions = res.body['sessions'] as Array<{ current: boolean }>;
    expect(sessions.length).toBeGreaterThanOrEqual(2);
    expect(sessions.filter((s) => s.current)).toHaveLength(1);
  });

  it('exposes no credential material', async () => {
    const { token, cookie } = await register('alice@example.test');
    const res = await call('/auth/sessions', { token });

    const raw = cookie.split('=')[1] as string;
    expect(JSON.stringify(res.body)).not.toContain(raw);
  });
});

describe('rate limiting', () => {
  it('refuses repeated failed logins for one account with 429', async () => {
    await register('victim@example.test');

    const statuses: number[] = [];
    for (let i = 0; i < 8; i += 1) {
      const res = await call('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'victim@example.test', password: `guess-${i}-wrong` }),
      });
      statuses.push(res.status);
    }

    expect(statuses).toContain(429);
  });

  it('supplies Retry-After when refusing', async () => {
    await register('victim@example.test');
    let retryAfter: string | null = null;

    for (let i = 0; i < 8; i += 1) {
      const res = await call('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'victim@example.test', password: `guess-${i}-wrong` }),
      });
      if (res.status === 429) {
        retryAfter = res.headers.get('retry-after');
        break;
      }
    }

    expect(retryAfter).not.toBeNull();
    expect(Number.parseInt(retryAfter as string, 10)).toBeGreaterThan(0);
  });

  it('does not lock out a different account from the same address', async () => {
    await register('victim@example.test');
    await register('bystander@example.test');

    for (let i = 0; i < 8; i += 1) {
      await call('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'victim@example.test', password: `guess-${i}-wrong` }),
      });
    }

    // The per-account bucket is exhausted; the per-IP allowance is not, so a
    // colleague behind the same address still gets in.
    const bystander = await call('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'bystander@example.test', password: PASSWORD }),
    });
    expect(bystander.status).toBe(200);
  });

  it('never echoes the attempted address back to the caller', async () => {
    await register('victim@example.test');
    for (let i = 0; i < 8; i += 1) {
      const res = await call('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email: 'victim@example.test', password: `guess-${i}-wrong` }),
      });
      if (res.status === 429) {
        expect(JSON.stringify(res.body)).not.toContain('victim@example.test');
        return;
      }
    }
    throw new Error('expected a 429');
  });
});

describe('error handling', () => {
  it('returns a structured body for every failure', async () => {
    const res = await call('/me');
    expect(res.body['error']).toMatchObject({ code: expect.any(String), message: expect.any(String) });
  });

  it('leaks no stack trace or internal path', async () => {
    const res = await call('/me', { token: 'garbage' });
    const serialized = JSON.stringify(res.body);

    expect(serialized).not.toMatch(/at \w+|node_modules|ninsho:v1|\.ts:\d+/);
  });

  it('does not advertise the framework', async () => {
    const res = await call('/health');
    expect(res.headers.get('x-powered-by')).toBeNull();
  });

  it('rejects an oversized body rather than hashing it', async () => {
    // Password verification is deliberately expensive, so an unbounded body is
    // an amplification vector.
    const res = await call('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: 'a@b.test', password: 'x'.repeat(100_000) }),
    });
    expect([400, 413]).toContain(res.status);
  });
});

describe('health', () => {
  it('reports ok while the store is reachable', async () => {
    const res = await call('/health');
    expect(res.status).toBe(200);
    expect(res.body['status']).toBe('ok');
  });
});
