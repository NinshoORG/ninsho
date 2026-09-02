import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { MemoryStore } from '@ninsho/server';
import { createApp } from './app.js';
import { lastResetLink, resetUsers } from './users.js';
import { resetCredentials } from './credentials.js';

/**
 * Password reset, end to end over real HTTP.
 *
 * ─── Why each test is here ────────────────────────────────────────────────
 * Every way of botching this flow is a full account takeover, and the ones
 * that survive review are the quiet ones: a link that works twice, a link that
 * still works after a new one was sent, sessions left alive after the password
 * changed, and an endpoint that answers differently for a real address.
 *
 * None of those is visible from a unit test of the token primitive. They are
 * properties of the *flow*, so the flow is what is tested.
 * ──────────────────────────────────────────────────────────────────────────
 */

const PASSWORD = 'correct-horse-battery-staple';
const NEW_PASSWORD = 'a-completely-different-passphrase';

let server: Server;
let baseUrl: string;
let store: MemoryStore;

interface Json {
  readonly status: number;
  readonly body: Record<string, unknown>;
  readonly headers: Headers;
}

async function call(
  path: string,
  init: RequestInit & { token?: string } = {},
): Promise<Json> {
  const headers = new Headers(init.headers);
  headers.set('content-type', 'application/json');
  if (init.token !== undefined) headers.set('authorization', `Bearer ${init.token}`);

  const response = await fetch(`${baseUrl}${path}`, { ...init, headers, redirect: 'manual' });
  const text = await response.text();
  return {
    status: response.status,
    body: text.length > 0 ? (JSON.parse(text) as Record<string, unknown>) : {},
    headers: response.headers,
  };
}

async function signUp(email: string): Promise<{ token: string; id: string }> {
  const res = await call('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ email, password: PASSWORD }),
  });
  return {
    token: res.body['accessToken'] as string,
    id: (res.body['user'] as { id: string }).id,
  };
}

const forgot = (email: string) =>
  call('/auth/password/forgot', { method: 'POST', body: JSON.stringify({ email }) });

const doReset = (token: string, password = NEW_PASSWORD) =>
  call('/auth/password/reset', { method: 'POST', body: JSON.stringify({ token, password }) });

const login = (email: string, password: string) =>
  call('/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) });

beforeEach(async () => {
  resetUsers();
  resetCredentials();
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

describe('the reset flow', () => {
  it('resets the password and lets the user sign in with the new one', async () => {
    await signUp('ada@example.test');

    expect((await forgot('ada@example.test')).status).toBe(202);
    const link = lastResetLink();
    expect(link?.email).toBe('ada@example.test');

    expect((await doReset(link!.token)).status).toBe(204);

    expect((await login('ada@example.test', NEW_PASSWORD)).status).toBe(200);
    // And the old password is genuinely gone, not merely superseded.
    expect((await login('ada@example.test', PASSWORD)).status).toBe(401);
  });

  it('revokes every existing session', async () => {
    // The step people forget. Whoever forced the reset may already hold a
    // session; leaving it alive means the password change accomplished
    // nothing.
    const { token } = await signUp('ada@example.test');
    expect((await call('/me', { token })).status).toBe(200);

    await forgot('ada@example.test');
    await doReset(lastResetLink()!.token);

    expect((await call('/me', { token })).status).toBe(401);
  });

  it('refuses a link that has already been used', async () => {
    await signUp('ada@example.test');
    await forgot('ada@example.test');
    const link = lastResetLink()!;

    expect((await doReset(link.token)).status).toBe(204);
    expect((await doReset(link.token, 'yet-another-passphrase')).status).toBe(400);
  });

  it('lets exactly one of several simultaneous clicks through', async () => {
    await signUp('ada@example.test');
    await forgot('ada@example.test');
    const link = lastResetLink()!;

    const results = await Promise.all(
      Array.from({ length: 8 }, () => doReset(link.token)),
    );

    expect(results.filter((r) => r.status === 204)).toHaveLength(1);
    expect(results.filter((r) => r.status === 400)).toHaveLength(7);
  });

  it('invalidates the earlier link when a second is requested', async () => {
    // An old email sitting in an inbox must stop working once a new one is
    // sent, which is what a user asking twice expects.
    await signUp('ada@example.test');

    await forgot('ada@example.test');
    const first = lastResetLink()!.token;
    await forgot('ada@example.test');
    const second = lastResetLink()!.token;

    expect(first).not.toBe(second);
    expect((await doReset(first)).status).toBe(400);
    expect((await doReset(second)).status).toBe(204);
  });
});

/**
 * This endpoint needs only an address, where /auth/login at least demands a
 * password guess — so leaking existence here is cheaper to exploit.
 */
describe('it does not reveal which accounts exist', () => {
  it('answers identically for a real and an unknown address', async () => {
    await signUp('ada@example.test');

    const real = await forgot('ada@example.test');
    const fake = await forgot('nobody@example.test');

    expect(real.status).toBe(fake.status);
    expect(JSON.stringify(real.body)).toBe(JSON.stringify(fake.body));
  });

  it('answers the same for a malformed body', async () => {
    const missing = await call('/auth/password/forgot', { method: 'POST', body: '{}' });
    const numeric = await call('/auth/password/forgot', {
      method: 'POST',
      body: JSON.stringify({ email: 42 }),
    });

    expect(missing.status).toBe(202);
    expect(JSON.stringify(missing.body)).toBe(JSON.stringify(numeric.body));
  });

  it('sends nothing for an address with no account', async () => {
    await forgot('nobody@example.test');
    expect(lastResetLink()).toBeUndefined();
  });
});

describe('bad reset attempts', () => {
  it.each([
    ['a token that was never issued', { token: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', password: NEW_PASSWORD }],
    ['an empty token', { token: '', password: NEW_PASSWORD }],
  ])('refuses %s', async (_label, body) => {
    const res = await call('/auth/password/reset', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    expect(res.status).toBe(400);
  });

  it.each([
    ['a missing token', { password: NEW_PASSWORD }],
    ['a missing password', { token: 'x' }],
    ['a numeric token', { token: 1, password: NEW_PASSWORD }],
    ['an empty body', {}],
  ])('rejects %s with a 400, not a 500', async (_label, body) => {
    const res = await call('/auth/password/reset', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    expect(res.status).toBe(400);
  });

  it('enforces the password policy on the new password', async () => {
    await signUp('ada@example.test');
    await forgot('ada@example.test');

    const res = await doReset(lastResetLink()!.token, 'short');
    expect(res.status).toBe(400);
    expect(res.body['error']).toMatchObject({ code: 'WEAK_PASSWORD' });
  });

  it('leaves the link usable after a rejected weak password', async () => {
    // The token is consumed only once the request is worth acting on;
    // otherwise a typo would cost the user another email.
    await signUp('ada@example.test');
    await forgot('ada@example.test');
    const link = lastResetLink()!.token;

    expect((await doReset(link, 'short')).status).toBe(400);
    expect((await doReset(link)).status).toBe(204);
  });

  it('says the same thing whichever way the token was wrong', async () => {
    await signUp('ada@example.test');
    await forgot('ada@example.test');
    const link = lastResetLink()!.token;
    await doReset(link);

    const used = await doReset(link);
    const never = await doReset('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');

    expect(JSON.stringify(used.body)).toBe(JSON.stringify(never.body));
    expect(JSON.stringify(used.body)).not.toMatch(/expired|used|found/i);
  });
});

describe('rate limiting', () => {
  it('stops one address being flooded with reset emails', async () => {
    // Without this the endpoint is an email-flooding tool aimed at a user, and
    // no property of the token itself helps.
    await signUp('ada@example.test');

    const statuses: number[] = [];
    for (let i = 0; i < 6; i += 1) {
      statuses.push((await forgot('ada@example.test')).status);
    }

    expect(statuses).toContain(429);
  });
});
