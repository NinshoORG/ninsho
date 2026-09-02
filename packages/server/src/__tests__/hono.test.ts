import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { Hono } from 'hono';
import type { Principal } from '@ninsho/core';
import { Ninsho } from '../ninsho.js';
import { MemoryStore } from '../store/memory.js';
import { toHono, getAuth, AUTH_CONTEXT_KEY, type HonoLikeContext } from '../hono.js';

/**
 * The Hono adapter, against real Hono.
 *
 * ─── The case that matters ────────────────────────────────────────────────
 * A Hono middleware halts by *returning a Response* and continues by awaiting
 * `next()`. Ninsho's middleware halts by writing a response and continues by
 * calling `next()`. Translating the first into the second wrongly — in the
 * direction of "continue" — produces an authorization check that logs a denial
 * and then serves the resource anyway.
 *
 * So every negative test below asserts the route handler did not run, not
 * merely that the status was 403. And it runs against real Hono, because a
 * stubbed context would confirm my expectations of Hono and nothing else.
 * ──────────────────────────────────────────────────────────────────────────
 */

const ALICE: Principal = { userId: 'user_alice', roles: ['user'], scopes: ['profile:read'] };
const ADMIN: Principal = { userId: 'user_root', roles: ['admin'], scopes: ['profile:read'] };

let app: Hono;
let auth: Ninsho;
let store: MemoryStore;
/** Set by any route that actually ran, so a leaked denial is visible. */
let handlerRan: boolean;

beforeEach(() => {
  store = new MemoryStore();
  auth = new Ninsho({ store });
  handlerRan = false;

  app = new Hono();

  app.use('/me', toHono(auth.verify()));
  app.get('/me', (c) => {
    handlerRan = true;
    const context = getAuth(c as unknown as HonoLikeContext);
    return c.json({ userId: context.userId, roles: context.roles });
  });

  app.use('/admin', toHono([auth.verify(), auth.requireRole('admin')]));
  app.get('/admin', (c) => {
    handlerRan = true;
    return c.json({ ok: true });
  });

  app.use('/scoped', toHono([auth.verify(), auth.requireScope('orders:write')]));
  app.get('/scoped', (c) => {
    handlerRan = true;
    return c.json({ ok: true });
  });

  app.use(
    '/users/:id/orders',
    toHono([auth.verify(), auth.requireOwner((req) => req.params?.['id'])]),
  );
  app.get('/users/:id/orders', (c) => {
    handlerRan = true;
    return c.json({ orders: [] });
  });

  app.use('/sensitive', toHono([auth.verify(), auth.requireFreshAuth(300)]));
  app.post('/sensitive', (c) => {
    handlerRan = true;
    return c.json({ ok: true });
  });

  // Body-based selector, which is the one case needing the opt-in parse.
  app.use(
    '/orders',
    toHono([auth.verify(), auth.requireOwner((req) => (req.body as { owner?: string })?.owner)], {
      parseJsonBody: true,
    }),
  );
  app.post('/orders', (c) => {
    handlerRan = true;
    return c.json({ ok: true });
  });
});

afterEach(async () => store.close());

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

describe('verify()', () => {
  it('admits a valid token and exposes the identity to the handler', async () => {
    const pair = await auth.createSession(ALICE);
    const res = await app.request('/me', { headers: bearer(pair.accessToken) });

    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ userId: 'user_alice', roles: ['user'] });
    expect(handlerRan).toBe(true);
  });

  it('rejects a missing token without running the handler', async () => {
    const res = await app.request('/me');

    expect(res.status).toBe(401);
    // The assertion that matters: a denial must not fall through.
    expect(handlerRan).toBe(false);
  });

  it('rejects a garbage token without running the handler', async () => {
    const res = await app.request('/me', { headers: bearer('not-a-real-token') });

    expect(res.status).toBe(401);
    expect(handlerRan).toBe(false);
  });

  it('rejects a revoked token', async () => {
    const pair = await auth.createSession(ALICE);
    const context = await auth.engine.verify(pair.accessToken);
    await auth.revokeSession(context.sessionId, 'logout');

    const res = await app.request('/me', { headers: bearer(pair.accessToken) });
    expect(res.status).toBe(401);
    expect(handlerRan).toBe(false);
  });

  it('sends Ninsho’s error body, not Hono’s default', async () => {
    const res = await app.request('/me');
    expect(await res.json()).toMatchObject({ error: { code: 'TOKEN_MISSING' } });
  });

  it('carries the WWW-Authenticate challenge through Hono', async () => {
    // `setHeader` maps to `c.header`, and a header set by a middleware has to
    // survive onto the Response it returns.
    const res = await app.request('/me');
    expect(res.headers.get('www-authenticate')).toMatch(/^Bearer error="/);
  });
});

describe('authorization guards', () => {
  it('admits a caller with the required role', async () => {
    const pair = await auth.createSession(ADMIN);
    const res = await app.request('/admin', { headers: bearer(pair.accessToken) });

    expect(res.status).toBe(200);
    expect(handlerRan).toBe(true);
  });

  it('refuses a caller without it, and does not run the handler', async () => {
    const pair = await auth.createSession(ALICE);
    const res = await app.request('/admin', { headers: bearer(pair.accessToken) });

    expect(res.status).toBe(403);
    expect(handlerRan).toBe(false);
  });

  it('short-circuits a chain at the first failure', async () => {
    // No token at all: verify() must answer, and requireRole() must never run.
    const res = await app.request('/admin');

    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: { code: 'TOKEN_MISSING' } });
    expect(handlerRan).toBe(false);
  });

  it('refuses a missing scope', async () => {
    const pair = await auth.createSession(ALICE);
    const res = await app.request('/scoped', { headers: bearer(pair.accessToken) });

    expect(res.status).toBe(403);
    expect(handlerRan).toBe(false);
  });

  it('reads route parameters for an ownership check', async () => {
    // Hono exposes params through a function rather than a property, so this
    // is the test that proves the request view translates them.
    const pair = await auth.createSession(ALICE);

    const own = await app.request('/users/user_alice/orders', {
      headers: bearer(pair.accessToken),
    });
    expect(own.status).toBe(200);

    handlerRan = false;
    const other = await app.request('/users/user_bob/orders', {
      headers: bearer(pair.accessToken),
    });
    expect(other.status).toBe(403);
    expect(handlerRan).toBe(false);
  });
});

describe('the opt-in body parse', () => {
  it('exposes the body to a selector when enabled', async () => {
    const pair = await auth.createSession(ALICE);
    const res = await app.request('/orders', {
      method: 'POST',
      headers: { ...bearer(pair.accessToken), 'content-type': 'application/json' },
      body: JSON.stringify({ owner: 'user_alice' }),
    });

    expect(res.status).toBe(200);
    expect(handlerRan).toBe(true);
  });

  it('refuses when the body names someone else', async () => {
    const pair = await auth.createSession(ALICE);
    const res = await app.request('/orders', {
      method: 'POST',
      headers: { ...bearer(pair.accessToken), 'content-type': 'application/json' },
      body: JSON.stringify({ owner: 'user_bob' }),
    });

    expect(res.status).toBe(403);
    expect(handlerRan).toBe(false);
  });

  it('fails the check on a malformed body rather than erroring', async () => {
    // A selector that finds nothing fails its check — the fail-closed outcome
    // `ValueSelector` already specifies — rather than becoming a 500.
    const pair = await auth.createSession(ALICE);
    const res = await app.request('/orders', {
      method: 'POST',
      headers: { ...bearer(pair.accessToken), 'content-type': 'application/json' },
      body: 'not json{',
    });

    expect(res.status).toBe(403);
    expect(handlerRan).toBe(false);
  });

  it('leaves the body readable by the route handler', async () => {
    // Hono caches the parse, so reading it in middleware must not consume it.
    const local = new Hono();
    local.use('/echo', toHono(auth.verify(), { parseJsonBody: true }));
    local.post('/echo', async (c) => c.json({ seen: await c.req.json() }));

    const pair = await auth.createSession(ALICE);
    const res = await local.request('/echo', {
      method: 'POST',
      headers: { ...bearer(pair.accessToken), 'content-type': 'application/json' },
      body: JSON.stringify({ hello: 'world' }),
    });

    expect(await res.json()).toEqual({ seen: { hello: 'world' } });
  });
});

describe('step-up through the adapter', () => {
  it('admits a session that just authenticated', async () => {
    const pair = await auth.createSession(ALICE);
    const res = await app.request('/sensitive', {
      method: 'POST',
      headers: bearer(pair.accessToken),
    });

    expect(res.status).toBe(200);
  });

  it('refuses a stale authentication even with a freshly minted token', async () => {
    const local = new Hono();
    local.use('/sensitive', toHono([auth.verify(), auth.requireFreshAuth(1)]));
    local.post('/sensitive', (c) => {
      handlerRan = true;
      return c.json({ ok: true });
    });

    const pair = await auth.createSession(ALICE);
    const refreshed = await auth.refresh(pair.refreshToken);
    await new Promise((resolve) => setTimeout(resolve, 1100));

    const res = await local.request('/sensitive', {
      method: 'POST',
      headers: bearer(refreshed.accessToken),
    });

    expect(res.status).toBe(403);
    expect(handlerRan).toBe(false);
  });
});

describe('adapter contract', () => {
  it('refuses an empty chain rather than permitting everything', () => {
    expect(() => toHono([])).toThrow(/at least one middleware/);
  });

  it('stores the identity under a namespaced context key', async () => {
    // A plain `auth` key is shared with every other middleware in the app, and
    // a collision would silently replace an identity rather than fail.
    const local = new Hono();
    local.use('/probe', toHono(auth.verify()));
    local.get('/probe', (c) => c.json({ key: c.get(AUTH_CONTEXT_KEY as never) !== undefined }));

    const pair = await auth.createSession(ALICE);
    const res = await local.request('/probe', { headers: bearer(pair.accessToken) });

    expect(await res.json()).toEqual({ key: true });
  });

  it('throws a clear error when getAuth runs without verify', () => {
    const fake = { get: () => undefined } as unknown as HonoLikeContext;
    expect(() => getAuth(fake)).toThrow(/Mount toHono\(auth\.verify\(\)\)/);
  });

  it('surfaces an unexpected middleware failure rather than hanging', async () => {
    // A middleware that never settles would hang the request. A 500 is a far
    // better failure than a timeout.
    const local = new Hono();
    local.use('/boom', toHono(() => {
      throw new Error('middleware exploded');
    }));
    local.get('/boom', (c) => c.json({ ok: true }));

    const res = await local.request('/boom');
    expect(res.status).toBe(500);
  });
});
