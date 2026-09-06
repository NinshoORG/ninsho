import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Koa from 'koa';
import Router from '@koa/router';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import type { Principal } from '@ninsho/core';
import { Ninsho } from '../ninsho.js';
import { MemoryStore } from '../store/memory.js';
import { toKoa, getAuth, AUTH_STATE_KEY, type KoaLikeContext } from '../koa.js';

/**
 * The Koa adapter, against real Koa over real HTTP.
 *
 * ─── The case that matters ────────────────────────────────────────────────
 * A Koa middleware halts by *not calling* `next()`. There is no return value
 * saying so, no `Response` to hand back — the absence of a call is the whole
 * signal. Translating "the Ninsho middleware wrote a response" into that
 * wrongly, in the direction of "continue", produces an authorization check
 * that sets a 403 and then lets the route handler overwrite it with the
 * resource.
 *
 * That failure is invisible to a test asserting only on status codes, because
 * the handler's own `ctx.status = 200` lands last. So every negative test here
 * asserts the route handler did not run, and does it against real Koa: a
 * stubbed context would confirm my expectations of Koa and nothing else.
 * ──────────────────────────────────────────────────────────────────────────
 */

const ALICE: Principal = { userId: 'user_alice', roles: ['user'], scopes: ['profile:read'] };
const ADMIN: Principal = { userId: 'user_root', roles: ['admin'], scopes: ['profile:read'] };

let auth: Ninsho;
let store: MemoryStore;
let server: Server;
let baseUrl: string;
/** Set by any route that actually ran, so a leaked denial is visible. */
let handlerRan: boolean;

/** Koa ships no body parser, so this is the smallest honest stand-in for one. */
const jsonBody: Koa.Middleware = async (ctx, next) => {
  if (ctx.method === 'POST') {
    const chunks: Buffer[] = [];
    for await (const chunk of ctx.req) chunks.push(chunk as Buffer);
    if (chunks.length > 0) {
      try {
        (ctx.request as { body?: unknown }).body = JSON.parse(Buffer.concat(chunks).toString());
      } catch {
        // Left absent, which is what a guard's selector should then see.
      }
    }
  }
  await next();
};

beforeEach(async () => {
  store = new MemoryStore();
  auth = new Ninsho({ store });
  handlerRan = false;

  const app = new Koa();
  const router = new Router();

  const ran = <T>(body: T) => (ctx: Koa.Context): void => {
    handlerRan = true;
    ctx.body = body;
  };

  router.get('/me', toKoa(auth.verify()) as Koa.Middleware, (ctx) => {
    handlerRan = true;
    const context = getAuth(ctx as unknown as KoaLikeContext);
    ctx.body = { userId: context.userId, roles: context.roles };
  });

  router.get(
    '/admin',
    toKoa([auth.verify(), auth.requireRole('admin')]) as Koa.Middleware,
    ran({ ok: true }),
  );

  router.get(
    '/scoped',
    toKoa([auth.verify(), auth.requireScope('orders:write')]) as Koa.Middleware,
    ran({ ok: true }),
  );

  router.get(
    '/users/:id/orders',
    toKoa([auth.verify(), auth.requireOwner((req) => req.params?.['id'])]) as Koa.Middleware,
    ran({ orders: [] }),
  );

  router.post(
    '/sensitive',
    toKoa([auth.verify(), auth.requireFreshAuth(300)]) as Koa.Middleware,
    ran({ ok: true }),
  );

  // A one-second window, so a real session can be made stale by waiting.
  router.post(
    '/very-sensitive',
    toKoa([auth.verify(), auth.requireFreshAuth(1)]) as Koa.Middleware,
    ran({ ok: true }),
  );

  router.post(
    '/orders',
    toKoa([
      auth.verify(),
      auth.requireOwner((req) => (req.body as { owner?: string })?.owner),
    ]) as Koa.Middleware,
    ran({ ok: true }),
  );

  // Two separate toKoa() calls over one route, which is how a real application
  // mounts an app-wide verify and a per-route guard.
  router.get(
    '/composed',
    toKoa(auth.verify()) as Koa.Middleware,
    toKoa(auth.requireRole('admin')) as Koa.Middleware,
    ran({ ok: true }),
  );

  app.use(jsonBody);
  app.use(router.routes());
  app.use(router.allowedMethods());

  server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await store.close();
});

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

const get = (path: string, headers: Record<string, string> = {}): Promise<Response> =>
  fetch(`${baseUrl}${path}`, { headers });

const post = (
  path: string,
  headers: Record<string, string> = {},
  body?: unknown,
): Promise<Response> =>
  fetch(`${baseUrl}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });

describe('verify()', () => {
  it('admits a valid token and exposes the identity to the handler', async () => {
    const pair = await auth.createSession(ALICE);
    const res = await get('/me', bearer(pair.accessToken));

    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ userId: 'user_alice', roles: ['user'] });
    expect(handlerRan).toBe(true);
  });

  it('rejects a missing token without running the handler', async () => {
    const res = await get('/me');

    expect(res.status).toBe(401);
    // The assertion that matters: a denial must not fall through.
    expect(handlerRan).toBe(false);
  });

  it('rejects a garbage token without running the handler', async () => {
    const res = await get('/me', bearer('not-a-real-token'));

    expect(res.status).toBe(401);
    expect(handlerRan).toBe(false);
  });

  it('rejects a revoked token', async () => {
    const pair = await auth.createSession(ALICE);
    const context = await auth.engine.verify(pair.accessToken);
    await auth.revokeSession(context.sessionId, 'logout');

    const res = await get('/me', bearer(pair.accessToken));
    expect(res.status).toBe(401);
    expect(handlerRan).toBe(false);
  });

  it('sends Ninsho’s error body, not Koa’s default', async () => {
    const res = await get('/me');
    expect(await res.json()).toMatchObject({ error: { code: 'TOKEN_MISSING' } });
  });

  it('carries the WWW-Authenticate challenge through Koa', async () => {
    // `setHeader` maps to `ctx.set`, and a header set by a middleware has to
    // survive onto the response Koa finally writes.
    const res = await get('/me');
    expect(res.headers.get('www-authenticate')).toMatch(/^Bearer error="/);
  });
});

describe('a repeated Authorization header', () => {
  /**
   * Written to find out what actually happens, and it was not what I assumed.
   *
   * Node's HTTP server does not join duplicate `Authorization` headers the way
   * it joins ordinary ones — it keeps the **first** and silently discards the
   * rest. Measured: two headers on the wire, `rawHeaders` shows both, and
   * `req.headers.authorization` shows one clean credential. So the array check
   * in `extractBearer` could never fire on any Node server, and this request
   * was answered 200 with the first token before `rawHeaders` was threaded
   * through.
   *
   * That is exactly the desync the check exists to prevent: a proxy that
   * validates the last occurrence and an application that reads the first
   * disagree about who is calling.
   */
  it('is refused, and the handler never runs', async () => {
    const pair = await auth.createSession(ALICE);
    const http = await import('node:http');

    const { status, body } = await new Promise<{ status: number; body: string }>(
      (resolve, reject) => {
        const url = new URL(`${baseUrl}/me`);
        const request = http.request(
          {
            hostname: url.hostname,
            port: url.port,
            path: url.pathname,
            method: 'GET',
            // The flat `[name, value, name, value]` form, which is the only
            // way to put a genuinely repeated header on the wire.
            headers: [
              'host',
              url.host,
              'authorization',
              `Bearer ${pair.accessToken}`,
              'authorization',
              'Bearer other',
            ],
          },
          (response) => {
            let text = '';
            response.on('data', (chunk) => (text += String(chunk)));
            response.on('end', () =>
              resolve({ status: response.statusCode ?? 0, body: text }),
            );
          },
        );
        request.on('error', reject);
        request.end();
      },
    );

    expect(status).toBe(401);
    expect(JSON.parse(body)).toMatchObject({ error: { code: 'TOKEN_MISSING' } });
    expect(handlerRan).toBe(false);
  });
});

describe('authorization guards', () => {
  it('admits a caller with the required role', async () => {
    const pair = await auth.createSession(ADMIN);
    const res = await get('/admin', bearer(pair.accessToken));

    expect(res.status).toBe(200);
    expect(handlerRan).toBe(true);
  });

  it('refuses a caller without the role, and the handler never runs', async () => {
    const pair = await auth.createSession(ALICE);
    const res = await get('/admin', bearer(pair.accessToken));

    expect(res.status).toBe(403);
    expect(handlerRan).toBe(false);
  });

  it('refuses a caller without the scope', async () => {
    const pair = await auth.createSession(ALICE);
    const res = await get('/scoped', bearer(pair.accessToken));

    expect(res.status).toBe(403);
    expect(handlerRan).toBe(false);
  });

  it('reads a route parameter for the ownership check', async () => {
    // `@koa/router` puts them on `ctx.params`, which is where the adapter
    // looks. If it looked elsewhere every ownership check would fail open or
    // closed for the wrong reason.
    const pair = await auth.createSession(ALICE);

    const mine = await get('/users/user_alice/orders', bearer(pair.accessToken));
    expect(mine.status).toBe(200);
    expect(handlerRan).toBe(true);

    handlerRan = false;
    const theirs = await get('/users/user_bob/orders', bearer(pair.accessToken));
    expect(theirs.status).toBe(403);
    expect(handlerRan).toBe(false);
  });

  it('reads a parsed body for the ownership check when one is present', async () => {
    const pair = await auth.createSession(ALICE);

    const mine = await post('/orders', bearer(pair.accessToken), { owner: 'user_alice' });
    expect(mine.status).toBe(200);

    handlerRan = false;
    const theirs = await post('/orders', bearer(pair.accessToken), { owner: 'user_bob' });
    expect(theirs.status).toBe(403);
    expect(handlerRan).toBe(false);
  });

  it('refuses when no body parser ran and the selector finds nothing', async () => {
    // Koa ships no body parser, so `ctx.request.body` may simply be absent.
    // The fail-closed outcome is the specified one: a selector that finds
    // nothing fails its check rather than admitting the request.
    const pair = await auth.createSession(ALICE);
    const res = await fetch(`${baseUrl}/orders`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...bearer(pair.accessToken) },
    });

    expect(res.status).toBe(403);
    expect(handlerRan).toBe(false);
  });

  it('refuses a stale authentication even with a freshly minted token', async () => {
    // The point of `requireFreshAuth`: rotation mints a new access token but
    // does not reset when the user actually authenticated.
    const pair = await auth.createSession(ALICE);
    const refreshed = await auth.refresh(pair.refreshToken);
    await new Promise((resolve) => setTimeout(resolve, 1100));

    const res = await post('/very-sensitive', bearer(refreshed.accessToken));

    expect(res.status).toBe(403);
    expect(handlerRan).toBe(false);
  });

  it('admits a freshly authenticated caller', async () => {
    const pair = await auth.createSession(ALICE);
    const res = await post('/sensitive', bearer(pair.accessToken));

    expect(res.status).toBe(200);
    expect(handlerRan).toBe(true);
  });
});

describe('composition', () => {
  it('lets two separate toKoa() calls share one identity', async () => {
    // Each call builds its own request view, so the second must find the
    // identity the first established or a correctly written application gets a
    // 500 instead of a 200.
    const pair = await auth.createSession(ADMIN);
    const res = await get('/composed', bearer(pair.accessToken));

    expect(res.status).toBe(200);
    expect(handlerRan).toBe(true);
  });

  it('still denies through a composed chain', async () => {
    const pair = await auth.createSession(ALICE);
    const res = await get('/composed', bearer(pair.accessToken));

    expect(res.status).toBe(403);
    expect(handlerRan).toBe(false);
  });
});

describe('the adapter itself', () => {
  it('refuses an empty chain rather than permitting every request', () => {
    // An empty chain reads as a guard and would admit everything behind it.
    expect(() => toKoa([])).toThrow(/at least one middleware/);
  });

  it('throws a directed error when getAuth runs before verify', () => {
    const ctx = { state: {} } as unknown as KoaLikeContext;
    expect(() => getAuth(ctx)).toThrow(/Mount toKoa\(auth\.verify\(\)\)/);
  });

  it('stores the identity under a namespaced state key', async () => {
    // `ctx.state` is shared with every other middleware in the application; a
    // plain `auth` key would silently replace someone else's value.
    expect(AUTH_STATE_KEY).toBe('ninshoAuth');

    const pair = await auth.createSession(ALICE);
    const res = await get('/me', bearer(pair.accessToken));
    expect(res.status).toBe(200);
  });

  it('imports nothing from Koa', async () => {
    // The adapter is structural. If it ever imported Koa, every consumer of
    // `@ninsho/server` would pull the framework into their bundle.
    const source = await import('node:fs/promises').then((fs) =>
      fs.readFile(new URL('../koa.ts', import.meta.url), 'utf8'),
    );
    expect(source).not.toMatch(/from 'koa'/);
    expect(source).not.toMatch(/from '@koa\/router'/);
  });
});
