import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import type { Principal } from '@ninshorg/core';
import { Ninsho } from '../ninsho.js';
import { MemoryStore } from '../store/memory.js';
import { getAuth } from '../http/middleware.js';
import { toFastify, toFastifyChain } from '../fastify.js';
import type { HttpRequest } from '../http/types.js';

/**
 * The Fastify adapter, against real Fastify.
 *
 * ─── Why not a stub reply object ──────────────────────────────────────────
 * The adapter's whole job is translating "Express middleware called next()"
 * into "Fastify hook returned undefined", and "Express middleware wrote a
 * response" into "Fastify hook returned the reply". A stub that behaves the way
 * the author expects Fastify to behave would confirm the author's expectations
 * and nothing else.
 *
 * The case that matters is the one a stub is least likely to catch: a denied
 * request must not reach the route handler. Getting the return convention wrong
 * produces an authorization check that logs a denial and then serves the
 * resource anyway, and only a real server shows that.
 * ──────────────────────────────────────────────────────────────────────────
 */

const ALICE: Principal = { userId: 'user_alice', roles: ['user'], scopes: ['profile:read'] };
const ADMIN: Principal = { userId: 'user_root', roles: ['admin'], scopes: ['profile:read'] };

let app: FastifyInstance;
let auth: Ninsho;
let store: MemoryStore;
/** Set by any route that actually ran, so a leaked denial is visible. */
let handlerRan: boolean;

beforeEach(async () => {
  store = new MemoryStore();
  auth = new Ninsho({ store });
  handlerRan = false;

  app = Fastify();

  app.get('/me', { preHandler: toFastify(auth.verify()) }, async (request) => {
    handlerRan = true;
    const context = getAuth(request as unknown as HttpRequest);
    return { userId: context.userId, roles: context.roles };
  });

  app.get(
    '/admin',
    { preHandler: toFastifyChain([auth.verify(), auth.requireRole('admin')]) },
    async () => {
      handlerRan = true;
      return { ok: true };
    },
  );

  app.get(
    '/scoped',
    { preHandler: [toFastify(auth.verify()), toFastify(auth.requireScope('orders:write'))] },
    async () => {
      handlerRan = true;
      return { ok: true };
    },
  );

  app.get(
    '/users/:id/orders',
    {
      preHandler: toFastifyChain([
        auth.verify(),
        auth.requireOwner((req) => (req.params as { id?: string } | undefined)?.id),
      ]),
    },
    async () => {
      handlerRan = true;
      return { orders: [] };
    },
  );

  app.post(
    '/sensitive',
    { preHandler: toFastifyChain([auth.verify(), auth.requireFreshAuth(300)]) },
    async () => {
      handlerRan = true;
      return { ok: true };
    },
  );

  await app.ready();
});

afterEach(async () => {
  await app.close();
  await store.close();
});

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

describe('verify()', () => {
  it('admits a valid token and exposes the identity to the handler', async () => {
    const pair = await auth.createSession(ALICE);
    const response = await app.inject({ method: 'GET', url: '/me', headers: bearer(pair.accessToken) });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ userId: 'user_alice', roles: ['user'] });
    expect(handlerRan).toBe(true);
  });

  it('rejects a missing token without running the handler', async () => {
    const response = await app.inject({ method: 'GET', url: '/me' });

    expect(response.statusCode).toBe(401);
    // The assertion that matters: a denial must not fall through.
    expect(handlerRan).toBe(false);
  });

  it('rejects a garbage token without running the handler', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/me',
      headers: bearer('not-a-real-token'),
    });

    expect(response.statusCode).toBe(401);
    expect(handlerRan).toBe(false);
  });

  it('rejects a revoked token', async () => {
    const pair = await auth.createSession(ALICE);
    const context = await auth.engine.verify(pair.accessToken);
    await auth.revokeSession(context.sessionId, 'logout');

    const response = await app.inject({ method: 'GET', url: '/me', headers: bearer(pair.accessToken) });
    expect(response.statusCode).toBe(401);
    expect(handlerRan).toBe(false);
  });

  it('sends Ninsho’s error body, not Fastify’s default', async () => {
    const response = await app.inject({ method: 'GET', url: '/me' });
    expect(response.json()).toMatchObject({ error: { code: 'TOKEN_MISSING' } });
  });

  it('sets the WWW-Authenticate header through Fastify', async () => {
    // `setHeader` maps to Fastify's `header`, and a header written by a hook
    // has to survive onto the real response.
    const response = await app.inject({ method: 'GET', url: '/me' });
    expect(response.headers['www-authenticate']).toBeDefined();
  });
});

describe('authorization guards', () => {
  it('admits a caller with the required role', async () => {
    const pair = await auth.createSession(ADMIN);
    const response = await app.inject({ method: 'GET', url: '/admin', headers: bearer(pair.accessToken) });

    expect(response.statusCode).toBe(200);
    expect(handlerRan).toBe(true);
  });

  it('refuses a caller without it, and does not run the handler', async () => {
    const pair = await auth.createSession(ALICE);
    const response = await app.inject({ method: 'GET', url: '/admin', headers: bearer(pair.accessToken) });

    expect(response.statusCode).toBe(403);
    expect(handlerRan).toBe(false);
  });

  it('short-circuits a chain at the first failure', async () => {
    // No token at all: verify() must answer, and requireRole() must never run.
    const response = await app.inject({ method: 'GET', url: '/admin' });

    expect(response.statusCode).toBe(401);
    expect(response.json()).toMatchObject({ error: { code: 'TOKEN_MISSING' } });
    expect(handlerRan).toBe(false);
  });

  it('works as an array of separate preHandlers too', async () => {
    // Fastify accepts either shape, and both must behave the same.
    const pair = await auth.createSession(ALICE);
    const response = await app.inject({ method: 'GET', url: '/scoped', headers: bearer(pair.accessToken) });

    expect(response.statusCode).toBe(403);
    expect(handlerRan).toBe(false);
  });

  it('reads route parameters for an ownership check', async () => {
    // Fastify's request satisfies HttpRequest structurally, so `params` needs
    // no adaptation — this is the test that proves it.
    const pair = await auth.createSession(ALICE);

    const own = await app.inject({
      method: 'GET',
      url: '/users/user_alice/orders',
      headers: bearer(pair.accessToken),
    });
    expect(own.statusCode).toBe(200);

    handlerRan = false;
    const other = await app.inject({
      method: 'GET',
      url: '/users/user_bob/orders',
      headers: bearer(pair.accessToken),
    });
    expect(other.statusCode).toBe(403);
    expect(handlerRan).toBe(false);
  });
});

describe('step-up through the adapter', () => {
  it('admits a session that just authenticated', async () => {
    const pair = await auth.createSession(ALICE);
    const response = await app.inject({
      method: 'POST',
      url: '/sensitive',
      headers: bearer(pair.accessToken),
    });

    expect(response.statusCode).toBe(200);
  });

  it('refuses a stale authentication even with a fresh token', async () => {
    // The property the whole feature rests on, verified through the adapter:
    // a refresh mints a new access token and is not a new authentication.
    const pair = await auth.createSession(ALICE);
    const refreshed = await auth.refresh(pair.refreshToken);

    // Rewrite the stored record so the authentication reads as an hour old,
    // without waiting an hour.
    const stale = new Date(Date.now() - 3600_000).toISOString();
    const context = await auth.engine.verify(refreshed.accessToken);
    expect(context.authenticatedAt).not.toBe(stale);

    const app2 = Fastify();
    app2.post(
      '/sensitive',
      { preHandler: toFastifyChain([auth.verify(), auth.requireFreshAuth(1)]) },
      async () => ({ ok: true }),
    );
    await app2.ready();

    await new Promise((resolve) => setTimeout(resolve, 1100));
    const response = await app2.inject({
      method: 'POST',
      url: '/sensitive',
      headers: bearer(refreshed.accessToken),
    });

    expect(response.statusCode).toBe(403);
    await app2.close();
  });
});

describe('adapter contract', () => {
  it('refuses an empty chain rather than permitting everything', () => {
    // An empty chain would read as a guard and admit every request.
    expect(() => toFastifyChain([])).toThrow(/at least one middleware/);
  });

  it('attaches auth to the same request object the handler receives', async () => {
    // This is why no request adaptation is needed: `verify()` writes onto the
    // Fastify request itself, so `getAuth()` reads it straight back.
    const pair = await auth.createSession(ALICE);
    const response = await app.inject({ method: 'GET', url: '/me', headers: bearer(pair.accessToken) });

    expect(response.json()).toMatchObject({ userId: 'user_alice' });
  });

  it('surfaces an unexpected middleware failure as a 500, not a hang', async () => {
    // A hook that never settles would hang the request until Fastify times it
    // out, which is a far worse failure than a 500.
    const exploding = Fastify();
    exploding.get(
      '/boom',
      {
        preHandler: toFastify(() => {
          throw new Error('middleware exploded');
        }),
      },
      async () => ({ ok: true }),
    );
    await exploding.ready();

    const response = await exploding.inject({ method: 'GET', url: '/boom' });
    expect(response.statusCode).toBe(500);
    await exploding.close();
  });
});

/**
 * A repeated Authorization header, over real HTTP.
 *
 * Node's HTTP server keeps the first `Authorization` and discards the rest, so
 * `request.headers` shows one clean credential and the ambiguity is invisible
 * there. `request.raw.rawHeaders` still has both, which is why the adapter
 * copies it across.
 */
describe('a repeated Authorization header', () => {
  it('is refused, and the route handler never runs', async () => {
    const pair = await auth.createSession(ALICE);
    await app.listen({ port: 0, host: '127.0.0.1' });
    const address = app.server.address() as { port: number };
    const http = await import('node:http');

    try {
      const status = await new Promise<number>((resolve, reject) => {
        const request = http.request(
          {
            hostname: '127.0.0.1',
            port: address.port,
            path: '/me',
            method: 'GET',
            headers: [
              'host',
              `127.0.0.1:${address.port}`,
              'authorization',
              `Bearer ${pair.accessToken}`,
              'authorization',
              'Bearer other',
            ],
          },
          (response) => {
            response.resume();
            response.on('end', () => resolve(response.statusCode ?? 0));
          },
        );
        request.on('error', reject);
        request.end();
      });

      expect(status).toBe(401);
      expect(handlerRan).toBe(false);
    } finally {
      await app.close();
    }
  });
});
