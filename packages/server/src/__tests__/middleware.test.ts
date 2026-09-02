import { describe, it, expect, beforeEach } from 'vitest';
import type { AuthContext, Principal } from '@ninsho/core';
import { MemoryStore } from '../store/memory.js';
import { OpaqueEngine } from '../engine/opaque.js';
import { PasetoEngine } from '../engine/paseto.js';
import { KeyRing, generateKeyPair } from '../keys/keyring.js';
import { MemoryAuditSink } from '../audit.js';
import {
  createErrorHandler,
  createRequireAllRoles,
  createRequireOwner,
  createRequireRole,
  createRequireScope,
  createRequireTenant,
  createVerify,
  getAuth,
} from '../http/middleware.js';
import type { HttpRequest, HttpResponse, Middleware } from '../http/types.js';

const ALICE: Principal = {
  userId: 'user_alice',
  roles: ['user'],
  scopes: ['orders:read'],
};

/** Captures what a middleware wrote, mimicking the Express response surface. */
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

interface RunResult {
  readonly res: FakeResponse;
  readonly nextCalled: boolean;
  readonly nextError: unknown;
  readonly code: string | undefined;
}

/** Runs a middleware to completion and reports what happened. */
async function run(mw: Middleware, req: HttpRequest): Promise<RunResult> {
  const res = new FakeResponse();
  let nextCalled = false;
  let nextError: unknown;

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
      mw(req, res, (error?: unknown) => {
        nextCalled = true;
        nextError = error;
        done();
      }),
    ).then(() => {
      setTimeout(done, 20);
    });
  });

  const body = res.body as { error?: { code?: string } } | undefined;
  return { res, nextCalled, nextError, code: body?.error?.code };
}

const request = (
  overrides: Partial<HttpRequest> & { token?: string } = {},
): HttpRequest => {
  const { token, ...rest } = overrides;
  return {
    headers: token === undefined ? {} : { authorization: `Bearer ${token}` },
    ...rest,
  } as HttpRequest;
};

/** A request that has already been authenticated as `auth`. */
const authed = (auth: Partial<AuthContext>, extra: Partial<HttpRequest> = {}): HttpRequest =>
  ({
    headers: {},
    ...extra,
    auth: {
      userId: 'user_alice',
      roles: ['user'],
      scopes: ['orders:read'],
      tokenId: 't1',
      sessionId: 's1',
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      strategy: 'opaque',
      ...auth,
    },
  }) as HttpRequest;

let store: MemoryStore;
let engine: OpaqueEngine;
let audit: MemoryAuditSink;

beforeEach(() => {
  store = new MemoryStore();
  engine = new OpaqueEngine(store, { accessTokenTtl: 300, clockToleranceSeconds: 5 });
  audit = new MemoryAuditSink();
});

const verify = (onStoreError: 'closed' | 'open' = 'closed'): Middleware =>
  createVerify({ engine, onStoreError, audit });

/**
 * RFC 7235 §3.1: "The server generating a 401 response MUST send a
 * WWW-Authenticate header field containing at least one challenge."
 *
 * Clients and HTTP libraries read it to decide how to retry. Omitting it makes
 * a 401 indistinguishable from a generic refusal.
 */
describe('the 401 challenge', () => {
  it('sends WWW-Authenticate on a missing credential', async () => {
    const result = await run(verify(), request());

    expect(result.res.statusCode).toBe(401);
    expect(result.res.headers.get('WWW-Authenticate')).toBe('Bearer error="TOKEN_MISSING"');
  });

  it('sends it on an invalid credential too', async () => {
    const result = await run(verify(), request({ token: 'garbage' }));

    expect(result.res.statusCode).toBe(401);
    expect(String(result.res.headers.get('WWW-Authenticate'))).toMatch(/^Bearer error="/);
  });

  it('carries only the code, never the detail', async () => {
    // The header is as public as the body and keeps the same separation:
    // `detail` explains the failure server-side and appears in neither. A
    // strict shape check is the assertion that proves it — the code itself is
    // meant to be public, so scanning for words inside it would test nothing.
    const result = await run(verify(), request({ token: 'garbage' }));
    const challenge = String(result.res.headers.get('WWW-Authenticate'));

    expect(challenge).toMatch(/^Bearer error="[A-Z_]+"$/);
  });

  it('does not send a challenge on a 403', async () => {
    // The caller authenticated; they are simply not permitted. Inviting them
    // to re-authenticate would be wrong advice.
    const issued = await engine.issue({
      principal: ALICE,
      sessionId: 's1',
      authenticatedAt: new Date().toISOString(),
    });
    const req = request({ token: issued.token });
    await run(verify(), req);

    const result = await run(createRequireRole(audit)('admin'), req);
    expect(result.res.statusCode).toBe(403);
    expect(result.res.headers.get('WWW-Authenticate')).toBeUndefined();
  });
});

describe('bearer extraction', () => {
  it('authenticates a valid token and populates req.auth', async () => {
    const issued = await engine.issue({ principal: ALICE, sessionId: 's1' , authenticatedAt: new Date().toISOString() });
    const req = request({ token: issued.token });

    const result = await run(verify(), req);

    expect(result.nextCalled).toBe(true);
    expect(req.auth).toMatchObject({ userId: 'user_alice', tokenId: issued.tokenId });
  });

  it('accepts a lowercase scheme, per RFC 7235', async () => {
    const issued = await engine.issue({ principal: ALICE, sessionId: 's1' , authenticatedAt: new Date().toISOString() });
    const req = { headers: { authorization: `bearer ${issued.token}` } } as HttpRequest;
    expect((await run(verify(), req)).nextCalled).toBe(true);
  });

  it.each([
    ['no header', {}],
    ['an empty header', { authorization: '' }],
    ['a Basic credential', { authorization: 'Basic dXNlcjpwYXNz' }],
    ['a bare token with no scheme', { authorization: 'abc123' }],
    ['the scheme alone', { authorization: 'Bearer' }],
    ['a scheme with only spaces', { authorization: 'Bearer    ' }],
    ['a scheme-prefixed lookalike', { authorization: 'NotBearer abc' }],
  ])('rejects %s with 401 TOKEN_MISSING', async (_label, headers) => {
    const result = await run(verify(), { headers } as HttpRequest);
    expect(result.res.statusCode).toBe(401);
    expect(result.code).toBe('TOKEN_MISSING');
    expect(result.nextCalled).toBe(false);
  });

  /**
   * Proxies disagree about how to collapse a repeated Authorization header, so
   * two systems in one request path can end up believing different credentials
   * were presented. Refusing is the only unambiguous answer.
   */
  it('refuses a repeated Authorization header rather than picking one', async () => {
    const issued = await engine.issue({ principal: ALICE, sessionId: 's1' , authenticatedAt: new Date().toISOString() });
    const req = {
      headers: { authorization: [`Bearer ${issued.token}`, 'Bearer other'] },
    } as unknown as HttpRequest;

    const result = await run(verify(), req);
    expect(result.code).toBe('TOKEN_MISSING');
  });

  it('rejects a well-formed but unknown token with 401 TOKEN_INVALID', async () => {
    const result = await run(verify(), request({ token: 'not-a-real-token' }));
    expect(result.res.statusCode).toBe(401);
    expect(result.code).toBe('TOKEN_INVALID');
  });

  /**
   * SECURITY: credentials must never travel in a URL. Query strings reach
   * access logs, browser history, Referer headers and analytics pipelines.
   */
  it('ignores a token supplied in the query string', async () => {
    const issued = await engine.issue({ principal: ALICE, sessionId: 's1' , authenticatedAt: new Date().toISOString() });
    const req = { headers: {}, query: { access_token: issued.token } } as HttpRequest;

    const result = await run(verify(), req);
    expect(result.code).toBe('TOKEN_MISSING');
  });

  it('never leaks internal detail into the response body', async () => {
    const result = await run(verify(), request({ token: 'garbage' }));
    const serialized = JSON.stringify(result.res.body);
    expect(serialized).not.toMatch(/store|record|hash|ninsho:v1/i);
  });
});

/**
 * ─── Audit finding H3 ─────────────────────────────────────────────────────
 * The predecessor defaulted to fail-open, so a Redis outage silently disabled
 * revocation — its headline feature — with no way to notice.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('store outage behaviour', () => {
  /** A store whose every read throws, simulating an outage. */
  function brokenStore(): MemoryStore {
    const broken = new MemoryStore();
    broken.get = async (): Promise<never> => {
      throw new Error('ECONNREFUSED 10.0.0.5:6379');
    };
    broken.exists = async (): Promise<never> => {
      throw new Error('ECONNREFUSED 10.0.0.5:6379');
    };
    return broken;
  }

  it('refuses with 503 when fail-closed', async () => {
    const failing = new OpaqueEngine(brokenStore(), {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
    });
    const mw = createVerify({ engine: failing, onStoreError: 'closed', audit });

    const result = await run(mw, request({ token: 'anything' }));
    expect(result.res.statusCode).toBe(503);
    expect(result.code).toBe('SERVICE_UNAVAILABLE');
  });

  it('does not leak the store address in the 503', async () => {
    const failing = new OpaqueEngine(brokenStore(), {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
    });
    const mw = createVerify({ engine: failing, onStoreError: 'closed', audit });

    const result = await run(mw, request({ token: 'anything' }));
    expect(JSON.stringify(result.res.body)).not.toContain('10.0.0.5');
  });

  it('records the refusal for later reconstruction', async () => {
    const failing = new OpaqueEngine(brokenStore(), {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
    });
    await run(
      createVerify({ engine: failing, onStoreError: 'closed', audit }),
      request({ token: 'anything' }),
    );
    expect(audit.ofType('store.unavailable')).toHaveLength(1);
  });

  /**
   * The asymmetry that governs what fail-open can mean. Under `opaque` the
   * store holds the identity itself, so an outage leaves nothing to fall back
   * on — "open" would mean admitting a request whose caller is unknown. The
   * middleware refuses regardless of configuration; this is the runtime
   * backstop behind the config-time rejection.
   */
  it('still refuses under fail-open when the engine cannot identify without the store', async () => {
    const failing = new OpaqueEngine(brokenStore(), {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
    });
    expect(failing.canVerifyWithoutStore).toBe(false);

    const mw = createVerify({ engine: failing, onStoreError: 'open', audit });
    const result = await run(mw, request({ token: 'anything' }));

    expect(result.res.statusCode).toBe(503);
  });

  it('admits a signature-valid token under fail-open when the engine can', async () => {
    // PASETO verifies locally, so only the denylist lookup was lost.
    const key = generateKeyPair('k');
    const good = new MemoryStore();
    const pasetoEngine = new PasetoEngine(good, new KeyRing({ active: key }), {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'https://id.test',
      audience: 'api',
    });
    const issued = await pasetoEngine.issue({ principal: ALICE, sessionId: 's1' , authenticatedAt: new Date().toISOString() });

    const failingEngine = new PasetoEngine(brokenStore(), new KeyRing({ active: key }), {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'https://id.test',
      audience: 'api',
    });
    expect(failingEngine.canVerifyWithoutStore).toBe(true);

    const req = request({ token: issued.token });
    const result = await run(
      createVerify({ engine: failingEngine, onStoreError: 'open', audit }),
      req,
    );

    expect(result.nextCalled).toBe(true);
    expect(req.auth?.userId).toBe('user_alice');
  });

  it('records every fail-open admission, since revoked tokens were accepted', async () => {
    const key = generateKeyPair('k');
    const good = new PasetoEngine(new MemoryStore(), new KeyRing({ active: key }), {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'https://id.test',
      audience: 'api',
    });
    const issued = await good.issue({ principal: ALICE, sessionId: 's1' , authenticatedAt: new Date().toISOString() });

    const failing = new PasetoEngine(brokenStore(), new KeyRing({ active: key }), {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'https://id.test',
      audience: 'api',
    });

    await run(
      createVerify({ engine: failing, onStoreError: 'open', audit }),
      request({ token: issued.token }),
    );

    const events = audit.ofType('store.unavailable');
    expect(events).toHaveLength(1);
    expect(events[0]?.reason).toBe('admitted_without_revocation_check');
    expect(events[0]?.userId).toBe('user_alice');
  });
});

describe('getAuth', () => {
  it('returns the context when verify has run', () => {
    expect(getAuth(authed({})).userId).toBe('user_alice');
  });

  /**
   * Throwing turns a middleware-ordering mistake into a loud failure on the
   * first request, instead of `req.auth?.userId` quietly evaluating to
   * undefined inside an ownership comparison.
   */
  it('throws a directive error when verify has not run', () => {
    expect(() => getAuth({ headers: {} } as HttpRequest)).toThrow(/Mount verify\(\) before/);
  });
});

describe('requireRole', () => {
  const requireRole = (r: string | string[]): Middleware => createRequireRole(audit)(r);

  it('allows a caller holding the role', async () => {
    expect((await run(requireRole('user'), authed({}))).nextCalled).toBe(true);
  });

  it('allows a caller holding any one of several roles', async () => {
    const req = authed({ roles: ['support'] });
    expect((await run(requireRole(['admin', 'support']), req)).nextCalled).toBe(true);
  });

  it('refuses with 403 when the role is absent', async () => {
    const result = await run(requireRole('admin'), authed({}));
    expect(result.res.statusCode).toBe(403);
    expect(result.code).toBe('FORBIDDEN');
  });

  it('uses 403, not 401 — the caller is authenticated, just not permitted', async () => {
    expect((await run(requireRole('admin'), authed({}))).res.statusCode).not.toBe(401);
  });

  it('records the denial', async () => {
    await run(requireRole('admin'), authed({}));
    expect(audit.ofType('authz.denied')).toHaveLength(1);
  });

  it('is not fooled by a role that is a prefix of the required one', async () => {
    const result = await run(requireRole('admin'), authed({ roles: ['admin-readonly'] }));
    expect(result.res.statusCode).toBe(403);
  });

  it('is case-sensitive', async () => {
    expect((await run(requireRole('Admin'), authed({ roles: ['admin'] }))).res.statusCode).toBe(403);
  });

  /** An empty list would permit everyone while reading as a restriction. */
  it('refuses to be constructed with no roles', () => {
    expect(() => requireRole([])).toThrow(/at least one role/);
  });

  it('throws if verify did not run', async () => {
    const result = await run(requireRole('user'), { headers: {} } as HttpRequest);
    expect(result.res.statusCode).toBe(500);
  });
});

describe('requireAllRoles', () => {
  const requireAll = (r: string[]): Middleware => createRequireAllRoles(audit)(r);

  it('allows a caller holding every role', async () => {
    const req = authed({ roles: ['admin', 'billing'] });
    expect((await run(requireAll(['admin', 'billing']), req)).nextCalled).toBe(true);
  });

  it('refuses when any role is missing', async () => {
    const req = authed({ roles: ['admin'] });
    expect((await run(requireAll(['admin', 'billing']), req)).res.statusCode).toBe(403);
  });
});

describe('requireScope', () => {
  const requireScope = (s: string | string[]): Middleware => createRequireScope(audit)(s);

  it('allows a caller holding the scope', async () => {
    expect((await run(requireScope('orders:read'), authed({}))).nextCalled).toBe(true);
  });

  it('refuses when the scope is absent', async () => {
    expect((await run(requireScope('orders:write'), authed({}))).res.statusCode).toBe(403);
  });

  it('does not treat a read scope as granting write', async () => {
    const req = authed({ scopes: ['orders:read'] });
    expect((await run(requireScope('orders:write'), req)).res.statusCode).toBe(403);
  });

  it('does not honour a wildcard that was never granted explicitly', async () => {
    // Implicit wildcard expansion is a common and dangerous convenience.
    const req = authed({ scopes: ['orders:*'] });
    expect((await run(requireScope('orders:write'), req)).res.statusCode).toBe(403);
  });
});

/**
 * ─── OWASP API Security #1 — broken object-level authorization ────────────
 * The shape is always the same: a route reads `/users/:id/orders`, the handler
 * trusts `:id` because the request was authenticated, and any signed-in user
 * reads any other user's data by changing a number.
 *
 * Authentication says who is calling. It says nothing about what they may
 * address. The predecessor offered nothing for this gap at all.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('requireOwner', () => {
  const byParam = (): Middleware =>
    createRequireOwner(audit)((req) => req.params?.['id']);

  it('allows a caller addressing their own resource', async () => {
    const req = authed({}, { params: { id: 'user_alice' } });
    expect((await run(byParam(), req)).nextCalled).toBe(true);
  });

  it('refuses a caller addressing someone else’s resource', async () => {
    const req = authed({}, { params: { id: 'user_bob' } });
    const result = await run(byParam(), req);

    expect(result.res.statusCode).toBe(403);
    expect(result.code).toBe('FORBIDDEN');
  });

  it('refuses even when the caller is an admin, unless the route says otherwise', async () => {
    // There is deliberately no "admins bypass ownership" flag: that is a
    // per-route policy decision, and a general escape hatch would be reached
    // for reflexively.
    const req = authed({ roles: ['admin'] }, { params: { id: 'user_bob' } });
    expect((await run(byParam(), req)).res.statusCode).toBe(403);
  });

  /**
   * The failure that matters most. A selector pointing at a renamed route
   * parameter returns undefined; treating that as a pass would silently
   * disable the check on every route using it.
   */
  it('refuses when the owner cannot be determined', async () => {
    const req = authed({}, { params: {} });
    expect((await run(byParam(), req)).res.statusCode).toBe(403);
  });

  it('refuses when the selector throws', async () => {
    const mw = createRequireOwner(audit)(() => {
      throw new Error('selector blew up');
    });
    expect((await run(mw, authed({}))).res.statusCode).toBe(403);
  });

  it('refuses an empty owner id', async () => {
    const req = authed({}, { params: { id: '' } });
    expect((await run(byParam(), req)).res.statusCode).toBe(403);
  });

  it('does not confirm the resource exists or name its owner', async () => {
    const req = authed({}, { params: { id: 'user_bob' } });
    const result = await run(byParam(), req);
    expect(JSON.stringify(result.res.body)).not.toContain('user_bob');
  });

  it('reads an owner from the body as readily as from a param', async () => {
    const mw = createRequireOwner(audit)(
      (req) => (req.body as { ownerId?: string } | undefined)?.ownerId,
    );
    const allowed = authed({}, { body: { ownerId: 'user_alice' } });
    const denied = authed({}, { body: { ownerId: 'user_bob' } });

    expect((await run(mw, allowed)).nextCalled).toBe(true);
    expect((await run(mw, denied)).res.statusCode).toBe(403);
  });

  it('records the denial for monitoring', async () => {
    await run(byParam(), authed({}, { params: { id: 'user_bob' } }));
    const events = audit.ofType('authz.denied');
    expect(events).toHaveLength(1);
    expect(events[0]?.userId).toBe('user_alice');
  });
});

describe('requireTenant', () => {
  const byParam = (): Middleware =>
    createRequireTenant(audit)((req) => req.params?.['tenantId']);

  it('allows a caller within their tenant', async () => {
    const req = authed({ tenant: 'acme' }, { params: { tenantId: 'acme' } });
    expect((await run(byParam(), req)).nextCalled).toBe(true);
  });

  it('refuses a caller reaching across tenants', async () => {
    const req = authed({ tenant: 'acme' }, { params: { tenantId: 'globex' } });
    expect((await run(byParam(), req)).res.statusCode).toBe(403);
  });

  /**
   * A token with no tenant claim predates tenanting or came from a
   * misconfigured path. Neither should reach tenant-scoped data.
   */
  it('refuses a token carrying no tenant', async () => {
    const req = authed({}, { params: { tenantId: 'acme' } });
    expect((await run(byParam(), req)).res.statusCode).toBe(403);
  });

  it('refuses when the tenant cannot be determined', async () => {
    const req = authed({ tenant: 'acme' }, { params: {} });
    expect((await run(byParam(), req)).res.statusCode).toBe(403);
  });

  it('is not fooled by a tenant that is a prefix of another', async () => {
    const req = authed({ tenant: 'acme' }, { params: { tenantId: 'acme-staging' } });
    expect((await run(byParam(), req)).res.statusCode).toBe(403);
  });
});

describe('composition', () => {
  it('applies checks in order, refusing at the first failure', async () => {
    const req = authed({ roles: ['user'] }, { params: { id: 'user_bob' } });

    const role = await run(createRequireRole(audit)('user'), req);
    expect(role.nextCalled).toBe(true);

    const owner = await run(createRequireOwner(audit)((r) => r.params?.['id']), req);
    expect(owner.res.statusCode).toBe(403);
  });

  it('passes a caller satisfying every check', async () => {
    const req = authed(
      { roles: ['admin'], scopes: ['orders:write'], tenant: 'acme' },
      { params: { id: 'user_alice', tenantId: 'acme' } },
    );

    for (const mw of [
      createRequireRole(audit)('admin'),
      createRequireScope(audit)('orders:write'),
      createRequireTenant(audit)((r) => r.params?.['tenantId']),
      createRequireOwner(audit)((r) => r.params?.['id']),
    ]) {
      expect((await run(mw, req)).nextCalled).toBe(true);
    }
  });
});

describe('error handler', () => {
  it('forwards non-Ninsho errors to the next handler', async () => {
    const handler = createErrorHandler();
    const res = new FakeResponse();
    let forwarded: unknown;

    handler(new Error('database exploded'), { headers: {} } as HttpRequest, res, (e) => {
      forwarded = e;
    });

    expect((forwarded as Error).message).toBe('database exploded');
    expect(res.statusCode).toBeUndefined();
  });
});
