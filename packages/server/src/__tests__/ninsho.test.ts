import { describe, it, expect, beforeEach } from 'vitest';
import {
  ConfigurationError,
  RefreshInvalidError,
  RefreshReuseError,
  TokenInvalidError,
  TokenRevokedError,
  type Principal,
} from '@ninshorg/core';
import { Ninsho } from '../ninsho.js';
import { MemoryStore } from '../store/memory.js';
import { MemoryAuditSink } from '../audit.js';
import { generateKeyPair } from '../keys/keyring.js';
import { getAuth } from '../http/middleware.js';
import type { HttpRequest, HttpResponse, Middleware } from '../http/types.js';

const ALICE: Principal = { userId: 'user_alice', roles: ['user'], scopes: ['orders:read'] };

let store: MemoryStore;
let audit: MemoryAuditSink;
let auth: Ninsho;

beforeEach(() => {
  store = new MemoryStore();
  audit = new MemoryAuditSink();
  auth = new Ninsho({ store, audit });
});

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

const bearer = (token: string, extra: Partial<HttpRequest> = {}): HttpRequest =>
  ({ headers: { authorization: `Bearer ${token}` }, ...extra }) as HttpRequest;

/**
 * The developer-experience claim, asserted rather than asserted-in-prose: the
 * shortest possible configuration is also the most secure one.
 */
describe('minimal configuration', () => {
  it('needs only a store', () => {
    expect(() => new Ninsho({ store: new MemoryStore() })).not.toThrow();
  });

  it('requires no signing keys under the default strategy', () => {
    // The predecessor made every user generate an Ed25519 keypair and paste
    // PKCS#8 DER hex into .env before anything worked.
    expect(auth.config.strategy).toBe('opaque');
    expect(auth.config.keys).toBeUndefined();
  });

  it('applies secure defaults without being asked', () => {
    expect(auth.config.onStoreError).toBe('closed');
    expect(auth.config.accessTokenTtl).toBe(300);
    expect(auth.config.refreshGraceSeconds).toBe(30);
    expect(auth.config.binding).toBe('none');
  });

  it('raises no warnings for the default configuration', () => {
    expect(audit.ofType('config.insecure')).toHaveLength(0);
  });

  it('fails at construction on a bad configuration, not at first request', () => {
    expect(() => new Ninsho({ store, accessTokenTtl: -1 })).toThrow(ConfigurationError);
  });
});

/**
 * Weakening choices are accepted but never silent — an operator sees them at
 * startup rather than discovering them during an incident.
 */
describe('startup warnings', () => {
  it('announces a weakening choice as config.insecure', () => {
    const sink = new MemoryAuditSink();
    new Ninsho({
      store: new MemoryStore(),
      audit: sink,
      accessTokenTtl: 7200,
      refreshTokenTtl: 604_800,
    });

    const events = sink.ofType('config.insecure');
    expect(events).toHaveLength(1);
    expect(events[0]?.reason).toMatch(/Long-lived access tokens/);
  });

  it('announces fail-open, which suspends revocation during an outage', () => {
    const sink = new MemoryAuditSink();
    new Ninsho({
      store: new MemoryStore(),
      audit: sink,
      strategy: 'paseto',
      issuer: 'https://id.test',
      audience: 'api',
      keys: { active: generateKeyPair('k') },
      onStoreError: 'open',
    });

    expect(sink.ofType('config.insecure')[0]?.reason).toMatch(/revoked tokens will be accepted/i);
  });
});

describe('session lifecycle through the facade', () => {
  it('creates a session and verifies its access token', async () => {
    const pair = await auth.createSession(ALICE);
    const req = bearer(pair.accessToken);

    const result = await run(auth.verify(), req);
    expect(result.nextCalled).toBe(true);
    expect(getAuth(req).userId).toBe('user_alice');
  });

  it('rotates on refresh', async () => {
    const first = await auth.createSession(ALICE);
    const second = await auth.refresh(first.refreshToken);
    expect(second.refreshToken).not.toBe(first.refreshToken);
  });

  it('detects reuse and ends the session', async () => {
    // Grace disabled so a replay is unambiguous. This asserts the facade wires
    // reuse detection through; session.test.ts covers the timing in depth.
    const strict = new Ninsho({ store, audit, refreshGraceSeconds: 0 });
    const first = await strict.createSession(ALICE);
    const second = await strict.refresh(first.refreshToken);

    await expect(strict.refresh(first.refreshToken)).rejects.toThrow(RefreshReuseError);
    // The replacement chain died with the family.
    await expect(strict.refresh(second.refreshToken)).rejects.toThrow(RefreshInvalidError);
  });

  it('revokes a session, killing its access token', async () => {
    const pair = await auth.createSession(ALICE);
    await auth.revokeSession(pair.sessionId);

    const result = await run(auth.verify(), bearer(pair.accessToken));
    expect(result.res.statusCode).toBe(401);
    await expect(auth.refresh(pair.refreshToken)).rejects.toThrow(RefreshInvalidError);
  });

  it('signs a user out everywhere', async () => {
    const a = await auth.createSession(ALICE);
    const b = await auth.createSession(ALICE);
    await auth.revokeAllForUser(ALICE.userId);

    for (const pair of [a, b]) {
      expect((await run(auth.verify(), bearer(pair.accessToken))).res.statusCode).toBe(401);
    }
  });

  it('lists sessions without exposing credentials', async () => {
    const pair = await auth.createSession(ALICE);
    const list = await auth.listSessions(ALICE.userId, pair.sessionId);

    expect(list).toHaveLength(1);
    expect(list[0]?.current).toBe(true);
    expect(JSON.stringify(list)).not.toContain(pair.refreshToken);
  });
});

describe('authorization through the facade', () => {
  it('enforces roles', async () => {
    const pair = await auth.createSession(ALICE);
    const req = bearer(pair.accessToken);
    await run(auth.verify(), req);

    expect((await run(auth.requireRole('user'), req)).nextCalled).toBe(true);
    expect((await run(auth.requireRole('admin'), req)).res.statusCode).toBe(403);
  });

  it('enforces scopes', async () => {
    const pair = await auth.createSession(ALICE);
    const req = bearer(pair.accessToken);
    await run(auth.verify(), req);

    expect((await run(auth.requireScope('orders:read'), req)).nextCalled).toBe(true);
    expect((await run(auth.requireScope('orders:write'), req)).res.statusCode).toBe(403);
  });

  it('enforces ownership', async () => {
    const pair = await auth.createSession(ALICE);
    const own = bearer(pair.accessToken, { params: { id: 'user_alice' } });
    const other = bearer(pair.accessToken, { params: { id: 'user_bob' } });
    await run(auth.verify(), own);
    await run(auth.verify(), other);

    const mw = auth.requireOwner((req) => req.params?.['id']);
    expect((await run(mw, own)).nextCalled).toBe(true);
    expect((await run(mw, other)).res.statusCode).toBe(403);
  });
});

describe('rate limiting through the facade', () => {
  it('refuses past the limit', async () => {
    const mw = auth.rateLimit({
      action: 'login',
      perIp: { limit: 2, windowMs: 60_000 },
      trustProxy: false,
    });
    const req = ({ headers: {}, ip: '1.1.1.1' }) as unknown as HttpRequest;

    for (let i = 0; i < 3; i += 1) await run(mw, req);
    expect((await run(mw, req)).res.statusCode).toBe(429);
  });

  /**
   * TypeScript already requires `trustProxy`, but a JavaScript consumer can
   * omit it. Without an eager check that reaches address parsing and crashes
   * confusingly, instead of naming the decision the setting exists to force.
   */
  it('refuses to build a limiter without a trustProxy decision', () => {
    expect(() =>
      auth.rateLimit({
        action: 'login',
        perIp: { limit: 5, windowMs: 60_000 },
      } as never),
    ).toThrow(ConfigurationError);
  });

  it('names both failure directions when refusing', () => {
    expect(() =>
      auth.rateLimit({ action: 'x', perIp: { limit: 5, windowMs: 60_000 } } as never),
    ).toThrow(/locks out every user|rotating an X-Forwarded-For/);
  });
});

describe('the paseto strategy through the facade', () => {
  const build = (): Ninsho =>
    new Ninsho({
      store: new MemoryStore(),
      audit,
      strategy: 'paseto',
      issuer: 'https://id.test',
      audience: 'orders-api',
      keys: { active: generateKeyPair('2026-08') },
    });

  it('issues and verifies a signed token', async () => {
    const paseto = build();
    const pair = await paseto.createSession(ALICE);
    expect(pair.accessToken.startsWith('v4.public.')).toBe(true);

    const req = bearer(pair.accessToken);
    expect((await run(paseto.verify(), req)).nextCalled).toBe(true);
    expect(getAuth(req).strategy).toBe('paseto');
  });

  it('revokes a stateless token through the denylist', async () => {
    const paseto = build();
    const pair = await paseto.createSession(ALICE);
    await paseto.revokeSession(pair.sessionId);

    await expect(paseto.engine.verify(pair.accessToken)).rejects.toThrow(TokenRevokedError);
  });

  it('rejects a token minted for a different audience', async () => {
    const orders = build();
    const pair = await orders.createSession(ALICE);

    const billing = new Ninsho({
      store: new MemoryStore(),
      audit,
      strategy: 'paseto',
      issuer: 'https://id.test',
      audience: 'billing-api',
      keys: { active: generateKeyPair('2026-08') },
    });

    await expect(billing.engine.verify(pair.accessToken)).rejects.toThrow(TokenInvalidError);
  });
});

describe('operations', () => {
  it('reports store health', async () => {
    await expect(auth.health()).resolves.toBe(true);
  });

  it('reports an unhealthy store after close', async () => {
    await auth.close();
    await expect(auth.health()).resolves.toBe(false);
  });

  it('exposes the resolved config for diagnostics', () => {
    expect(auth.config.accessTokenTtl).toBe(300);
  });
});
