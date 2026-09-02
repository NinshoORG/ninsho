import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import type { Principal } from '@ninsho/core';
import { MemoryStore } from '../store/memory.js';
import { OpaqueEngine } from '../engine/opaque.js';
import { SessionManager } from '../session/manager.js';
import { MemoryAuditSink } from '../audit.js';
import { createRequireFreshAuth, createVerify } from '../http/middleware.js';
import type { HttpRequest, HttpResponse, Middleware } from '../http/types.js';

/**
 * Step-up authentication — WebAuthn-free, session-level re-authentication.
 *
 * ─── The mistake this feature exists to prevent ───────────────────────────
 * The obvious way to build "did the user authenticate recently?" is to compare
 * the access token's `issuedAt` against the clock. It is wrong in a way that
 * looks right: rotation mints a new access token every few minutes for as long
 * as a session lives, so on a session refreshed for thirty days `issuedAt` is
 * always minutes old. The check would pass for everyone, forever, while
 * reading in the code as a real control.
 *
 * These tests exist to pin that distinction down — most importantly the one
 * asserting a refresh does *not* reset the clock, which is the case a naive
 * implementation gets wrong.
 * ──────────────────────────────────────────────────────────────────────────
 */

const ALICE: Principal = { userId: 'user_alice', roles: ['user'], scopes: [] };

let store: MemoryStore;
let engine: OpaqueEngine;
let sessions: SessionManager;
let audit: MemoryAuditSink;

beforeEach(() => {
  store = new MemoryStore();
  engine = new OpaqueEngine(store, { accessTokenTtl: 300, clockToleranceSeconds: 5 });
  audit = new MemoryAuditSink();
  sessions = new SessionManager(store, engine, {
    refreshTokenTtl: 3600 * 24 * 30,
    refreshGraceSeconds: 30,
    clockToleranceSeconds: 5,
    audit,
  });
});

afterEach(() => {
  vi.useRealTimers();
});

/** Captures what a middleware wrote, mimicking the Express response surface. */
class FakeResponse implements HttpResponse {
  statusCode: number | undefined;
  body: unknown;
  status(code: number): HttpResponse {
    this.statusCode = code;
    return this;
  }
  json(body: unknown): unknown {
    this.body = body;
    return body;
  }
  setHeader(): unknown {
    return this;
  }
}

interface ChainResult {
  readonly passed: boolean;
  readonly status: number | undefined;
  readonly body: unknown;
}

/**
 * Runs a chain to completion.
 *
 * A denied guard writes the response itself rather than calling `next(error)`,
 * so the outcome has to be read from what reached the client — which is also
 * the thing worth asserting about.
 */
async function run(middlewares: Middleware[], req: HttpRequest): Promise<ChainResult> {
  const res = new FakeResponse();

  for (const middleware of middlewares) {
    let advanced = false;

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
        middleware(req, res, () => {
          advanced = true;
          done();
        }),
      ).then(() => setTimeout(done, 20));
    });

    if (!advanced) return { passed: false, status: res.statusCode, body: res.body };
  }

  return { passed: true, status: res.statusCode, body: res.body };
}

const request = (token: string): HttpRequest =>
  ({ headers: { authorization: `Bearer ${token}` } }) as HttpRequest;

const verify = (): Middleware =>
  createVerify({ engine, audit, onStoreError: 'closed' });

const fresh = (seconds: number): Middleware => createRequireFreshAuth(audit)(seconds);

describe('the freshness check', () => {
  it('admits a session that was just created', async () => {
    const pair = await sessions.create(ALICE);
    const result = await run([verify(), fresh(300)], request(pair.accessToken));

    expect(result.passed).toBe(true);
  });

  it('refuses a session older than the window', async () => {
    vi.useFakeTimers();
    const pair = await sessions.create(ALICE);

    // Refresh after the window passes, so the access token is valid and only
    // the *authentication* is stale. That is the case worth testing: a live
    // token on an old session is exactly what a step-up check must catch.
    vi.advanceTimersByTime(301_000);
    const rotated = await sessions.refresh(pair.refreshToken);

    const result = await run([verify(), fresh(300)], request(rotated.accessToken));
    expect(result.passed).toBe(false);
    expect(result.status).toBe(403);
  });

  it('admits a session just inside the window', async () => {
    vi.useFakeTimers();
    const pair = await sessions.create(ALICE);

    vi.advanceTimersByTime(299_000);
    expect((await run([verify(), fresh(300)], request(pair.accessToken))).passed).toBe(true);
  });

  it('records the denial as an authorization event', async () => {
    vi.useFakeTimers();
    const pair = await sessions.create(ALICE);
    vi.advanceTimersByTime(600_000);
    const rotated = await sessions.refresh(pair.refreshToken);

    await run([verify(), fresh(60)], request(rotated.accessToken));
    expect(audit.events.some((e) => e.type === 'authz.denied')).toBe(true);
  });
});

/**
 * The heart of it. A refresh proves possession of a token, not that the user
 * is present — so it must not reset the clock this check reads.
 */
describe('refreshing does not count as authenticating', () => {
  it('keeps the original authentication time across a rotation', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));

    const first = await sessions.create(ALICE);
    const originalContext = await engine.verify(first.accessToken);
    expect(originalContext.authenticatedAt).toBe('2026-01-01T00:00:00.000Z');

    // Ten minutes later, the client refreshes.
    vi.advanceTimersByTime(600_000);
    const rotated = await sessions.refresh(first.refreshToken);
    const rotatedContext = await engine.verify(rotated.accessToken);

    // The token is new; the authentication is not.
    expect(rotatedContext.issuedAt).toBe('2026-01-01T00:10:00.000Z');
    expect(rotatedContext.authenticatedAt).toBe('2026-01-01T00:00:00.000Z');
  });

  it('will not let a refresh satisfy a check the session had failed', async () => {
    // The attack a naive implementation permits: a stale session refreshes,
    // gets a token minted seconds ago, and walks through a step-up gate.
    vi.useFakeTimers();
    const pair = await sessions.create(ALICE);

    vi.advanceTimersByTime(3600_000); // an hour later
    expect((await run([verify(), fresh(300)], request(pair.accessToken))).passed).toBe(false);

    const rotated = await sessions.refresh(pair.refreshToken);
    const result = await run([verify(), fresh(300)], request(rotated.accessToken));

    expect(result.passed).toBe(false);
    expect(result.status).toBe(403);
  });

  it('survives many rotations without drifting', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));

    let pair = await sessions.create(ALICE);
    for (let i = 0; i < 5; i += 1) {
      vi.advanceTimersByTime(120_000);
      pair = await sessions.refresh(pair.refreshToken);
    }

    const context = await engine.verify(pair.accessToken);
    expect(context.authenticatedAt).toBe('2026-01-01T00:00:00.000Z');
  });

  it('is satisfied by re-authenticating, which is the intended remedy', async () => {
    vi.useFakeTimers();
    const stale = await sessions.create(ALICE);
    vi.advanceTimersByTime(3600_000);

    expect((await run([verify(), fresh(300)], request(stale.accessToken))).passed).toBe(false);

    // The application re-authenticates the user and starts a new session.
    const reauthenticated = await sessions.create(ALICE);
    expect((await run([verify(), fresh(300)], request(reauthenticated.accessToken))).passed).toBe(
      true,
    );
  });

  it('does not reset the clock when a parallel tab adopts a rotation', async () => {
    // The grace path mints a token too, and must follow the same rule.
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));

    const first = await sessions.create(ALICE);
    vi.advanceTimersByTime(600_000);

    await sessions.refresh(first.refreshToken);
    // The same token again, inside the grace window — the adoption path.
    const adopted = await sessions.refresh(first.refreshToken);

    const context = await engine.verify(adopted.accessToken);
    expect(context.authenticatedAt).toBe('2026-01-01T00:00:00.000Z');
  });
});

describe('configuration and failure modes', () => {
  it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])(
    'refuses a maxAgeSeconds of %s at construction',
    (value) => {
      // A non-positive window would reject every request while reading as a
      // freshness requirement; an infinite one would admit every request while
      // reading as a restriction.
      expect(() => createRequireFreshAuth(audit)(value)).toThrow(/positive maxAgeSeconds/);
    },
  );

  it('fails closed on an unparseable authentication time', async () => {
    const pair = await sessions.create(ALICE);
    const req = request(pair.accessToken);
    await run([verify()], req);

    // Corrupt the context the way a bad record would.
    (req as { auth?: unknown }).auth = { ...req.auth, authenticatedAt: 'not-a-date' };
    const result = await run([fresh(300)], req);

    expect(result.passed).toBe(false);
    expect(result.status).toBe(403);
  });

  it('refuses to run without verify() having populated the context', async () => {
    // Mounting it alone is a configuration mistake, and one that must not
    // silently permit the request.
    const result = await run([fresh(300)], { headers: {} } as HttpRequest);
    expect(result.passed).toBe(false);
  });

  it('never puts the age in the client-facing body', async () => {
    vi.useFakeTimers();
    const pair = await sessions.create(ALICE);
    vi.advanceTimersByTime(3600_000);
    const rotated = await sessions.refresh(pair.refreshToken);

    const result = await run([verify(), fresh(300)], request(rotated.accessToken));

    // What the client actually receives carries no age and no explanation.
    expect(JSON.stringify(result.body)).not.toMatch(/\d+s old|authentication/i);
    expect(result.status).toBe(403);
    // The reason is still recorded server-side, in the audit trail.
    const denial = audit.events.find((e) => e.type === 'authz.denied') as
      | { reason?: string }
      | undefined;
    expect(denial?.reason).toMatch(/authentication is \d+s old/);
  });
});
