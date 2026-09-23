/**
 * Rolling upgrades: state an earlier release wrote is honoured by this one.
 *
 * ─── Why this exists ──────────────────────────────────────────────────────
 * During a rolling deploy the old and new versions share one Redis. Every
 * session a user holds was written by the old release and is about to be read
 * by the new one. If the new release misreads those records, the mild outcome
 * is that everybody is signed out. The serious one is the reverse: a session
 * revoked before the upgrade reading as live after it.
 *
 * Keys are namespaced (`ninsho:v1:`) so a deliberate schema change can make
 * old records invisible instead of misread — docs/stability.md lists that as
 * a breaking change. What nothing tested before was the ordinary case: a
 * release that keeps the namespace and changes a record anyway.
 *
 * ─── How ──────────────────────────────────────────────────────────────────
 * fixtures/upgrade/<version>.json is the store a *published* release left
 * behind, recorded by scripts/record-upgrade-fixture.mjs, plus the tokens and
 * keys needed to use it. Each test seeds a fresh store from it, builds today's
 * Ninsho with the configuration that wrote it, freezes the clock at the moment
 * of recording, and checks today's code does what that release would have
 * done — including refusing what it had already refused.
 *
 * Fixtures are history. They are never edited or re-recorded; each new
 * release adds one, and every release after it is tested against all of them.
 * ──────────────────────────────────────────────────────────────────────────
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { createPrivateKey } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  RefreshInvalidError,
  RefreshReuseError,
  TokenInvalidError,
  TokenRevokedError,
} from '@ninshorg/core';
import { Ninsho } from '../ninsho.js';
import type { NinshoConfig } from '../config.js';
import { MemoryStore } from '../store/memory.js';
import { MemoryAuditSink } from '../audit.js';
import { KEYS } from '../keys.js';
import { OneTimeTokenError } from '../tokens/one-time.js';
import { createDpopProof, type DpopKeyPair } from '../dpop/sign.js';
import type { HttpRequest, HttpResponse, Middleware } from '../http/types.js';

// ── The recordings ───────────────────────────────────────────────────────────

type Entry = { key: string; value: string } | { key: string; members: string[] };

interface Section {
  readonly config: Partial<NinshoConfig>;
  readonly tokens: Record<string, Record<string, string> | string>;
  readonly expect: { readonly userId: string; readonly liveSessions?: number };
  readonly keys: readonly Entry[];
}

interface Fixture {
  readonly version: string;
  readonly recordedAt: number;
  readonly namespace: string;
  readonly opaque: Section;
  readonly paseto: Section;
  readonly dpop: Section & {
    readonly key: { algorithm: DpopKeyPair['algorithm']; jkt: string; publicJwk: DpopKeyPair['publicJwk']; privateJwk: object };
  };
}

const DIR = fileURLToPath(new URL('./fixtures/upgrade/', import.meta.url));
const FIXTURES: Fixture[] = readdirSync(DIR)
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => JSON.parse(readFileSync(join(DIR, f), 'utf8')) as Fixture);

/** `ninsho:v1`, read from the key builders rather than restated here. */
const NAMESPACE = KEYS.userSessions('_').replace(/:user:_:sess$/, '');

const token = (section: Section, group: string, field: string): string => {
  const value = (section.tokens[group] as Record<string, string> | undefined)?.[field];
  if (typeof value !== 'string') throw new Error(`fixture has no tokens.${group}.${field}`);
  return value;
};

/** A fresh store holding exactly what the release left behind. */
async function seeded(section: Section): Promise<MemoryStore> {
  const store = new MemoryStore();
  for (const entry of section.keys) {
    if ('value' in entry) await store.set(entry.key, entry.value);
    else for (const member of entry.members) await store.sAdd(entry.key, member);
  }
  return store;
}

/** Today's Ninsho, configured the way the release that wrote the store was. */
async function today(section: Section): Promise<Ninsho> {
  return new Ninsho({ store: await seeded(section), audit: new MemoryAuditSink(), ...section.config });
}

// ── A minimal HTTP harness, for the DPoP middleware ──────────────────────────

class Res implements HttpResponse {
  statusCode: number | undefined;
  constructor(private readonly settled: () => void) {}
  status(code: number): HttpResponse {
    this.statusCode = code;
    return this;
  }
  json(body: unknown): unknown {
    this.settled();
    return body;
  }
  setHeader(): unknown {
    return this;
  }
}

/**
 * Runs a middleware until it answers or continues. A Ninsho middleware returns
 * void and settles through a promise it does not hand back, so awaiting the
 * call itself returns before the verdict — a first draft of this harness did
 * exactly that, and read every request as neither accepted nor refused.
 */
function run(mw: Middleware, req: HttpRequest): Promise<{ status: number | undefined; next: boolean }> {
  return new Promise((resolve) => {
    const res: Res = new Res(() => resolve({ status: res.statusCode, next: false }));
    void mw(req, res, () => resolve({ status: res.statusCode, next: true }));
  });
}

const ORIGIN = 'https://api.example.test';
const request = (headers: Record<string, string>): HttpRequest =>
  ({ method: 'GET', originalUrl: '/me', protocol: 'https', headers: { host: 'api.example.test', ...headers } }) as unknown as HttpRequest;

// ── The tests ────────────────────────────────────────────────────────────────

describe('upgrade compatibility', () => {
  it('has the state of at least one earlier release to test against', () => {
    // An empty fixtures directory would make every test below vanish and the
    // suite pass having checked nothing.
    expect(FIXTURES.length).toBeGreaterThan(0);
  });

  describe.each(FIXTURES)('state written by @ninshorg/server $version', (fx) => {
    beforeEach(() => {
      // Only Date: the records' own timestamps govern validity, and real timers
      // keep the store and the middleware behaving normally.
      vi.useFakeTimers({ now: fx.recordedAt + 1_000, toFake: ['Date'] });
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    it('was written under the namespace this version reads', () => {
      // A namespace bump is the deliberate way to retire old records, and a
      // breaking change under docs/stability.md. If this fails, that is what
      // happened — move the older fixtures aside on purpose, and say so.
      expect(fx.namespace).toBe(NAMESPACE);
    });

    describe('opaque sessions', () => {
      const s = fx.opaque;

      it('verifies an access token that release issued', async () => {
        const auth = await today(s);
        const context = await auth.engine.verify(token(s, 'live', 'accessToken'));
        expect(context.userId).toBe(s.expect.userId);
        expect(context.sessionId).toBe(token(s, 'live', 'sessionId'));
      });

      it('rotates a refresh token that release issued', async () => {
        const auth = await today(s);
        const pair = await auth.refresh(token(s, 'live', 'refreshToken'));
        const context = await auth.engine.verify(pair.accessToken);
        expect(context.userId).toBe(s.expect.userId);
        expect(context.sessionId).toBe(token(s, 'live', 'sessionId'));
      });

      it('still treats a refresh token that release had rotated as theft', async () => {
        const auth = await today(s);
        await expect(auth.refresh(token(s, 'rotated', 'spentRefreshToken'))).rejects.toThrow(RefreshReuseError);
        // And the family is gone, including the pair that rotation produced.
        await expect(auth.engine.verify(token(s, 'rotated', 'accessToken'))).rejects.toThrow(TokenInvalidError);
        await expect(auth.refresh(token(s, 'rotated', 'refreshToken'))).rejects.toThrow(RefreshInvalidError);
      });

      it('keeps a session that release revoked revoked', async () => {
        // The failure that matters most: an upgrade must never bring a
        // signed-out session back.
        const auth = await today(s);
        await expect(auth.engine.verify(token(s, 'revoked', 'accessToken'))).rejects.toThrow(TokenInvalidError);
        await expect(auth.refresh(token(s, 'revoked', 'refreshToken'))).rejects.toThrow(RefreshInvalidError);
      });

      it('lists the sessions that release recorded', async () => {
        const auth = await today(s);
        expect(await auth.listSessions(s.expect.userId)).toHaveLength(s.expect.liveSessions ?? -1);
      });

      it('signs out everywhere, reaching every session that release wrote', async () => {
        const auth = await today(s);
        await auth.revokeAllForUser(s.expect.userId, 'logout_all');
        await expect(auth.engine.verify(token(s, 'live', 'accessToken'))).rejects.toThrow(TokenInvalidError);
        await expect(auth.engine.verify(token(s, 'second', 'accessToken'))).rejects.toThrow(TokenInvalidError);
        expect(await auth.listSessions(s.expect.userId)).toHaveLength(0);
      });

      it('redeems a reset link that release issued, exactly once', async () => {
        const auth = await today(s);
        const reset = s.tokens['reset'] as string;
        expect((await auth.oneTimeTokens.consume('password-reset', reset)).subject).toBe(s.expect.userId);
        await expect(auth.oneTimeTokens.consume('password-reset', reset)).rejects.toBeInstanceOf(OneTimeTokenError);
      });
    });

    describe('PASETO sessions', () => {
      const s = fx.paseto;

      it('verifies an access token that release signed', async () => {
        const auth = await today(s);
        expect((await auth.engine.verify(token(s, 'live', 'accessToken'))).userId).toBe(s.expect.userId);
      });

      it('rotates a refresh token that release issued', async () => {
        const auth = await today(s);
        const pair = await auth.refresh(token(s, 'live', 'refreshToken'));
        expect((await auth.engine.verify(pair.accessToken)).userId).toBe(s.expect.userId);
      });

      it('still treats a refresh token that release had rotated as theft', async () => {
        const auth = await today(s);
        await expect(auth.refresh(token(s, 'rotated', 'spentRefreshToken'))).rejects.toThrow(RefreshReuseError);
      });

      it('keeps a token that release revoked revoked, though its signature still verifies', async () => {
        // A PASETO token is self-contained: nothing about it changes when it is
        // revoked. Only the denylist record says so, and if an upgrade misread
        // that record the token would verify perfectly.
        const auth = await today(s);
        await expect(auth.engine.verify(token(s, 'revoked', 'accessToken'))).rejects.toThrow(TokenRevokedError);
      });
    });

    describe('DPoP-bound sessions', () => {
      const s = fx.dpop;
      const key = (): DpopKeyPair => ({
        algorithm: s.key.algorithm,
        jkt: s.key.jkt,
        publicJwk: s.key.publicJwk,
        privateKey: createPrivateKey({ key: s.key.privateJwk as never, format: 'jwk' }),
      });

      it('accepts a request proven with the key that release bound the session to', async () => {
        const auth = await today(s);
        const access = token(s, 'live', 'accessToken');
        const proof = createDpopProof(key(), { method: 'GET', url: `${ORIGIN}/me`, accessToken: access });
        const req = request({ authorization: `DPoP ${access}`, dpop: proof });
        const out = await run(auth.verify(), req);
        expect(out.next).toBe(true);
        expect(req.auth?.userId).toBe(s.expect.userId);
      });

      it('still refuses that session’s token without the key', async () => {
        const auth = await today(s);
        const access = token(s, 'live', 'accessToken');
        const out = await run(auth.verify(), request({ authorization: `DPoP ${access}` }));
        expect(out.next).toBe(false);
        expect(out.status).toBe(401);
      });
    });
  });
});
