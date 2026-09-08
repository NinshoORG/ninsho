import { describe, it, expect, beforeEach } from 'vitest';
import {
  Ninsho,
  MemoryStore,
  jwkThumbprint as serverThumbprint,
  verifyDpopProof,
  parseJwk,
  type Principal,
} from '@ninshorg/server';
import { NinshoClient } from './client.js';
import { MemoryKeyStore } from './storage.js';
import { generateDpopKey, jwkThumbprint as clientThumbprint } from './keys.js';
import { createProof } from './proof.js';

/**
 * ─── The tests that justify shipping two implementations ──────────────────
 * The client mints DPoP proofs with WebCrypto; the server verifies them with
 * `node:crypto`. Two codebases, two crypto APIs, one wire format. If they
 * disagree about anything — the canonical JWK form, the signature encoding,
 * the signing input — every request fails, and it fails only in production
 * where the two actually meet.
 *
 * So they are tested against each other rather than each against its own
 * assumptions.
 * ──────────────────────────────────────────────────────────────────────────
 */

const ALICE: Principal = { userId: 'user_alice', roles: ['user'], scopes: [] };
const ORIGIN = 'https://api.example.test';

const verifyOptions = {
  maxAgeSeconds: 60,
  clockToleranceSeconds: 5,
};

describe('thumbprints agree across implementations', () => {
  it('computes the same RFC 7638 thumbprint for the same key', async () => {
    // The thumbprint is what binds a token to a key. If the two sides
    // disagreed, every bound token would be rejected as belonging to another
    // key — and the cause would be invisible from either side alone.
    for (let i = 0; i < 20; i += 1) {
      const key = await generateDpopKey();
      const fromClient = await clientThumbprint(key.publicJwk);
      const fromServer = serverThumbprint(parseJwk(key.publicJwk));
      expect(fromClient).toBe(fromServer);
    }
  });

  it('produces a JWK the server accepts as valid', async () => {
    const key = await generateDpopKey();
    expect(() => parseJwk(key.publicJwk)).not.toThrow();
  });

  it('agrees with the key’s own cached thumbprint', async () => {
    const key = await generateDpopKey();
    expect(key.thumbprint).toBe(serverThumbprint(parseJwk(key.publicJwk)));
  });
});

describe('proofs cross the boundary', () => {
  it('produces proofs the server verifies', async () => {
    const key = await generateDpopKey();
    const proof = await createProof(key, { method: 'GET', url: `${ORIGIN}/orders` });

    const verified = verifyDpopProof(proof, {
      method: 'GET',
      url: `${ORIGIN}/orders`,
      ...verifyOptions,
    });

    expect(verified.jkt).toBe(key.thumbprint);
    expect(verified.algorithm).toBe('ES256');
  });

  it('produces a token-bound proof the server accepts', async () => {
    const key = await generateDpopKey();
    const token = 'an-access-token-value';
    const proof = await createProof(key, {
      method: 'POST',
      url: `${ORIGIN}/orders`,
      accessToken: token,
    });

    // The `ath` hash must match what the server computes independently.
    expect(() =>
      verifyDpopProof(proof, {
        method: 'POST',
        url: `${ORIGIN}/orders`,
        accessToken: token,
        ...verifyOptions,
      }),
    ).not.toThrow();
  });

  it('keeps agreeing across many keys and requests', async () => {
    // ECDSA signatures vary per invocation, and a length or encoding edge case
    // would show up intermittently rather than always. Repetition is the point.
    for (let i = 0; i < 30; i += 1) {
      const key = await generateDpopKey();
      const path = `/resource/${i}`;
      const proof = await createProof(key, { method: 'PUT', url: `${ORIGIN}${path}` });

      expect(() =>
        verifyDpopProof(proof, { method: 'PUT', url: `${ORIGIN}${path}`, ...verifyOptions }),
      ).not.toThrow();
    }
  });

  it('produces canonical base64url in every segment', async () => {
    // The server rejects non-canonical encodings. A client that emitted them
    // would fail intermittently — only when a segment length hit the wrong
    // boundary — which is the worst kind of interop bug to diagnose.
    for (let i = 0; i < 30; i += 1) {
      const key = await generateDpopKey();
      const proof = await createProof(key, {
        method: 'GET',
        url: `${ORIGIN}/x`,
        accessToken: 'tok'.repeat(i + 1),
      });

      expect(() =>
        verifyDpopProof(proof, { method: 'GET', url: `${ORIGIN}/x`, accessToken: 'tok'.repeat(i + 1), ...verifyOptions }),
      ).not.toThrow();
    }
  });

  it('is rejected by the server when the method does not match', async () => {
    const key = await generateDpopKey();
    const proof = await createProof(key, { method: 'GET', url: `${ORIGIN}/x` });

    expect(() =>
      verifyDpopProof(proof, { method: 'DELETE', url: `${ORIGIN}/x`, ...verifyOptions }),
    ).toThrow();
  });
});

/**
 * The full round trip: a client signs in, the server binds the session to the
 * client's key, and subsequent requests carry proofs the server accepts.
 */
describe('end-to-end session', () => {
  let store: MemoryStore;
  let auth: Ninsho;

  /** Minimal API: sign-in, a protected route, refresh, sign-out. */
  function createServer(instance: Ninsho): typeof globalThis.fetch {
    return async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(typeof input === 'string' ? input : input.toString());
      const method = (init?.method ?? 'GET').toUpperCase();
      const headers = new Headers(init?.headers);

      // Adapt a fetch Request into the shape the middleware reads. A real HTTP
      // server always populates `host`; fetch sets it at the network layer,
      // which does not exist here, so the harness supplies it. Without it the
      // server reconstructs `https://localhost/...` and every proof's `htu`
      // legitimately fails to match — which is the check working, not a bug.
      const req = {
        method,
        originalUrl: url.pathname,
        protocol: url.protocol.replace(':', ''),
        headers: { host: url.host, ...Object.fromEntries(headers.entries()) },
      } as never;

      const json = (status: number, body: unknown): Response =>
        new Response(JSON.stringify(body), {
          status,
          headers: { 'content-type': 'application/json' },
        });

      try {
        if (url.pathname === '/auth/login' && method === 'POST') {
          const jkt = await instance.confirmProofOfPossession(req);
          const pair = await instance.createSession(ALICE, { confirmationKey: jkt });
          sessionRefreshToken = pair.refreshToken;
          return json(200, { accessToken: pair.accessToken });
        }

        if (url.pathname === '/auth/refresh' && method === 'POST') {
          const jkt = await instance.confirmProofOfPossession(req);
          const pair = await instance.refresh(sessionRefreshToken, { confirmationKey: jkt });
          sessionRefreshToken = pair.refreshToken;
          return json(200, { accessToken: pair.accessToken });
        }

        // Protected routes: run the real verify middleware.
        const verified = await new Promise<boolean>((resolve) => {
          void instance.verify()(
            req,
            {
              status: () => ({ json: () => resolve(false) }) as never,
              json: () => resolve(false),
            } as never,
            () => resolve(true),
          );
        });

        if (!verified) return json(401, { error: { code: 'UNAUTHORIZED' } });
        return json(200, { path: url.pathname, ok: true });
      } catch {
        return json(401, { error: { code: 'UNAUTHORIZED' } });
      }
    };
  }

  let sessionRefreshToken = '';

  beforeEach(() => {
    store = new MemoryStore();
    auth = new Ninsho({ store, binding: 'dpop' });
    sessionRefreshToken = '';
  });

  it('signs in and reaches a protected route', async () => {
    const client = new NinshoClient({
      baseUrl: ORIGIN,
      keyStore: new MemoryKeyStore(),
      fetch: createServer(auth),
    });

    const signIn = await client.signIn('/auth/login', { email: 'a@b.test' });
    expect(signIn.status).toBe(200);
    expect(client.isAuthenticated).toBe(true);

    const response = await client.fetch('/me');
    expect(response.status).toBe(200);
  });

  it('binds the session to the client’s own key', async () => {
    const keyStore = new MemoryKeyStore();
    const client = new NinshoClient({
      baseUrl: ORIGIN,
      keyStore,
      fetch: createServer(auth),
    });

    await client.signIn('/auth/login', {});
    const thumbprint = await client.getThumbprint();

    // A second client with a different key must not be able to use the first
    // one's token — that is the property the whole mechanism provides.
    const attacker = new NinshoClient({
      baseUrl: ORIGIN,
      keyStore: new MemoryKeyStore(),
      fetch: createServer(auth),
    });
    attacker.setAccessToken(client.accessToken);

    expect(await attacker.getThumbprint()).not.toBe(thumbprint);
    expect((await attacker.fetch('/me')).status).toBe(401);
  });

  it('reuses one key across many requests', async () => {
    const client = new NinshoClient({
      baseUrl: ORIGIN,
      keyStore: new MemoryKeyStore(),
      fetch: createServer(auth),
    });
    await client.signIn('/auth/login', {});
    const thumbprint = await client.getThumbprint();

    for (const path of ['/a', '/b', '/c', '/d']) {
      expect((await client.fetch(path)).status).toBe(200);
    }
    // Each request minted a fresh proof, but from the same bound key.
    expect(await client.getThumbprint()).toBe(thumbprint);
  });

  it('refreshes automatically when the token has expired', async () => {
    const shortLived = new Ninsho({
      store: new MemoryStore(),
      binding: 'dpop',
      accessTokenTtl: 2,
      refreshTokenTtl: 3600,
      // The default 5s tolerance would exceed a 2s lifetime, which config
      // validation correctly refuses — it would keep every token valid past
      // its own expiry.
      clockToleranceSeconds: 0,
    });
    const client = new NinshoClient({
      baseUrl: ORIGIN,
      keyStore: new MemoryKeyStore(),
      fetch: createServer(shortLived),
    });

    await client.signIn('/auth/login', {});
    const original = client.accessToken;

    await new Promise((r) => setTimeout(r, 2600));

    // The 401 is handled internally: refresh, then retry.
    const response = await client.fetch('/me');
    expect(response.status).toBe(200);
    expect(client.accessToken).not.toBe(original);
  }, 20_000);

  it('discards the key on sign-out', async () => {
    const keyStore = new MemoryKeyStore();
    const client = new NinshoClient({
      baseUrl: ORIGIN,
      keyStore,
      fetch: createServer(auth),
    });

    await client.signIn('/auth/login', {});
    const before = await client.getThumbprint();

    await client.signOut('/auth/logout');

    expect(client.accessToken).toBeNull();
    await expect(keyStore.load()).resolves.toBeNull();
    // A fresh key, so the next user of this browser does not inherit one a
    // still-live session elsewhere is bound to.
    expect(await client.getThumbprint()).not.toBe(before);
  });
});
