import { describe, it, expect, beforeEach } from 'vitest';
import { NinshoClient } from './client.js';
import { MemoryKeyStore } from './storage.js';
import { generateDpopKey } from './keys.js';
import { createProof } from './proof.js';
import { fromBase64Url, toBase64Url } from './encoding.js';

const ORIGIN = 'https://api.example.test';

/** Records every request a client makes, and replies with a scripted response. */
function recorder(
  handler: (url: string, init: RequestInit) => Response | Promise<Response>,
): { fetch: typeof globalThis.fetch; calls: Array<{ url: string; init: RequestInit }> } {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fetchImpl = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = typeof input === 'string' ? input : input.toString();
    calls.push({ url, init });
    return handler(url, init);
  }) as typeof globalThis.fetch;
  return { fetch: fetchImpl, calls };
}

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });

function headerOf(init: RequestInit, name: string): string | null {
  return new Headers(init.headers).get(name);
}

/**
 * ─── The property browser DPoP exists for ─────────────────────────────────
 * The private key is generated non-extractable, so no script can read it —
 * including script an attacker injects. A bearer token is a string that an XSS
 * copies and uses forever; a DPoP key cannot leave the browser at all.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('key material cannot be exfiltrated', () => {
  it('generates a non-extractable private key', async () => {
    const key = await generateDpopKey();
    expect(key.privateKey.extractable).toBe(false);
  });

  it('refuses every attempt to export the private key', async () => {
    const key = await generateDpopKey();

    for (const format of ['jwk', 'pkcs8', 'raw'] as const) {
      await expect(crypto.subtle.exportKey(format, key.privateKey)).rejects.toThrow();
    }
  });

  it('still exports the public key, which is not secret', async () => {
    const key = await generateDpopKey();
    await expect(crypto.subtle.exportKey('jwk', key.publicKey)).resolves.toBeDefined();
  });

  it('gives every client a distinct key', async () => {
    const thumbprints = new Set<string>();
    for (let i = 0; i < 20; i += 1) {
      thumbprints.add((await generateDpopKey()).thumbprint);
    }
    expect(thumbprints.size).toBe(20);
  });

  it('exposes only the public half on the key object', async () => {
    const key = await generateDpopKey();
    // A serialized key object must not contain anything secret — someone will
    // eventually log one.
    const serialized = JSON.stringify(key);
    expect(serialized).not.toContain('"d"');
  });
});

describe('encoding', () => {
  it('round-trips bytes through base64url', () => {
    for (let length = 0; length < 200; length += 7) {
      const bytes = crypto.getRandomValues(new Uint8Array(length));
      expect(fromBase64Url(toBase64Url(bytes))).toEqual(bytes);
    }
  });

  it('emits unpadded, URL-safe output', () => {
    for (let length = 1; length < 64; length += 1) {
      const encoded = toBase64Url(crypto.getRandomValues(new Uint8Array(length)));
      expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
    }
  });

  it('handles a large input without exceeding the argument limit', () => {
    // Naive `String.fromCharCode(...bytes)` throws on large arrays, which is
    // why the encoder chunks. Filled in 64KB slices because getRandomValues
    // itself caps at 65,536 bytes per call.
    const bytes = new Uint8Array(200_000);
    for (let offset = 0; offset < bytes.length; offset += 65_536) {
      crypto.getRandomValues(bytes.subarray(offset, Math.min(offset + 65_536, bytes.length)));
    }

    expect(() => toBase64Url(bytes)).not.toThrow();
    expect(fromBase64Url(toBase64Url(bytes))).toEqual(bytes);
  });
});

describe('proof construction', () => {
  it('commits to the method and URI', async () => {
    const key = await generateDpopKey();
    const proof = await createProof(key, { method: 'delete', url: `${ORIGIN}/orders/7` });

    const payload = JSON.parse(
      new TextDecoder().decode(fromBase64Url(proof.split('.')[1] as string)),
    ) as Record<string, unknown>;

    expect(payload['htm']).toBe('DELETE');
    expect(payload['htu']).toBe(`${ORIGIN}/orders/7`);
  });

  it('strips the query string, as the specification requires', async () => {
    const key = await generateDpopKey();
    const proof = await createProof(key, { method: 'GET', url: `${ORIGIN}/x?secret=value` });

    const payload = JSON.parse(
      new TextDecoder().decode(fromBase64Url(proof.split('.')[1] as string)),
    ) as Record<string, unknown>;

    // A query string in `htu` would also leak parameters into the proof.
    expect(payload['htu']).toBe(`${ORIGIN}/x`);
    expect(proof).not.toContain('secret');
  });

  it('uses a fresh identifier for every proof', async () => {
    const key = await generateDpopKey();
    const ids = new Set<string>();

    for (let i = 0; i < 50; i += 1) {
      const proof = await createProof(key, { method: 'GET', url: `${ORIGIN}/x` });
      const payload = JSON.parse(
        new TextDecoder().decode(fromBase64Url(proof.split('.')[1] as string)),
      ) as { jti: string };
      ids.add(payload.jti);
    }
    // Reused identifiers would be rejected by the server's replay guard.
    expect(ids.size).toBe(50);
  });

  it('carries the public key but never the private one', async () => {
    const key = await generateDpopKey();
    const proof = await createProof(key, { method: 'GET', url: `${ORIGIN}/x` });

    const header = JSON.parse(
      new TextDecoder().decode(fromBase64Url(proof.split('.')[0] as string)),
    ) as { jwk: Record<string, unknown>; typ: string; alg: string };

    expect(header.typ).toBe('dpop+jwt');
    expect(header.alg).toBe('ES256');
    expect(Object.keys(header.jwk).sort()).toEqual(['crv', 'kty', 'x', 'y']);
    expect(header.jwk['d']).toBeUndefined();
  });
});

describe('request handling', () => {
  let keyStore: MemoryKeyStore;

  beforeEach(() => {
    keyStore = new MemoryKeyStore();
  });

  it('attaches a DPoP proof to every request', async () => {
    const { fetch, calls } = recorder(() => json(200, { ok: true }));
    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });

    await client.fetch('/a');
    await client.fetch('/b');

    expect(calls).toHaveLength(2);
    for (const call of calls) {
      expect(headerOf(call.init, 'DPoP')).toBeTruthy();
    }
    // Distinct proofs, not one reused.
    expect(headerOf(calls[0]!.init, 'DPoP')).not.toBe(headerOf(calls[1]!.init, 'DPoP'));
  });

  it('uses the DPoP authorization scheme once a token is held', async () => {
    const { fetch, calls } = recorder(() => json(200, {}));
    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });
    client.setAccessToken('token-value');

    await client.fetch('/a');
    expect(headerOf(calls[0]!.init, 'Authorization')).toBe('DPoP token-value');
  });

  it('sends no Authorization header before sign-in', async () => {
    const { fetch, calls } = recorder(() => json(200, {}));
    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });

    await client.fetch('/public');
    expect(headerOf(calls[0]!.init, 'Authorization')).toBeNull();
  });

  it('includes credentials so the httpOnly refresh cookie travels', async () => {
    const { fetch, calls } = recorder(() => json(200, {}));
    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });

    await client.fetch('/a');
    expect(calls[0]!.init.credentials).toBe('include');
  });

  it('resolves relative paths and passes absolute URLs through', async () => {
    const { fetch, calls } = recorder(() => json(200, {}));
    const client = new NinshoClient({ baseUrl: `${ORIGIN}/`, keyStore, fetch });

    await client.fetch('orders');
    await client.fetch('/orders');
    await client.fetch('https://other.test/x');

    expect(calls[0]!.url).toBe(`${ORIGIN}/orders`);
    expect(calls[1]!.url).toBe(`${ORIGIN}/orders`);
    expect(calls[2]!.url).toBe('https://other.test/x');
  });

  it('preserves the caller’s headers and body', async () => {
    const { fetch, calls } = recorder(() => json(200, {}));
    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });

    await client.fetch('/a', {
      method: 'POST',
      headers: { 'x-custom': 'kept' },
      body: '{"a":1}',
    });

    expect(headerOf(calls[0]!.init, 'x-custom')).toBe('kept');
    expect(calls[0]!.init.body).toBe('{"a":1}');
  });
});

describe('automatic refresh', () => {
  let keyStore: MemoryKeyStore;

  beforeEach(() => {
    keyStore = new MemoryKeyStore();
  });

  it('refreshes on a 401 and retries the original request', async () => {
    let expired = true;
    const { fetch, calls } = recorder((url) => {
      if (url.endsWith('/auth/refresh')) {
        expired = false;
        return json(200, { accessToken: 'fresh-token' });
      }
      return expired ? json(401, {}) : json(200, { ok: true });
    });

    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });
    client.setAccessToken('stale-token');

    const response = await client.fetch('/me');

    expect(response.status).toBe(200);
    expect(client.accessToken).toBe('fresh-token');
    expect(calls.map((c) => c.url)).toEqual([
      `${ORIGIN}/me`,
      `${ORIGIN}/auth/refresh`,
      `${ORIGIN}/me`,
    ]);
  });

  /**
   * The single most important behaviour in this class. Without it, a page that
   * fires six requests when a token expires starts six refreshes — and under
   * rotation, five of them present a token another has already rotated. The
   * server reads that as theft, correctly, and ends the session. A normal page
   * load would look like an attack.
   */
  it('collapses concurrent refreshes into one', async () => {
    let refreshes = 0;
    let expired = true;
    const { fetch } = recorder(async (url) => {
      if (url.endsWith('/auth/refresh')) {
        refreshes += 1;
        await new Promise((r) => setTimeout(r, 20));
        expired = false;
        return json(200, { accessToken: 'fresh-token' });
      }
      return expired ? json(401, {}) : json(200, { ok: true });
    });

    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });
    client.setAccessToken('stale-token');

    const responses = await Promise.all(
      Array.from({ length: 8 }, (_, i) => client.fetch(`/r${i}`)),
    );

    expect(refreshes).toBe(1);
    for (const response of responses) expect(response.status).toBe(200);
  });

  it('allows a later refresh after an earlier one completes', async () => {
    let refreshes = 0;
    const { fetch } = recorder((url) => {
      if (url.endsWith('/auth/refresh')) {
        refreshes += 1;
        return json(200, { accessToken: `token-${refreshes}` });
      }
      return json(401, {});
    });

    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });
    client.setAccessToken('stale');

    await client.refresh();
    await client.refresh();
    // The single-flight lock must release, not latch.
    expect(refreshes).toBe(2);
  });

  it('does not retry more than once', async () => {
    const { fetch, calls } = recorder((url) =>
      url.endsWith('/auth/refresh') ? json(200, { accessToken: 'fresh' }) : json(401, {}),
    );

    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });
    client.setAccessToken('stale');

    const response = await client.fetch('/me');
    // A second 401 after a successful refresh is a real refusal, not a stale
    // token — retrying again would loop.
    expect(response.status).toBe(401);
    expect(calls).toHaveLength(3);
  });

  it('clears the token when the session is genuinely over', async () => {
    const { fetch } = recorder((url) =>
      url.endsWith('/auth/refresh') ? json(401, {}) : json(401, {}),
    );

    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });
    client.setAccessToken('revoked');

    await client.fetch('/me');
    // Leaving it set would make every later request retry against a session
    // that no longer exists.
    expect(client.accessToken).toBeNull();
    expect(client.isAuthenticated).toBe(false);
  });

  it('keeps the token through a network failure', async () => {
    const { fetch } = recorder((url) => {
      if (url.endsWith('/auth/refresh')) throw new Error('network down');
      return json(401, {});
    });

    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });
    client.setAccessToken('still-valid');

    await client.fetch('/me');
    // A dropped connection is not evidence the session ended.
    expect(client.accessToken).toBe('still-valid');
  });

  it('does not attempt a refresh when no token was held', async () => {
    const { fetch, calls } = recorder(() => json(401, {}));
    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });

    await client.fetch('/public');
    // A 401 on an unauthenticated request means "sign in", not "refresh".
    expect(calls).toHaveLength(1);
  });

  it('sends no ath on the refresh proof', async () => {
    const { fetch, calls } = recorder((url) =>
      url.endsWith('/auth/refresh') ? json(200, { accessToken: 'new' }) : json(401, {}),
    );

    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });
    client.setAccessToken('stale');
    await client.fetch('/me');

    const refreshCall = calls.find((c) => c.url.endsWith('/auth/refresh'));
    const proof = headerOf(refreshCall!.init, 'DPoP') as string;
    const payload = JSON.parse(
      new TextDecoder().decode(fromBase64Url(proof.split('.')[1] as string)),
    ) as Record<string, unknown>;

    // The expired token is not what is being presented; the refresh token
    // travels in the cookie.
    expect(payload['ath']).toBeUndefined();
  });
});

describe('sign-in and sign-out', () => {
  it('captures the access token from a sign-in response', async () => {
    const { fetch } = recorder(() => json(200, { accessToken: 'issued' }));
    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore: new MemoryKeyStore(), fetch });

    await client.signIn('/auth/login', { email: 'a@b.test' });
    expect(client.accessToken).toBe('issued');
  });

  it('leaves the client unauthenticated when sign-in fails', async () => {
    const { fetch } = recorder(() => json(401, { error: {} }));
    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore: new MemoryKeyStore(), fetch });

    await client.signIn('/auth/login', {});
    expect(client.isAuthenticated).toBe(false);
  });

  it('returns a readable body from sign-in', async () => {
    // The response is cloned internally, so the caller can still read it.
    const { fetch } = recorder(() => json(200, { accessToken: 'x', user: { id: 'u1' } }));
    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore: new MemoryKeyStore(), fetch });

    const response = await client.signIn('/auth/login', {});
    await expect(response.json()).resolves.toMatchObject({ user: { id: 'u1' } });
  });

  it('discards the key and token on sign-out', async () => {
    const keyStore = new MemoryKeyStore();
    const { fetch } = recorder(() => json(204, {}));
    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });

    client.setAccessToken('token');
    const before = await client.getThumbprint();
    await client.signOut();

    expect(client.accessToken).toBeNull();
    await expect(keyStore.load()).resolves.toBeNull();
    // A shared machine is exactly where sign-out has to be thorough.
    expect(await client.getThumbprint()).not.toBe(before);
  });

  it('clears local state even when the server call fails', async () => {
    const keyStore = new MemoryKeyStore();
    const { fetch } = recorder(() => {
      throw new Error('network down');
    });
    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });
    client.setAccessToken('token');

    await client.signOut();
    // A network failure must not leave a browser believing it is signed in.
    expect(client.accessToken).toBeNull();
    await expect(keyStore.load()).resolves.toBeNull();
  });
});

describe('key persistence', () => {
  it('reuses a stored key across client instances', async () => {
    const keyStore = new MemoryKeyStore();
    const { fetch } = recorder(() => json(200, {}));

    const first = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });
    const thumbprint = await first.getThumbprint();

    // Simulates a page reload: new client, same store.
    const second = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });
    expect(await second.getThumbprint()).toBe(thumbprint);
  });

  /**
   * REGRESSION. Concurrent callers each found no key, each generated one, and
   * each wrote it — last write wins. Requests already in flight would then be
   * signing proofs with a key the store no longer held, and a session bound to
   * a discarded key is broken with nothing in the logs to explain it.
   */
  it('generates a key only once, however many callers arrive at once', async () => {
    const keyStore = new MemoryKeyStore();
    const { fetch } = recorder(() => json(200, {}));
    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });

    const results = await Promise.all(Array.from({ length: 20 }, () => client.getThumbprint()));
    expect(new Set(results).size).toBe(1);

    // And the key that was stored is the one every caller received.
    const stored = await keyStore.load();
    expect(stored?.thumbprint).toBe(results[0]);
  });

  it('signs concurrent first requests with one consistent key', async () => {
    const keyStore = new MemoryKeyStore();
    const { fetch, calls } = recorder(() => json(200, {}));
    const client = new NinshoClient({ baseUrl: ORIGIN, keyStore, fetch });

    // Eight requests before any key exists — a realistic page load.
    await Promise.all(Array.from({ length: 8 }, (_, i) => client.fetch(`/r${i}`)));

    const thumbprints = new Set(
      calls.map((call) => {
        const proof = headerOf(call.init, 'DPoP') as string;
        const header = JSON.parse(
          new TextDecoder().decode(fromBase64Url(proof.split('.')[0] as string)),
        ) as { jwk: { x: string } };
        return header.jwk.x;
      }),
    );
    expect(thumbprints.size).toBe(1);
  });
});
