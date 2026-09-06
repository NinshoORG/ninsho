import { describe, it, expect } from 'vitest';
import { TokenInvalidError, TokenMissingError } from '@ninsho/core';
import { MemoryAuditSink } from '../audit.js';
import {
  defaultRequestUrl,
  establishProofOfPossession,
  type DpopContext,
} from '../http/dpop-middleware.js';
import { DpopReplayGuard } from '../dpop/replay.js';
import { MemoryStore } from '../store/memory.js';
import { generateDpopKeyPair, createDpopProof, jwkThumbprint } from '../dpop/index.js';
import type { HttpRequest } from '../http/types.js';

/**
 * The request side of DPoP, on its own.
 *
 * `dpop-integration.test.ts` drives this through a wired-up application, which
 * is where the *binding* belongs. What that cannot reach is what happens when
 * the request itself is shaped unusually — because a wired-up test sends
 * ordinary requests, and every interesting case here is a request nobody sends
 * by accident.
 *
 * Both halves of the reconstruction take client-supplied input. The `Host`
 * header is documented as such at the top of the module. The *request target*
 * was not, and is: HTTP permits an absolute-form target, and a
 * protocol-relative one looks like a path to every framework in the chain.
 */

const RP = 'https://api.example.com';

const request = (overrides: Record<string, unknown> = {}): HttpRequest =>
  ({
    method: 'GET',
    url: '/orders',
    headers: { host: 'api.example.com' },
    protocol: 'https',
    ...overrides,
  }) as unknown as HttpRequest;

describe('defaultRequestUrl', () => {
  it('reconstructs an ordinary request', () => {
    expect(defaultRequestUrl(request())).toBe(`${RP}/orders`);
  });

  it('keeps the query, which is part of what was signed', () => {
    expect(defaultRequestUrl(request({ url: '/orders?page=2' }))).toBe(`${RP}/orders?page=2`);
  });

  it('prefers originalUrl, which is the pre-routing path', () => {
    // Express rewrites `req.url` inside a mounted router; the proof was minted
    // against the URL the client actually requested.
    expect(defaultRequestUrl(request({ originalUrl: '/api/orders', url: '/orders' }))).toBe(
      `${RP}/api/orders`,
    );
  });

  it.each([
    ['an absolute-form target', 'https://evil.example/orders'],
    ['a plaintext absolute target', 'http://evil.example/orders'],
    ['a protocol-relative target', '//evil.example/orders'],
    ['a protocol-relative target with credentials', '//user:pw@evil.example/orders'],
  ])('does not let %s replace the authority', (_label, url) => {
    // REGRESSION. `new URL(target, base)` discards the base entirely for any
    // of these, so the reconstruction became whatever origin the client named
    // — and the `htu` comparison, which exists to keep a proof scoped to one
    // endpoint, compared two values the client controlled.
    const reconstructed = defaultRequestUrl(request({ url }));

    expect(new URL(reconstructed).origin).toBe(RP);
    expect(reconstructed).not.toContain('evil.example');
    expect(reconstructed).toBe(`${RP}/orders`);
  });

  it('reads a forwarded protocol, taking the first hop only', () => {
    const url = defaultRequestUrl(
      request({ protocol: 'http', headers: { host: 'api.example.com', 'x-forwarded-proto': 'https, http' } }),
    );
    expect(url).toBe(`${RP}/orders`);
  });

  it('falls back to http when nothing states a protocol', () => {
    expect(defaultRequestUrl(request({ protocol: undefined }))).toBe(
      'http://api.example.com/orders',
    );
  });

  it('reads Express’s secure flag when there is no protocol', () => {
    expect(defaultRequestUrl(request({ protocol: undefined, secure: true }))).toBe(
      `${RP}/orders`,
    );
  });

  it('falls back to localhost when the Host header is absent or repeated', () => {
    expect(defaultRequestUrl(request({ headers: {} }))).toBe('https://localhost/orders');
    expect(defaultRequestUrl(request({ headers: { host: ['a', 'b'] } }))).toBe(
      'https://localhost/orders',
    );
  });

  it('never throws, whatever the request looks like', () => {
    // It is called outside the try block that turns proof failures into a 401,
    // so a throw here would surface as a 500 — an infrastructure error where a
    // mismatch is the right answer.
    const shapes: Record<string, unknown>[] = [
      { url: undefined, originalUrl: undefined },
      { url: '' },
      { url: '::::' },
      { headers: { host: 'not a host', 'x-forwarded-proto': 'not a protocol' } },
      { headers: { host: '' } },
      { protocol: '', headers: { host: 'api.example.com' } },
    ];

    for (const shape of shapes) {
      expect(() => defaultRequestUrl(request(shape))).not.toThrow();
      expect(typeof defaultRequestUrl(request(shape))).toBe('string');
    }
  });

  it('never throws on random targets', () => {
    for (let i = 0; i < 500; i += 1) {
      const bytes = new Uint8Array(Math.floor(Math.random() * 40));
      crypto.getRandomValues(bytes);
      const url = Buffer.from(bytes).toString('latin1');

      expect(() => defaultRequestUrl(request({ url }))).not.toThrow();
    }
  });
});

describe('establishProofOfPossession', () => {
  const context = (store: MemoryStore, overrides: Partial<DpopContext> = {}): DpopContext => ({
    replayGuard: new DpopReplayGuard(store, 'closed', 120),
    maxAgeSeconds: 60,
    clockToleranceSeconds: 5,
    audit: new MemoryAuditSink(),
    ...overrides,
  });

  const proofRequest = async (
    over: Record<string, unknown> = {},
  ): Promise<{ req: HttpRequest; jkt: string; store: MemoryStore }> => {
    const store = new MemoryStore();
    const keys = await generateDpopKeyPair();
    const proof = await createDpopProof(keys, { method: 'GET', url: `${RP}/orders` });
    return {
      store,
      jkt: await jwkThumbprint(keys.publicJwk),
      req: request({ headers: { host: 'api.example.com', dpop: proof }, ...over }),
    };
  };

  it('returns the thumbprint the token must be bound to', async () => {
    const { req, jkt, store } = await proofRequest();
    await expect(establishProofOfPossession(req, undefined, context(store))).resolves.toBe(jkt);
    await store.close();
  });

  it('refuses a request with no proof', async () => {
    const store = new MemoryStore();
    await expect(
      establishProofOfPossession(request(), undefined, context(store)),
    ).rejects.toThrow(TokenMissingError);
    await store.close();
  });

  it('refuses two proofs joined into one header', async () => {
    // REGRESSION. Node joins duplicate `DPoP` headers with a comma rather than
    // arraying them, so the array check RFC 9449 §4.3 step 1 is written around
    // could never fire on a Node server. The joined pair was still refused,
    // but as an unparseable JWS — the ambiguity itself went unnoticed.
    const { req, store } = await proofRequest();
    const joined = request({
      headers: { host: 'api.example.com', dpop: `${req.headers['dpop'] as string}, other` },
    });

    const error = await establishProofOfPossession(joined, undefined, context(store)).catch(
      (e: unknown) => e as unknown,
    );
    expect(error).toBeInstanceOf(TokenMissingError);
    // `NinshoError` keeps diagnostics in `detail`; `message` is the fixed,
    // uninformative text a client sees.
    expect((error as { detail?: string }).detail).toMatch(/multiple proofs/);
    await store.close();
  });

  it('refuses a duplicate only rawHeaders can see', async () => {
    const { req, store } = await proofRequest();
    const duplicated = request({
      headers: req.headers,
      rawHeaders: ['Host', 'api.example.com', 'DPoP', 'a', 'dpop', 'b'],
    });

    const error = await establishProofOfPossession(duplicated, undefined, context(store)).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(TokenMissingError);
    expect((error as { detail?: string }).detail).toMatch(/2 DPoP headers/);
    await store.close();
  });

  it('refuses a proof minted for another URL', async () => {
    const store = new MemoryStore();
    const keys = await generateDpopKeyPair();
    const proof = await createDpopProof(keys, { method: 'GET', url: `${RP}/admin` });

    await expect(
      establishProofOfPossession(
        request({ headers: { host: 'api.example.com', dpop: proof } }),
        undefined,
        context(store),
      ),
    ).rejects.toThrow(TokenInvalidError);
    await store.close();
  });

  it('refuses a proof steered onto another origin by the request target', async () => {
    // The two halves of the fix meeting: a client that mints a proof for
    // `https://evil.example/orders` and sends `GET //evil.example/orders`
    // would, before this, have had the server reconstruct the same string and
    // agree with itself.
    const store = new MemoryStore();
    const keys = await generateDpopKeyPair();
    const proof = await createDpopProof(keys, {
      method: 'GET',
      url: 'https://evil.example/orders',
    });

    await expect(
      establishProofOfPossession(
        request({ url: '//evil.example/orders', headers: { host: 'api.example.com', dpop: proof } }),
        undefined,
        context(store),
      ),
    ).rejects.toThrow(TokenInvalidError);
    await store.close();
  });

  it('refuses a replayed proof and says so in the audit trail', async () => {
    const { req, store } = await proofRequest();
    const audit = new MemoryAuditSink();
    const ctx = context(store, { audit });

    await expect(establishProofOfPossession(req, undefined, ctx)).resolves.toBeTypeOf('string');

    const replayed = await establishProofOfPossession(req, undefined, ctx).catch(
      (e: unknown) => e as unknown,
    );
    expect(replayed).toBeInstanceOf(TokenInvalidError);
    expect((replayed as { detail?: string }).detail).toMatch(/already been used/);

    expect(audit.events.some((e) => e.type === 'token.rejected')).toBe(true);
    await store.close();
  });

  it('honours a caller-supplied requestUrl over the request', async () => {
    // The escape hatch for deployments where `Host` is not normalised
    // upstream. If it were ignored, the documented advice would be useless.
    const store = new MemoryStore();
    const keys = await generateDpopKeyPair();
    const proof = await createDpopProof(keys, { method: 'GET', url: `${RP}/from-config` });

    await expect(
      establishProofOfPossession(
        request({ url: '/anything', headers: { host: 'attacker.example', dpop: proof } }),
        undefined,
        context(store, { requestUrl: () => `${RP}/from-config` }),
      ),
    ).resolves.toBeTypeOf('string');
    await store.close();
  });

  it('requires ath once a token is presented, and not before', async () => {
    // RFC 9449 §4.3 step 11. The login route sends its first proof before any
    // token exists, so demanding a hash of nothing there would make the flow
    // impossible.
    const store = new MemoryStore();
    const keys = await generateDpopKeyPair();

    const withoutAth = await createDpopProof(keys, { method: 'GET', url: `${RP}/orders` });
    const req = request({ headers: { host: 'api.example.com', dpop: withoutAth } });

    await expect(establishProofOfPossession(req, undefined, context(store))).resolves.toBeTypeOf(
      'string',
    );

    const fresh = new MemoryStore();
    await expect(
      establishProofOfPossession(req, 'some-access-token', context(fresh)),
    ).rejects.toThrow(TokenInvalidError);

    await store.close();
    await fresh.close();
  });
});
