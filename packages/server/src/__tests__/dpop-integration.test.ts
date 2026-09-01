import { describe, it, expect, beforeEach } from 'vitest';
import { ConfigurationError, type Principal } from '@ninsho/core';
import { Ninsho } from '../ninsho.js';
import { MemoryStore } from '../store/memory.js';
import { MemoryAuditSink } from '../audit.js';
import { generateKeyPair } from '../keys/keyring.js';
import { getAuth } from '../http/middleware.js';
import { createDpopProof, generateDpopKeyPair, type DpopKeyPair } from '../dpop/sign.js';
import type { HttpRequest, HttpResponse, Middleware } from '../http/types.js';

const ALICE: Principal = { userId: 'user_alice', roles: ['user'], scopes: [] };
const ORIGIN = 'https://api.example.test';

let store: MemoryStore;
let audit: MemoryAuditSink;
let auth: Ninsho;
let key: DpopKeyPair;

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

async function run(mw: Middleware, req: HttpRequest): Promise<{
  res: FakeResponse;
  nextCalled: boolean;
  code: string | undefined;
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
  const body = res.body as { error?: { code?: string } } | undefined;
  return { res, nextCalled, code: body?.error?.code };
}

/** A request carrying a bearer token and, optionally, a DPoP proof. */
function request(options: {
  token?: string;
  proof?: string;
  method?: string;
  path?: string;
}): HttpRequest {
  const method = options.method ?? 'GET';
  const path = options.path ?? '/me';
  return {
    method,
    originalUrl: path,
    protocol: 'https',
    headers: {
      host: 'api.example.test',
      ...(options.token !== undefined && { authorization: `DPoP ${options.token}` }),
      ...(options.proof !== undefined && { dpop: options.proof }),
    },
  } as unknown as HttpRequest;
}

/** Signs a proof for the request that will carry it. */
function proofFor(
  keyPair: DpopKeyPair,
  options: { token?: string; method?: string; path?: string; jti?: string },
): string {
  return createDpopProof(keyPair, {
    method: options.method ?? 'GET',
    url: `${ORIGIN}${options.path ?? '/me'}`,
    ...(options.token !== undefined && { accessToken: options.token }),
    ...(options.jti !== undefined && { jti: options.jti }),
  });
}

/** Establishes a DPoP-bound session, as a login route would. */
async function login(instance: Ninsho, keyPair: DpopKeyPair): Promise<{
  accessToken: string;
  refreshToken: string;
  sessionId: string;
}> {
  const loginProof = proofFor(keyPair, { method: 'POST', path: '/auth/login' });
  const jkt = await instance.confirmProofOfPossession(
    request({ proof: loginProof, method: 'POST', path: '/auth/login' }),
  );
  const pair = await instance.createSession(ALICE, { confirmationKey: jkt });
  return {
    accessToken: pair.accessToken,
    refreshToken: pair.refreshToken,
    sessionId: pair.sessionId,
  };
}

beforeEach(() => {
  store = new MemoryStore();
  audit = new MemoryAuditSink();
  auth = new Ninsho({ store, audit, binding: 'dpop' });
  key = generateDpopKeyPair('ES256');
});

describe('configuration', () => {
  it('accepts binding: dpop', () => {
    expect(() => new Ninsho({ store: new MemoryStore(), binding: 'dpop' })).not.toThrow();
  });

  it('defaults to a 60-second proof window', () => {
    expect(auth.config.dpopProofMaxAgeSeconds).toBe(60);
  });

  it('rejects a proof window setting under bearer semantics', () => {
    // Setting it would suggest a proof is being checked when none is.
    expect(
      () => new Ninsho({ store: new MemoryStore(), dpopProofMaxAgeSeconds: 30 }),
    ).toThrow(ConfigurationError);
  });

  it('warns about a wide proof window', () => {
    const sink = new MemoryAuditSink();
    new Ninsho({
      store: new MemoryStore(),
      audit: sink,
      binding: 'dpop',
      dpopProofMaxAgeSeconds: 3600,
    });
    expect(sink.ofType('config.insecure')[0]?.reason).toMatch(/captured proof usable/);
  });

  it('refuses to confirm a proof under bearer semantics', async () => {
    const bearer = new Ninsho({ store: new MemoryStore() });
    await expect(bearer.confirmProofOfPossession(request({}))).rejects.toThrow(
      /requires binding: 'dpop'/,
    );
  });

  /**
   * Fail closed. Issuing an unbound token here would mean a deployment believed
   * it had proof-of-possession while handing out bearer credentials — and
   * nothing downstream would reveal it, because an unbound token verifies
   * perfectly well.
   */
  it('refuses to create an unbound session while DPoP is enabled', () => {
    expect(() => auth.createSession(ALICE)).toThrow(/requires a confirmationKey/);
  });
});

describe('the happy path', () => {
  it('binds a session to the proof key and accepts matching requests', async () => {
    const session = await login(auth, key);
    const req = request({
      token: session.accessToken,
      proof: proofFor(key, { token: session.accessToken }),
    });

    const result = await run(auth.verify(), req);
    expect(result.nextCalled).toBe(true);
    expect(getAuth(req).confirmationKey).toBe(key.jkt);
  });

  it.each(['ES256', 'EdDSA'] as const)('works with a %s client key', async (algorithm) => {
    const clientKey = generateDpopKeyPair(algorithm);
    const session = await login(auth, clientKey);

    const result = await run(
      auth.verify(),
      request({
        token: session.accessToken,
        proof: proofFor(clientKey, { token: session.accessToken }),
      }),
    );
    expect(result.nextCalled).toBe(true);
  });

  it('accepts a fresh proof on each subsequent request', async () => {
    const session = await login(auth, key);

    for (const path of ['/me', '/orders', '/profile']) {
      const result = await run(
        auth.verify(),
        request({
          token: session.accessToken,
          proof: proofFor(key, { token: session.accessToken, path }),
          path,
        }),
      );
      expect(result.nextCalled).toBe(true);
    }
  });

  it('works under the paseto strategy too', async () => {
    const paseto = new Ninsho({
      store: new MemoryStore(),
      audit,
      binding: 'dpop',
      strategy: 'paseto',
      issuer: 'https://id.test',
      audience: 'api',
      keys: { active: generateKeyPair('k1') },
    });
    const clientKey = generateDpopKeyPair();
    const session = await login(paseto, clientKey);

    const req = request({
      token: session.accessToken,
      proof: proofFor(clientKey, { token: session.accessToken }),
    });
    const result = await run(paseto.verify(), req);

    expect(result.nextCalled).toBe(true);
    // The binding travels inside the signed payload as the `cnf` claim, so it
    // cannot be stripped without invalidating the signature.
    expect(getAuth(req).confirmationKey).toBe(clientKey.jkt);
  });
});

/**
 * ─── The property DPoP exists for ─────────────────────────────────────────
 * SECURITY.md previously said, of bearer tokens: "anyone holding a valid access
 * token can use it, and no configuration changes this." These are the tests
 * that make that statement conditional.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('a stolen token is useless without the key', () => {
  it('refuses a stolen token presented with no proof at all', async () => {
    const session = await login(auth, key);

    // The attacker has the token — from a log, an XSS, a proxy — but not the
    // private key, which never left the client.
    const result = await run(auth.verify(), request({ token: session.accessToken }));

    expect(result.res.statusCode).toBe(401);
    expect(result.nextCalled).toBe(false);
  });

  it("refuses a stolen token presented with the attacker's own key", async () => {
    const session = await login(auth, key);
    const attackerKey = generateDpopKeyPair();

    // A perfectly valid proof — signed by the wrong key.
    const result = await run(
      auth.verify(),
      request({
        token: session.accessToken,
        proof: proofFor(attackerKey, { token: session.accessToken }),
      }),
    );

    expect(result.res.statusCode).toBe(401);
  });

  it('refuses a captured proof replayed with the token it came from', async () => {
    const session = await login(auth, key);
    const proof = proofFor(key, { token: session.accessToken });

    // First use succeeds.
    expect((await run(auth.verify(), request({ token: session.accessToken, proof }))).nextCalled).toBe(
      true,
    );

    // The same proof again — captured verbatim by a logging proxy, say — must
    // not work. Without single-use enforcement it would stay valid for its
    // whole acceptance window.
    const replay = await run(auth.verify(), request({ token: session.accessToken, proof }));
    expect(replay.res.statusCode).toBe(401);
  });

  it('records a replayed proof for monitoring', async () => {
    const session = await login(auth, key);
    const proof = proofFor(key, { token: session.accessToken });

    await run(auth.verify(), request({ token: session.accessToken, proof }));
    await run(auth.verify(), request({ token: session.accessToken, proof }));

    expect(
      audit.ofType('token.rejected').some((e) => e.reason === 'dpop_proof_replayed'),
    ).toBe(true);
  });

  it('refuses a proof minted for a different endpoint', async () => {
    const session = await login(auth, key);
    // Captured from /me, replayed against /admin.
    const proof = proofFor(key, { token: session.accessToken, path: '/me' });

    const result = await run(
      auth.verify(),
      request({ token: session.accessToken, proof, path: '/admin' }),
    );
    expect(result.res.statusCode).toBe(401);
  });

  it('refuses a proof minted for a different method', async () => {
    const session = await login(auth, key);
    // Captured from a GET, replayed as a DELETE.
    const proof = proofFor(key, { token: session.accessToken, method: 'GET' });

    const result = await run(
      auth.verify(),
      request({ token: session.accessToken, proof, method: 'DELETE' }),
    );
    expect(result.res.statusCode).toBe(401);
  });

  it('refuses a proof bound to a different token', async () => {
    const first = await login(auth, key);
    const second = await login(auth, key);

    // A proof for one token cannot authorise another, even from the same key —
    // that is what `ath` is for.
    const result = await run(
      auth.verify(),
      request({
        token: first.accessToken,
        proof: proofFor(key, { token: second.accessToken }),
      }),
    );
    expect(result.res.statusCode).toBe(401);
  });

  it('refuses a stale proof', async () => {
    const session = await login(auth, key);
    const stale = createDpopProof(key, {
      method: 'GET',
      url: `${ORIGIN}/me`,
      accessToken: session.accessToken,
      issuedAtMs: Date.now() - 600_000,
    });

    const result = await run(auth.verify(), request({ token: session.accessToken, proof: stale }));
    expect(result.res.statusCode).toBe(401);
  });

  it('refuses two DPoP headers rather than choosing one', async () => {
    const session = await login(auth, key);
    const req = request({ token: session.accessToken });
    (req.headers as Record<string, unknown>)['dpop'] = [
      proofFor(key, { token: session.accessToken }),
      proofFor(key, { token: session.accessToken }),
    ];

    const result = await run(auth.verify(), req);
    expect(result.res.statusCode).toBe(401);
  });

  it('does not disclose why a proof was refused', async () => {
    const session = await login(auth, key);
    const attackerKey = generateDpopKeyPair();

    const result = await run(
      auth.verify(),
      request({
        token: session.accessToken,
        proof: proofFor(attackerKey, { token: session.accessToken }),
      }),
    );

    const serialized = JSON.stringify(result.res.body);
    expect(serialized).not.toMatch(/jkt|thumbprint|signature|jwk|cnf/i);
  });
});

/**
 * RFC 9449 §5. The refresh token is the longest-lived credential in the system,
 * so leaving it unbound would make it the obvious thing to steal.
 */
describe('refresh tokens are bound too', () => {
  it('rotates when the correct key is presented', async () => {
    const session = await login(auth, key);
    const rotated = await auth.refresh(session.refreshToken, { confirmationKey: key.jkt });

    expect(rotated.refreshToken).not.toBe(session.refreshToken);
  });

  it('refuses a stolen refresh token with no proof', async () => {
    const session = await login(auth, key);
    await expect(auth.refresh(session.refreshToken)).rejects.toThrow();
  });

  it("refuses a stolen refresh token with the attacker's key", async () => {
    const session = await login(auth, key);
    const attackerKey = generateDpopKeyPair();

    await expect(
      auth.refresh(session.refreshToken, { confirmationKey: attackerKey.jkt }),
    ).rejects.toThrow();
  });

  it('carries the binding across rotations', async () => {
    const session = await login(auth, key);

    let current = session.refreshToken;
    for (let i = 0; i < 3; i += 1) {
      const rotated = await auth.refresh(current, { confirmationKey: key.jkt });
      current = rotated.refreshToken;
    }

    // Still bound after three rotations — the binding is not silently dropped
    // somewhere in the chain.
    await expect(auth.refresh(current)).rejects.toThrow();
    await expect(auth.refresh(current, { confirmationKey: key.jkt })).resolves.toBeDefined();
  });

  it('issues bound access tokens from a rotation', async () => {
    const session = await login(auth, key);
    const rotated = await auth.refresh(session.refreshToken, { confirmationKey: key.jkt });

    // The new access token must be bound too, or rotation would be a way to
    // downgrade to a bearer credential.
    const unbound = await run(auth.verify(), request({ token: rotated.accessToken }));
    expect(unbound.res.statusCode).toBe(401);

    const bound = await run(
      auth.verify(),
      request({
        token: rotated.accessToken,
        proof: proofFor(key, { token: rotated.accessToken }),
      }),
    );
    expect(bound.nextCalled).toBe(true);
  });

  it('enforces the binding on the grace path as well', async () => {
    const session = await login(auth, key);
    await auth.refresh(session.refreshToken, { confirmationKey: key.jkt });

    const attackerKey = generateDpopKeyPair();
    // Inside the grace window, the old token resolves to its replacement — but
    // that path hands back a live credential, so it must check the binding too.
    await expect(
      auth.refresh(session.refreshToken, { confirmationKey: attackerKey.jkt }),
    ).rejects.toThrow();
  });
});

describe('bearer mode is unaffected', () => {
  it('still accepts an unbound token when binding is none', async () => {
    const bearer = new Ninsho({ store: new MemoryStore(), audit });
    const pair = await bearer.createSession(ALICE);

    const result = await run(bearer.verify(), request({ token: pair.accessToken }));
    expect(result.nextCalled).toBe(true);
  });

  it('ignores a DPoP header when binding is none', async () => {
    const bearer = new Ninsho({ store: new MemoryStore(), audit });
    const pair = await bearer.createSession(ALICE);

    const result = await run(
      bearer.verify(),
      request({ token: pair.accessToken, proof: 'not-even-a-valid-proof' }),
    );
    expect(result.nextCalled).toBe(true);
  });

  it('accepts the Bearer scheme as well as DPoP', async () => {
    const session = await login(auth, key);
    const req = request({
      token: session.accessToken,
      proof: proofFor(key, { token: session.accessToken }),
    });
    // The binding is enforced by the token's own cnf, not by the scheme name,
    // so accepting Bearer here cannot be used to shed a binding.
    (req.headers as Record<string, unknown>)['authorization'] = `Bearer ${session.accessToken}`;

    expect((await run(auth.verify(), req)).nextCalled).toBe(true);
  });
});

describe('request URI reconstruction', () => {
  it('can be overridden for deployments where Host is not trustworthy', async () => {
    const session = await login(auth, key);
    auth.setRequestUrlBuilder(() => `${ORIGIN}/me`);

    const req = request({
      token: session.accessToken,
      proof: proofFor(key, { token: session.accessToken, path: '/me' }),
    });
    // A forged Host is now irrelevant: the URI comes from configuration.
    (req.headers as Record<string, unknown>)['host'] = 'evil.example.test';

    expect((await run(auth.verify(), req)).nextCalled).toBe(true);
  });
});

/**
 * ─── REGRESSION: a failed binding check must not consume the token ────────
 * The first implementation checked the DPoP binding inside `#rotate`, which
 * runs *after* the atomic `take()` that consumes the refresh token. An attacker
 * holding a stolen refresh token — but not the key — could therefore destroy
 * the session simply by presenting it: the token was consumed, the rotation
 * then failed, and the legitimate client's next refresh found nothing.
 *
 * A denial of service handed to precisely the party the binding exists to shut
 * out. Found by a test asserting the binding survived several rotations.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('regression: a rejected proof must not consume the refresh token', () => {
  it('leaves the token usable after a refresh with no proof', async () => {
    const session = await login(auth, key);

    await expect(auth.refresh(session.refreshToken)).rejects.toThrow();

    // The legitimate client, with its key, must still be able to refresh.
    await expect(
      auth.refresh(session.refreshToken, { confirmationKey: key.jkt }),
    ).resolves.toBeDefined();
  });

  it("leaves the token usable after a refresh with an attacker's key", async () => {
    const session = await login(auth, key);
    const attackerKey = generateDpopKeyPair();

    await expect(
      auth.refresh(session.refreshToken, { confirmationKey: attackerKey.jkt }),
    ).rejects.toThrow();

    await expect(
      auth.refresh(session.refreshToken, { confirmationKey: key.jkt }),
    ).resolves.toBeDefined();
  });

  it('survives repeated attacker attempts without losing the session', async () => {
    const session = await login(auth, key);
    const attackerKey = generateDpopKeyPair();

    for (let i = 0; i < 10; i += 1) {
      await auth.refresh(session.refreshToken).catch(() => undefined);
      await auth
        .refresh(session.refreshToken, { confirmationKey: attackerKey.jkt })
        .catch(() => undefined);
    }

    // Ten failed attempts, and the session is intact.
    await expect(
      auth.refresh(session.refreshToken, { confirmationKey: key.jkt }),
    ).resolves.toBeDefined();
  });

  it('raises no false reuse alarm from the rejected attempts', async () => {
    const session = await login(auth, key);
    await auth.refresh(session.refreshToken).catch(() => undefined);
    await auth.refresh(session.refreshToken, { confirmationKey: key.jkt });

    // A consumed-then-failed token would have looked like theft on the next
    // legitimate use, which is the worst possible false positive.
    expect(audit.ofType('refresh.reuse_detected')).toHaveLength(0);
  });
});
