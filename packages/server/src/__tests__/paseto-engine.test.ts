import { describe, it, expect, beforeEach } from 'vitest';
import {
  KeyError,
  TokenExpiredError,
  TokenInvalidError,
  TokenRevokedError,
  type Principal,
} from '@ninsho/core';
import { MemoryStore } from '../store/memory.js';
import { PasetoEngine } from '../engine/paseto.js';
import { KeyRing, generateKeyPair, loadPrivateKey } from '../keys/keyring.js';
import { signV4Public } from '../paseto/v4.js';

const PRINCIPAL: Principal = {
  userId: 'user_alice',
  roles: ['user'],
  scopes: ['orders:read'],
};
const SESSION = 'sess_1';
const ISSUER = 'https://id.acme.test';
const AUDIENCE = 'orders-api';

const KEY_2026_08 = generateKeyPair('2026-08');
const KEY_2026_05 = generateKeyPair('2026-05');

let store: MemoryStore;
let engine: PasetoEngine;

function build(
  keys = new KeyRing({ active: KEY_2026_08 }),
  overrides: { issuer?: string; audience?: string; ttl?: number } = {},
): PasetoEngine {
  return new PasetoEngine(store, keys, {
    accessTokenTtl: overrides.ttl ?? 300,
    clockToleranceSeconds: 5,
    issuer: overrides.issuer ?? ISSUER,
    audience: overrides.audience ?? AUDIENCE,
  });
}

beforeEach(() => {
  store = new MemoryStore();
  engine = build();
});

const issue = (): ReturnType<PasetoEngine['issue']> =>
  engine.issue({ principal: PRINCIPAL, sessionId: SESSION , authenticatedAt: new Date().toISOString() });

describe('issue', () => {
  it('produces a v4.public token', async () => {
    const issued = await issue();
    expect(issued.token.startsWith('v4.public.')).toBe(true);
  });

  it('stamps the active key id into the footer', async () => {
    const issued = await issue();
    const footer = Buffer.from(issued.token.split('.')[3]!, 'base64url').toString('utf8');
    expect(JSON.parse(footer)).toEqual({ kid: '2026-08' });
  });

  it('reports the strategy on the verified context', async () => {
    const issued = await issue();
    await expect(engine.verify(issued.token)).resolves.toMatchObject({ strategy: 'paseto' });
  });

  /**
   * SECURITY: v4.public is signed, not encrypted. Anyone holding the token can
   * read every claim — this test documents that plainly rather than letting a
   * developer discover it from a leak.
   */
  it('leaves claims readable to anyone holding the token', async () => {
    const issued = await issue();
    const body = Buffer.from(issued.token.split('.')[2]!, 'base64url');
    const claims = JSON.parse(body.subarray(0, body.length - 64).toString('utf8'));

    expect(claims.sub).toBe('user_alice');
    expect(claims.roles).toEqual(['user']);
    expect(claims.iss).toBe(ISSUER);
    expect(claims.aud).toBe(AUDIENCE);
  });

  it('gives each token a distinct id', async () => {
    const ids = new Set<string>();
    for (let i = 0; i < 100; i += 1) ids.add((await issue()).tokenId);
    expect(ids.size).toBe(100);
  });
});

describe('verify', () => {
  it('returns the full context', async () => {
    const issued = await issue();
    await expect(engine.verify(issued.token)).resolves.toMatchObject({
      userId: 'user_alice',
      roles: ['user'],
      scopes: ['orders:read'],
      tokenId: issued.tokenId,
      sessionId: SESSION,
    });
  });

  it('carries a tenant through when present', async () => {
    const issued = await engine.issue({
      principal: { ...PRINCIPAL, tenant: 'acme' },
      sessionId: SESSION,
      authenticatedAt: new Date().toISOString(),
    });
    await expect(engine.verify(issued.token)).resolves.toMatchObject({ tenant: 'acme' });
  });

  it.each([
    ['an empty string', ''],
    ['a JWT', 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.'],
    ['random text', 'nonsense'],
    ['a footerless token', 'v4.public.aGVsbG8'],
  ])('rejects %s', async (_label, candidate) => {
    await expect(engine.verify(candidate)).rejects.toThrow(TokenInvalidError);
  });

  it.each([
    ['undefined', undefined],
    ['null', null],
    ['a number', 7],
  ])('rejects %s without an unexpected error type', async (_label, candidate) => {
    await expect(engine.verify(candidate as unknown as string)).rejects.toThrow(
      TokenInvalidError,
    );
  });
});

/**
 * ─── Audit finding H4 ─────────────────────────────────────────────────────
 * The predecessor emitted no `iss` or `aud` and validated neither, so a token
 * minted by any deployment sharing a key was accepted everywhere. These are
 * the tests for the fix.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('issuer and audience scoping', () => {
  it('rejects a token minted for a different service', async () => {
    const ordersToken = (await issue()).token;
    const billing = build(new KeyRing({ active: KEY_2026_08 }), { audience: 'billing-api' });

    // Same key, same issuer — only the audience differs. Without the aud check
    // this token would authenticate against a service it was never meant for.
    await expect(billing.verify(ordersToken)).rejects.toThrow(TokenInvalidError);
  });

  it('rejects a token minted by a different issuer', async () => {
    const stagingToken = (await build(new KeyRing({ active: KEY_2026_08 }), {
      issuer: 'https://id.staging.test',
    }).issue({ principal: PRINCIPAL, sessionId: SESSION , authenticatedAt: new Date().toISOString() })).token;

    // A staging token working in production is not a theoretical concern.
    await expect(engine.verify(stagingToken)).rejects.toThrow(TokenInvalidError);
  });

  it('accepts a token whose issuer and audience both match', async () => {
    const issued = await issue();
    const sameService = build();
    await expect(sameService.verify(issued.token)).resolves.toBeDefined();
  });

  it('reports a mismatch as invalid rather than expired', async () => {
    // Reporting "expired" would send a client into a pointless refresh loop
    // for a token that will never be valid here.
    const ordersToken = (await issue()).token;
    const billing = build(new KeyRing({ active: KEY_2026_08 }), { audience: 'billing-api' });

    await expect(billing.verify(ordersToken)).rejects.not.toThrow(TokenExpiredError);
  });
});

/**
 * ─── Audit finding H4, second half ────────────────────────────────────────
 * A single static keypair meant rotation invalidated every outstanding token,
 * so nobody rotated. The overlap window is what makes rotation routine.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('key rotation', () => {
  it('signs with the active key and reports its id', () => {
    const ring = new KeyRing({ active: KEY_2026_08, previous: [KEY_2026_05] });
    expect(ring.signingKid).toBe('2026-08');
  });

  it('still verifies tokens signed by a retired key', async () => {
    // Token minted before the rotation.
    const oldEngine = build(new KeyRing({ active: KEY_2026_05 }));
    const oldToken = (await oldEngine.issue({ principal: PRINCIPAL, sessionId: SESSION , authenticatedAt: new Date().toISOString() })).token;

    // After rotation, the old key is verify-only but still present.
    const rotated = build(new KeyRing({ active: KEY_2026_08, previous: [KEY_2026_05] }));

    await expect(rotated.verify(oldToken)).resolves.toMatchObject({ userId: 'user_alice' });
  });

  it('causes no forced sign-out during the overlap', async () => {
    const before = build(new KeyRing({ active: KEY_2026_05 }));
    const tokens = await Promise.all(
      Array.from({ length: 5 }, () => before.issue({ principal: PRINCIPAL, sessionId: SESSION , authenticatedAt: new Date().toISOString() })),
    );

    const rotated = build(new KeyRing({ active: KEY_2026_08, previous: [KEY_2026_05] }));
    for (const t of tokens) {
      await expect(rotated.verify(t.token)).resolves.toBeDefined();
    }
  });

  it('rejects tokens from a key dropped from the set', async () => {
    const oldEngine = build(new KeyRing({ active: KEY_2026_05 }));
    const oldToken = (await oldEngine.issue({ principal: PRINCIPAL, sessionId: SESSION , authenticatedAt: new Date().toISOString() })).token;

    // Overlap window over; the retired key has been removed.
    const current = build(new KeyRing({ active: KEY_2026_08 }));
    await expect(current.verify(oldToken)).rejects.toThrow(TokenInvalidError);
  });

  it('rejects a token naming a key id that does not exist', async () => {
    const issued = await issue();
    const forgedFooter = Buffer.from('{"kid":"attacker-key"}').toString('base64url');
    const parts = issued.token.split('.');

    await expect(
      engine.verify(`v4.public.${parts[2]}.${forgedFooter}`),
    ).rejects.toThrow(TokenInvalidError);
  });

  /**
   * The footer is readable before verification, which is how key selection
   * works at all. An attacker will therefore try pointing it at a key they
   * control the private half of. The signature check is what stops them.
   */
  it('does not let a swapped kid select an attacker-chosen key', async () => {
    const attackerKey = generateKeyPair('2026-05');
    // Attacker signs their own claims but labels the token with a kid the
    // verifier trusts.
    const forged = signV4Public(
      JSON.stringify({
        jti: 'x', sub: 'user_admin', iss: ISSUER, aud: AUDIENCE,
        iat: new Date().toISOString(), nbf: new Date().toISOString(),
        exp: new Date(Date.now() + 60_000).toISOString(),
        sid: 's', roles: ['admin'], scopes: [],
      }),
      loadPrivateKey(attackerKey.privateKey),
      JSON.stringify({ kid: '2026-05' }),
    );

    const ring = new KeyRing({ active: KEY_2026_08, previous: [KEY_2026_05] });
    await expect(build(ring).verify(forged)).rejects.toThrow(TokenInvalidError);
  });
});

describe('key loading', () => {
  it('accepts raw 32-byte hex keys', () => {
    expect(() => new KeyRing({ active: generateKeyPair('k') })).not.toThrow();
  });

  it.each([
    ['not hex', 'zzzz'],
    ['odd length', 'abc'],
    ['empty', ''],
  ])('rejects a private key that is %s', (_label, value) => {
    expect(
      () => new KeyRing({ active: { kid: 'k', privateKey: value, publicKey: KEY_2026_08.publicKey } }),
    ).toThrow(KeyError);
  });

  it('rejects a non-Ed25519 key by name', () => {
    // A P-256 key parses as PKCS#8 and would otherwise fail deep inside
    // signing with something unhelpful.
    const p256 = Buffer.from(
      '308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420' +
        '0000000000000000000000000000000000000000000000000000000000000001a144034200',
      'hex',
    ).toString('hex');
    expect(
      () => new KeyRing({ active: { kid: 'k', privateKey: p256, publicKey: KEY_2026_08.publicKey } }),
    ).toThrow(KeyError);
  });

  it.each(['', 'has spaces', 'a'.repeat(65), 'has/slash'])(
    'rejects the invalid kid %j',
    (kid) => {
      expect(() => generateKeyPair(kid)).toThrow(KeyError);
    },
  );

  it('rejects duplicate key ids, which would make selection order-dependent', () => {
    expect(
      () => new KeyRing({ active: KEY_2026_08, previous: [{ kid: '2026-08', publicKey: KEY_2026_05.publicKey }] }),
    ).toThrow(/duplicate kid/);
  });

  it('lists every verification key id', () => {
    const ring = new KeyRing({ active: KEY_2026_08, previous: [KEY_2026_05] });
    expect([...ring.verificationKids].sort()).toEqual(['2026-05', '2026-08']);
  });

  it('resolves an unknown kid to null rather than throwing', () => {
    expect(new KeyRing({ active: KEY_2026_08 }).resolve('nope')).toBeNull();
  });
});

describe('time claims', () => {
  it('rejects an expired token', async () => {
    const shortLived = build(new KeyRing({ active: KEY_2026_08 }), { ttl: 1 });
    const issued = await shortLived.issue({ principal: PRINCIPAL, sessionId: SESSION , authenticatedAt: new Date().toISOString() });

    await new Promise((r) => {
      setTimeout(r, 6500);
    });

    await expect(shortLived.verify(issued.token)).rejects.toThrow(TokenExpiredError);
  }, 15_000);

  it('rejects a token whose nbf is in the future', async () => {
    const future = new Date(Date.now() + 3600_000).toISOString();
    const token = signV4Public(
      JSON.stringify({
        jti: 'j', sub: 'u', iss: ISSUER, aud: AUDIENCE,
        iat: future, nbf: future, exp: new Date(Date.now() + 7200_000).toISOString(),
        sid: 's', roles: ['user'], scopes: [],
      }),
      loadPrivateKey(KEY_2026_08.privateKey),
      JSON.stringify({ kid: '2026-08' }),
    );

    await expect(engine.verify(token)).rejects.toThrow(TokenInvalidError);
  });
});

describe('malformed claims', () => {
  const signClaims = (claims: unknown): string =>
    signV4Public(
      JSON.stringify(claims),
      loadPrivateKey(KEY_2026_08.privateKey),
      JSON.stringify({ kid: '2026-08' }),
    );

  const valid = {
    jti: 'j', sub: 'u', iss: ISSUER, aud: AUDIENCE,
    iat: new Date().toISOString(), nbf: new Date().toISOString(),
    exp: new Date(Date.now() + 60_000).toISOString(),
    sid: 's', roles: ['user'], scopes: [],
  };

  /**
   * A valid signature proves the bytes came from a key holder. It says nothing
   * about their shape — a token signed by an older version of this library, or
   * by a sibling service with a different claim set, must be rejected rather
   * than yielding a half-populated context to authorization code.
   */
  it.each([
    ['roles as a string', { ...valid, roles: 'admin' }],
    ['roles containing a non-string', { ...valid, roles: [{ a: 1 }] }],
    ['scopes missing', { ...valid, scopes: undefined }],
    ['sub missing', { ...valid, sub: undefined }],
    ['sub empty', { ...valid, sub: '' }],
    ['sid missing', { ...valid, sid: undefined }],
    ['jti missing', { ...valid, jti: undefined }],
    ['tenant as a number', { ...valid, tenant: 7 }],
    ['a JSON array', []],
    ['a JSON string', 'hello'],
  ])('rejects properly-signed but malformed claims: %s', async (_label, claims) => {
    await expect(engine.verify(signClaims(claims))).rejects.toThrow(TokenInvalidError);
  });

  it('does not let claims pollute Object.prototype', async () => {
    const token = signV4Public(
      '{"__proto__":{"pollutedPaseto":"yes"},"jti":"j","sub":"u","iss":"' + ISSUER +
        '","aud":"' + AUDIENCE + '","iat":"2026-01-01T00:00:00.000Z","nbf":"2026-01-01T00:00:00.000Z","exp":"2999-01-01T00:00:00.000Z","sid":"s","roles":[],"scopes":[]}',
      loadPrivateKey(KEY_2026_08.privateKey),
      JSON.stringify({ kid: '2026-08' }),
    );

    await engine.verify(token).catch(() => undefined);
    expect(({} as Record<string, unknown>)['pollutedPaseto']).toBeUndefined();
  });
});

describe('revocation', () => {
  it('rejects a revoked token', async () => {
    const issued = await issue();
    await expect(engine.verify(issued.token)).resolves.toBeDefined();

    await engine.revoke(issued.tokenId);
    await expect(engine.verify(issued.token)).rejects.toThrow(TokenRevokedError);
  });

  it('is idempotent', async () => {
    const issued = await issue();
    await engine.revoke(issued.tokenId);
    await expect(engine.revoke(issued.tokenId)).resolves.toBeUndefined();
  });

  it('leaves other tokens alone', async () => {
    const a = await issue();
    const b = await issue();
    await engine.revoke(a.tokenId);

    await expect(engine.verify(a.token)).rejects.toThrow(TokenRevokedError);
    await expect(engine.verify(b.token)).resolves.toBeDefined();
  });

  it('revokes every token in a session', async () => {
    const a = await issue();
    const b = await issue();

    await engine.revokeSession(SESSION);

    await expect(engine.verify(a.token)).rejects.toThrow(TokenRevokedError);
    await expect(engine.verify(b.token)).rejects.toThrow(TokenRevokedError);
  });

  it('does not touch a different session', async () => {
    const mine = await engine.issue({ principal: PRINCIPAL, sessionId: 'sess_mine' , authenticatedAt: new Date().toISOString() });
    const theirs = await engine.issue({ principal: PRINCIPAL, sessionId: 'sess_theirs' , authenticatedAt: new Date().toISOString() });

    await engine.revokeSession('sess_mine');

    await expect(engine.verify(mine.token)).rejects.toThrow(TokenRevokedError);
    await expect(engine.verify(theirs.token)).resolves.toBeDefined();
  });

  it('is safe for an unknown session', async () => {
    await expect(engine.revokeSession('sess_nope')).resolves.toBeUndefined();
  });

  /**
   * The denylist entry expires when the token would have anyway, which is what
   * keeps it bounded without a cleanup job.
   */
  it('does not retain denylist entries beyond the token lifetime', async () => {
    const shortLived = build(new KeyRing({ active: KEY_2026_08 }), { ttl: 1 });
    const issued = await shortLived.issue({ principal: PRINCIPAL, sessionId: SESSION , authenticatedAt: new Date().toISOString() });
    await shortLived.revoke(issued.tokenId);

    const before = store.size();
    await new Promise((r) => {
      setTimeout(r, 1200);
    });
    expect(store.size()).toBeLessThan(before);
  });
});

/**
 * A key set that cannot verify its own signature.
 *
 * Both halves parse independently and both are Ed25519, so pasting the private
 * key of one pair beside the public key of another constructs happily — and
 * then the process signs every token with one key and verifies with the other.
 * Every request answers `TOKEN_INVALID`, which reads as a token problem and
 * sends whoever is debugging it to look at sessions, cookies and clocks rather
 * than at the two lines of configuration that are wrong.
 */
describe('the active key pair must be a pair', () => {
  it('refuses halves from different pairs', () => {
    const a = generateKeyPair('k1');
    const b = generateKeyPair('k2');

    expect(
      () => new KeyRing({ active: { kid: 'k1', privateKey: a.privateKey, publicKey: b.publicKey } }),
    ).toThrow(/not two halves of the same key pair/);
  });

  it('accepts a genuine pair', () => {
    const key = generateKeyPair('k1');
    expect(() => new KeyRing({ active: key })).not.toThrow();
  });

  it('names the failure as configuration rather than as a token problem', () => {
    // The whole point: the message has to send someone to the right file.
    const a = generateKeyPair('k1');
    const b = generateKeyPair('k2');

    let message = '';
    try {
      new KeyRing({ active: { kid: 'k1', privateKey: a.privateKey, publicKey: b.publicKey } });
    } catch (error) {
      message = (error as Error).message;
    }

    expect(message).toContain('keys.active.privateKey');
    expect(message).toContain('keys.active.publicKey');
  });

  it('does not check previous keys, which have no private half to check', () => {
    // `previous` entries are typed as `VerificationKey` — a kid and a public
    // key, nothing to round trip against. Asserted so the absence of a check
    // reads as a consequence of the shape rather than an oversight.
    const active = generateKeyPair('k2');
    const retired = generateKeyPair('k1');

    expect(
      () => new KeyRing({ active, previous: [{ kid: 'k1', publicKey: retired.publicKey }] }),
    ).not.toThrow();
  });

  it('still signs and verifies its own tokens after the check', async () => {
    // The check must not disturb the key material it probes.
    const ring = new KeyRing({ active: generateKeyPair('k1') });
    const store = new MemoryStore();
    const engine = new PasetoEngine(store, ring, {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'https://example.test',
      audience: 'api',
    });

    const issued = await engine.issue({
      principal: { userId: 'u', roles: [], scopes: [] },
      sessionId: 's',
      authenticatedAt: new Date().toISOString(),
    });

    await expect(engine.verify(issued.token)).resolves.toMatchObject({ userId: 'u' });
    await store.close();
  });
});
