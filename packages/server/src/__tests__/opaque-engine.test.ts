import { describe, it, expect, beforeEach } from 'vitest';
import {
  TokenExpiredError,
  TokenInvalidError,
  generateToken,
  hashToken,
  type Principal,
} from '@ninshorg/core';
import { MemoryStore } from '../store/memory.js';
import { OpaqueEngine } from '../engine/opaque.js';
import { KEYS } from '../keys.js';

const PRINCIPAL: Principal = {
  userId: 'user_alice',
  roles: ['user'],
  scopes: ['orders:read'],
};

const SESSION = 'sess_alice_1';

let store: MemoryStore;
let engine: OpaqueEngine;

beforeEach(() => {
  store = new MemoryStore();
  engine = new OpaqueEngine(store, { accessTokenTtl: 300, clockToleranceSeconds: 5 });
});

const issue = (
  overrides: { principal?: Principal; sessionId?: string } = {},
): ReturnType<OpaqueEngine['issue']> =>
  engine.issue({
    principal: overrides.principal ?? PRINCIPAL,
    sessionId: overrides.sessionId ?? SESSION,
    authenticatedAt: new Date().toISOString(),
  });

describe('issue', () => {
  it('returns a token, an id, and both timestamps', async () => {
    const issued = await issue();
    expect(issued.token).toBeTypeOf('string');
    expect(issued.token.length).toBeGreaterThan(30);
    expect(issued.tokenId).toBeTypeOf('string');
    expect(Date.parse(issued.issuedAt)).not.toBeNaN();
    expect(Date.parse(issued.expiresAt)).not.toBeNaN();
  });

  it('sets expiry from the configured TTL', async () => {
    const issued = await issue();
    const lifetime = Date.parse(issued.expiresAt) - Date.parse(issued.issuedAt);
    expect(lifetime).toBe(300_000);
  });

  it('produces a distinct token and id every time', async () => {
    const tokens = new Set<string>();
    const ids = new Set<string>();
    for (let i = 0; i < 200; i += 1) {
      const issued = await issue();
      tokens.add(issued.token);
      ids.add(issued.tokenId);
    }
    expect(tokens.size).toBe(200);
    expect(ids.size).toBe(200);
  });

  it('emits URL-safe tokens, so they survive headers and cookies unescaped', async () => {
    const { token } = await issue();
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  /**
   * SECURITY: the raw token must never be a key or a value in the store.
   * Read access to the store — a backup, a replica, an exposed instance —
   * must not yield usable credentials.
   */
  it('never stores the raw token', async () => {
    const { token } = await issue();

    // Keyed by the hash, not the token itself.
    await expect(store.get(KEYS.accessToken(token))).resolves.toBeNull();
    await expect(store.get(KEYS.accessToken(hashToken(token)))).resolves.not.toBeNull();

    // And the token does not appear inside the stored record either.
    const record = await store.get(KEYS.accessToken(hashToken(token)));
    expect(record).not.toContain(token);
  });

  it('indexes the token under its session so the session can be terminated', async () => {
    const { token } = await issue();
    const members = await store.sMembers(KEYS.sessionTokens(SESSION));
    expect(members).toContain(hashToken(token));
  });

  it('makes the token verifiable the moment it is returned', async () => {
    // A caller must never hold a credential that is not yet usable.
    const { token } = await issue();
    await expect(engine.verify(token)).resolves.toBeDefined();
  });
});

describe('verify', () => {
  it('returns the full auth context for a valid token', async () => {
    const issued = await issue();
    const auth = await engine.verify(issued.token);

    expect(auth).toMatchObject({
      userId: 'user_alice',
      roles: ['user'],
      scopes: ['orders:read'],
      tokenId: issued.tokenId,
      sessionId: SESSION,
      strategy: 'opaque',
    });
    expect(auth.expiresAt).toBe(issued.expiresAt);
  });

  it('carries the tenant through when present', async () => {
    const issued = await issue({
      principal: { ...PRINCIPAL, tenant: 'acme' },
    });
    await expect(engine.verify(issued.token)).resolves.toMatchObject({ tenant: 'acme' });
  });

  it('omits tenant entirely when absent, rather than setting it undefined', async () => {
    const issued = await issue();
    const auth = await engine.verify(issued.token);
    expect('tenant' in auth).toBe(false);
  });

  // ── Adversarial ──────────────────────────────────────────────────────────

  it('rejects a token that was never issued', async () => {
    await expect(engine.verify(generateToken())).rejects.toThrow(TokenInvalidError);
  });

  it.each([
    ['an empty string', ''],
    ['whitespace', '   '],
    ['a short string', 'a'],
    ['a JSON payload', '{"userId":"admin"}'],
    ['a path traversal attempt', '../../etc/passwd'],
    ['a Redis command injection attempt', 'FLUSHALL\r\nGET x'],
    ['a very long string', 'x'.repeat(10_000)],
  ])('rejects %s', async (_label, candidate) => {
    await expect(engine.verify(candidate)).rejects.toThrow(TokenInvalidError);
  });

  it.each([
    ['undefined', undefined],
    ['null', null],
    ['a number', 12345],
    ['an object', { token: 'x' }],
    ['an array', ['x']],
  ])('rejects %s without throwing an unexpected error type', async (_label, candidate) => {
    await expect(
      engine.verify(candidate as unknown as string),
    ).rejects.toThrow(TokenInvalidError);
  });

  it('rejects a token whose last character was altered', async () => {
    const { token } = await issue();
    const tampered = `${token.slice(0, -1)}${token.endsWith('A') ? 'B' : 'A'}`;
    await expect(engine.verify(tampered)).rejects.toThrow(TokenInvalidError);
  });

  it('rejects a truncated token', async () => {
    const { token } = await issue();
    await expect(engine.verify(token.slice(0, -1))).rejects.toThrow(TokenInvalidError);
  });

  it('rejects the token hash presented as though it were the token', async () => {
    // The hash is what an attacker would obtain from a leaked store dump.
    // It must not be usable as a credential.
    const { token } = await issue();
    await expect(engine.verify(hashToken(token))).rejects.toThrow(TokenInvalidError);
  });

  it('rejects a token id presented as though it were the token', async () => {
    const { tokenId } = await issue();
    await expect(engine.verify(tokenId)).rejects.toThrow(TokenInvalidError);
  });

  it('does not reveal, through the error, whether a token ever existed', async () => {
    const issued = await issue();
    await engine.revoke(issued.tokenId);

    const revoked = await engine.verify(issued.token).catch((e: unknown) => e);
    const neverExisted = await engine.verify(generateToken()).catch((e: unknown) => e);

    // Same class and same client-facing message: an attacker cannot use the
    // response to distinguish a revoked credential from a fabricated one.
    expect((revoked as Error).constructor).toBe((neverExisted as Error).constructor);
    expect((revoked as Error).message).toBe((neverExisted as Error).message);
  });

  // ── Corrupted store contents ─────────────────────────────────────────────
  // A record can be malformed because a schema changed, because something else
  // wrote to the key, or because a value was truncated. None of these are
  // reasons to authenticate a request.

  it('rejects a record that is not valid JSON', async () => {
    const token = generateToken();
    await store.set(KEYS.accessToken(hashToken(token)), 'not json{', 300);
    await expect(engine.verify(token)).rejects.toThrow(TokenInvalidError);
  });

  it.each([
    ['a JSON array', '[]'],
    ['a JSON string', '"hello"'],
    ['JSON null', 'null'],
    ['a number', '42'],
  ])('rejects a record that is %s', async (_label, body) => {
    const token = generateToken();
    await store.set(KEYS.accessToken(hashToken(token)), body, 300);
    await expect(engine.verify(token)).rejects.toThrow(TokenInvalidError);
  });

  it.each([
    ['missing principal', { tokenId: 't', sessionId: 's', issuedAt: 'x', expiresAt: 'y' }],
    ['missing tokenId', { sessionId: 's', principal: PRINCIPAL, issuedAt: 'x', expiresAt: 'y' }],
    ['missing userId', { tokenId: 't', sessionId: 's', principal: { roles: [], scopes: [] }, issuedAt: 'x', expiresAt: 'y' }],
    ['empty userId', { tokenId: 't', sessionId: 's', principal: { userId: '', roles: [], scopes: [] }, issuedAt: 'x', expiresAt: 'y' }],
    ['roles as a string', { tokenId: 't', sessionId: 's', principal: { userId: 'u', roles: 'admin', scopes: [] }, issuedAt: 'x', expiresAt: 'y' }],
    ['roles containing a non-string', { tokenId: 't', sessionId: 's', principal: { userId: 'u', roles: [{ admin: true }], scopes: [] }, issuedAt: 'x', expiresAt: 'y' }],
    ['tenant as a number', { tokenId: 't', sessionId: 's', principal: { userId: 'u', roles: [], scopes: [], tenant: 7 }, issuedAt: 'x', expiresAt: 'y' }],
  ])('rejects a structurally invalid record: %s', async (_label, record) => {
    const token = generateToken();
    await store.set(KEYS.accessToken(hashToken(token)), JSON.stringify(record), 300);
    await expect(engine.verify(token)).rejects.toThrow(TokenInvalidError);
  });

  it('does not let a record pollute Object.prototype', async () => {
    const token = generateToken();
    await store.set(
      KEYS.accessToken(hashToken(token)),
      '{"__proto__":{"polluted":"yes"},"tokenId":"t","sessionId":"s","principal":{"userId":"u","roles":[],"scopes":[]},"issuedAt":"2026-01-01T00:00:00.000Z","expiresAt":"2999-01-01T00:00:00.000Z"}',
      300,
    );

    await engine.verify(token).catch(() => undefined);
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });

  // ── Expiry ───────────────────────────────────────────────────────────────

  it('rejects a record whose expiry has passed, even if the store still holds it', async () => {
    // Guards against a store with approximate expiry, or a clock that moved:
    // neither may extend a token's life.
    const token = generateToken();
    const record = {
      tokenId: 'tok_stale',
      sessionId: SESSION,
      principal: PRINCIPAL,
      issuedAt: new Date(Date.now() - 7200_000).toISOString(),
      authenticatedAt: new Date(Date.now() - 7200_000).toISOString(),
      expiresAt: new Date(Date.now() - 3600_000).toISOString(),
    };
    await store.set(KEYS.accessToken(hashToken(token)), JSON.stringify(record), 300);

    await expect(engine.verify(token)).rejects.toThrow(TokenExpiredError);
  });

  it('cleans up a token it found expired, so it cannot be presented again', async () => {
    const token = generateToken();
    const record = {
      tokenId: 'tok_cleanup',
      sessionId: SESSION,
      principal: PRINCIPAL,
      issuedAt: new Date(Date.now() - 7200_000).toISOString(),
      authenticatedAt: new Date(Date.now() - 7200_000).toISOString(),
      expiresAt: new Date(Date.now() - 3600_000).toISOString(),
    };
    await store.set(KEYS.accessToken(hashToken(token)), JSON.stringify(record), 300);
    await store.set(KEYS.accessTokenId('tok_cleanup'), hashToken(token), 300);

    await engine.verify(token).catch(() => undefined);
    await expect(store.get(KEYS.accessToken(hashToken(token)))).resolves.toBeNull();
  });

  it('rejects an unparseable expiry rather than treating it as valid', async () => {
    const token = generateToken();
    const record = {
      tokenId: 'tok_bad_exp',
      sessionId: SESSION,
      principal: PRINCIPAL,
      issuedAt: new Date().toISOString(),
      authenticatedAt: new Date().toISOString(),
      expiresAt: 'not-a-date',
    };
    await store.set(KEYS.accessToken(hashToken(token)), JSON.stringify(record), 300);
    await expect(engine.verify(token)).rejects.toThrow(TokenExpiredError);
  });

  it('rejects a record with no authentication time', async () => {
    // Substituting `issuedAt` would look harmless and would silently make
    // every step-up check wrong, because rotation refreshes `issuedAt` and not
    // the authentication time. So the record is refused instead.
    const token = generateToken();
    const record = {
      tokenId: 'tok_no_auth_time',
      sessionId: SESSION,
      principal: PRINCIPAL,
      issuedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 300_000).toISOString(),
    };
    await store.set(KEYS.accessToken(hashToken(token)), JSON.stringify(record), 300);
    await expect(engine.verify(token)).rejects.toThrow(TokenInvalidError);
  });

  it('surfaces the authentication time on the verified context', async () => {
    const authenticatedAt = new Date(Date.now() - 60_000).toISOString();
    const issued = await engine.issue({
      principal: PRINCIPAL,
      sessionId: SESSION,
      authenticatedAt,
    });

    await expect(engine.verify(issued.token)).resolves.toMatchObject({ authenticatedAt });
  });
});

describe('revoke', () => {
  it('makes the token stop verifying immediately', async () => {
    const issued = await issue();
    await expect(engine.verify(issued.token)).resolves.toBeDefined();

    await engine.revoke(issued.tokenId);
    await expect(engine.verify(issued.token)).rejects.toThrow(TokenInvalidError);
  });

  it('is idempotent', async () => {
    const issued = await issue();
    await engine.revoke(issued.tokenId);
    await expect(engine.revoke(issued.tokenId)).resolves.toBeUndefined();
  });

  it('succeeds for a token id that never existed', async () => {
    await expect(engine.revoke('tok_never_existed')).resolves.toBeUndefined();
  });

  it('leaves other tokens in the same session alone', async () => {
    const first = await issue();
    const second = await issue();

    await engine.revoke(first.tokenId);

    await expect(engine.verify(first.token)).rejects.toThrow(TokenInvalidError);
    await expect(engine.verify(second.token)).resolves.toBeDefined();
  });

  it('removes the token from its session index, leaving no dangling entry', async () => {
    const issued = await issue();
    await engine.revoke(issued.tokenId);

    const members = await store.sMembers(KEYS.sessionTokens(SESSION));
    expect(members).not.toContain(hashToken(issued.token));
  });

  it('clears the reverse index too', async () => {
    const issued = await issue();
    await engine.revoke(issued.tokenId);
    await expect(store.get(KEYS.accessTokenId(issued.tokenId))).resolves.toBeNull();
  });
});

describe('revokeSession', () => {
  it('kills every token in the session', async () => {
    const a = await issue();
    const b = await issue();
    const c = await issue();

    await engine.revokeSession(SESSION);

    for (const issued of [a, b, c]) {
      await expect(engine.verify(issued.token)).rejects.toThrow(TokenInvalidError);
    }
  });

  it('leaves other sessions untouched', async () => {
    const mine = await issue({ sessionId: 'sess_mine' });
    const theirs = await issue({ sessionId: 'sess_theirs' });

    await engine.revokeSession('sess_mine');

    await expect(engine.verify(mine.token)).rejects.toThrow(TokenInvalidError);
    await expect(engine.verify(theirs.token)).resolves.toBeDefined();
  });

  it('is idempotent and safe for an unknown session', async () => {
    await expect(engine.revokeSession('sess_never_existed')).resolves.toBeUndefined();
    await engine.revokeSession(SESSION);
    await expect(engine.revokeSession(SESSION)).resolves.toBeUndefined();
  });

  it('clears the session index and every reverse index', async () => {
    const a = await issue();
    const b = await issue();

    await engine.revokeSession(SESSION);

    await expect(store.sMembers(KEYS.sessionTokens(SESSION))).resolves.toEqual([]);
    await expect(store.get(KEYS.accessTokenId(a.tokenId))).resolves.toBeNull();
    await expect(store.get(KEYS.accessTokenId(b.tokenId))).resolves.toBeNull();
  });

  it('leaves the store with no residue for that session', async () => {
    const before = store.size();
    await issue();
    await issue();
    await engine.revokeSession(SESSION);
    expect(store.size()).toBe(before);
  });
});

describe('cross-user isolation', () => {
  it('does not let one user’s token resolve to another user', async () => {
    const alice = await issue({
      principal: { userId: 'user_alice', roles: ['user'], scopes: [] },
      sessionId: 'sess_a',
    });
    const bob = await issue({
      principal: { userId: 'user_bob', roles: ['admin'], scopes: [] },
      sessionId: 'sess_b',
    });

    await expect(engine.verify(alice.token)).resolves.toMatchObject({
      userId: 'user_alice',
      roles: ['user'],
    });
    await expect(engine.verify(bob.token)).resolves.toMatchObject({
      userId: 'user_bob',
      roles: ['admin'],
    });
  });

  it('does not let revoking one user affect another', async () => {
    const alice = await issue({ sessionId: 'sess_a' });
    const bob = await issue({ sessionId: 'sess_b' });

    await engine.revokeSession('sess_a');
    await expect(engine.verify(bob.token)).resolves.toBeDefined();
    void alice;
  });
});
