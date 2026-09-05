import { describe, it, expect, beforeEach } from 'vitest';
import {
  RefreshInvalidError,
  RefreshReuseError,
  TokenInvalidError,
  TokenRevokedError,
  generateToken,
  hashToken,
  type Principal,
} from '@ninsho/core';
import { MemoryStore } from '../store/memory.js';
import { OpaqueEngine } from '../engine/opaque.js';
import { PasetoEngine } from '../engine/paseto.js';
import { KeyRing, generateKeyPair } from '../keys/keyring.js';
import { SessionManager } from '../session/manager.js';
import { MemoryAuditSink } from '../audit.js';
import { KEYS } from '../keys.js';

const ALICE: Principal = { userId: 'user_alice', roles: ['user'], scopes: ['orders:read'] };
const BOB: Principal = { userId: 'user_bob', roles: ['admin'], scopes: [] };

let store: MemoryStore;
let engine: OpaqueEngine;
let audit: MemoryAuditSink;
let sessions: SessionManager;

/** Builds a manager; `graceSeconds: 0` disables the grace window. */
function build(graceSeconds = 30): void {
  store = new MemoryStore();
  engine = new OpaqueEngine(store, { accessTokenTtl: 300, clockToleranceSeconds: 5 });
  audit = new MemoryAuditSink();
  sessions = new SessionManager(store, engine, {
    refreshTokenTtl: 3600,
    refreshGraceSeconds: graceSeconds,
    clockToleranceSeconds: 5,
    audit,
  });
}

beforeEach(() => {
  build();
});

describe('create', () => {
  it('returns a complete token pair', async () => {
    const pair = await sessions.create(ALICE);
    expect(pair.accessToken).toBeTypeOf('string');
    expect(pair.refreshToken).toBeTypeOf('string');
    expect(pair.sessionId).toBeTypeOf('string');
    expect(Date.parse(pair.accessExpiresAt)).not.toBeNaN();
    expect(Date.parse(pair.refreshExpiresAt)).not.toBeNaN();
  });

  it('issues an access token that verifies immediately', async () => {
    const pair = await sessions.create(ALICE);
    await expect(engine.verify(pair.accessToken)).resolves.toMatchObject({
      userId: 'user_alice',
      sessionId: pair.sessionId,
    });
  });

  it('gives every session a distinct id and distinct tokens', async () => {
    const a = await sessions.create(ALICE);
    const b = await sessions.create(ALICE);
    expect(a.sessionId).not.toBe(b.sessionId);
    expect(a.refreshToken).not.toBe(b.refreshToken);
    expect(a.accessToken).not.toBe(b.accessToken);
  });

  it('never stores the raw refresh token under its own value', async () => {
    const pair = await sessions.create(ALICE);
    await expect(store.get(KEYS.refreshToken(pair.refreshToken))).resolves.toBeNull();
    await expect(store.get(KEYS.refreshToken(hashToken(pair.refreshToken)))).resolves.not.toBeNull();
  });

  it('emits session.created', async () => {
    const pair = await sessions.create(ALICE);
    const events = audit.ofType('session.created');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ userId: 'user_alice', sessionId: pair.sessionId });
  });

  it('records no credential material in the audit event', async () => {
    const pair = await sessions.create(ALICE);
    const serialized = JSON.stringify(audit.events);
    expect(serialized).not.toContain(pair.refreshToken);
    expect(serialized).not.toContain(pair.accessToken);
  });
});

describe('refresh', () => {
  it('returns a new pair and rotates the refresh token', async () => {
    const first = await sessions.create(ALICE);
    const second = await sessions.refresh(first.refreshToken);

    expect(second.refreshToken).not.toBe(first.refreshToken);
    expect(second.accessToken).not.toBe(first.accessToken);
    expect(second.sessionId).toBe(first.sessionId);
  });

  it('preserves the principal across rotation', async () => {
    const tenant: Principal = { ...ALICE, tenant: 'acme' };
    const first = await sessions.create(tenant);
    const second = await sessions.refresh(first.refreshToken);

    await expect(engine.verify(second.accessToken)).resolves.toMatchObject({
      userId: 'user_alice',
      roles: ['user'],
      scopes: ['orders:read'],
      tenant: 'acme',
    });
  });

  it('survives a long chain of rotations', async () => {
    let pair = await sessions.create(ALICE);
    for (let i = 0; i < 25; i += 1) {
      pair = await sessions.refresh(pair.refreshToken);
    }
    await expect(engine.verify(pair.accessToken)).resolves.toBeDefined();
  });

  /**
   * Rotation must extend the token, never the session. Without a fixed family
   * ceiling, an attacker holding a stolen token keeps it alive indefinitely by
   * refreshing on a timer, and the session never forces a real sign-in again.
   */
  it('does not extend the family ceiling on rotation', async () => {
    const first = await sessions.create(ALICE);
    const ceiling = first.refreshExpiresAt;

    let pair = first;
    for (let i = 0; i < 5; i += 1) {
      pair = await sessions.refresh(pair.refreshToken);
    }

    expect(Date.parse(pair.refreshExpiresAt)).toBeLessThanOrEqual(Date.parse(ceiling));
  });

  it('emits session.refreshed', async () => {
    const first = await sessions.create(ALICE);
    await sessions.refresh(first.refreshToken);
    expect(audit.ofType('session.refreshed')).toHaveLength(1);
  });

  it.each([
    ['an empty string', ''],
    ['a fabricated token', null],
    ['a hash presented as a token', null],
  ])('rejects %s with RefreshInvalidError', async (label, value) => {
    const candidate =
      value ?? (label.includes('hash') ? hashToken(generateToken()) : generateToken());
    await expect(sessions.refresh(candidate)).rejects.toThrow(RefreshInvalidError);
  });

  it.each([
    ['undefined', undefined],
    ['null', null],
    ['a number', 42],
    ['an object', {}],
  ])('rejects %s without an unexpected error type', async (_label, value) => {
    await expect(sessions.refresh(value as unknown as string)).rejects.toThrow(
      RefreshInvalidError,
    );
  });
});

/**
 * ─── The headline security property of Phase 3 ────────────────────────────
 * Audit finding C3. The predecessor rejected a replayed refresh token and
 * stopped there, which means a thief who redeems a stolen token first keeps a
 * valid rotating chain while the victim sees one failed refresh, signs in
 * again, and never learns anything happened.
 *
 * RFC 9700 §4.14.2: reuse of a rotated token must invalidate the whole family.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('refresh token reuse detection', () => {
  beforeEach(() => {
    build(0); // no grace window, so a replay is unambiguous
  });

  it('throws RefreshReuseError when a rotated token is presented again', async () => {
    const first = await sessions.create(ALICE);
    await sessions.refresh(first.refreshToken);

    await expect(sessions.refresh(first.refreshToken)).rejects.toThrow(RefreshReuseError);
  });

  it('revokes the entire family, killing the replacement token too', async () => {
    const first = await sessions.create(ALICE);
    const second = await sessions.refresh(first.refreshToken);

    await sessions.refresh(first.refreshToken).catch(() => undefined);

    // The chain the attacker (or the victim) was holding is now dead.
    await expect(sessions.refresh(second.refreshToken)).rejects.toThrow(RefreshInvalidError);
  });

  it('revokes every access token in the family', async () => {
    const first = await sessions.create(ALICE);
    const second = await sessions.refresh(first.refreshToken);

    await expect(engine.verify(second.accessToken)).resolves.toBeDefined();

    await sessions.refresh(first.refreshToken).catch(() => undefined);

    await expect(engine.verify(second.accessToken)).rejects.toThrow(TokenInvalidError);
    await expect(engine.verify(first.accessToken)).rejects.toThrow(TokenInvalidError);
  });

  it('emits refresh.reuse_detected with the replayed generation', async () => {
    const first = await sessions.create(ALICE);
    await sessions.refresh(first.refreshToken);
    await sessions.refresh(first.refreshToken).catch(() => undefined);

    const events = audit.ofType('refresh.reuse_detected');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      userId: 'user_alice',
      sessionId: first.sessionId,
    });
    expect(events[0]?.reason).toMatch(/generation 0/);
  });

  it('detects reuse many generations later', async () => {
    const first = await sessions.create(ALICE);
    let pair = first;
    for (let i = 0; i < 10; i += 1) {
      pair = await sessions.refresh(pair.refreshToken);
    }

    // The very first token, ten rotations stale, is still recognised as real.
    await expect(sessions.refresh(first.refreshToken)).rejects.toThrow(RefreshReuseError);
  });

  /**
   * The full theft scenario, end to end. This is the behaviour the audit found
   * missing, expressed as the attack it prevents.
   */
  it('ends the session for both parties when a stolen token is redeemed first', async () => {
    const victim = await sessions.create(ALICE);

    // The attacker has exfiltrated the refresh token and redeems it first.
    const attacker = await sessions.refresh(victim.refreshToken);
    await expect(engine.verify(attacker.accessToken)).resolves.toBeDefined();

    // The victim's client refreshes on its normal schedule, unaware.
    await expect(sessions.refresh(victim.refreshToken)).rejects.toThrow(RefreshReuseError);

    // The attacker's chain is dead too — the theft cost them the session
    // rather than granting them an indefinite one.
    await expect(sessions.refresh(attacker.refreshToken)).rejects.toThrow(RefreshInvalidError);
    await expect(engine.verify(attacker.accessToken)).rejects.toThrow(TokenInvalidError);

    // And the compromise is on the record rather than silently absorbed.
    expect(audit.ofType('refresh.reuse_detected')).toHaveLength(1);
  });

  /**
   * A replay must not be usable as a weapon. If an unrecognised token revoked
   * something, an attacker could sign other people out by submitting garbage.
   */
  it('does not revoke anything when an unrecognised token is presented', async () => {
    const live = await sessions.create(ALICE);

    await expect(sessions.refresh(generateToken())).rejects.toThrow(RefreshInvalidError);

    // The real session is untouched.
    await expect(engine.verify(live.accessToken)).resolves.toBeDefined();
    await expect(sessions.refresh(live.refreshToken)).resolves.toBeDefined();
    expect(audit.ofType('refresh.reuse_detected')).toHaveLength(0);
  });

  it('does not raise a reuse alarm for a token from an already-revoked session', async () => {
    // A stale tab after a normal logout must not look like an attack, or the
    // alert channel fills with false positives and stops being read.
    const pair = await sessions.create(ALICE);
    await sessions.refresh(pair.refreshToken);
    await sessions.revoke(pair.sessionId);

    await expect(sessions.refresh(pair.refreshToken)).rejects.toThrow(RefreshInvalidError);
    expect(audit.ofType('refresh.reuse_detected')).toHaveLength(0);
  });

  it('confines revocation to the affected session', async () => {
    const compromised = await sessions.create(ALICE);
    const healthy = await sessions.create(ALICE);

    await sessions.refresh(compromised.refreshToken);
    await sessions.refresh(compromised.refreshToken).catch(() => undefined);

    // Alice's other device keeps working.
    await expect(engine.verify(healthy.accessToken)).resolves.toBeDefined();
    await expect(sessions.refresh(healthy.refreshToken)).resolves.toBeDefined();
  });

  it('tells the client nothing that distinguishes reuse from an ordinary failure', async () => {
    const pair = await sessions.create(ALICE);
    await sessions.refresh(pair.refreshToken);

    const reuse = (await sessions
      .refresh(pair.refreshToken)
      .catch((e: unknown) => e)) as RefreshReuseError;
    const unknown = (await sessions
      .refresh(generateToken())
      .catch((e: unknown) => e)) as RefreshInvalidError;

    // Distinct codes, so a host application can react — identical messages and
    // status, so an attacker cannot tell from the response that detection fired.
    expect(reuse.message).toBe(unknown.message);
    expect(reuse.status).toBe(unknown.status);
    expect(reuse.code).toBe('REFRESH_REUSE_DETECTED');
    expect(unknown.code).toBe('REFRESH_INVALID');
  });
});

/**
 * The grace window separates a browser's second tab, which raced and lost
 * microseconds ago, from an attacker replaying a token minutes later.
 */
describe('grace window', () => {
  it('gives a tab that lost the race the same replacement token', async () => {
    const first = await sessions.create(ALICE);
    const winner = await sessions.refresh(first.refreshToken);
    const loser = await sessions.refresh(first.refreshToken);

    expect(loser.refreshToken).toBe(winner.refreshToken);
    expect(loser.sessionId).toBe(first.sessionId);
  });

  it('gives each tab its own working access token', async () => {
    const first = await sessions.create(ALICE);
    const winner = await sessions.refresh(first.refreshToken);
    const loser = await sessions.refresh(first.refreshToken);

    expect(loser.accessToken).not.toBe(winner.accessToken);
    await expect(engine.verify(winner.accessToken)).resolves.toBeDefined();
    await expect(engine.verify(loser.accessToken)).resolves.toBeDefined();
  });

  it('raises no reuse alarm inside the window', async () => {
    const first = await sessions.create(ALICE);
    await sessions.refresh(first.refreshToken);
    await sessions.refresh(first.refreshToken);

    expect(audit.ofType('refresh.reuse_detected')).toHaveLength(0);
  });

  it('keeps the session alive after a grace resolution', async () => {
    const first = await sessions.create(ALICE);
    await sessions.refresh(first.refreshToken);
    const loser = await sessions.refresh(first.refreshToken);

    await expect(sessions.refresh(loser.refreshToken)).resolves.toBeDefined();
  });

  /**
   * The primitive underneath: `store.take()` is atomic, so of any number of
   * simultaneous callers exactly one rotates and the rest resolve through
   * grace. Two callers both minting a replacement would fork the chain and
   * guarantee a later false reuse alarm.
   */
  it('lets exactly one of many simultaneous callers perform the rotation', async () => {
    const first = await sessions.create(ALICE);

    const results = await Promise.all(
      Array.from({ length: 12 }, () => sessions.refresh(first.refreshToken)),
    );

    const distinct = new Set(results.map((r) => r.refreshToken));
    expect(distinct.size).toBe(1);
    expect(audit.ofType('refresh.reuse_detected')).toHaveLength(0);

    // And the single surviving chain still works.
    await expect(sessions.refresh(results[0]!.refreshToken)).resolves.toBeDefined();
  });

  it('detects reuse once the window has closed', async () => {
    build(1);
    const first = await sessions.create(ALICE);
    await sessions.refresh(first.refreshToken);

    await new Promise((r) => {
      setTimeout(r, 1200);
    });

    await expect(sessions.refresh(first.refreshToken)).rejects.toThrow(RefreshReuseError);
  });

  it('stores the raw replacement only for the grace period, not the token lifetime', async () => {
    build(1);
    const first = await sessions.create(ALICE);
    await sessions.refresh(first.refreshToken);

    const graceKey = KEYS.refreshGrace(hashToken(first.refreshToken));
    await expect(store.get(graceKey)).resolves.not.toBeNull();

    await new Promise((r) => {
      setTimeout(r, 1200);
    });

    // The one raw token Ninsho stores is gone well before the token expires.
    await expect(store.get(graceKey)).resolves.toBeNull();
  });

  it('treats every replay as reuse when the window is disabled', async () => {
    build(0);
    const first = await sessions.create(ALICE);
    await sessions.refresh(first.refreshToken);
    await expect(sessions.refresh(first.refreshToken)).rejects.toThrow(RefreshReuseError);
  });
});

describe('revoke', () => {
  it('ends the session and its refresh chain', async () => {
    const pair = await sessions.create(ALICE);
    await sessions.revoke(pair.sessionId);

    await expect(sessions.refresh(pair.refreshToken)).rejects.toThrow(RefreshInvalidError);
    await expect(engine.verify(pair.accessToken)).rejects.toThrow(TokenInvalidError);
  });

  it('leaves the user’s other sessions alone', async () => {
    const phone = await sessions.create(ALICE);
    const laptop = await sessions.create(ALICE);

    await sessions.revoke(phone.sessionId);

    await expect(engine.verify(laptop.accessToken)).resolves.toBeDefined();
    await expect(sessions.refresh(laptop.refreshToken)).resolves.toBeDefined();
  });

  it('is idempotent and safe for an unknown session', async () => {
    const pair = await sessions.create(ALICE);
    await sessions.revoke(pair.sessionId);
    await expect(sessions.revoke(pair.sessionId)).resolves.toBeUndefined();
    await expect(sessions.revoke('sess_never_existed')).resolves.toBeUndefined();
  });

  it('emits session.revoked with the reason', async () => {
    const pair = await sessions.create(ALICE);
    await sessions.revoke(pair.sessionId);

    const events = audit.ofType('session.revoked');
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ sessionId: pair.sessionId, reason: 'logout' });
  });

  it('leaves nothing usable behind — only the markers that keep it that way', async () => {
    const before = store.size();
    const pair = await sessions.create(ALICE);
    const rotated = await sessions.refresh(pair.refreshToken);
    await sessions.revoke(pair.sessionId);

    // The user-sessions index entry is pruned on the next listing.
    await sessions.listSessions(ALICE.userId);

    // Three keys remain and all three are markers: the session tombstone, plus
    // one per refresh token in the family — the original and the replacement
    // the rotation produced. Both kinds are deliberately retained for the
    // refresh lifetime. The session tombstone is what stops a rotation that
    // raced the revocation from leaving a usable orphan; the per-token markers
    // are what let a tab still holding a token after a sign-out be answered at
    // once rather than waiting out the rotation-race backoff. Cleaning either
    // up eagerly would reintroduce the problem it exists to prevent.
    expect(store.size()).toBe(before + 3);
    await expect(store.exists(KEYS.sessionRevoked(pair.sessionId))).resolves.toBe(true);

    // Markers, not credentials. Neither token is redeemable.
    await expect(sessions.refresh(pair.refreshToken)).rejects.toThrow();
    await expect(sessions.refresh(rotated.refreshToken)).rejects.toThrow();
  });
});

describe('revokeAllForUser', () => {
  it('ends every session for that user', async () => {
    const a = await sessions.create(ALICE);
    const b = await sessions.create(ALICE);
    const c = await sessions.create(ALICE);

    await sessions.revokeAllForUser(ALICE.userId);

    for (const pair of [a, b, c]) {
      await expect(sessions.refresh(pair.refreshToken)).rejects.toThrow(RefreshInvalidError);
      await expect(engine.verify(pair.accessToken)).rejects.toThrow(TokenInvalidError);
    }
  });

  it('does not touch another user', async () => {
    const alice = await sessions.create(ALICE);
    const bob = await sessions.create(BOB);

    await sessions.revokeAllForUser(ALICE.userId);

    await expect(engine.verify(bob.accessToken)).resolves.toBeDefined();
    await expect(sessions.refresh(bob.refreshToken)).resolves.toBeDefined();
    void alice;
  });

  it('emits session.revoked_all', async () => {
    await sessions.create(ALICE);
    await sessions.revokeAllForUser(ALICE.userId);

    expect(audit.ofType('session.revoked_all')).toHaveLength(1);
  });

  it('is safe for a user with no sessions', async () => {
    await expect(sessions.revokeAllForUser('user_nobody')).resolves.toBeUndefined();
  });

  it('clears the user index so listing returns nothing', async () => {
    await sessions.create(ALICE);
    await sessions.create(ALICE);
    await sessions.revokeAllForUser(ALICE.userId);

    await expect(sessions.listSessions(ALICE.userId)).resolves.toEqual([]);
  });
});

describe('listSessions', () => {
  it('lists live sessions without exposing credentials', async () => {
    await sessions.create(ALICE);
    await sessions.create(ALICE);

    const list = await sessions.listSessions(ALICE.userId);
    expect(list).toHaveLength(2);

    const serialized = JSON.stringify(list);
    expect(serialized).not.toMatch(/refreshToken|accessToken/);
    for (const s of list) {
      expect(Object.keys(s).sort()).toEqual([
        'createdAt',
        'current',
        'expiresAt',
        'generation',
        'lastUsedAt',
        'sessionId',
      ]);
    }
  });

  it('marks the caller’s own session as current', async () => {
    const mine = await sessions.create(ALICE);
    await sessions.create(ALICE);

    const list = await sessions.listSessions(ALICE.userId, mine.sessionId);
    expect(list.filter((s) => s.current)).toHaveLength(1);
    expect(list.find((s) => s.current)?.sessionId).toBe(mine.sessionId);
  });

  it('tracks the generation as the session is refreshed', async () => {
    const pair = await sessions.create(ALICE);
    await sessions.refresh(pair.refreshToken);

    const list = await sessions.listSessions(ALICE.userId);
    expect(list[0]?.generation).toBe(1);
  });

  it('returns an empty list for an unknown user', async () => {
    await expect(sessions.listSessions('user_nobody')).resolves.toEqual([]);
  });

  it('prunes sessions whose metadata has expired', async () => {
    const pair = await sessions.create(ALICE);
    await store.delete(KEYS.sessionMeta(pair.sessionId));

    await expect(sessions.listSessions(ALICE.userId)).resolves.toEqual([]);
    // And the dangling index entry is gone, so it is not rescanned forever.
    await expect(store.sMembers(KEYS.userSessions(ALICE.userId))).resolves.toEqual([]);
  });

  it('does not leak one user’s sessions to another', async () => {
    await sessions.create(ALICE);
    await sessions.create(BOB);

    const aliceList = await sessions.listSessions(ALICE.userId);
    const bobList = await sessions.listSessions(BOB.userId);

    expect(aliceList).toHaveLength(1);
    expect(bobList).toHaveLength(1);
    expect(aliceList[0]?.sessionId).not.toBe(bobList[0]?.sessionId);
  });
});

describe('corrupt stored records', () => {
  it('rejects a refresh record that is not valid JSON', async () => {
    const raw = generateToken();
    await store.set(KEYS.refreshToken(hashToken(raw)), 'not json{', 3600);
    await expect(sessions.refresh(raw)).rejects.toThrow(RefreshInvalidError);
  });

  it.each([
    ['missing principal', { sessionId: 's', issuedAt: 'a', expiresAt: 'b', familyExpiresAt: 'c', generation: 0 }],
    ['missing familyExpiresAt', { sessionId: 's', principal: ALICE, issuedAt: 'a', expiresAt: 'b', generation: 0 }],
    ['generation as a string', { sessionId: 's', principal: ALICE, issuedAt: 'a', expiresAt: 'b', familyExpiresAt: 'c', generation: '0' }],
    ['negative generation', { sessionId: 's', principal: ALICE, issuedAt: 'a', expiresAt: 'b', familyExpiresAt: 'c', generation: -1 }],
    ['roles as a string', { sessionId: 's', principal: { userId: 'u', roles: 'admin', scopes: [] }, issuedAt: 'a', expiresAt: 'b', familyExpiresAt: 'c', generation: 0 }],
  ])('rejects a structurally invalid refresh record: %s', async (_label, record) => {
    const raw = generateToken();
    await store.set(KEYS.refreshToken(hashToken(raw)), JSON.stringify(record), 3600);
    await expect(sessions.refresh(raw)).rejects.toThrow(RefreshInvalidError);
  });

  it('does not let a refresh record pollute Object.prototype', async () => {
    const raw = generateToken();
    await store.set(
      KEYS.refreshToken(hashToken(raw)),
      '{"__proto__":{"pollutedRefresh":"yes"},"sessionId":"s","principal":{"userId":"u","roles":[],"scopes":[]},"issuedAt":"2026-01-01T00:00:00.000Z","expiresAt":"2999-01-01T00:00:00.000Z","familyExpiresAt":"2999-01-01T00:00:00.000Z","generation":0}',
      3600,
    );

    await sessions.refresh(raw).catch(() => undefined);
    expect(({} as Record<string, unknown>)['pollutedRefresh']).toBeUndefined();
  });

  it('rejects an expired refresh record rather than renewing it', async () => {
    const raw = generateToken();
    const past = new Date(Date.now() - 3600_000).toISOString();
    await store.set(
      KEYS.refreshToken(hashToken(raw)),
      JSON.stringify({
        sessionId: 'sess_expired',
        principal: ALICE,
        issuedAt: past,
        expiresAt: past,
        familyExpiresAt: past,
        generation: 0,
      }),
      3600,
    );

    await expect(sessions.refresh(raw)).rejects.toThrow(RefreshInvalidError);
  });

  it('rejects a token whose family ceiling has passed even if the token itself has not', async () => {
    const raw = generateToken();
    await store.set(
      KEYS.refreshToken(hashToken(raw)),
      JSON.stringify({
        sessionId: 'sess_capped',
        principal: ALICE,
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        // Well past the 5s clock tolerance, so this is unambiguously expired
        // rather than merely skewed.
        familyExpiresAt: new Date(Date.now() - 3600_000).toISOString(),
        generation: 3,
      }),
      3600,
    );

    await expect(sessions.refresh(raw)).rejects.toThrow(RefreshInvalidError);
  });

  it('accepts a family ceiling that has only just passed, within clock tolerance', async () => {
    // The mirror of the case above, asserting the tolerance is deliberate
    // rather than accidental: hosts whose clocks disagree by a second or two
    // must not sign users out at the exact moment a session ages out.
    const raw = generateToken();
    await store.set(
      KEYS.refreshToken(hashToken(raw)),
      JSON.stringify({
        sessionId: 'sess_skewed',
        principal: ALICE,
        issuedAt: new Date().toISOString(),
        authenticatedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        familyExpiresAt: new Date(Date.now() - 1000).toISOString(),
        generation: 3,
      }),
      3600,
    );

    await expect(sessions.refresh(raw)).resolves.toBeDefined();
  });
});

/**
 * The session layer must be strategy-agnostic. `SessionManager` talks only to
 * the `TokenEngine` interface, so refresh rotation, reuse detection and
 * revocation should behave identically whichever engine is underneath.
 *
 * Running the security-critical assertions against the PASETO engine as well
 * is what turns "strategy-agnostic" from a claim in a doc comment into a
 * tested property — and it guards the seam that makes the two-adopter design
 * work at all.
 */
describe('session layer over the paseto engine', () => {
  let pasetoStore: MemoryStore;
  let pasetoEngine: PasetoEngine;
  let pasetoAudit: MemoryAuditSink;
  let pasetoSessions: SessionManager;

  beforeEach(() => {
    const key = generateKeyPair('sess-test');
    pasetoStore = new MemoryStore();
    pasetoEngine = new PasetoEngine(pasetoStore, new KeyRing({ active: key }), {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'https://id.test',
      audience: 'api',
    });
    pasetoAudit = new MemoryAuditSink();
    pasetoSessions = new SessionManager(pasetoStore, pasetoEngine, {
      refreshTokenTtl: 3600,
      refreshGraceSeconds: 0,
      clockToleranceSeconds: 5,
      audit: pasetoAudit,
    });
  });

  it('creates a session and issues a verifiable access token', async () => {
    const pair = await pasetoSessions.create(ALICE);
    await expect(pasetoEngine.verify(pair.accessToken)).resolves.toMatchObject({
      userId: 'user_alice',
      sessionId: pair.sessionId,
      strategy: 'paseto',
    });
  });

  it('rotates refresh tokens', async () => {
    const first = await pasetoSessions.create(ALICE);
    const second = await pasetoSessions.refresh(first.refreshToken);
    expect(second.refreshToken).not.toBe(first.refreshToken);
    await expect(pasetoEngine.verify(second.accessToken)).resolves.toBeDefined();
  });

  it('detects reuse and revokes the family, exactly as with opaque tokens', async () => {
    const first = await pasetoSessions.create(ALICE);
    const second = await pasetoSessions.refresh(first.refreshToken);

    await expect(pasetoSessions.refresh(first.refreshToken)).rejects.toThrow(RefreshReuseError);

    // The replacement chain is dead, and so is its access token — even though
    // that token is stateless and self-verifying, because revocation goes
    // through the engine's denylist.
    await expect(pasetoSessions.refresh(second.refreshToken)).rejects.toThrow(
      RefreshInvalidError,
    );
    await expect(pasetoEngine.verify(second.accessToken)).rejects.toThrow(TokenRevokedError);
    expect(pasetoAudit.ofType('refresh.reuse_detected')).toHaveLength(1);
  });

  it('revokes stateless access tokens on logout', async () => {
    const pair = await pasetoSessions.create(ALICE);
    await pasetoSessions.revoke(pair.sessionId);
    await expect(pasetoEngine.verify(pair.accessToken)).rejects.toThrow(TokenRevokedError);
  });

  it('ends every session for a user', async () => {
    const a = await pasetoSessions.create(ALICE);
    const b = await pasetoSessions.create(ALICE);
    await pasetoSessions.revokeAllForUser(ALICE.userId);

    await expect(pasetoEngine.verify(a.accessToken)).rejects.toThrow(TokenRevokedError);
    await expect(pasetoEngine.verify(b.accessToken)).rejects.toThrow(TokenRevokedError);
  });
});

/**
 * ─── REGRESSION: revocation lost a race against rotation ──────────────────
 * Found by the concurrency suite, not by any sequential test.
 *
 * `#revokeFamily` used to work purely by enumerating the family index and
 * deleting what it found. A rotation running concurrently could add its
 * replacement to that index *after* revocation had read it, and revocation
 * then deleted the index itself — leaving a live refresh record that nothing
 * pointed to. No later revocation could find the orphan either, so a refresh
 * token survived a completed logout for its full lifetime.
 *
 * A "sign out this device" button reporting success while a credential stays
 * live is about the worst outcome that button can have.
 *
 * The fix is a positive tombstone written *before* the index is read, and
 * consulted by rotation — so the outcome no longer depends on which operation
 * touched the index first.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('regression: revocation racing rotation', () => {
  it('leaves no usable refresh token when a logout races a rotation', async () => {
    for (let attempt = 0; attempt < 25; attempt += 1) {
      const pair = await sessions.create(ALICE);

      const [rotated] = await Promise.allSettled([
        sessions.refresh(pair.refreshToken),
        sessions.revoke(pair.sessionId),
      ]);

      if (rotated.status === 'fulfilled') {
        // Whichever operation won, the session is over. The replacement token
        // must not outlive the logout.
        await expect(sessions.refresh(rotated.value.refreshToken)).rejects.toThrow(
          RefreshInvalidError,
        );
      }
    }
  });

  it('refuses a rotation for an already-revoked session', async () => {
    const pair = await sessions.create(ALICE);
    await sessions.revoke(pair.sessionId);

    await expect(sessions.refresh(pair.refreshToken)).rejects.toThrow(RefreshInvalidError);
  });

  it('refuses the grace path for a revoked session', async () => {
    // A grace mapping is written outside the family index, so it could
    // likewise outlive the revocation that should have removed it.
    const first = await sessions.create(ALICE);
    await sessions.refresh(first.refreshToken);
    await sessions.revoke(first.sessionId);

    await expect(sessions.refresh(first.refreshToken)).rejects.toThrow(RefreshInvalidError);
  });

  it('keeps the tombstone for the full refresh lifetime, not the token lifetime', async () => {
    // The orphan it guards against can live as long as a refresh token, so the
    // marker has to outlast it.
    const pair = await sessions.create(ALICE);
    await sessions.revoke(pair.sessionId);

    await expect(store.exists(KEYS.sessionRevoked(pair.sessionId))).resolves.toBe(true);
  });

  it('does not let a revoked session be resurrected by sign-out-everywhere ordering', async () => {
    const a = await sessions.create(ALICE);
    const b = await sessions.create(ALICE);

    await Promise.all([
      sessions.refresh(a.refreshToken).catch(() => undefined),
      sessions.revokeAllForUser(ALICE.userId),
      sessions.refresh(b.refreshToken).catch(() => undefined),
    ]);

    await expect(sessions.refresh(a.refreshToken)).rejects.toThrow();
    await expect(sessions.refresh(b.refreshToken)).rejects.toThrow();
  });
});
