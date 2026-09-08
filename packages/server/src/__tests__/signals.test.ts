import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { hashSignal, type Principal } from '@ninshorg/core';
import { MemoryStore } from '../store/memory.js';
import { OpaqueEngine } from '../engine/opaque.js';
import { SessionManager } from '../session/manager.js';
import { MemoryAuditSink } from '../audit.js';
import { KEYS } from '../keys.js';

/**
 * Client signals.
 *
 * ─── What these are for, and what they are emphatically not ───────────────
 * Every field here is client-controlled and trivially forged, so nothing in
 * Ninsho branches on them. A forged `User-Agent` must never be able to end
 * someone's session, and the tests below assert that directly.
 *
 * What they buy is one thing, and it is worth the storage: when a rotated
 * refresh token is replayed, the alarm can say whether the replay came from
 * the same client as the rest of the family. A replay from somewhere else is
 * close to certain theft; one from the same client is more often a retry or a
 * double-submit in the application's own code. Those deserve different
 * responses, and without signals an operator cannot tell them apart.
 * ──────────────────────────────────────────────────────────────────────────
 */

const ALICE: Principal = { userId: 'user_alice', roles: ['user'], scopes: [] };

const CHROME = { userAgent: 'Mozilla/5.0 Chrome/120', ip: '203.0.113.10' };
const CURL = { userAgent: 'curl/8.4.0', ip: '198.51.100.7' };

let store: MemoryStore;
let engine: OpaqueEngine;
let audit: MemoryAuditSink;
let sessions: SessionManager;

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

beforeEach(() => build());
afterEach(async () => store.close());

const reuseEvent = () =>
  audit.events.find((e) => e.type === 'refresh.reuse_detected') as
    | { signalMatch?: string }
    | undefined;

/** The raw values must never reach the store — an IP address is personal data. */
describe('signals are stored hashed, never raw', () => {
  it('records hashes and not the values', async () => {
    await sessions.create(ALICE, { signals: CHROME });
    const [summary] = await sessions.listSessions(ALICE.userId);

    expect(summary?.signals?.userAgentHash).toBe(hashSignal(CHROME.userAgent));
    expect(summary?.signals?.ipHash).toBe(hashSignal(CHROME.ip));
  });

  it('leaves no trace of the raw value anywhere in the record', async () => {
    const pair = await sessions.create(ALICE, { signals: CHROME });
    const context = await engine.verify(pair.accessToken);
    const raw = (await store.get(KEYS.sessionMeta(context.sessionId))) as string;

    expect(raw).not.toContain(CHROME.ip);
    expect(raw).not.toContain('Chrome');
  });

  it('truncates, so the hash is a correlation handle and not a lookup key', async () => {
    // A full SHA-256 of an IP is reversible by anyone willing to enumerate the
    // address space. Sixteen hex characters is enough to compare and not
    // enough to build a rainbow table worth keeping.
    await sessions.create(ALICE, { signals: CHROME });
    const [summary] = await sessions.listSessions(ALICE.userId);

    expect(summary?.signals?.ipHash).toHaveLength(16);
  });

  it('records nothing when no signals are supplied', async () => {
    await sessions.create(ALICE);
    const [summary] = await sessions.listSessions(ALICE.userId);

    expect(summary?.signals).toBeUndefined();
  });

  it('records only the field that was supplied', async () => {
    await sessions.create(ALICE, { signals: { ip: '203.0.113.10' } });
    const [summary] = await sessions.listSessions(ALICE.userId);

    expect(summary?.signals?.ipHash).toBeDefined();
    expect(summary?.signals?.userAgentHash).toBeUndefined();
  });

  it('ignores empty strings rather than hashing them into a shared value', async () => {
    // Hashing '' would give every signal-less session the same handle and make
    // them look like one client.
    await sessions.create(ALICE, { signals: { userAgent: '', ip: '' } });
    const [summary] = await sessions.listSessions(ALICE.userId);

    expect(summary?.signals).toBeUndefined();
  });
});

/** The reason the feature exists. */
describe('classifying a reuse alarm', () => {
  it('reports `different` when a replay comes from another client', async () => {
    build(0);
    const pair = await sessions.create(ALICE, { signals: CHROME });
    await sessions.refresh(pair.refreshToken, { signals: CHROME });

    // The thief replays the original from their own machine.
    await expect(
      sessions.refresh(pair.refreshToken, { signals: CURL }),
    ).rejects.toThrow();

    expect(reuseEvent()?.signalMatch).toBe('different');
  });

  it('reports `same` when the replay looks like the legitimate client', async () => {
    // More often a retry or a double-submit than theft, and worth telling
    // apart before signing someone out and paging an operator.
    build(0);
    const pair = await sessions.create(ALICE, { signals: CHROME });
    await sessions.refresh(pair.refreshToken, { signals: CHROME });

    await expect(
      sessions.refresh(pair.refreshToken, { signals: CHROME }),
    ).rejects.toThrow();

    expect(reuseEvent()?.signalMatch).toBe('same');
  });

  it('reports `unknown` rather than guessing when the request had no signals', async () => {
    build(0);
    const pair = await sessions.create(ALICE, { signals: CHROME });
    await sessions.refresh(pair.refreshToken);
    await expect(sessions.refresh(pair.refreshToken)).rejects.toThrow();

    // Not `same`: an absent signal establishes nothing, and reporting
    // confidence that was never established is worse than reporting none.
    expect(reuseEvent()?.signalMatch).toBe('unknown');
  });

  it('reports `unknown` when the session was created without signals', async () => {
    build(0);
    const pair = await sessions.create(ALICE);
    await sessions.refresh(pair.refreshToken, { signals: CHROME });
    await expect(
      sessions.refresh(pair.refreshToken, { signals: CHROME }),
    ).rejects.toThrow();

    expect(reuseEvent()?.signalMatch).toBe('unknown');
  });

  it('reports `different` when only the address moved', async () => {
    // One field disagreeing is enough. A stolen token used from the same
    // browser build on another network still moved.
    build(0);
    const pair = await sessions.create(ALICE, { signals: CHROME });
    await sessions.refresh(pair.refreshToken, { signals: CHROME });

    await expect(
      sessions.refresh(pair.refreshToken, {
        signals: { userAgent: CHROME.userAgent, ip: '198.51.100.99' },
      }),
    ).rejects.toThrow();

    expect(reuseEvent()?.signalMatch).toBe('different');
  });

  it('still revokes the family regardless of what the signals said', async () => {
    // The classification informs the alarm; it never softens the response.
    build(0);
    const pair = await sessions.create(ALICE, { signals: CHROME });
    const rotated = await sessions.refresh(pair.refreshToken, { signals: CHROME });

    await expect(
      sessions.refresh(pair.refreshToken, { signals: CHROME }),
    ).rejects.toThrow();

    expect(reuseEvent()?.signalMatch).toBe('same');
    await expect(sessions.refresh(rotated.refreshToken)).rejects.toThrow();
  });
});

/**
 * Signals are forgeable by definition. Nothing may depend on them.
 */
describe('signals are never a control', () => {
  it('does not reject a refresh whose signals changed', async () => {
    // A user moving between wifi and cellular changes address mid-session.
    // Treating that as an attack would sign out honest people constantly, and
    // an attacker can trivially copy whatever value would have been accepted.
    const pair = await sessions.create(ALICE, { signals: CHROME });

    await expect(
      sessions.refresh(pair.refreshToken, { signals: CURL }),
    ).resolves.toBeTruthy();
  });

  it('does not reject a refresh that supplies no signals at all', async () => {
    const pair = await sessions.create(ALICE, { signals: CHROME });
    await expect(sessions.refresh(pair.refreshToken)).resolves.toBeTruthy();
  });

  it('does not let a forged signal end someone else’s session', async () => {
    // The whole threat model for this feature in one test: if a mismatch
    // caused revocation, anyone who guessed a token could also choose the
    // header that revokes it.
    const pair = await sessions.create(ALICE, { signals: CHROME });

    await sessions.refresh(pair.refreshToken, { signals: CURL }).catch(() => undefined);
    const [summary] = await sessions.listSessions(ALICE.userId);

    expect(summary).toBeDefined();
    expect(audit.events.some((e) => e.type === 'session.revoked')).toBe(false);
  });
});

describe('signals survive the session lifecycle', () => {
  it('persists across rotations', async () => {
    // `lastUsedAt` is rewritten on every refresh; the signals must not be lost
    // in the process, or a long-lived session stops being classifiable.
    let pair = await sessions.create(ALICE, { signals: CHROME });
    for (let i = 0; i < 3; i += 1) {
      pair = await sessions.refresh(pair.refreshToken, { signals: CHROME });
    }

    const [summary] = await sessions.listSessions(ALICE.userId);
    expect(summary?.signals?.ipHash).toBe(hashSignal(CHROME.ip));
  });

  it('keeps each session’s own signals in a multi-device listing', async () => {
    await sessions.create(ALICE, { signals: CHROME });
    await sessions.create(ALICE, { signals: CURL });

    const summaries = await sessions.listSessions(ALICE.userId);
    const hashes = summaries.map((s) => s.signals?.ipHash);

    expect(new Set(hashes).size).toBe(2);
    expect(hashes).toContain(hashSignal(CHROME.ip));
    expect(hashes).toContain(hashSignal(CURL.ip));
  });

  it('tolerates a malformed signals field rather than losing the session', async () => {
    // They are an audit aid. Dropping a session because one is corrupt would
    // be the wrong trade.
    const pair = await sessions.create(ALICE, { signals: CHROME });
    const context = await engine.verify(pair.accessToken);
    const key = KEYS.sessionMeta(context.sessionId);
    const meta = JSON.parse((await store.get(key)) as string) as Record<string, unknown>;

    await store.set(key, JSON.stringify({ ...meta, signals: 'not an object' }), 3600);

    const summaries = await sessions.listSessions(ALICE.userId);
    expect(summaries).toHaveLength(1);
    expect(summaries[0]?.signals).toBeUndefined();
  });
});
