import { describe, it, expect } from 'vitest';
import {
  generateId,
  generateToken,
  sha256,
  hashToken,
  hashSignal,
  safeEqual,
} from '../crypto.js';

/** base64url alphabet only — no `+`, `/` or `=`, so values are URL and cookie safe. */
const URL_SAFE = /^[A-Za-z0-9_-]+$/;

describe('generateId', () => {
  it('produces URL-safe output', () => {
    for (let i = 0; i < 100; i += 1) {
      expect(generateId()).toMatch(URL_SAFE);
    }
  });

  it('encodes 128 bits by default', () => {
    // 16 bytes -> ceil(16/3)*4 = 24 chars with padding, 22 once base64url strips it.
    expect(generateId()).toHaveLength(22);
  });

  it('honours a custom entropy size', () => {
    expect(generateId(32)).toHaveLength(43);
  });

  it('does not repeat across a large sample', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 20_000; i += 1) seen.add(generateId());
    expect(seen.size).toBe(20_000);
  });
});

describe('generateToken', () => {
  it('produces URL-safe output', () => {
    expect(generateToken()).toMatch(URL_SAFE);
  });

  it('encodes 256 bits by default', () => {
    expect(generateToken()).toHaveLength(43);
  });

  it('does not repeat across a large sample', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 20_000; i += 1) seen.add(generateToken());
    expect(seen.size).toBe(20_000);
  });

  /**
   * A weak or broken generator is the failure mode that matters most here, and
   * it usually shows up as skewed output. This is a smoke test, not a
   * statistical proof: it catches a constant, a counter, or a generator stuck
   * on part of its alphabet.
   */
  it('spreads output across the alphabet', () => {
    const chars = new Set<string>();
    for (let i = 0; i < 500; i += 1) {
      for (const c of generateToken()) chars.add(c);
    }
    // base64url has 64 symbols; 500 * 43 draws should reach nearly all of them.
    expect(chars.size).toBeGreaterThan(60);
  });
});

describe('sha256', () => {
  it('matches the known digest of the empty string', () => {
    expect(sha256('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('matches the known digest of "abc"', () => {
    expect(sha256('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('is deterministic and 64 hex characters', () => {
    const a = sha256('ninsho');
    expect(a).toBe(sha256('ninsho'));
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it('handles non-ASCII input without mangling it', () => {
    expect(sha256('認証')).not.toBe(sha256('ninsho'));
    expect(sha256('認証')).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('hashToken', () => {
  it('never returns the raw token', () => {
    const raw = generateToken();
    expect(hashToken(raw)).not.toBe(raw);
    expect(hashToken(raw)).not.toContain(raw);
  });

  it('is deterministic, so a presented token can be looked up', () => {
    const raw = generateToken();
    expect(hashToken(raw)).toBe(hashToken(raw));
  });

  it('separates tokens that differ by a single character', () => {
    expect(hashToken('token-a')).not.toBe(hashToken('token-b'));
  });
});

describe('hashSignal', () => {
  it('truncates to 16 hex characters', () => {
    expect(hashSignal('Mozilla/5.0')).toMatch(/^[0-9a-f]{16}$/);
  });

  it('is stable for the same signal', () => {
    expect(hashSignal('Mozilla/5.0')).toBe(hashSignal('Mozilla/5.0'));
  });
});

/**
 * safeEqual guards secret comparison. The defensive cases matter as much as
 * the happy path: returning false for malformed input is what keeps a missing
 * or wrongly-typed claim from throwing an unhandled TypeError partway through
 * a verification chain.
 */
describe('safeEqual', () => {
  it('accepts identical strings', () => {
    expect(safeEqual('abc123', 'abc123')).toBe(true);
    const token = generateToken();
    expect(safeEqual(token, token)).toBe(true);
  });

  it('rejects differing strings of equal length', () => {
    expect(safeEqual('abc123', 'abc124')).toBe(false);
    expect(safeEqual('abc123', 'zbc123')).toBe(false);
  });

  it('rejects strings of differing length', () => {
    expect(safeEqual('abc', 'abcd')).toBe(false);
    expect(safeEqual('', 'a')).toBe(false);
  });

  it('rejects two empty strings — an absent secret never matches', () => {
    expect(safeEqual('', '')).toBe(false);
  });

  it.each([
    ['undefined', undefined],
    ['null', null],
    ['a number', 12345],
    ['an object', { toString: () => 'abc123' }],
    ['an array', ['abc123']],
    ['a boolean', true],
  ])('rejects %s rather than throwing', (_label, value) => {
    expect(() => safeEqual('abc123', value)).not.toThrow();
    expect(safeEqual('abc123', value)).toBe(false);
    expect(safeEqual(value, 'abc123')).toBe(false);
  });

  it('does not coerce an object whose toString matches', () => {
    // A permissive implementation would stringify this and wrongly return true.
    expect(safeEqual('abc123', { toString: () => 'abc123' })).toBe(false);
  });

  it('compares by bytes, not by unicode normalization', () => {
    // Same rendered glyph, different code points. These are not equal secrets.
    expect(safeEqual('é', 'é')).toBe(false);
  });
});
