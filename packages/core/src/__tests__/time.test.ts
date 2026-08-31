import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  nowIso,
  isoIn,
  isoToMs,
  isExpired,
  isNotYetValid,
  secondsUntil,
} from '../time.js';

afterEach(() => {
  vi.useRealTimers();
});

describe('nowIso / isoIn', () => {
  it('produces parseable ISO 8601 with a Z suffix', () => {
    expect(nowIso()).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  });

  it('offsets forward by the given seconds', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-08-31T12:00:00.000Z'));
    expect(isoIn(900)).toBe('2026-08-31T12:15:00.000Z');
  });

  it('offsets backward for negative seconds', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-08-31T12:00:00.000Z'));
    expect(isoIn(-60)).toBe('2026-08-31T11:59:00.000Z');
  });

  it('round-trips through isoToMs', () => {
    const iso = isoIn(300);
    expect(isoToMs(iso)).toBeCloseTo(Date.now() + 300_000, -3);
  });
});

describe('isoToMs', () => {
  it.each([
    ['garbage', 'not-a-date'],
    ['an empty string', ''],
    ['a partial date', '2026-13-45T99:99:99Z'],
  ])('returns NaN for %s', (_label, input) => {
    expect(Number.isNaN(isoToMs(input))).toBe(true);
  });
});

/**
 * Both predicates must fail closed. An unparseable timestamp means the
 * credential's validity window cannot be established, and an unknown window is
 * never a reason to honour a credential. A permissive implementation returning
 * `false` here would make a token with a corrupted `exp` valid forever.
 */
describe('isExpired', () => {
  it('is false for a future timestamp', () => {
    expect(isExpired(isoIn(60))).toBe(false);
  });

  it('is true for a past timestamp', () => {
    expect(isExpired(isoIn(-60))).toBe(true);
  });

  it.each([
    ['garbage', 'not-a-date'],
    ['an empty string', ''],
    ['a nonsense date', '9999-99-99T00:00:00Z'],
  ])('fails closed on %s', (_label, input) => {
    expect(isExpired(input)).toBe(true);
  });

  it('honours clock tolerance for a recently expired timestamp', () => {
    // Expired 5s ago, but the hosts are allowed to disagree by 30s.
    expect(isExpired(isoIn(-5), 30)).toBe(false);
    expect(isExpired(isoIn(-5), 0)).toBe(true);
  });

  it('does not let tolerance rescue a long-expired timestamp', () => {
    expect(isExpired(isoIn(-3600), 30)).toBe(true);
  });

  it('does not let tolerance rescue an unparseable timestamp', () => {
    expect(isExpired('not-a-date', 86_400)).toBe(true);
  });
});

describe('isNotYetValid', () => {
  it('is true for a future timestamp', () => {
    expect(isNotYetValid(isoIn(60))).toBe(true);
  });

  it('is false for a past timestamp', () => {
    expect(isNotYetValid(isoIn(-60))).toBe(false);
  });

  it('fails closed on an unparseable timestamp', () => {
    expect(isNotYetValid('not-a-date')).toBe(true);
  });

  it('honours clock tolerance for a slightly future timestamp', () => {
    expect(isNotYetValid(isoIn(5), 30)).toBe(false);
    expect(isNotYetValid(isoIn(5), 0)).toBe(true);
  });
});

describe('secondsUntil', () => {
  it('returns the remaining whole seconds', () => {
    expect(secondsUntil(isoIn(300))).toBeGreaterThan(295);
    expect(secondsUntil(isoIn(300))).toBeLessThanOrEqual(300);
  });

  it('floors at zero for a past timestamp, never returning a negative TTL', () => {
    // A negative TTL passed to a store means "no expiry" in some clients —
    // a revocation entry that never expires, or worse, one rejected outright.
    expect(secondsUntil(isoIn(-300))).toBe(0);
  });

  it('returns zero for an unparseable timestamp', () => {
    expect(secondsUntil('not-a-date')).toBe(0);
  });
});
