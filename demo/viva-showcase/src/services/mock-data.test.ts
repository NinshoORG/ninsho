import { describe, expect, it } from 'vitest';
import { findUserByEmail, verifyUserPassword } from './mock-data.js';

describe('demo credential check', () => {
  it('accepts the seeded password, case- and whitespace-insensitively on email', () => {
    expect(verifyUserPassword('alice@example.com', 'password123')?.id).toBe('usr_alice_secureshop');
    expect(verifyUserPassword('  ALICE@example.com ', 'password123')?.id).toBe(
      'usr_alice_secureshop',
    );
  });

  it('refuses a wrong password and an unknown account alike', () => {
    expect(verifyUserPassword('alice@example.com', 'password124')).toBeNull();
    expect(verifyUserPassword('nobody@example.com', 'password123')).toBeNull();
    // An unknown account is compared against an empty string, which must not
    // become a way in.
    expect(verifyUserPassword('nobody@example.com', '')).toBeNull();
  });

  it('returns null rather than throwing for non-string JSON bodies', () => {
    for (const value of [undefined, null, 42, ['alice@example.com'], { $ne: '' }]) {
      expect(verifyUserPassword(value, 'password123')).toBeNull();
      expect(verifyUserPassword('alice@example.com', value)).toBeNull();
    }
  });

  it('does not resolve Object.prototype members as accounts', () => {
    for (const key of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
      expect(findUserByEmail(key)).toBeNull();
      expect(verifyUserPassword(key, undefined)).toBeNull();
      expect(verifyUserPassword(key, '')).toBeNull();
    }
  });
});
