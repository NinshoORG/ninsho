import { describe, it, expect, afterEach } from 'vitest';
import { VirtualAuthenticator, encodeCbor, rawToDerSignature, type Encodable } from './testing.js';
import { decodeCbor } from './cbor.js';
import { derToRawSignature } from './der.js';

const original = process.env['NODE_ENV'];

afterEach(() => {
  if (original === undefined) delete process.env['NODE_ENV'];
  else process.env['NODE_ENV'] = original;
});

/**
 * The guard follows the `MemoryStore` precedent: a test double may ship as
 * long as it must be named explicitly and cannot be selected by an environment
 * variable.
 */
describe('the production guard', () => {
  it('refuses to construct under NODE_ENV=production', async () => {
    // A VirtualAuthenticator running server-side means the server holds the
    // credential private key — WebAuthn defeated, with every signature still
    // verifying and nothing to notice.
    process.env['NODE_ENV'] = 'production';
    await expect(VirtualAuthenticator.create()).rejects.toThrow(/cannot be used in production/);
  });

  it('constructs normally otherwise', async () => {
    process.env['NODE_ENV'] = 'test';
    await expect(VirtualAuthenticator.create()).resolves.toBeInstanceOf(VirtualAuthenticator);
  });

  it('has no opt-out flag', async () => {
    // Deliberately not configurable. There is no legitimate reason to want
    // this in production, so there is no argument that enables it.
    process.env['NODE_ENV'] = 'production';
    await expect(VirtualAuthenticator.create()).rejects.toThrow();
  });
});

/**
 * The encoder and the DER writer are the inverses of the decoder and the DER
 * reader, written independently. Round-tripping them checks that the two
 * directions agree without either one defining what "correct" means.
 */
describe('the helpers round-trip against the parsers', () => {
  it.each([
    ['zero', 0],
    ['a small integer', 23],
    ['a one-byte argument', 200],
    ['a two-byte argument', 60_000],
    ['a four-byte argument', 100_000_000],
    ['a negative integer', -1000],
    ['a string', 'passkey'],
    ['an empty string', ''],
    ['true', true],
    ['null', null],
  ])('round-trips %s', (_label, value) => {
    expect(decodeCbor(encodeCbor(value as Encodable))).toEqual(value);
  });

  it('round-trips nested structures', () => {
    const value: Encodable = [1, [2, 3], 'x'];
    expect(decodeCbor(encodeCbor(value))).toEqual(value);
  });

  it('round-trips a map with integer keys, as COSE uses', () => {
    const map = new Map<string | number, Encodable>([
      [1, 2],
      [3, -7],
      [-1, 1],
    ]);
    expect(decodeCbor(encodeCbor(map))).toEqual(map);
  });

  it('round-trips byte strings of many lengths', () => {
    for (const length of [0, 1, 23, 24, 255, 256, 1000]) {
      const bytes = new Uint8Array(length);
      crypto.getRandomValues(bytes);
      expect(decodeCbor(encodeCbor(bytes))).toEqual(bytes);
    }
  });

  it('produces DER the strict reader accepts, for every padding case', () => {
    // The interesting cases are a leading zero byte, a set high bit, and a
    // body long enough to need the long-form length.
    for (const [r, s] of [
      [new Uint8Array(32).fill(1), new Uint8Array(32).fill(2)],
      [new Uint8Array(32).fill(0xff), new Uint8Array(32).fill(0xff)],
      [Uint8Array.from({ length: 32 }, (_, i) => (i === 31 ? 1 : 0)), new Uint8Array(32).fill(0x7f)],
    ] as const) {
      const raw = new Uint8Array(64);
      raw.set(r, 0);
      raw.set(s, 32);
      expect(derToRawSignature(rawToDerSignature(raw), 32)).toEqual(raw);
    }
  });

  it('round-trips 500 random signatures', () => {
    for (let i = 0; i < 500; i += 1) {
      const raw = new Uint8Array(64);
      crypto.getRandomValues(raw);
      // r and s must be non-zero for the strict reader to accept them.
      raw[0] = (raw[0] as number) | 1;
      raw[32] = (raw[32] as number) | 1;
      expect(derToRawSignature(rawToDerSignature(raw), 32)).toEqual(raw);
    }
  });
});
