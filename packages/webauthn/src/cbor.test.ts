import { describe, it, expect } from 'vitest';
import { CborError, decodeCbor, decodeCborPrefix, type CborValue } from './cbor.js';

const hex = (value: string): Uint8Array =>
  new Uint8Array((value.match(/../g) ?? []).map((byte) => Number.parseInt(byte, 16)));

/**
 * ─── RFC 8949 Appendix A ──────────────────────────────────────────────────
 * The specification's own worked examples. This decoder parses
 * attacker-controlled input — a hostile browser can send anything — so its
 * correctness needs to rest on published vectors rather than on the author
 * agreeing with themselves.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('RFC 8949 test vectors', () => {
  it.each([
    ['00', 0],
    ['01', 1],
    ['0a', 10],
    ['17', 23],
    ['1818', 24],
    ['1819', 25],
    ['1864', 100],
    ['1903e8', 1000],
    ['1a000f4240', 1_000_000],
    ['1b000000e8d4a51000', 1_000_000_000_000],
  ])('decodes the unsigned integer %s', (encoded, expected) => {
    expect(decodeCbor(hex(encoded))).toBe(expected);
  });

  it.each([
    ['20', -1],
    ['29', -10],
    ['3863', -100],
    ['3903e7', -1000],
  ])('decodes the negative integer %s', (encoded, expected) => {
    expect(decodeCbor(hex(encoded))).toBe(expected);
  });

  it.each([
    ['40', ''],
    ['4401020304', '01020304'],
  ])('decodes the byte string %s', (encoded, expectedHex) => {
    const value = decodeCbor(hex(encoded)) as Uint8Array;
    expect(Buffer.from(value).toString('hex')).toBe(expectedHex);
  });

  it.each([
    ['60', ''],
    ['6161', 'a'],
    ['6449455446', 'IETF'],
    ['62225c', '"\\'],
    ['62c3bc', 'ü'],
    ['63e6b0b4', '水'],
  ])('decodes the text string %s', (encoded, expected) => {
    expect(decodeCbor(hex(encoded))).toBe(expected);
  });

  it.each([
    ['80', []],
    ['83010203', [1, 2, 3]],
    ['8301820203820405', [1, [2, 3], [4, 5]]],
  ])('decodes the array %s', (encoded, expected) => {
    expect(decodeCbor(hex(encoded))).toEqual(expected);
  });

  it('decodes a map with integer keys', () => {
    // COSE keys use integer labels, so this is the shape that matters most.
    const value = decodeCbor(hex('a201020304')) as Map<number, CborValue>;
    expect(value.get(1)).toBe(2);
    expect(value.get(3)).toBe(4);
  });

  it('decodes a map with text keys and a nested array', () => {
    const value = decodeCbor(hex('a26161016162820203')) as Map<string, CborValue>;
    expect(value.get('a')).toBe(1);
    expect(value.get('b')).toEqual([2, 3]);
  });

  it.each([
    ['f4', false],
    ['f5', true],
    ['f6', null],
  ])('decodes the simple value %s', (encoded, expected) => {
    expect(decodeCbor(hex(encoded))).toBe(expected);
  });

  it('decodes a 25-element array', () => {
    const encoded = '98190102030405060708090a0b0c0d0e0f101112131415161718181819';
    expect(decodeCbor(hex(encoded))).toEqual(Array.from({ length: 25 }, (_, i) => i + 1));
  });
});

/**
 * Everything the decoder deliberately refuses. Each of these is a construct
 * that CTAP2 canonical CBOR forbids anyway, and each is a place where a more
 * permissive parser grows an attack surface.
 */
describe('constructs that are refused', () => {
  it.each([
    ['an indefinite-length byte string', '5f42010243030405ff'],
    ['an indefinite-length text string', '7f657374726561646d696e67ff'],
    ['an indefinite-length array', '9f018202039f0405ffff'],
    ['an indefinite-length map', 'bf61610161629f0203ffff'],
  ])('refuses %s', (_label, encoded) => {
    // Indefinite lengths are where CBOR parsers historically grow bugs, and
    // WebAuthn never uses them.
    expect(() => decodeCbor(hex(encoded))).toThrow(/indefinite/);
  });

  it('refuses tags', () => {
    // Major type 6. CTAP2 canonical CBOR forbids them.
    expect(() => decodeCbor(hex('c11a514b67b0'))).toThrow(CborError);
  });

  it.each([
    ['a half float', 'f93c00'],
    ['a single float', 'fa47c35000'],
    ['a double float', 'fb7e37e43c8800759c'],
  ])('refuses %s', (_label, encoded) => {
    expect(() => decodeCbor(hex(encoded))).toThrow(CborError);
  });

  it('refuses undefined', () => {
    expect(() => decodeCbor(hex('f7'))).toThrow(/undefined/);
  });

  it.each(['1c', '1d', '1e'])('refuses the reserved additional information %s', (encoded) => {
    expect(() => decodeCbor(hex(encoded))).toThrow(/reserved/);
  });

  /**
   * A repeated key is ambiguous, and implementations disagree about which one
   * wins — precisely the disagreement an attacker uses to make two systems
   * read the same bytes differently.
   */
  it('refuses duplicate map keys', () => {
    expect(() => decodeCbor(hex('a2616101616102'))).toThrow(/duplicate/);
  });

  it('refuses non-string, non-integer map keys', () => {
    // A map keyed by an array.
    expect(() => decodeCbor(hex('a1820102 03'.replace(/ /g, '')))).toThrow(/map keys/);
  });

  it('refuses malformed UTF-8 rather than substituting replacement characters', () => {
    // A silent replacement would change the string's meaning with nothing to
    // indicate it had happened.
    expect(() => decodeCbor(hex('62c328'))).toThrow(CborError);
  });
});

describe('hostile input', () => {
  it('refuses trailing bytes after a complete value', () => {
    // Ignoring them lets an attacker append data one parser reads and another
    // does not.
    expect(() => decodeCbor(hex('01' + 'ff'))).toThrow(/trailing/);
  });

  it.each([
    ['a truncated integer', '18'],
    ['a truncated byte string', '4401'],
    ['a truncated array', '8301'],
    ['a truncated map', 'a201'],
    ['nothing at all', ''],
  ])('refuses %s', (_label, encoded) => {
    expect(() => decodeCbor(hex(encoded))).toThrow(CborError);
  });

  /**
   * The allocation guard. A four-byte header can declare a four-billion-byte
   * string; a decoder that allocates before checking is a denial of service
   * that costs the attacker nothing to trigger.
   */
  it('refuses a declared length larger than the input', () => {
    // Claims a 4 GB byte string in a 5-byte message.
    expect(() => decodeCbor(hex('5affffffff'))).toThrow(/exceeds/);
  });

  it('refuses an array claiming more elements than could fit', () => {
    expect(() => decodeCbor(hex('9affffffff'))).toThrow(/exceeds/);
  });

  it('refuses a map claiming more pairs than could fit', () => {
    expect(() => decodeCbor(hex('baffffffff'))).toThrow(/exceeds/);
  });

  /**
   * Deeply nested arrays drive a recursive decoder into a stack overflow. A
   * few hundred bytes is enough, so the depth limit is not optional.
   */
  it('refuses nesting beyond the depth limit', () => {
    // 40 nested single-element arrays: 81 81 81 ... 01
    const deep = `${'81'.repeat(40)}01`;
    expect(() => decodeCbor(hex(deep))).toThrow(/nesting/);
  });

  it('accepts nesting within the limit', () => {
    const shallow = `${'81'.repeat(8)}01`;
    expect(() => decodeCbor(hex(shallow))).not.toThrow();
  });

  it('never throws anything but CborError on random input', () => {
    // An unexpected exception type means an unhandled path, which a caller
    // cannot map to a clean refusal.
    for (let i = 0; i < 2000; i += 1) {
      const length = Math.floor(Math.random() * 40);
      const bytes = new Uint8Array(length);
      crypto.getRandomValues(bytes);

      try {
        decodeCbor(bytes);
      } catch (error) {
        if (!(error instanceof CborError)) {
          throw new Error(
            `uncontrolled ${(error as Error).constructor.name} for ` +
              `${Buffer.from(bytes).toString('hex')}: ${(error as Error).message}`,
          );
        }
      }
    }
  });
});

describe('decodeCborPrefix', () => {
  /**
   * Attested credential data embeds a COSE key in a larger buffer with no
   * length prefix, so the only way to find where the key ends is to decode it
   * and report the offset.
   */
  it('reports how many bytes a value consumed', () => {
    const { value, bytesRead } = decodeCborPrefix(hex('a201020304' + 'deadbeef'));
    expect(bytesRead).toBe(5);
    expect((value as Map<number, CborValue>).get(1)).toBe(2);
  });

  it('tolerates trailing bytes, unlike decodeCbor', () => {
    expect(() => decodeCborPrefix(hex('01ffffff'))).not.toThrow();
    expect(() => decodeCbor(hex('01ffffff'))).toThrow(/trailing/);
  });

  it('still refuses a truncated value', () => {
    expect(() => decodeCborPrefix(hex('a201'))).toThrow(CborError);
  });
});
