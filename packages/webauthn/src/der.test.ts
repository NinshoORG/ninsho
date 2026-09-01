import { describe, it, expect } from 'vitest';
import { createSign, generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { DerError, derToRawSignature } from './der.js';

const hex = (value: string): Uint8Array =>
  new Uint8Array((value.match(/../g) ?? []).map((byte) => Number.parseInt(byte, 16)));

const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

/** Builds a DER SEQUENCE{INTEGER r, INTEGER s} from raw integer bodies. */
const der = (r: string, s: string): Uint8Array => {
  const body =
    `02${(r.length / 2).toString(16).padStart(2, '0')}${r}` +
    `02${(s.length / 2).toString(16).padStart(2, '0')}${s}`;
  return hex(`30${(body.length / 2).toString(16).padStart(2, '0')}${body}`);
};

describe('well-formed signatures', () => {
  it('left-pads both halves to the field width', () => {
    // r = 0x01, s = 0x02 — the extreme case for padding.
    const raw = derToRawSignature(der('01', '02'), 32);
    expect(raw).toHaveLength(64);
    expect(toHex(raw.subarray(0, 32))).toBe('01'.padStart(64, '0'));
    expect(toHex(raw.subarray(32))).toBe('02'.padStart(64, '0'));
  });

  it('strips the sign-clearing zero byte', () => {
    // 0x00ff is the minimal encoding of 255: without the zero byte, DER would
    // read it as negative.
    const raw = derToRawSignature(der('00ff', '00ff'), 32);
    expect(toHex(raw.subarray(0, 32))).toBe('ff'.padStart(64, '0'));
    expect(toHex(raw.subarray(32))).toBe('ff'.padStart(64, '0'));
  });

  it('handles full-width values that need no padding', () => {
    const full = '7f'.repeat(32);
    const raw = derToRawSignature(der(full, full), 32);
    expect(toHex(raw.subarray(0, 32))).toBe(full);
    expect(toHex(raw.subarray(32))).toBe(full);
  });

  it('accepts the long-form length a full-width signature requires', () => {
    // Two 33-byte INTEGERs push the SEQUENCE body past 0x80 — this is the
    // shape a real P-256 signature takes when both halves have a high bit set.
    const value = `00${'ff'.repeat(32)}`;
    const raw = derToRawSignature(der(value, value), 32);
    expect(raw).toHaveLength(64);
  });
});

/**
 * The differential test. A parser agreeing with its own author proves nothing;
 * these signatures are produced by OpenSSL through node:crypto and verified by
 * WebCrypto, so the conversion has to satisfy two implementations that know
 * nothing about this code.
 */
describe('against real signatures', () => {
  it('converts 200 OpenSSL P-256 signatures into a form WebCrypto verifies', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });

    const verifyKey = await crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: 'P-256', x: jwk.x as string, y: jwk.y as string },
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );

    // 200 iterations because a short r or s — the case padding exists for —
    // shows up in roughly 1 signature in 256 per half.
    for (let i = 0; i < 200; i += 1) {
      const message = new Uint8Array(32);
      crypto.getRandomValues(message);

      const derSig = createSign('SHA256').update(message).sign(privateKey);
      const raw = derToRawSignature(new Uint8Array(derSig), 32);

      const ok = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        verifyKey,
        raw,
        message,
      );
      expect(ok, `signature ${i} (${toHex(new Uint8Array(derSig))}) failed to verify`).toBe(true);
    }
  });

  it('produces a signature that fails against a different message', async () => {
    // Guards against the conversion "succeeding" by producing something that
    // verifies unconditionally.
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const verifyKey = await crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: 'P-256', x: jwk.x as string, y: jwk.y as string },
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    );

    const signed = new TextEncoder().encode('the real message');
    const other = new TextEncoder().encode('a different message');
    const raw = derToRawSignature(
      new Uint8Array(createSign('SHA256').update(signed).sign(privateKey)),
      32,
    );

    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, verifyKey, raw, other);
    expect(ok).toBe(false);
  });

  it('refuses the raw P1363 form rather than guessing at the encoding', () => {
    // A 64-byte raw signature is not DER. Silently accepting it would mean the
    // parser guesses at encodings, which is how two encodings become one bug.
    const raw = new Uint8Array(64);
    crypto.getRandomValues(raw);
    expect(() => derToRawSignature(raw, 32)).toThrow(DerError);
  });
});

describe('malformed encodings', () => {
  it('refuses a non-SEQUENCE tag', () => {
    expect(() => derToRawSignature(hex('3106020101020102'), 32)).toThrow(/not a DER SEQUENCE/);
  });

  it('refuses a declared length shorter than the content', () => {
    // SEQUENCE says 4 bytes, but 6 follow.
    expect(() => derToRawSignature(hex('3004020101020102'), 32)).toThrow(/does not match/);
  });

  it('refuses trailing bytes after the SEQUENCE', () => {
    expect(() => derToRawSignature(hex('3006020101020102aabb'), 32)).toThrow(/does not match/);
  });

  it('refuses indefinite length', () => {
    expect(() => derToRawSignature(hex('3080020101020102'), 32)).toThrow(/indefinite/);
  });

  it.each([
    ['a redundant leading zero in a long-form length', '3082004a'],
    ['a long form used for a short value', '308101'],
  ])('refuses %s', (_label, encoded) => {
    expect(() => derToRawSignature(hex(encoded), 32)).toThrow(/non-minimal length/);
  });

  it('refuses a length field wider than any signature needs', () => {
    expect(() => derToRawSignature(hex('3084ffffffff'), 32)).toThrow(/implausible/);
  });

  it('refuses a second element that is not an INTEGER', () => {
    // SEQUENCE { INTEGER 1, OCTET STRING 2 }
    expect(() => derToRawSignature(hex('3006020101040102'), 32)).toThrow(/expected an INTEGER/);
  });

  it.each([
    ['a negative r', der('81', '01')],
    ['a negative s', der('01', '81')],
  ])('refuses %s', (_label, encoded) => {
    expect(() => derToRawSignature(encoded, 32)).toThrow(/negative INTEGER/);
  });

  it.each([
    ['r', der('00', '01')],
    ['s', der('01', '00')],
  ])('refuses a zero %s', (_label, encoded) => {
    // r = 0 or s = 0 is not a valid ECDSA signature at all.
    expect(() => derToRawSignature(encoded, 32)).toThrow(/is zero/);
  });

  it('refuses padding that does not clear a sign bit', () => {
    // 0x00 0x01 — the zero byte is unnecessary, so this is a second spelling
    // of the same value.
    expect(() => derToRawSignature(der('0001', '01'), 32)).toThrow(/non-minimal INTEGER/);
  });

  it('refuses an INTEGER wider than the field', () => {
    // 33 significant bytes cannot be a P-256 field element. The leading byte
    // has to have its high bit clear, or the sign check refuses it first and
    // the width check never runs.
    expect(() => derToRawSignature(der(`01${'ff'.repeat(32)}`, '01'), 32)).toThrow(/too large/);
  });

  it.each([
    ['an empty input', ''],
    ['a bare SEQUENCE tag', '30'],
    ['a zero-length INTEGER', '3004020002 0101'.replace(/ /g, '')],
    ['a truncated INTEGER body', '3003022001'],
  ])('refuses %s', (_label, encoded) => {
    expect(() => derToRawSignature(hex(encoded), 32)).toThrow(DerError);
  });

  it('never throws anything but DerError on random input', () => {
    for (let i = 0; i < 5000; i += 1) {
      const bytes = new Uint8Array(Math.floor(Math.random() * 80));
      crypto.getRandomValues(bytes);
      // Bias toward inputs that get past the first byte, so the fuzzer spends
      // its time in the length and INTEGER paths rather than bouncing off the
      // tag check.
      if (bytes.length > 0 && i % 2 === 0) bytes[0] = 0x30;

      try {
        derToRawSignature(bytes, 32);
      } catch (error) {
        if (!(error instanceof DerError)) {
          throw new Error(
            `uncontrolled ${(error as Error).constructor.name} for ${toHex(bytes)}: ` +
              `${(error as Error).message}`,
          );
        }
      }
    }
  });

  it('never reads past the end of the buffer', () => {
    // Every prefix of a valid signature must be refused cleanly rather than
    // reading whatever happens to follow it.
    const valid = new Uint8Array(
      createSign('SHA256')
        .update(new Uint8Array(32))
        .sign(generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey),
    );

    for (let cut = 0; cut < valid.length; cut += 1) {
      expect(() => derToRawSignature(valid.subarray(0, cut), 32), `prefix of ${cut}`).toThrow(
        DerError,
      );
    }
    expect(() => derToRawSignature(valid, 32)).not.toThrow();
  });
});

describe('other curves', () => {
  it('converts P-384 signatures at a 48-byte field width', async () => {
    // The field size is a parameter, not a constant, and the only way to know
    // it is honoured is to use a different one.
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-384' });
    const jwk = publicKey.export({ format: 'jwk' });
    const verifyKey = await crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: 'P-384', x: jwk.x as string, y: jwk.y as string },
      { name: 'ECDSA', namedCurve: 'P-384' },
      false,
      ['verify'],
    );

    const message = new TextEncoder().encode('p384');
    const raw = derToRawSignature(new Uint8Array(nodeSign('SHA384', message, privateKey)), 48);

    expect(raw).toHaveLength(96);
    const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, verifyKey, raw, message);
    expect(ok).toBe(true);
  });
});
