import { describe, it, expect } from 'vitest';
import {
  pae,
  readFooterUnverified,
  signV4Public,
  verifyV4Public,
  PasetoFormatError,
  V4_PUBLIC_HEADER,
} from '../paseto/v4.js';
import { generateKeyPair, loadPrivateKey, loadPublicKey } from '../keys/keyring.js';
import vectors from './fixtures/paseto-v4-public.json' with { type: 'json' };

/**
 * ─── Why this file is the load-bearing evidence for Phase 4 ───────────────
 * Ninsho implements PASETO v4.public rather than depending on a package. The
 * cryptography is `node:crypto`'s Ed25519; what is implemented here is PAE and
 * base64url framing. The justification for that choice rests entirely on being
 * able to *prove* the implementation correct, and these are the specification's
 * own test vectors, fetched from paseto-standard/test-vectors.
 *
 * If any assertion in the first block fails, the implementation is wrong and
 * the decision to own it was wrong with it.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('official PASETO v4.public test vectors', () => {
  it('has the expected vectors loaded', () => {
    expect(vectors.tests).toHaveLength(3);
    expect(vectors.tests.map((t) => t.name)).toEqual(['4-S-1', '4-S-2', '4-S-3']);
  });

  it.each(vectors.tests)('$name — verifies the specification token', (vector) => {
    const publicKey = loadPublicKey(vector.publicKey);
    const result = verifyV4Public(vector.token, publicKey, vector.implicit);

    expect(result.payload).toBe(vector.payload);
    expect(result.footer).toBe(vector.footer);
  });

  it.each(vectors.tests)('$name — reproduces the specification token byte for byte', (vector) => {
    // Ed25519 is deterministic (RFC 8032), so a correct implementation must
    // produce the exact bytes the specification lists — not merely something
    // that happens to verify.
    const privateKey = loadPrivateKey(vector.secretKey);
    const token = signV4Public(vector.payload, privateKey, vector.footer, vector.implicit);

    expect(token).toBe(vector.token);
  });

  it.each(vectors.tests)('$name — rejects the token under a different implicit assertion', (vector) => {
    const publicKey = loadPublicKey(vector.publicKey);
    // The implicit assertion is authenticated but never transmitted, so a
    // verifier supplying the wrong one must reject. Accepting anyway would
    // mean it was not really covered by the signature.
    expect(() => verifyV4Public(vector.token, publicKey, `${vector.implicit}x`)).toThrow(
      PasetoFormatError,
    );
  });
});

describe('PAE', () => {
  it('encodes the empty list as a bare count', () => {
    expect(pae([]).toString('hex')).toBe('0000000000000000');
  });

  it('encodes one empty piece as count plus zero length', () => {
    expect(pae([Buffer.alloc(0)]).toString('hex')).toBe('01000000000000000000000000000000');
  });

  it('length-prefixes each piece', () => {
    expect(pae([Buffer.from('a')]).toString('hex')).toBe(
      '0100000000000000' + '0100000000000000' + '61',
    );
  });

  /**
   * The reason PAE exists. Without length prefixes these two inputs would
   * serialize identically, and an attacker could move bytes between the
   * payload and the footer while keeping the signature valid.
   */
  it('distinguishes groupings that would otherwise concatenate identically', () => {
    const a = pae([Buffer.from('ab'), Buffer.from('c')]);
    const b = pae([Buffer.from('a'), Buffer.from('bc')]);
    expect(a.equals(b)).toBe(false);
  });

  it('clears the most significant bit of every length prefix', () => {
    // The spec requires this so implementations without unsigned 64-bit
    // integers cannot be led into reading a negative length.
    const encoded = pae([Buffer.alloc(0)]);
    expect(encoded[7]! & 0x80).toBe(0);
    expect(encoded[15]! & 0x80).toBe(0);
  });
});

describe('sign and verify round trip', () => {
  const keys = generateKeyPair('test-key');
  const privateKey = loadPrivateKey(keys.privateKey);
  const publicKey = loadPublicKey(keys.publicKey);

  it('round-trips a payload with no footer', () => {
    const token = signV4Public('{"hello":"world"}', privateKey);
    expect(token.startsWith(V4_PUBLIC_HEADER)).toBe(true);
    expect(verifyV4Public(token, publicKey).payload).toBe('{"hello":"world"}');
  });

  it('round-trips a payload with a footer', () => {
    const token = signV4Public('{"a":1}', privateKey, '{"kid":"k1"}');
    const result = verifyV4Public(token, publicKey);
    expect(result.payload).toBe('{"a":1}');
    expect(result.footer).toBe('{"kid":"k1"}');
  });

  it('handles non-ASCII payloads without corruption', () => {
    const payload = '{"name":"認証","emoji":"🔐"}';
    const token = signV4Public(payload, privateKey);
    expect(verifyV4Public(token, publicKey).payload).toBe(payload);
  });

  it('reads the footer without a key', () => {
    const token = signV4Public('{}', privateKey, '{"kid":"abc"}');
    expect(readFooterUnverified(token)).toBe('{"kid":"abc"}');
  });

  it('reports an empty footer when there is none', () => {
    expect(readFooterUnverified(signV4Public('{}', privateKey))).toBe('');
  });
});

describe('tamper resistance', () => {
  const keys = generateKeyPair('k');
  const privateKey = loadPrivateKey(keys.privateKey);
  const publicKey = loadPublicKey(keys.publicKey);
  const other = generateKeyPair('other');
  const otherPublic = loadPublicKey(other.publicKey);

  const token = signV4Public('{"role":"user"}', privateKey, '{"kid":"k"}');

  it('rejects a token signed by a different key', () => {
    expect(() => verifyV4Public(token, otherPublic)).toThrow(PasetoFormatError);
  });

  it('rejects a modified payload', () => {
    const forged = signV4Public('{"role":"admin"}', loadPrivateKey(other.privateKey));
    expect(() => verifyV4Public(forged, publicKey)).toThrow(PasetoFormatError);
  });

  it('rejects a token whose body has been altered', () => {
    const [, , body] = token.split('.');
    const flipped = `${body!.slice(0, -2)}${body!.slice(-2) === 'AA' ? 'AB' : 'AA'}`;
    expect(() => verifyV4Public(`v4.public.${flipped}`, publicKey)).toThrow(PasetoFormatError);
  });

  /**
   * The footer is readable before verification but is inside the signed
   * preimage. Swapping it — the obvious attack, since it is where the key id
   * lives — must invalidate the signature.
   */
  it('rejects a swapped footer', () => {
    const parts = token.split('.');
    const evilFooter = Buffer.from('{"kid":"attacker"}').toString('base64url');
    expect(() => verifyV4Public(`v4.public.${parts[2]}.${evilFooter}`, publicKey)).toThrow(
      PasetoFormatError,
    );
  });

  it('rejects a footer that is removed after signing', () => {
    const parts = token.split('.');
    expect(() => verifyV4Public(`v4.public.${parts[2]}`, publicKey)).toThrow(PasetoFormatError);
  });

  it('rejects a footer added to a token signed without one', () => {
    const plain = signV4Public('{}', privateKey);
    const footer = Buffer.from('{"kid":"k"}').toString('base64url');
    expect(() => verifyV4Public(`${plain}.${footer}`, publicKey)).toThrow(PasetoFormatError);
  });

  it.each([
    ['a JWT', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc'],
    ['a v4.local token', 'v4.local.AAAAAAAAAAAAAAAA'],
    ['a v2.public token', 'v2.public.eyJhIjoxfQ'],
    ['a v3.public token', 'v3.public.eyJhIjoxfQ'],
    ['the header alone', 'v4.public.'],
    ['an empty string', ''],
    ['random text', 'not-a-token'],
    ['too many segments', 'v4.public.aaaa.bbbb.cccc'],
  ])('rejects %s', (_label, candidate) => {
    expect(() => verifyV4Public(candidate, publicKey)).toThrow(PasetoFormatError);
  });

  it.each([
    ['undefined', undefined],
    ['null', null],
    ['a number', 42],
    ['an object', {}],
  ])('rejects %s without an unexpected error type', (_label, candidate) => {
    expect(() => verifyV4Public(candidate as unknown as string, publicKey)).toThrow(
      PasetoFormatError,
    );
  });

  it('rejects a body too short to hold a signature', () => {
    const tiny = Buffer.from('short').toString('base64url');
    expect(() => verifyV4Public(`v4.public.${tiny}`, publicKey)).toThrow(/too short/);
  });

  /**
   * Node's base64url decoder is lenient — several spellings decode to the same
   * bytes. Accepting all of them would give one token multiple valid textual
   * forms, which invites parser-mismatch bugs between systems that log,
   * deduplicate, or denylist by token string.
   */
  it('rejects non-canonical base64url in the body', () => {
    const parts = token.split('.');
    expect(() => verifyV4Public(`v4.public.${parts[2]}=`, publicKey)).toThrow(
      /non-canonical/,
    );
  });

  it('rejects base64url containing standard-alphabet characters', () => {
    expect(() => verifyV4Public('v4.public.a+b/c==', publicKey)).toThrow(PasetoFormatError);
  });
});

describe('algorithm confusion', () => {
  /**
   * The property PASETO is chosen for. There is no `alg` field to manipulate:
   * the version and purpose are the literal prefix, and this implementation
   * matches it exactly. JWT's `alg: none` and HMAC-verified-against-a-public-key
   * attacks cannot be *expressed* in this format, let alone succeed.
   */
  it('has no algorithm field an attacker could target', () => {
    const keys = generateKeyPair('k');
    const token = signV4Public('{"a":1}', loadPrivateKey(keys.privateKey));

    // Everything before the payload is a fixed literal.
    expect(token.slice(0, V4_PUBLIC_HEADER.length)).toBe('v4.public.');
    expect(token).not.toMatch(/alg/i);
  });

  it.each(['v4.PUBLIC.', 'V4.public.', 'v4.public', 'v5.public.'])(
    'rejects the near-miss header %s',
    (header) => {
      const keys = generateKeyPair('k');
      const publicKey = loadPublicKey(keys.publicKey);
      const token = signV4Public('{"a":1}', loadPrivateKey(keys.privateKey));
      const body = token.slice(V4_PUBLIC_HEADER.length);
      expect(() => verifyV4Public(`${header}${body}`, publicKey)).toThrow(PasetoFormatError);
    },
  );
});
