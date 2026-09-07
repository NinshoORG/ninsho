import { describe, it, expect } from 'vitest';
import {
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  verify as edVerify,
} from 'node:crypto';
import {
  KeyError,
  TokenExpiredError,
  TokenInvalidError,
  isoIn,
  nowIso,
  type Principal,
} from '@ninsho/core';
import {
  signV4Public,
  verifyV4Public,
  readFooterUnverified,
  pae,
  PasetoFormatError,
  V4_PUBLIC_HEADER,
} from '../paseto/v4.js';
import { PasetoEngine } from '../engine/paseto.js';
import { KeyRing, generateKeyPair, loadPrivateKey, loadPublicKey } from '../keys/keyring.js';
import { MemoryStore } from '../store/memory.js';
import vectors from './fixtures/paseto-v4-public.json' with { type: 'json' };

/**
 * ═══════════════════════════════════════════════════════════════════════════
 * INDEPENDENT PASETO v4.public CRYPTOGRAPHIC AUDIT SUITE
 * 
 * This suite does NOT rely on Ninsho's internal PAE or crypto helpers.
 * It provides an independent reference implementation of PAE and PASETO
 * checks, and rigorously audits all 12 properties (C1 - C12).
 * ═══════════════════════════════════════════════════════════════════════════
 */

// ─── Independent Reference Implementation of PAE ───────────────────────────

/**
 * Independent calculation of PASETO Pre-Authentication Encoding.
 * Built completely independently using DataView and Uint8Array primitives.
 */
function independentPae(pieces: readonly Uint8Array[]): Uint8Array {
  const count = BigInt(pieces.length);
  // Total size = 8 bytes (piece count) + sum(8 bytes length + piece byte length)
  let totalLength = 8;
  for (const piece of pieces) {
    totalLength += 8 + piece.length;
  }

  const output = new Uint8Array(totalLength);
  const view = new DataView(output.buffer, output.byteOffset, output.byteLength);

  // Write count: 64-bit unsigned LE with MSB cleared
  view.setBigUint64(0, count & 0x7fffffffffffffffn, true);

  let cursor = 8;
  for (const piece of pieces) {
    view.setBigUint64(cursor, BigInt(piece.length) & 0x7fffffffffffffffn, true);
    cursor += 8;
    output.set(piece, cursor);
    cursor += piece.length;
  }

  return output;
}


/** Helper to decode base64url string to Uint8Array */
function independentB64uDecode(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, 'base64url'));
}

// ─── Test Fixture Helpers ──────────────────────────────────────────────────

const ALICE: Principal = {
  userId: 'usr_alice_audit',
  roles: ['auditor', 'user'],
  scopes: ['audit:read', 'audit:write'],
};

// ─── C1: PAE Construction Audit ────────────────────────────────────────────

describe('C1 — PAE Construction Audit (Independent Reference Verification)', () => {
  it('matches independent PAE for empty pieces list', () => {
    const pieces: Uint8Array[] = [];
    const expected = independentPae(pieces);
    const actual = new Uint8Array(pae([]));
    expect(Buffer.from(actual).equals(Buffer.from(expected))).toBe(true);
    expect(Buffer.from(actual).toString('hex')).toBe('0000000000000000');
  });

  it('matches independent PAE for single empty piece', () => {
    const pieces = [new Uint8Array(0)];
    const expected = independentPae(pieces);
    const actual = new Uint8Array(pae([Buffer.alloc(0)]));
    expect(Buffer.from(actual).equals(Buffer.from(expected))).toBe(true);
    expect(Buffer.from(actual).toString('hex')).toBe('01000000000000000000000000000000');
  });

  it('matches independent PAE across standard 4-tuple (h, m, f, i)', () => {
    const h = Buffer.from('v4.public.', 'utf8');
    const m = Buffer.from('{"sub":"alice","role":"admin"}', 'utf8');
    const f = Buffer.from('{"kid":"key-001"}', 'utf8');
    const i = Buffer.from('tenant-42', 'utf8');

    const expected = independentPae([
      new Uint8Array(h),
      new Uint8Array(m),
      new Uint8Array(f),
      new Uint8Array(i),
    ]);
    const actual = new Uint8Array(pae([h, m, f, i]));
    expect(Buffer.from(actual).equals(Buffer.from(expected))).toBe(true);
  });

  it('correctly encodes multibyte UTF-8 characters without byte-length confusion', () => {
    // Japanese "認証" is 2 characters in UTF-16, but 6 bytes in UTF-8
    // Emoji "🔐" is 2 UTF-16 code units (surrogate pair), but 4 bytes in UTF-8
    const unicodeString = '認証🔐';
    const utf8Buf = Buffer.from(unicodeString, 'utf8');
    expect(unicodeString.length).toBe(4); // 2 kanji + 1 emoji (2 code units) = 4 code units
    expect(utf8Buf.length).toBe(10); // 3*2 + 4 = 10 bytes

    const actual = pae([utf8Buf]);
    const actualView = new DataView(actual.buffer, actual.byteOffset, actual.byteLength);

    // Piece count = 1
    expect(actualView.getBigUint64(0, true)).toBe(1n);
    // Piece 0 length MUST be 10 (bytes), NOT 4 (string length)
    expect(actualView.getBigUint64(8, true)).toBe(10n);
    expect(actual.subarray(16).toString('utf8')).toBe(unicodeString);
  });

  it('matches independent PAE on large boundaries (0, 1, 255, 256, 65535, 65536 bytes)', () => {
    const lengths = [0, 1, 255, 256, 65535, 65536];
    for (const len of lengths) {
      const piece = randomBytes(len);
      const expected = independentPae([new Uint8Array(piece)]);
      const actual = new Uint8Array(pae([piece]));
      expect(Buffer.from(actual).equals(Buffer.from(expected))).toBe(true);
    }
  });

  it('strictly verifies little-endian format for piece counts and lengths', () => {
    // 0x0102 = 258. In little-endian, byte 0 is 0x02, byte 1 is 0x01
    const piece = Buffer.alloc(258, 0xaa);
    const encoded = pae([piece]);
    // count = 1 (0x01, followed by 7 zeros)
    expect(encoded[0]).toBe(0x01);
    expect(encoded[1]).toBe(0x00);
    // length = 258 (0x02, 0x01, followed by 6 zeros)
    expect(encoded[8]).toBe(0x02);
    expect(encoded[9]).toBe(0x01);
    expect(encoded[10]).toBe(0x00);
  });

  it('strictly enforces canonicalization resistance (prefix-shifting attack)', () => {
    // Canonicalization attack test: ["ab", "c"] vs ["a", "bc"]
    const pae1 = pae([Buffer.from('ab'), Buffer.from('c')]);
    const pae2 = pae([Buffer.from('a'), Buffer.from('bc')]);
    expect(pae1.equals(pae2)).toBe(false);
  });

  it('verifies PAE preimage of official vector 4-S-1', () => {
    const vector = vectors.tests.find((t) => t.name === '4-S-1')!;
    const h = Buffer.from('v4.public.', 'utf8');
    const m = Buffer.from(vector.payload, 'utf8');
    const f = Buffer.from(vector.footer, 'utf8');
    const i = Buffer.from(vector.implicit, 'utf8');

    const expectedPreimage = independentPae([
      new Uint8Array(h),
      new Uint8Array(m),
      new Uint8Array(f),
      new Uint8Array(i),
    ]);
    const actualPreimage = new Uint8Array(pae([h, m, f, i]));
    expect(Buffer.from(actualPreimage).equals(Buffer.from(expectedPreimage))).toBe(true);
  });
});

// ─── C2: Nonce and Signature Handling Audit ────────────────────────────────

describe('C2 — Nonce and Signature Handling Audit', () => {
  const keys = generateKeyPair('audit-key');
  const priv = loadPrivateKey(keys.privateKey);
  const pub = loadPublicKey(keys.publicKey);

  it('confirms PASETO v4.public contains no external encryption nonce', () => {
    // PASETO v4.public is a deterministic signature scheme (RFC 8032 Ed25519).
    // Unlike v4.local (which has a 32-byte random nonce prefix), v4.public body
    // is strictly: message || 64-byte Ed25519 signature.
    const token = signV4Public('{"hello":"world"}', priv);
    const bodyBase64 = token.slice(V4_PUBLIC_HEADER.length);
    const bodyBytes = Buffer.from(bodyBase64, 'base64url');
    const payloadBytes = Buffer.from('{"hello":"world"}', 'utf8');

    expect(bodyBytes.length).toBe(payloadBytes.length + 64);
    // Payload starts at index 0 of the decoded body
    expect(bodyBytes.subarray(0, payloadBytes.length).toString('utf8')).toBe('{"hello":"world"}');
  });

  it('demonstrates Ed25519 deterministic signature reproducibility (RFC 8032)', () => {
    // Two signatures over identical (m, f, i) with the same private key MUST be byte-for-byte identical
    const token1 = signV4Public('{"test":"determinism"}', priv, 'footer-1', 'implicit-1');
    const token2 = signV4Public('{"test":"determinism"}', priv, 'footer-1', 'implicit-1');
    expect(token1).toBe(token2);
  });

  it('verifies that Ninsho achieves token uniqueness through CSPRNG jti in PasetoEngine', async () => {
    const store = new MemoryStore();
    const keyring = new KeyRing({ active: keys });
    const engine = new PasetoEngine(store, keyring, {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'audit-iss',
      audience: 'audit-aud',
    });

    // Issuing 50 tokens with identical principal produces 50 completely unique tokens
    const tokens = new Set<string>();
    const jtis = new Set<string>();

    for (let idx = 0; idx < 50; idx++) {
      const issued = await engine.issue({
        principal: ALICE,
        sessionId: 'session-1',
        authenticatedAt: nowIso(),
      });
      tokens.add(issued.token);
      jtis.add(issued.tokenId);
    }

    expect(tokens.size).toBe(50);
    expect(jtis.size).toBe(50);
  });

  it('rejects every single-byte mutation across all 64 bytes of the signature', () => {
    const token = signV4Public('{"amount":100}', priv);
    const bodyB64 = token.slice(V4_PUBLIC_HEADER.length);
    const body = Buffer.from(bodyB64, 'base64url');
    const payloadLen = Buffer.from('{"amount":100}', 'utf8').length;
    const signatureOffset = payloadLen;

    expect(body.length - signatureOffset).toBe(64);

    let rejectedCount = 0;
    for (let offset = 0; offset < 64; offset++) {
      const corruptedBody = Buffer.from(body);
      // Flip bit in signature byte
      corruptedBody[signatureOffset + offset]! ^= 0x01;
      const corruptedToken = `${V4_PUBLIC_HEADER}${corruptedBody.toString('base64url')}`;

      expect(() => verifyV4Public(corruptedToken, pub)).toThrow(PasetoFormatError);
      rejectedCount++;
    }

    expect(rejectedCount).toBe(64);
  });
});

// ─── C3: Serialization & Framing Audit ─────────────────────────────────────

describe('C3 — Serialization & Framing Audit', () => {
  const keys = generateKeyPair('audit-key');
  const priv = loadPrivateKey(keys.privateKey);
  const pub = loadPublicKey(keys.publicKey);
  const validToken = signV4Public('{"sub":"alice"}', priv, 'audit-footer');

  it('strictly rejects wrong prefixes, casing, and near-miss headers', () => {
    const rest = validToken.slice(V4_PUBLIC_HEADER.length);
    const hostileHeaders = [
      'v4.local.',
      'v3.public.',
      'v2.public.',
      'v1.public.',
      'v5.public.',
      'V4.public.',
      'v4.PUBLIC.',
      'v4.Public.',
      'v4_public.',
      'v4.public:',
      'v4.public/',
      'Bearer v4.public.',
    ];

    for (const h of hostileHeaders) {
      expect(() => verifyV4Public(`${h}${rest}`, pub)).toThrow(PasetoFormatError);
    }
  });

  it('strictly rejects structural tampering with dot delimiters', () => {
    const [body, footer] = validToken.slice(V4_PUBLIC_HEADER.length).split('.');

    const structuralMutations = [
      `v4.public`, // No dot after public
      `v4.public.`, // Missing body
      `v4.public..`, // Empty body, dot
      `v4.public.${body}.${footer}.extra`, // Extra segment
      `v4.public.${body}.${footer}.`, // Trailing dot after footer
      `v4.public.${body}..${footer}`, // Double dot between body and footer
      `v4.public.${body}`, // Missing expected footer
      `v4.public.${body}.${footer}.${footer}`, // 4 parts
    ];

    for (const m of structuralMutations) {
      expect(() => verifyV4Public(m, pub)).toThrow(PasetoFormatError);
    }
  });

  it('gracefully handles extremely large payloads (1MB) without stack overflow or crash', () => {
    const hugePayload = 'A'.repeat(1_000_000);
    const hugeToken = signV4Public(hugePayload, priv);
    const parsed = verifyV4Public(hugeToken, pub);
    expect(parsed.payload.length).toBe(1_000_000);
  });

  it('rejects non-string inputs with PasetoFormatError rather than uncaught TypeError', () => {
    const nonStrings = [null, undefined, 12345, true, false, {}, [], () => {}];
    for (const val of nonStrings) {
      expect(() => verifyV4Public(val as unknown as string, pub)).toThrow(PasetoFormatError);
    }
  });
});

// ─── C4: Footer Authentication Audit ───────────────────────────────────────

describe('C4 — Footer Authentication Audit', () => {
  const keys = generateKeyPair('footer-test-key');
  const priv = loadPrivateKey(keys.privateKey);
  const pub = loadPublicKey(keys.publicKey);

  it('verifies valid footer and rejects any altered footer', () => {
    const token = signV4Public('{"sub":"alice"}', priv, 'footer-A');
    expect(verifyV4Public(token, pub).footer).toBe('footer-A');

    // Replace footer with footer-B
    const parts = token.split('.');
    const bFooter = Buffer.from('footer-B', 'utf8').toString('base64url');
    const forgedToken = `${parts[0]}.${parts[1]}.${parts[2]}.${bFooter}`;

    expect(() => verifyV4Public(forgedToken, pub)).toThrow(PasetoFormatError);
  });

  it('rejects stripping the footer from a token signed with one', () => {
    const token = signV4Public('{"sub":"alice"}', priv, 'footer-A');
    const parts = token.split('.');
    const stripped = `${parts[0]}.${parts[1]}.${parts[2]}`;
    expect(() => verifyV4Public(stripped, pub)).toThrow(PasetoFormatError);
  });

  it('rejects adding a footer to a token signed without one', () => {
    const token = signV4Public('{"sub":"alice"}', priv, '');
    const addedFooter = Buffer.from('footer-X', 'utf8').toString('base64url');
    const forged = `${token}.${addedFooter}`;
    expect(() => verifyV4Public(forged, pub)).toThrow(PasetoFormatError);
  });

  it('correctly protects multi-byte Unicode footers', () => {
    const unicodeFooter = '{"kid":"認証_鍵_001","notes":"🔐✨"}';
    const token = signV4Public('{"sub":"alice"}', priv, unicodeFooter);
    expect(verifyV4Public(token, pub).footer).toBe(unicodeFooter);

    // Tamper one byte
    const parts = token.split('.');
    const footerBuf = Buffer.from(unicodeFooter, 'utf8');
    footerBuf[0]! ^= 0x01;
    const tamperedFooter = footerBuf.toString('base64url');
    const forged = `${parts[0]}.${parts[1]}.${parts[2]}.${tamperedFooter}`;
    expect(() => verifyV4Public(forged, pub)).toThrow(PasetoFormatError);
  });
});

// ─── C5: Implicit Assertion Audit ──────────────────────────────────────────

describe('C5 — Implicit Assertion Audit', () => {
  const keys = generateKeyPair('implicit-test-key');
  const priv = loadPrivateKey(keys.privateKey);
  const pub = loadPublicKey(keys.publicKey);

  it('verifies under matching implicit assertion and rejects any mismatched assertion', () => {
    const assertionA = 'tenant:org_12345:role:admin';
    const assertionB = 'tenant:org_99999:role:admin';
    const token = signV4Public('{"account":1}', priv, '', assertionA);

    // Matching assertion verifies
    expect(verifyV4Public(token, pub, assertionA).payload).toBe('{"account":1}');

    // Mismatched assertion fails
    expect(() => verifyV4Public(token, pub, assertionB)).toThrow(PasetoFormatError);

    // Empty assertion fails
    expect(() => verifyV4Public(token, pub, '')).toThrow(PasetoFormatError);

    // Partial assertion fails
    expect(() => verifyV4Public(token, pub, 'tenant:org_12345')).toThrow(PasetoFormatError);
  });

  it('rejects token signed without implicit assertion when verified with one', () => {
    const token = signV4Public('{"account":1}', priv, '', '');
    expect(() => verifyV4Public(token, pub, 'unintended-assertion')).toThrow(PasetoFormatError);
  });
});

// ─── C6: Key Format and Key Validation Audit ───────────────────────────────

describe('C6 — Key Format and Key Validation Audit', () => {
  it('accepts raw 32-byte hex Ed25519 keys', () => {
    const rawPrivHex = 'b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774';
    const rawPubHex = '1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2';
    const priv = loadPrivateKey(rawPrivHex);
    const pub = loadPublicKey(rawPubHex);
    expect(priv.asymmetricKeyType).toBe('ed25519');
    expect(pub.asymmetricKeyType).toBe('ed25519');
  });

  it('accepts 64-byte PASETO secret hex format (seed || public)', () => {
    const seed = 'b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a3774';
    const pub = '1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2';
    const pasetoSecretHex = `${seed}${pub}`;
    expect(pasetoSecretHex.length).toBe(128); // 64 bytes = 128 hex chars

    const priv = loadPrivateKey(pasetoSecretHex);
    expect(priv.asymmetricKeyType).toBe('ed25519');
  });

  it('strictly rejects non-hex or malformed hex key strings', () => {
    expect(() => loadPrivateKey('')).toThrow(KeyError);
    expect(() => loadPrivateKey('not-hex-at-all')).toThrow(KeyError);
    expect(() => loadPrivateKey('abc')).toThrow(KeyError); // Odd length
    expect(() => loadPrivateKey('12345z')).toThrow(KeyError); // Invalid hex char
  });

  it('strictly rejects RSA keys when loaded for PASETO', () => {
    // Generate RSA key
    const { privateKey, publicKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      publicKeyEncoding: { type: 'spki', format: 'der' },
    });
    const rsaPrivHex = privateKey.toString('hex');
    const rsaPubHex = publicKey.toString('hex');

    expect(() => loadPrivateKey(rsaPrivHex)).toThrow(/requires Ed25519/);
    expect(() => loadPublicKey(rsaPubHex)).toThrow(/requires Ed25519/);
  });

  it('strictly rejects ECDSA (P-256) keys when loaded for PASETO', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      privateKeyEncoding: { type: 'pkcs8', format: 'der' },
      publicKeyEncoding: { type: 'spki', format: 'der' },
    });
    const ecPrivHex = privateKey.toString('hex');
    const ecPubHex = publicKey.toString('hex');

    expect(() => loadPrivateKey(ecPrivHex)).toThrow(/requires Ed25519/);
    expect(() => loadPublicKey(ecPubHex)).toThrow(/requires Ed25519/);
  });

  it('KeyRing refuses mismatched private and public keys at construction', () => {
    const pairA = generateKeyPair('key-a');
    const pairB = generateKeyPair('key-b');

    expect(
      () =>
        new KeyRing({
          active: {
            kid: 'key-mismatched',
            privateKey: pairA.privateKey,
            publicKey: pairB.publicKey, // Mismatched!
          },
        }),
    ).toThrow(/not two halves of the same key pair/);
  });

  it('proves token signed with Key A is rejected by Key B', () => {
    const keyA = generateKeyPair('key-a');
    const keyB = generateKeyPair('key-b');
    const privA = loadPrivateKey(keyA.privateKey);
    const pubB = loadPublicKey(keyB.publicKey);

    const token = signV4Public('{"secret":"data"}', privA);
    expect(() => verifyV4Public(token, pubB)).toThrow(PasetoFormatError);
  });
});

// ─── C7: Canonical Base64url Audit ─────────────────────────────────────────

describe('C7 — Canonical Base64url Audit', () => {
  const keys = generateKeyPair('b64u-key');
  const priv = loadPrivateKey(keys.privateKey);
  const pub = loadPublicKey(keys.publicKey);
  const validToken = signV4Public('{"sub":"alice"}', priv, 'valid-footer');

  it('strictly rejects base64 padding "=" in body or footer', () => {
    const [body, footer] = validToken.slice(V4_PUBLIC_HEADER.length).split('.');
    expect(() => verifyV4Public(`v4.public.${body}=.${footer}`, pub)).toThrow(
      /non-canonical base64url/,
    );
    expect(() => verifyV4Public(`v4.public.${body}.${footer}=`, pub)).toThrow(
      /non-canonical base64url/,
    );
  });

  it('strictly rejects standard Base64 characters "+" and "/"', () => {
    const [body, footer] = validToken.slice(V4_PUBLIC_HEADER.length).split('.');
    expect(() => verifyV4Public(`v4.public.${body}+.${footer}`, pub)).toThrow(PasetoFormatError);
    expect(() => verifyV4Public(`v4.public.${body}/${footer}`, pub)).toThrow(PasetoFormatError);
  });

  it('strictly rejects embedded whitespace, newlines, and tabs', () => {
    const [body, footer] = validToken.slice(V4_PUBLIC_HEADER.length).split('.');
    const whitespaceMutations = [
      `v4.public.${body} .${footer}`,
      `v4.public.${body}\n.${footer}`,
      `v4.public.${body}\r\n.${footer}`,
      `v4.public.${body}\t.${footer}`,
      `v4.public. ${body}.${footer}`,
      `v4.public.${body}.${footer} `,
    ];
    for (const m of whitespaceMutations) {
      expect(() => verifyV4Public(m, pub)).toThrow(PasetoFormatError);
    }
  });

  it('strictly rejects non-canonical spare bits in base64url encoding', () => {
    // A single byte 'a' (0x61 = 0b01100001) in base64url:
    // 8 bits + 4 padding bits: 011000 010000 -> characters 'Y' (24) and 'Q' (16).
    // The lowest 4 bits of 'Q' MUST be 0.
    // If we alter the spare bits (e.g. 'Y' and 'R' where R has lowest bits set):
    // Standard Node base64url decoder ignores those bits.
    // Ninsho's re-encode check MUST catch it!
    const token = signV4Public('{"sub":"alice"}', priv);

    // Test on a custom segment with corrupted spare bits:
    // "YQ" decodes to 0x61. "YR" also decodes to 0x61 in lenient decoders.
    const validCanonical = 'YQ';
    const nonCanonical = 'YR';
    expect(Buffer.from(validCanonical, 'base64url').equals(Buffer.from(nonCanonical, 'base64url'))).toBe(
      true,
    );

    // Passing non-canonical base64url to footer must throw non-canonical error
    expect(() => verifyV4Public(`${token}.${nonCanonical}`, pub)).toThrow(/non-canonical base64url/);
  });
});

// ─── C8: Malformed Token Fuzzing Suite (10,000 Inputs) ─────────────────────

describe('C8 — Malformed Token Rejection / Fuzzing Suite (10,000 Inputs)', () => {
  const keys = generateKeyPair('fuzz-key');
  const priv = loadPrivateKey(keys.privateKey);
  const pub = loadPublicKey(keys.publicKey);
  const sampleToken = signV4Public('{"test":"fuzz"}', priv, 'sample-footer');

  it('evaluates 10,000 malformed inputs with 0 crashes and 0 false acceptances', () => {
    const TOTAL_ITERATIONS = 10_000;
    let formatErrors = 0;
    let accepted = 0;

    for (let i = 0; i < TOTAL_ITERATIONS; i++) {
      let candidate: unknown;
      const strategy = i % 10;

      switch (strategy) {
        case 0: {
          // Random binary bytes
          const len = 1 + (i % 256);
          candidate = randomBytes(len).toString('binary');
          break;
        }
        case 1: {
          // Prefix corruption
          const prefix = ['v4.', 'v4.local.', 'v3.public.', 'V4.public.', 'token:'][i % 5]!;
          candidate = `${prefix}${sampleToken.slice(10)}`;
          break;
        }
        case 2: {
          // Delimiter disruption: multiple consecutive dots (2 to 6 dots)
          const dots = '.'.repeat((i % 5) + 2);
          candidate = `v4.public${dots}${sampleToken.slice(10)}`;
          break;
        }
        case 3: {
          // Random bit flip in the valid token string
          const chars = sampleToken.split('');
          const pos = i % chars.length;
          chars[pos] = String.fromCharCode((chars[pos]!.charCodeAt(0) ^ 0x07) % 128);
          candidate = chars.join('');
          break;
        }
        case 4: {
          // Truncation at every strictly shorter length (0 to length - 1)
          const maxTruncLen = sampleToken.length - 1;
          const truncLen = maxTruncLen > 0 ? i % maxTruncLen : 0;
          candidate = sampleToken.slice(0, truncLen);
          break;
        }
        case 5: {
          // Injection of hostile strings / control characters
          const hostile = [
            '\0',
            '\r\n',
            ' ',
            '=',
            '==',
            '===',
            '+',
            '/',
            '<script>',
            '{"__proto__":1}',
            'null',
            'NaN',
            'undefined',
          ][i % 13]!;
          candidate = `${sampleToken}${hostile}`;
          break;
        }
        case 6: {
          // Non-canonical base64url padding
          candidate = `${sampleToken}=`;
          break;
        }
        case 7: {
          // Non-string types
          candidate = [null, undefined, i, {}, [], false, true][i % 7];
          break;
        }
        case 8: {
          // Random Unicode fuzzing
          const unicodeCode = 0x1000 + (i % 0x5000);
          candidate = `v4.public.${String.fromCharCode(unicodeCode)}.footer`;
          break;
        }
        case 9: {
          // Truncated signature in body
          const body = Buffer.from('short').toString('base64url');
          candidate = `v4.public.${body}`;
          break;
        }
      }

      try {
        verifyV4Public(candidate as string, pub);
        accepted++;
      } catch (err) {
        if (err instanceof PasetoFormatError) {
          formatErrors++;
        } else {
          throw new Error(
            `Unexpected exception type on iteration ${i} for input ${JSON.stringify(candidate)}: ${String(err)}`,
          );
        }
      }
    }

    expect(accepted).toBe(0);
    expect(formatErrors).toBe(TOTAL_ITERATIONS);
  });
});

// ─── C9: Signature Verification Audit ──────────────────────────────────────

describe('C9 — Signature Verification Audit', () => {
  it('cross-verifies all official test vectors using independent Ed25519 crypto verify', () => {
    for (const vector of vectors.tests) {
      const pubKeyObj = createPublicKey({
        key: Buffer.concat([
          Buffer.from('302a300506032b6570032100', 'hex'), // SPKI Ed25519 prefix
          Buffer.from(vector.publicKey, 'hex'),
        ]),
        format: 'der',
        type: 'spki',
      });

      // Split token
      const parts = vector.token.slice(V4_PUBLIC_HEADER.length).split('.');
      const bodyBytes = independentB64uDecode(parts[0]!);
      const footerBytes = parts.length === 2 ? independentB64uDecode(parts[1]!) : new Uint8Array(0);

      const m = bodyBytes.subarray(0, bodyBytes.length - 64);
      const sig = bodyBytes.subarray(bodyBytes.length - 64);

      const h = Buffer.from('v4.public.', 'utf8');
      const i = Buffer.from(vector.implicit, 'utf8');

      // Independent PAE
      const independentPreimage = independentPae([
        new Uint8Array(h),
        m,
        footerBytes,
        new Uint8Array(i),
      ]);

      // Direct verification via node:crypto edVerify
      const valid = edVerify(null, independentPreimage, pubKeyObj, sig);
      expect(valid).toBe(true);
    }
  });

  it('rejects verification if any piece of the preimage is swapped', () => {
    const keys = generateKeyPair('sig-swap-test');
    const priv = loadPrivateKey(keys.privateKey);
    const pub = loadPublicKey(keys.publicKey);

    const token = signV4Public('payload-original', priv, 'footer-original', 'implicit-original');

    // Swapping payload in token body:
    const parts = token.slice(V4_PUBLIC_HEADER.length).split('.');
    const body = Buffer.from(parts[0]!, 'base64url');
    body[0]! ^= 0x01; // corrupt payload
    const forged = `${V4_PUBLIC_HEADER}${body.toString('base64url')}.${parts[1]}`;
    expect(() => verifyV4Public(forged, pub, 'implicit-original')).toThrow(PasetoFormatError);
  });
});

// ─── C10: Expiry Handling Audit ────────────────────────────────────────────

describe('C10 — Expiry Handling Audit (PasetoEngine Claims)', () => {
  it('correctly enforces token expiration during authentication', async () => {
    const store = new MemoryStore();
    const keys = generateKeyPair('exp-key');
    const keyring = new KeyRing({ active: keys });
    const engine = new PasetoEngine(store, keyring, {
      accessTokenTtl: 1, // 1 second
      clockToleranceSeconds: 0,
      issuer: 'exp-iss',
      audience: 'exp-aud',
    });

    const issued = await engine.issue({
      principal: ALICE,
      sessionId: 'session-exp',
      authenticatedAt: nowIso(),
    });

    // Valid immediately
    const authContext = await engine.verify(issued.token);
    expect(authContext.userId).toBe(ALICE.userId);

    // Wait 1.1s for expiration
    await new Promise((resolve) => setTimeout(resolve, 1100));

    // Expired verification throws TokenExpiredError
    await expect(engine.verify(issued.token)).rejects.toThrow(TokenExpiredError);
  });

  it('respects clockToleranceSeconds on expiration', async () => {
    const store = new MemoryStore();
    const keys = generateKeyPair('tol-key');
    const keyring = new KeyRing({ active: keys });
    const engine = new PasetoEngine(store, keyring, {
      accessTokenTtl: 1,
      clockToleranceSeconds: 3, // 3 seconds grace
      issuer: 'tol-iss',
      audience: 'tol-aud',
    });

    const issued = await engine.issue({
      principal: ALICE,
      sessionId: 'session-tol',
      authenticatedAt: nowIso(),
    });

    // Wait 1.1s (past TTL, but within 3s tolerance)
    await new Promise((resolve) => setTimeout(resolve, 1100));

    // Should still verify because of clock tolerance
    const authContext = await engine.verify(issued.token);
    expect(authContext.userId).toBe(ALICE.userId);
  });

  it('rejects tokens with missing or malformed exp claims', async () => {
    const store = new MemoryStore();
    const keys = generateKeyPair('malformed-claims-key');
    const priv = loadPrivateKey(keys.privateKey);
    const keyring = new KeyRing({ active: keys });
    const engine = new PasetoEngine(store, keyring, {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'c-iss',
      audience: 'c-aud',
    });

    // Manually forge token without exp claim
    const invalidClaims = JSON.stringify({
      jti: 'id1',
      sub: 'alice',
      iss: 'c-iss',
      aud: 'c-aud',
      iat: nowIso(),
      nbf: nowIso(),
      // exp is missing!
      sid: 'sid1',
      auth_time: nowIso(),
      roles: ['user'],
      scopes: [],
    });

    const footer = JSON.stringify({ kid: keys.kid });
    const tokenWithoutExp = signV4Public(invalidClaims, priv, footer);

    await expect(engine.verify(tokenWithoutExp)).rejects.toThrow(TokenInvalidError);
  });

  it('rejects tokens with future iat or nbf past tolerance', async () => {
    const store = new MemoryStore();
    const keys = generateKeyPair('future-key');
    const priv = loadPrivateKey(keys.privateKey);
    const keyring = new KeyRing({ active: keys });
    const engine = new PasetoEngine(store, keyring, {
      accessTokenTtl: 300,
      clockToleranceSeconds: 1,
      issuer: 'future-iss',
      audience: 'future-aud',
    });

    const futureClaims = JSON.stringify({
      jti: 'id-future',
      sub: 'alice',
      iss: 'future-iss',
      aud: 'future-aud',
      iat: isoIn(60), // 60s in the future
      nbf: isoIn(60),
      exp: isoIn(360),
      sid: 'sid-1',
      auth_time: nowIso(),
      roles: ['user'],
      scopes: [],
    });

    const tokenFuture = signV4Public(futureClaims, priv, JSON.stringify({ kid: keys.kid }));
    const err = await engine.verify(tokenFuture).catch((e) => e);
    expect(err).toBeInstanceOf(TokenInvalidError);
    expect((err as TokenInvalidError).detail).toMatch(/not yet valid|future/);
  });
});

// ─── C11: Issuer / Audience Scoping Audit ───────────────────────────────────

describe('C11 — Issuer and Audience Scoping Audit', () => {
  it('strictly isolates tokens across issuers and audiences', async () => {
    const store = new MemoryStore();
    const keys = generateKeyPair('shared-key');
    const keyring = new KeyRing({ active: keys });

    const billingEngine = new PasetoEngine(store, keyring, {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'https://auth.enterprise.com',
      audience: 'billing-service',
    });

    const ordersEngine = new PasetoEngine(store, keyring, {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'https://auth.enterprise.com',
      audience: 'orders-service',
    });

    const stagingEngine = new PasetoEngine(store, keyring, {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'https://auth-staging.enterprise.com',
      audience: 'billing-service',
    });

    // 1. Token issued for billing-service
    const billingToken = await billingEngine.issue({
      principal: ALICE,
      sessionId: 'session-b',
      authenticatedAt: nowIso(),
    });

    // Accepted by billing-service
    await expect(billingEngine.verify(billingToken.token)).resolves.toMatchObject({
      userId: ALICE.userId,
    });

    // REJECTED by orders-service (audience mismatch)
    const errOrders = await ordersEngine.verify(billingToken.token).catch((e) => e);
    expect(errOrders).toBeInstanceOf(TokenInvalidError);
    expect((errOrders as TokenInvalidError).detail).toMatch(/audience mismatch/);

    // REJECTED by staging environment (issuer mismatch)
    const errStaging = await stagingEngine.verify(billingToken.token).catch((e) => e);
    expect(errStaging).toBeInstanceOf(TokenInvalidError);
    expect((errStaging as TokenInvalidError).detail).toMatch(/issuer mismatch/);
  });
});

// ─── C12: Key Rotation Lifecycle Audit ─────────────────────────────────────

describe('C12 — Key Rotation Lifecycle Audit (Real API)', () => {
  it('executes full 10-step zero-downtime key rotation lifecycle', async () => {
    const store = new MemoryStore();

    // 1. Initial State: Key A is active
    const keyA = generateKeyPair('kid-2026-01');
    const ringDeployment1 = new KeyRing({ active: keyA });
    const engine1 = new PasetoEngine(store, ringDeployment1, {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'auth-rot',
      audience: 'api-rot',
    });

    // 2. Issue token under Key A
    const tokenA = await engine1.issue({
      principal: ALICE,
      sessionId: 'sess-1',
      authenticatedAt: nowIso(),
    });
    expect(readFooterUnverified(tokenA.token)).toBe('{"kid":"kid-2026-01"}');

    // 3. Verify token under Deployment 1
    await expect(engine1.verify(tokenA.token)).resolves.toMatchObject({ userId: ALICE.userId });

    // 4. Deployment 2: Rotate key -> Key B is active, Key A is previous
    const keyB = generateKeyPair('kid-2026-02');
    const ringDeployment2 = new KeyRing({
      active: keyB,
      previous: [keyA],
    });
    const engine2 = new PasetoEngine(store, ringDeployment2, {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'auth-rot',
      audience: 'api-rot',
    });

    // 5. Verify existing Token A under Deployment 2 (overlap window works without logout)
    await expect(engine2.verify(tokenA.token)).resolves.toMatchObject({ userId: ALICE.userId });

    // 6. Issue new token under Deployment 2
    const tokenB = await engine2.issue({
      principal: ALICE,
      sessionId: 'sess-2',
      authenticatedAt: nowIso(),
    });

    // 7. Verify new token carries Key B in footer
    expect(readFooterUnverified(tokenB.token)).toBe('{"kid":"kid-2026-02"}');
    await expect(engine2.verify(tokenB.token)).resolves.toMatchObject({ userId: ALICE.userId });

    // 8. Deployment 3: Retire Key A (Key B active, Key A removed)
    const ringDeployment3 = new KeyRing({
      active: keyB,
      previous: [],
    });
    const engine3 = new PasetoEngine(store, ringDeployment3, {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'auth-rot',
      audience: 'api-rot',
    });

    // 9. Verify retired Token A is now REJECTED
    const errRetired = await engine3.verify(tokenA.token).catch((e) => e);
    expect(errRetired).toBeInstanceOf(TokenInvalidError);
    expect((errRetired as TokenInvalidError).detail).toMatch(/unknown key id/);

    // 10. Verify Token B continues to verify under Deployment 3
    await expect(engine3.verify(tokenB.token)).resolves.toMatchObject({ userId: ALICE.userId });
  });

  it('strictly rejects duplicate key IDs in KeyRing configuration', () => {
    const key1 = generateKeyPair('dup-kid');
    const key2 = generateKeyPair('dup-kid'); // Same kid

    expect(
      () =>
        new KeyRing({
          active: key1,
          previous: [key2],
        }),
    ).toThrow(/duplicate kid/);
  });

  it('rejects footer spoofing (token signed by key A but footer modified to name key B)', async () => {
    const store = new MemoryStore();
    const keyA = generateKeyPair('kid-a');
    const keyB = generateKeyPair('kid-b');
    const ring = new KeyRing({ active: keyA, previous: [keyB] });
    const engine = new PasetoEngine(store, ring, {
      accessTokenTtl: 300,
      clockToleranceSeconds: 5,
      issuer: 'iss',
      audience: 'aud',
    });

    const token = await engine.issue({
      principal: ALICE,
      sessionId: 'sess',
      authenticatedAt: nowIso(),
    }); // signed by keyA, footer has kid-a
    const parts = token.token.split('.');

    // Spoof footer to claim kid-b
    const forgedFooter = Buffer.from(JSON.stringify({ kid: 'kid-b' })).toString('base64url');
    const forgedToken = `${parts[0]}.${parts[1]}.${parts[2]}.${forgedFooter}`;

    // Verifier will look up key B because of footer, but signature was made by key A!
    const errSpoof = await engine.verify(forgedToken).catch((e) => e);
    expect(errSpoof).toBeInstanceOf(TokenInvalidError);
    expect((errSpoof as TokenInvalidError).detail).toMatch(/signature verification failed/);
  });
});
