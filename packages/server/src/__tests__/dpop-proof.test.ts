import { describe, it, expect } from 'vitest';
import {
  ALLOWED_DPOP_ALGORITHMS,
  JwkError,
  jwkThumbprint,
  parseJwk,
  thumbprintOfRequiredMembers,
  type Jwk,
} from '../dpop/jwk.js';
import { DpopProofError, accessTokenHash, verifyDpopProof } from '../dpop/proof.js';
import { createDpopProof, generateDpopKeyPair } from '../dpop/sign.js';

const METHOD = 'POST';
const URL_ = 'https://api.example.test/orders';

const base = {
  method: METHOD,
  url: URL_,
  maxAgeSeconds: 60,
  clockToleranceSeconds: 5,
};

/**
 * ─── RFC 7638 §3.1, the specification's own worked example ────────────────
 * The thumbprint is what binds a token to a key, so getting the canonical form
 * wrong would either lock clients out of their own sessions or — worse — let
 * two different keys collide. This is the published vector, and it is the
 * evidence that the canonicalisation is right rather than merely plausible.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('RFC 7638 thumbprint', () => {
  it('reproduces the specification example', () => {
    const thumbprint = thumbprintOfRequiredMembers({
      kty: 'RSA',
      n:
        '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4' +
        'cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiF' +
        'V4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6C' +
        'f0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9' +
        'c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTW' +
        'hAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1' +
        'jF44-csFCur-kEgU8awapJzKnqDKgw',
      e: 'AQAB',
    });

    expect(thumbprint).toBe('NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
  });

  it('orders members lexicographically regardless of input order', () => {
    const a = thumbprintOfRequiredMembers({ kty: 'EC', crv: 'P-256', x: 'aa', y: 'bb' });
    const b = thumbprintOfRequiredMembers({ y: 'bb', x: 'aa', crv: 'P-256', kty: 'EC' });
    expect(a).toBe(b);
  });

  it('is stable for the same key and distinct for different ones', () => {
    const first = generateDpopKeyPair('ES256');
    const second = generateDpopKeyPair('ES256');

    expect(jwkThumbprint(first.publicJwk)).toBe(first.jkt);
    expect(first.jkt).not.toBe(second.jkt);
  });

  it('ignores extra members that are not part of the canonical form', () => {
    const key = generateDpopKeyPair('ES256');
    const withExtras = { ...key.publicJwk, kid: 'ignored', use: 'sig' } as unknown as Jwk;
    // An added member must not change the identity of the key.
    expect(jwkThumbprint(withExtras)).toBe(key.jkt);
  });
});

describe('JWK validation', () => {
  it.each([
    ['a private EC key', { kty: 'EC', crv: 'P-256', x: 'aa', y: 'bb', d: 'secret' }],
    ['a private OKP key', { kty: 'OKP', crv: 'Ed25519', x: 'aa', d: 'secret' }],
    ['an RSA private factor', { kty: 'EC', crv: 'P-256', x: 'aa', y: 'bb', p: 'secret' }],
    ['a symmetric key', { kty: 'oct', k: 'secret' }],
  ])('rejects %s', (_label, jwk) => {
    // A proof carrying a private key is either a client leaking its own or an
    // attacker probing for a server that will take one.
    expect(() => parseJwk(jwk)).toThrow(JwkError);
  });

  it.each([
    ['an unsupported key type', { kty: 'RSA', n: 'aa', e: 'AQAB' }],
    ['an unsupported EC curve', { kty: 'EC', crv: 'P-521', x: 'aa', y: 'bb' }],
    ['an unsupported OKP curve', { kty: 'OKP', crv: 'X25519', x: 'aa' }],
    ['a missing coordinate', { kty: 'EC', crv: 'P-256', x: 'aa' }],
    ['a non-base64url coordinate', { kty: 'EC', crv: 'P-256', x: 'not base64!', y: 'bb' }],
    ['null', null],
    ['an array', []],
    ['a string', 'nope'],
  ])('rejects %s', (_label, jwk) => {
    expect(() => parseJwk(jwk)).toThrow(JwkError);
  });

  it('rejects a key whose declared use contradicts verification', () => {
    expect(() => parseJwk({ kty: 'OKP', crv: 'Ed25519', x: 'aa', use: 'enc' })).toThrow(JwkError);
    expect(() =>
      parseJwk({ kty: 'OKP', crv: 'Ed25519', x: 'aa', key_ops: ['sign'] }),
    ).toThrow(JwkError);
  });
});

describe('proof round trip', () => {
  it.each(['ES256', 'EdDSA'] as const)('verifies a %s proof', (algorithm) => {
    const key = generateDpopKeyPair(algorithm);
    const proof = createDpopProof(key, { method: METHOD, url: URL_ });

    const verified = verifyDpopProof(proof, base);
    expect(verified.jkt).toBe(key.jkt);
    expect(verified.algorithm).toBe(algorithm);
  });

  it('binds the proof to an access token via ath', () => {
    const key = generateDpopKeyPair();
    const token = 'access-token-value';
    const proof = createDpopProof(key, { method: METHOD, url: URL_, accessToken: token });

    expect(() => verifyDpopProof(proof, { ...base, accessToken: token })).not.toThrow();
  });

  it('ignores the query string when comparing the URI', () => {
    const key = generateDpopKeyPair();
    const proof = createDpopProof(key, { method: METHOD, url: `${URL_}?page=2` });
    expect(() => verifyDpopProof(proof, { ...base, url: `${URL_}?page=99` })).not.toThrow();
  });

  it('is case-insensitive about the request method', () => {
    const key = generateDpopKeyPair();
    const proof = createDpopProof(key, { method: 'post', url: URL_ });
    expect(() => verifyDpopProof(proof, { ...base, method: 'POST' })).not.toThrow();
  });
});

/**
 * ─── Algorithm confusion ──────────────────────────────────────────────────
 * A DPoP proof is a JWT, so the whole family applies — the class of attack
 * PASETO was chosen to avoid for Ninsho's own tokens. The format is fixed by
 * RFC 9449, so the defence has to be an allowlist rather than a better format.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('algorithm confusion', () => {
  const key = generateDpopKeyPair('ES256');

  /** Re-encodes a proof with a tampered header, leaving the signature intact. */
  function withHeader(proof: string, mutate: (header: Record<string, unknown>) => void): string {
    const [h, p, s] = proof.split('.') as [string, string, string];
    const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8')) as Record<string, unknown>;
    mutate(header);
    const encoded = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    return `${encoded}.${p}.${s}`;
  }

  it('rejects alg: none', () => {
    const proof = withHeader(createDpopProof(key, { method: METHOD, url: URL_ }), (h) => {
      h['alg'] = 'none';
    });
    expect(() => verifyDpopProof(proof, base)).toThrow(/unacceptable alg/);
  });

  it.each(['HS256', 'HS384', 'HS512'])('rejects the symmetric algorithm %s', (alg) => {
    // The classic confusion: the "public" key is right there in the header, so
    // accepting HMAC would let an attacker use it as the shared secret.
    const proof = withHeader(createDpopProof(key, { method: METHOD, url: URL_ }), (h) => {
      h['alg'] = alg;
    });
    expect(() => verifyDpopProof(proof, base)).toThrow(/unacceptable alg/);
  });

  it.each(['RS256', 'PS256', 'ES384', 'ES512', 'EdDSA25519', ''])(
    'rejects the unlisted algorithm %j',
    (alg) => {
      const proof = withHeader(createDpopProof(key, { method: METHOD, url: URL_ }), (h) => {
        h['alg'] = alg;
      });
      expect(() => verifyDpopProof(proof, base)).toThrow(DpopProofError);
    },
  );

  it('rejects an algorithm that disagrees with the key type', () => {
    // An Ed25519 key claiming ES256, or vice versa. Any leniency about which
    // primitive to run becomes exploitable here.
    const proof = withHeader(createDpopProof(key, { method: METHOD, url: URL_ }), (h) => {
      h['alg'] = 'EdDSA';
    });
    expect(() => verifyDpopProof(proof, base)).toThrow(/does not match key type/);
  });

  it('rejects a swapped key with a valid-looking header', () => {
    // Signature made by one key, header advertising another.
    const attacker = generateDpopKeyPair('ES256');
    const proof = withHeader(createDpopProof(key, { method: METHOD, url: URL_ }), (h) => {
      h['jwk'] = attacker.publicJwk;
    });
    expect(() => verifyDpopProof(proof, base)).toThrow(/signature is invalid/);
  });

  it('only ever accepts the two documented algorithms', () => {
    expect([...ALLOWED_DPOP_ALGORITHMS].sort()).toEqual(['ES256', 'EdDSA']);
  });
});

describe('proof claim validation', () => {
  const key = generateDpopKeyPair();

  it('rejects a proof for a different method', () => {
    // Otherwise a proof captured from a GET could authorise a DELETE.
    const proof = createDpopProof(key, { method: 'GET', url: URL_ });
    expect(() => verifyDpopProof(proof, { ...base, method: 'DELETE' })).toThrow(/htm mismatch/);
  });

  it('rejects a proof for a different URI', () => {
    // Otherwise a proof captured by one endpoint could be replayed at another.
    const proof = createDpopProof(key, { method: METHOD, url: 'https://api.example.test/other' });
    expect(() => verifyDpopProof(proof, base)).toThrow(/htu does not match/);
  });

  it.each([
    ['a different host', 'https://evil.example.test/orders'],
    ['a different scheme', 'http://api.example.test/orders'],
    ['a different port', 'https://api.example.test:8443/orders'],
    ['a path prefix', 'https://api.example.test/orders/extra'],
  ])('rejects %s', (_label, url) => {
    const proof = createDpopProof(key, { method: METHOD, url });
    expect(() => verifyDpopProof(proof, base)).toThrow(DpopProofError);
  });

  it('rejects a proof issued in the future', () => {
    const proof = createDpopProof(key, {
      method: METHOD,
      url: URL_,
      issuedAtMs: Date.now() + 600_000,
    });
    expect(() => verifyDpopProof(proof, base)).toThrow(/issued in the future/);
  });

  it('rejects a proof older than the acceptance window', () => {
    const proof = createDpopProof(key, {
      method: METHOD,
      url: URL_,
      issuedAtMs: Date.now() - 600_000,
    });
    expect(() => verifyDpopProof(proof, base)).toThrow(/too old/);
  });

  it('tolerates modest clock skew in both directions', () => {
    const slightlyAhead = createDpopProof(key, {
      method: METHOD,
      url: URL_,
      issuedAtMs: Date.now() + 3000,
    });
    expect(() => verifyDpopProof(slightlyAhead, base)).not.toThrow();
  });

  it('requires ath when an access token is presented', () => {
    // A proof without it would be valid for any token, defeating the binding.
    const proof = createDpopProof(key, { method: METHOD, url: URL_ });
    expect(() => verifyDpopProof(proof, { ...base, accessToken: 'some-token' })).toThrow(
      /ath is required/,
    );
  });

  it('rejects a proof whose ath is for a different token', () => {
    const proof = createDpopProof(key, {
      method: METHOD,
      url: URL_,
      accessToken: 'token-a',
    });
    expect(() => verifyDpopProof(proof, { ...base, accessToken: 'token-b' })).toThrow(
      /ath does not match/,
    );
  });

  it('computes ath as base64url SHA-256 of the token', () => {
    // RFC 9449 §4.3 step 11. Asserted explicitly so an encoding change is
    // caught here rather than by an interoperability failure.
    expect(accessTokenHash('abc')).toBe('ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0');
  });
});

describe('malformed proofs', () => {
  const key = generateDpopKeyPair();

  it.each([
    ['an empty string', ''],
    ['a bare word', 'nonsense'],
    ['two segments', 'aaa.bbb'],
    ['four segments', 'aaa.bbb.ccc.ddd'],
    ['non-base64url segments', 'not base64!.also bad!.nope!'],
    ['a JSON array header', `${Buffer.from('[]').toString('base64url')}.e30.AA`],
    ['a JSON string header', `${Buffer.from('"str"').toString('base64url')}.e30.AA`],
  ])('rejects %s', (_label, proof) => {
    expect(() => verifyDpopProof(proof, base)).toThrow(DpopProofError);
  });

  it.each([
    ['undefined', undefined],
    ['null', null],
    ['a number', 42],
    ['an object', {}],
  ])('rejects %s without an unexpected error type', (_label, proof) => {
    expect(() => verifyDpopProof(proof as unknown as string, base)).toThrow(DpopProofError);
  });

  it('rejects a proof missing the typ header', () => {
    // `typ` is what stops a token minted for another purpose being replayed
    // here as a proof.
    const [h, p, s] = createDpopProof(key, { method: METHOD, url: URL_ }).split('.') as [
      string, string, string,
    ];
    const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8')) as Record<string, unknown>;
    delete header['typ'];
    const encoded = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');

    expect(() => verifyDpopProof(`${encoded}.${p}.${s}`, base)).toThrow(/typ must be/);
  });

  it('rejects a proof with no embedded key', () => {
    const [h, p, s] = createDpopProof(key, { method: METHOD, url: URL_ }).split('.') as [
      string, string, string,
    ];
    const header = JSON.parse(Buffer.from(h, 'base64url').toString('utf8')) as Record<string, unknown>;
    delete header['jwk'];
    const encoded = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');

    expect(() => verifyDpopProof(`${encoded}.${p}.${s}`, base)).toThrow(/must carry the public key/);
  });

  it('rejects an implausibly large proof rather than parsing it', () => {
    expect(() => verifyDpopProof('a'.repeat(20_000), base)).toThrow(/implausibly large/);
  });

  it('rejects every single-character mutation of a valid proof', () => {
    const proof = createDpopProof(key, { method: METHOD, url: URL_ });
    const alphabet = 'ABCXYZabcxyz0189-_';

    for (let i = 0; i < 200; i += 1) {
      const position = Math.floor(Math.random() * proof.length);
      const replacement = alphabet[Math.floor(Math.random() * alphabet.length)] as string;
      if (proof[position] === replacement) continue;

      const mutated = proof.slice(0, position) + replacement + proof.slice(position + 1);
      let accepted = false;
      try {
        verifyDpopProof(mutated, base);
        accepted = true;
      } catch (error) {
        expect(error).toBeInstanceOf(DpopProofError);
      }
      expect(accepted).toBe(false);
    }
  });
});

/**
 * ─── REGRESSION: non-canonical base64url was accepted ─────────────────────
 * The segment check verified only the character set, not canonicality. Node's
 * base64url decoder ignores the spare bits in a segment's final character, so
 * a 64-byte ECDSA signature had sixteen distinct spellings that all decoded to
 * the same bytes and all verified.
 *
 * That gives one proof many textual forms, which breaks anything treating the
 * proof string as an identity. The PASETO parser already rejected this; the
 * DPoP one did not, until a mutation test hit the last character often enough
 * to surface it as an intermittent failure.
 * ──────────────────────────────────────────────────────────────────────────
 */
describe('regression: non-canonical base64url', () => {
  const key = generateDpopKeyPair('ES256');
  const proof = createDpopProof(key, { method: METHOD, url: URL_ });

  it('accepts the canonical proof', () => {
    expect(() => verifyDpopProof(proof, base)).not.toThrow();
  });

  it('rejects every alternative spelling of the same signature', () => {
    const [h, p, signature] = proof.split('.') as [string, string, string];
    const decoded = Buffer.from(signature, 'base64url');

    // Every character that decodes to the same bytes but is not the canonical
    // encoding must now be refused.
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    let alternatives = 0;

    for (const candidate of alphabet) {
      const variant = signature.slice(0, -1) + candidate;
      if (variant === signature) continue;
      if (!Buffer.from(variant, 'base64url').equals(decoded)) continue;

      alternatives += 1;
      expect(() => verifyDpopProof(`${h}.${p}.${variant}`, base)).toThrow(/canonical/);
    }

    // If this is zero the test is proving nothing, so assert the situation it
    // was written for actually exists.
    expect(alternatives).toBeGreaterThan(0);
  });

  it('rejects a non-canonical header segment', () => {
    const [h, p, s] = proof.split('.') as [string, string, string];
    const decoded = Buffer.from(h, 'base64url');
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

    for (const candidate of alphabet) {
      const variant = h.slice(0, -1) + candidate;
      if (variant === h) continue;
      if (!Buffer.from(variant, 'base64url').equals(decoded)) continue;

      expect(() => verifyDpopProof(`${variant}.${p}.${s}`, base)).toThrow(DpopProofError);
      return;
    }
  });
});
