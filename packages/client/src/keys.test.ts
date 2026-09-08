import { describe, it, expect } from 'vitest';
import {
  assembleJws,
  describeKey,
  generateDpopKey,
  jwkThumbprint,
  signProof,
  type PublicJwk,
} from './keys.js';
import { fromBase64Url, toBase64Url, encodeJson, sha256Base64Url } from './encoding.js';
import { MemoryKeyStore } from './storage.js';

/**
 * The client's key handling, on its own.
 *
 * `client.test.ts` drives these through a whole request cycle, which is where
 * the *flow* belongs. What that cannot reach is a key the library did not
 * generate — and `describeKey` is exported, and `IndexedDbKeyStore.load()`
 * calls it on whatever the database happens to hold.
 */

describe('generateDpopKey', () => {
  it('produces a key whose private half cannot be read', async () => {
    // The property the whole mechanism rests on. An XSS that can read a bearer
    // token can copy it anywhere; it cannot copy this.
    const key = await generateDpopKey();

    expect(key.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('jwk', key.privateKey)).rejects.toThrow();
    await expect(crypto.subtle.exportKey('pkcs8', key.privateKey)).rejects.toThrow();
  });

  it('produces a P-256 signing key and nothing else', async () => {
    const key = await generateDpopKey();

    expect(key.privateKey.algorithm).toMatchObject({ name: 'ECDSA', namedCurve: 'P-256' });
    expect(key.privateKey.usages).toEqual(['sign']);
    expect(key.publicJwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
  });

  it('gives every key a distinct thumbprint', async () => {
    const seen = new Set<string>();
    for (let i = 0; i < 10; i += 1) seen.add((await generateDpopKey()).thumbprint);
    expect(seen.size).toBe(10);
  });
});

describe('describeKey', () => {
  it('describes a key the library generated', async () => {
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify'],
    );
    const described = await describeKey(pair.privateKey, pair.publicKey);

    expect(described.publicJwk.crv).toBe('P-256');
    expect(described.thumbprint).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it.each([['P-384'], ['P-521']])('refuses a %s key rather than calling it P-256', async (curve) => {
    // REGRESSION. The JWK was built with `crv: 'P-256'` hardcoded and only the
    // coordinates read from the export, so a key on another curve produced a
    // JWK that misdescribed itself — and a thumbprint computed over that lie,
    // which is the value the server binds a token to.
    //
    // It could not come from `generateDpopKey`, which always makes P-256. It
    // could come from the key store, which calls this on whatever the database
    // holds: an older version's key, another application sharing the database
    // name, or tampering.
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: curve }, false, [
      'sign',
      'verify',
    ]);

    await expect(describeKey(pair.privateKey, pair.publicKey)).rejects.toThrow(/P-256/);
  });

  it('refuses a key that is not EC at all', async () => {
    const pair = await crypto.subtle.generateKey(
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      false,
      ['sign', 'verify'],
    );

    await expect(describeKey(pair.privateKey, pair.publicKey)).rejects.toThrow();
  });

  it('refuses an extractable private key', async () => {
    // The store checks this on load; the exported function did not, so a
    // caller building a key themselves could hand over one whose bytes are
    // readable and get back something that looks like a DPoP key.
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );

    await expect(describeKey(pair.privateKey, pair.publicKey)).rejects.toThrow(/extractable/);
  });
});

describe('jwkThumbprint', () => {
  it('matches RFC 7638’s own worked example shape', async () => {
    // The canonical form is fixed: required members only, lexicographic order,
    // compact JSON. Built literally rather than by serialising an object, so
    // an extra member cannot change the result.
    const jwk: PublicJwk = { kty: 'EC', crv: 'P-256', x: 'abc', y: 'def' };
    const expected = await sha256Base64Url('{"crv":"P-256","kty":"EC","x":"abc","y":"def"}');

    expect(await jwkThumbprint(jwk)).toBe(expected);
  });

  it('changes with either coordinate', async () => {
    const base: PublicJwk = { kty: 'EC', crv: 'P-256', x: 'abc', y: 'def' };
    const differentX = await jwkThumbprint({ ...base, x: 'abd' });
    const differentY = await jwkThumbprint({ ...base, y: 'deg' });

    const original = await jwkThumbprint(base);
    expect(differentX).not.toBe(original);
    expect(differentY).not.toBe(original);
    expect(differentX).not.toBe(differentY);
  });

  it('is 43 characters of unpadded base64url', async () => {
    const key = await generateDpopKey();
    expect(key.thumbprint).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(key.thumbprint).not.toContain('=');
  });
});

describe('signProof', () => {
  it('returns a raw r‖s signature, which is what JOSE wants', async () => {
    // WebCrypto gives P1363 directly. Node's default is DER, and a client that
    // shipped DER here would produce proofs no JOSE verifier accepts.
    //
    // ─── REGRESSION: this assertion used to be probabilistic ──────────────
    // It ran once and asserted `bytes[0] !== 0x30`, reasoning that DER starts
    // with a SEQUENCE tag. But byte 0 of a raw signature is the high byte of
    // `r`, which is uniformly distributed. Measured over 4,096 signatures:
    // byte 0 was 0x30 in 23 of them, about one in 178 — and CI duly hit it on
    // main.
    //
    // A test that fails one run in a couple of hundred is worse than no test:
    // it teaches whoever sees it red to press re-run, and that habit is what
    // lets a real failure through. The check below is therefore *total* rather
    // than likely — it cannot fail by chance at all. The loop is for coverage
    // of the encoding across many keys, not a fix for the flake.
    // ──────────────────────────────────────────────────────────────────────
    for (let i = 0; i < 64; i += 1) {
      const key = await generateDpopKey();
      const bytes = fromBase64Url(await signProof(key.privateKey, 'header.payload'));

      // Length alone already separates the two encodings: P1363 for P-256 is
      // exactly 64 bytes, while DER wraps the same pair in a SEQUENCE and
      // lands at 70-72.
      expect(bytes).toHaveLength(64);

      // And a structural check that cannot fire by chance. DER declares its
      // own length in byte 1, so a real SEQUENCE here would read 0x30 62.
      // Raw bytes that merely happen to start 0x30 will not also carry 62.
      expect(bytes[0] === 0x30 && bytes[1] === bytes.length - 2).toBe(false);
    }
  });

  it('produces a signature the public key verifies', async () => {
    const key = await generateDpopKey();
    const input = 'header.payload';
    const signature = await signProof(key.privateKey, input);

    const raw = fromBase64Url(signature);
    await expect(
      crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        key.publicKey,
        raw.buffer.slice(raw.byteOffset, raw.byteOffset + raw.byteLength) as ArrayBuffer,
        new TextEncoder().encode(input),
      ),
    ).resolves.toBe(true);
  });
});

describe('assembleJws', () => {
  it('joins the two encoded segments and nothing more', () => {
    // It builds the signing *input*, not a finished JWS — the signature is
    // appended by the caller. Asserted because the name invites the other
    // reading.
    const out = assembleJws({ alg: 'ES256' }, { jti: 'x' });
    const [header, payload, ...rest] = out.split('.');

    expect(rest).toHaveLength(0);
    expect(JSON.parse(new TextDecoder().decode(fromBase64Url(header as string)))).toEqual({
      alg: 'ES256',
    });
    expect(JSON.parse(new TextDecoder().decode(fromBase64Url(payload as string)))).toEqual({
      jti: 'x',
    });
  });
});

describe('base64url encoding', () => {
  it('round-trips arbitrary bytes', () => {
    for (let i = 0; i < 200; i += 1) {
      const bytes = new Uint8Array(Math.floor(Math.random() * 120));
      crypto.getRandomValues(bytes);
      expect(Array.from(fromBase64Url(toBase64Url(bytes)))).toEqual(Array.from(bytes));
    }
  });

  it('emits unpadded base64url and nothing outside the alphabet', () => {
    for (let length = 0; length < 20; length += 1) {
      const bytes = new Uint8Array(length);
      crypto.getRandomValues(bytes);
      expect(toBase64Url(bytes)).toMatch(/^[A-Za-z0-9_-]*$/);
    }
  });

  it('handles an input larger than the argument limit of apply', () => {
    // Chunked internally; a naive `String.fromCharCode(...bytes)` throws here.
    // Filled in 64KB slices because `getRandomValues` refuses more than that
    // at once — a limit of the test's making, not the function's.
    const bytes = new Uint8Array(200_000);
    for (let i = 0; i < bytes.length; i += 65_536) {
      crypto.getRandomValues(bytes.subarray(i, Math.min(i + 65_536, bytes.length)));
    }

    expect(() => toBase64Url(bytes)).not.toThrow();
    expect(fromBase64Url(toBase64Url(bytes))).toHaveLength(200_000);
  });

  it.each([
    ['an invalid character', '!!!!'],
    ['a length that cannot be base64', 'a'],
    ['padding where none belongs', '===='],
    ['whitespace', 'a b c'],
  ])('refuses %s with a controlled error', (_label, input) => {
    // REGRESSION. `atob` throws a raw `DOMException` on any of these, and this
    // function is exported and used to decode request bodies in
    // `examples/express-api`. A library whose stated property is that no input
    // produces an uncontrolled exception should not hand one out here.
    expect(() => fromBase64Url(input)).toThrow(/base64url/);
  });

  it('never throws anything but a controlled error on random strings', () => {
    for (let i = 0; i < 500; i += 1) {
      const bytes = new Uint8Array(Math.floor(Math.random() * 20));
      crypto.getRandomValues(bytes);
      const input = String.fromCharCode(...bytes);

      try {
        fromBase64Url(input);
      } catch (error) {
        if (!(error instanceof Error) || error.constructor.name === 'DOMException') {
          throw new Error(`uncontrolled ${(error as Error).constructor.name} for ${input}`);
        }
      }
    }
  });

  it('encodes JSON as UTF-8 before base64url', () => {
    const encoded = encodeJson({ name: 'Ünïcodé', emoji: '🔐' });
    expect(JSON.parse(new TextDecoder().decode(fromBase64Url(encoded)))).toEqual({
      name: 'Ünïcodé',
      emoji: '🔐',
    });
  });
});

describe('MemoryKeyStore', () => {
  it('holds the same handles, so the key stays non-extractable', async () => {
    // A different persistence choice, not a weaker one. If it serialised the
    // key it would need an extractable one, which is the thing being avoided.
    const store = new MemoryKeyStore();
    const key = await generateDpopKey();

    await store.save(key);
    const loaded = await store.load();

    expect(loaded?.privateKey).toBe(key.privateKey);
    expect(loaded?.privateKey.extractable).toBe(false);
    expect(loaded?.thumbprint).toBe(key.thumbprint);
  });

  it('starts empty and clears', async () => {
    const store = new MemoryKeyStore();
    expect(await store.load()).toBeNull();

    await store.save(await generateDpopKey());
    expect(await store.load()).not.toBeNull();

    await store.clear();
    expect(await store.load()).toBeNull();
  });
});
