import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import {
  CoseError,
  ES256,
  EdDSA,
  RS256,
  SUPPORTED_ALGORITHMS,
  importCoseKey,
  verifyCoseSignature,
  type CoseAlgorithm,
} from './cose.js';
import { encodeCbor, coseKeyFromJwk, VirtualAuthenticator, type Encodable } from './testing.js';

const b64u = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');

/** A well-formed ES256 COSE key map, with individual fields overridable. */
const ec2Key = (overrides: Map<number, Encodable> = new Map()): Uint8Array => {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const map = new Map<number, Encodable>([
    [1, 2],
    [3, ES256],
    [-1, 1],
    [-2, new Uint8Array(Buffer.from(jwk.x as string, 'base64url'))],
    [-3, new Uint8Array(Buffer.from(jwk.y as string, 'base64url'))],
  ]);
  for (const [label, value] of overrides) map.set(label, value);
  return encodeCbor(map);
};

const rsaKey = (bits: number, exponent?: Uint8Array): Uint8Array => {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: bits });
  const jwk = publicKey.export({ format: 'jwk' });
  return encodeCbor(
    new Map<number, Encodable>([
      [1, 3],
      [3, RS256],
      [-1, new Uint8Array(Buffer.from(jwk.n as string, 'base64url'))],
      [-2, exponent ?? new Uint8Array(Buffer.from(jwk.e as string, 'base64url'))],
    ]),
  );
};

describe('importing well-formed keys', () => {
  it.each(SUPPORTED_ALGORITHMS)('imports and verifies an algorithm %i key', async (alg) => {
    // End to end: a real key pair signs real bytes, and the imported key has
    // to accept that signature. Anything less tests the parser but not the
    // thing the parser exists for.
    const authenticator = await VirtualAuthenticator.create(alg);
    const imported = await importCoseKey(await authenticator.coseKey());

    expect(imported.alg).toBe(alg);
    expect(imported.key.extractable).toBe(false);
    expect(imported.key.usages).toEqual(['verify']);

    const data = new TextEncoder().encode('signed payload');
    const signature = await authenticator.sign(data);
    expect(await verifyCoseSignature(imported, signature, data)).toBe(true);
  });

  it.each(SUPPORTED_ALGORITHMS)('rejects a signature over different data (alg %i)', async (alg) => {
    const authenticator = await VirtualAuthenticator.create(alg);
    const imported = await importCoseKey(await authenticator.coseKey());

    const signature = await authenticator.sign(new TextEncoder().encode('the real payload'));
    const other = new TextEncoder().encode('a different payload');
    expect(await verifyCoseSignature(imported, signature, other)).toBe(false);
  });

  it.each(SUPPORTED_ALGORITHMS)('rejects another key’s signature (alg %i)', async (alg) => {
    const signer = await VirtualAuthenticator.create(alg);
    const other = await VirtualAuthenticator.create(alg);
    const imported = await importCoseKey(await other.coseKey());

    const data = new TextEncoder().encode('payload');
    expect(await verifyCoseSignature(imported, await signer.sign(data), data)).toBe(false);
  });

  it('ignores unknown COSE labels', async () => {
    // Real authenticators occasionally include a key id. Refusing an unknown
    // label would lock out working hardware for no security gain, since the
    // labels that matter are all read explicitly.
    const key = ec2Key(new Map<number, Encodable>([[2, new Uint8Array([1, 2, 3])]]));
    await expect(importCoseKey(key)).resolves.toMatchObject({ alg: ES256 });
  });
});

/**
 * The algorithm-confusion cases. Each one is the browser telling the server
 * which code path to run; each one must be refused.
 */
describe('algorithm confusion', () => {
  it('refuses an algorithm the relying party did not allow', async () => {
    const authenticator = await VirtualAuthenticator.create(RS256);
    await expect(importCoseKey(await authenticator.coseKey(), [ES256])).rejects.toThrow(
      /not accepted by this relying party/,
    );
  });

  it('accepts that same key once the relying party allows it', async () => {
    // Confirms the previous rejection came from the allowlist and not from
    // something incidentally wrong with the key.
    const authenticator = await VirtualAuthenticator.create(RS256);
    await expect(importCoseKey(await authenticator.coseKey(), [ES256, RS256])).resolves.toBeTruthy();
  });

  it('refuses an EC2 key that claims RS256', async () => {
    // Interpreting a curve point as an RSA modulus is not a meaningful
    // operation, and guessing at what the caller meant is how a verifier ends
    // up running the attacker's chosen algorithm.
    const key = ec2Key(new Map<number, Encodable>([[3, RS256]]));
    await expect(importCoseKey(key)).rejects.toThrow(/does not match algorithm/);
  });

  it('refuses an RSA key that claims ES256', async () => {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' });
    const key = encodeCbor(
      new Map<number, Encodable>([
        [1, 3],
        [3, ES256],
        [-1, new Uint8Array(Buffer.from(jwk.n as string, 'base64url'))],
        [-2, new Uint8Array(Buffer.from(jwk.e as string, 'base64url'))],
      ]),
    );
    await expect(importCoseKey(key)).rejects.toThrow(/does not match algorithm/);
  });

  it('refuses an OKP key that claims ES256', async () => {
    const authenticator = await VirtualAuthenticator.create(EdDSA);
    const jwk = await authenticator.publicKeyJwk();
    const key = encodeCbor(
      new Map<number, Encodable>([
        [1, 1],
        [3, ES256],
        [-1, 6],
        [-2, new Uint8Array(Buffer.from(jwk.x as string, 'base64url'))],
      ]),
    );
    await expect(importCoseKey(key)).rejects.toThrow(/does not match algorithm/);
  });

  it.each([
    ['ES256K', -47],
    ['PS256', -37],
    ['ES384', -35],
    ['HMAC-256', 5],
    ['a nonsense identifier', 999],
  ])('refuses %s', async (_label, alg) => {
    const key = ec2Key(new Map<number, Encodable>([[3, alg]]));
    await expect(importCoseKey(key, [...SUPPORTED_ALGORITHMS, alg as CoseAlgorithm])).rejects.toThrow(
      /not supported/,
    );
  });

  it('refuses everything when the allowlist is empty', async () => {
    // A check that can only ever fail is nearly always a misconfiguration, and
    // saying so beats silently rejecting every user.
    const authenticator = await VirtualAuthenticator.create(ES256);
    await expect(importCoseKey(await authenticator.coseKey(), [])).rejects.toThrow(
      /no algorithms are allowed/,
    );
  });

  it('never lets the verify-time algorithm come from the signature', async () => {
    // An ES256 key handed an Ed25519-shaped 64-byte signature must fail, not
    // switch algorithms to match what it was given.
    const es256 = await VirtualAuthenticator.create(ES256);
    const ed = await VirtualAuthenticator.create(EdDSA);
    const imported = await importCoseKey(await es256.coseKey());

    const data = new TextEncoder().encode('payload');
    expect(await verifyCoseSignature(imported, await ed.sign(data), data)).toBe(false);
  });
});

describe('RSA parameter validation', () => {
  it('refuses a 512-bit modulus', async () => {
    // WebCrypto imports this without complaint — verified by the test below —
    // so the floor has to be enforced here or not at all.
    await expect(importCoseKey(rsaKey(512))).rejects.toThrow(/below the 2048-bit minimum/);
  });

  it('refuses a 1024-bit modulus', async () => {
    await expect(importCoseKey(rsaKey(1024))).rejects.toThrow(/below the 2048-bit minimum/);
  });

  it('accepts 2048 bits', async () => {
    await expect(importCoseKey(rsaKey(2048))).resolves.toMatchObject({ alg: RS256 });
  });

  it('confirms WebCrypto alone would have accepted the 512-bit key', async () => {
    // The justification for the check above, stated as a test rather than a
    // comment. If a future Node starts rejecting these on its own, this test
    // fails and tells us the check became redundant — rather than the check
    // quietly protecting nothing.
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 512 });
    const jwk = publicKey.export({ format: 'jwk' });
    await expect(
      crypto.subtle.importKey(
        'jwk',
        { kty: 'RSA', n: jwk.n as string, e: jwk.e as string },
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify'],
      ),
    ).resolves.toBeTruthy();
  });

  it('measures the modulus in significant bits, not buffer length', async () => {
    // A 512-bit modulus left-padded to 256 bytes still has 512 significant
    // bits. Measuring the buffer would wave it straight through.
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 512 });
    const jwk = publicKey.export({ format: 'jwk' });
    const n = new Uint8Array(Buffer.from(jwk.n as string, 'base64url'));
    const padded = new Uint8Array(256);
    padded.set(n, 256 - n.length);

    const key = encodeCbor(
      new Map<number, Encodable>([
        [1, 3],
        [3, RS256],
        [-1, padded],
        [-2, new Uint8Array(Buffer.from(jwk.e as string, 'base64url'))],
      ]),
    );
    await expect(importCoseKey(key)).rejects.toThrow(/below the 2048-bit minimum/);
  });

  it.each([
    ['e = 1, which makes the signature the message', new Uint8Array([0x01])],
    ['e = 0', new Uint8Array([0x00])],
    ['an even exponent', new Uint8Array([0x04])],
  ])('refuses %s', async (_label, exponent) => {
    await expect(importCoseKey(rsaKey(2048, exponent))).rejects.toThrow(/invalid RSA public exponent/);
  });

  it('refuses an implausibly large exponent', async () => {
    const huge = new Uint8Array(32).fill(0xff);
    await expect(importCoseKey(rsaKey(2048, huge))).rejects.toThrow(/implausibly large/);
  });

  it('refuses an oversized modulus', async () => {
    // Verification cost grows with the modulus, so an enormous key is a cheap
    // way to make the server do expensive work.
    const key = encodeCbor(
      new Map<number, Encodable>([
        [1, 3],
        [3, RS256],
        [-1, new Uint8Array(2048).fill(0xff)],
        [-2, new Uint8Array([0x01, 0x00, 0x01])],
      ]),
    );
    await expect(importCoseKey(key)).rejects.toThrow(/exceeds the 8192-bit limit/);
  });
});

describe('EC2 parameter validation', () => {
  it('refuses a curve other than P-256', async () => {
    const key = ec2Key(new Map<number, Encodable>([[-1, 2]])); // P-384
    await expect(importCoseKey(key)).rejects.toThrow(/unsupported EC2 curve/);
  });

  it.each([
    ['a short x', -2, new Uint8Array(31)],
    ['a short y', -3, new Uint8Array(31)],
    ['a long x', -2, new Uint8Array(33)],
  ])('refuses %s', async (_label, label, value) => {
    // Exactly 32 bytes, not "at most". A coordinate that one implementation
    // left-pads and another does not gives one key two encodings — and a
    // credential with two encodings has two identities.
    const key = ec2Key(new Map<number, Encodable>([[label, value]]));
    await expect(importCoseKey(key)).rejects.toThrow(/must be exactly 32 bytes/);
  });

  it('refuses a point that is not on the curve', async () => {
    // WebCrypto performs this check; the test records that it does, so the
    // absence of an explicit on-curve check here is a verified fact rather
    // than an oversight.
    const key = ec2Key(
      new Map<number, Encodable>([
        [-2, new Uint8Array(32).fill(1)],
        [-3, new Uint8Array(32).fill(2)],
      ]),
    );
    await expect(importCoseKey(key)).rejects.toThrow(CoseError);
  });

  it('refuses the point at infinity', async () => {
    const key = ec2Key(
      new Map<number, Encodable>([
        [-2, new Uint8Array(32)],
        [-3, new Uint8Array(32)],
      ]),
    );
    await expect(importCoseKey(key)).rejects.toThrow(CoseError);
  });
});

describe('Ed25519 parameter validation', () => {
  it('refuses a curve other than Ed25519', async () => {
    const authenticator = await VirtualAuthenticator.create(EdDSA);
    const jwk = await authenticator.publicKeyJwk();
    const key = encodeCbor(
      new Map<number, Encodable>([
        [1, 1],
        [3, EdDSA],
        [-1, 4], // X25519 — a key agreement curve, not a signing curve
        [-2, new Uint8Array(Buffer.from(jwk.x as string, 'base64url'))],
      ]),
    );
    await expect(importCoseKey(key)).rejects.toThrow(/unsupported OKP curve/);
  });

  it('refuses a public key of the wrong length', async () => {
    const key = encodeCbor(
      new Map<number, Encodable>([
        [1, 1],
        [3, EdDSA],
        [-1, 6],
        [-2, new Uint8Array(31)],
      ]),
    );
    await expect(importCoseKey(key)).rejects.toThrow(/must be 32 bytes/);
  });

  it('refuses a signature of the wrong length without consulting the library', async () => {
    const authenticator = await VirtualAuthenticator.create(EdDSA);
    const imported = await importCoseKey(await authenticator.coseKey());
    const data = new TextEncoder().encode('payload');

    expect(await verifyCoseSignature(imported, new Uint8Array(63), data)).toBe(false);
    expect(await verifyCoseSignature(imported, new Uint8Array(65), data)).toBe(false);
  });
});

describe('malformed key structures', () => {
  it('refuses input that is not CBOR', async () => {
    await expect(importCoseKey(new Uint8Array([0xff, 0xff, 0xff]))).rejects.toThrow(
      /not valid CBOR/,
    );
  });

  it('refuses CBOR that is not a map', async () => {
    await expect(importCoseKey(encodeCbor([1, 2, 3]))).rejects.toThrow(/not a CBOR map/);
  });

  it('refuses a key with no algorithm', async () => {
    const key = encodeCbor(
      new Map<number, Encodable>([
        [1, 2],
        [-1, 1],
        [-2, new Uint8Array(32)],
        [-3, new Uint8Array(32)],
      ]),
    );
    await expect(importCoseKey(key)).rejects.toThrow(/missing an algorithm/);
  });

  it('refuses a key with no key type', async () => {
    const key = encodeCbor(
      new Map<number, Encodable>([
        [3, ES256],
        [-1, 1],
        [-2, new Uint8Array(32)],
        [-3, new Uint8Array(32)],
      ]),
    );
    await expect(importCoseKey(key)).rejects.toThrow(/missing a key type/);
  });

  it('refuses an algorithm encoded as a string', async () => {
    const key = encodeCbor(
      new Map<string | number, Encodable>([
        [1, 2],
        [3, 'ES256'],
        [-1, 1],
        [-2, new Uint8Array(32)],
        [-3, new Uint8Array(32)],
      ]),
    );
    await expect(importCoseKey(key)).rejects.toThrow(/not an integer/);
  });

  it('refuses a coordinate encoded as a text string', async () => {
    const key = ec2Key(new Map<number, Encodable>([[-2, 'not bytes']]));
    await expect(importCoseKey(key)).rejects.toThrow(/not a byte string/);
  });

  it('refuses a missing coordinate', async () => {
    const key = encodeCbor(
      new Map<number, Encodable>([
        [1, 2],
        [3, ES256],
        [-1, 1],
        [-2, new Uint8Array(32)],
      ]),
    );
    await expect(importCoseKey(key)).rejects.toThrow(/missing the y coordinate/);
  });

  it('refuses trailing bytes after the key', async () => {
    // Inherited from the CBOR decoder, and worth asserting here: a key with
    // extra bytes appended must not parse into the same key.
    const valid = await (await VirtualAuthenticator.create(ES256)).coseKey();
    const padded = new Uint8Array(valid.length + 2);
    padded.set(valid);
    await expect(importCoseKey(padded)).rejects.toThrow(/not valid CBOR/);
  });

  it('reports every failure as a CoseError', async () => {
    // Callers map this one class onto a 400. An escaping DOMException or
    // TypeError from WebCrypto would become an unhandled 500 instead.
    const inputs = [
      new Uint8Array(0),
      new Uint8Array([0xa0]),
      encodeCbor(new Map<number, Encodable>([[1, 2]])),
      ec2Key(new Map<number, Encodable>([[-2, new Uint8Array(32).fill(9)]])),
      rsaKey(512),
    ];

    for (const input of inputs) {
      await expect(importCoseKey(input)).rejects.toBeInstanceOf(CoseError);
    }
  });

  it('never throws anything but CoseError on random input', async () => {
    for (let i = 0; i < 300; i += 1) {
      const bytes = new Uint8Array(Math.floor(Math.random() * 60));
      crypto.getRandomValues(bytes);
      if (bytes.length > 0 && i % 2 === 0) bytes[0] = 0xa5; // a 5-pair map

      try {
        await importCoseKey(bytes);
      } catch (error) {
        if (!(error instanceof CoseError)) {
          throw new Error(
            `uncontrolled ${(error as Error).constructor.name} for ` +
              `${Buffer.from(bytes).toString('hex')}: ${(error as Error).message}`,
          );
        }
      }
    }
  });
});

describe('key encodings are stable', () => {
  it('re-imports a key that was stored and read back', async () => {
    // The relying party stores the COSE bytes at registration and re-imports
    // them at every authentication. If that round trip were lossy, every
    // credential would work once.
    const authenticator = await VirtualAuthenticator.create(ES256);
    const stored = Buffer.from(await authenticator.coseKey()).toString('base64');

    const reloaded = await importCoseKey(new Uint8Array(Buffer.from(stored, 'base64')));
    const data = new TextEncoder().encode('payload');
    expect(await verifyCoseSignature(reloaded, await authenticator.sign(data), data)).toBe(true);
  });

  it('builds the same COSE bytes from an exported JWK', async () => {
    const authenticator = await VirtualAuthenticator.create(ES256);
    const direct = await authenticator.coseKey();
    const viaJwk = coseKeyFromJwk(await authenticator.publicKeyJwk(), ES256);
    expect(b64u(viaJwk)).toBe(b64u(direct));
  });
});
