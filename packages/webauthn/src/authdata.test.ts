import { describe, it, expect } from 'vitest';
import { AuthDataError, parseAuthenticatorData } from './authdata.js';
import {
  FLAG_AT,
  FLAG_BE,
  FLAG_BS,
  FLAG_ED,
  FLAG_UP,
  FLAG_UV,
  VirtualAuthenticator,
  buildAuthenticatorData,
  encodeCbor,
  type Encodable,
} from './testing.js';

const RP_ID = 'example.com';

const sha256 = async (value: string): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)));

const concat = (...chunks: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(chunks.reduce((sum, c) => sum + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

/** A bare 37-byte header with the given flags and counter. */
const header = async (flags: number, signCount = 0): Promise<Uint8Array> =>
  buildAuthenticatorData({ rpId: RP_ID, flags, signCount });

describe('the fixed header', () => {
  it('parses rpIdHash, flags and signCount', async () => {
    const data = await header(FLAG_UP | FLAG_UV, 42);
    const parsed = parseAuthenticatorData(data);

    expect(Buffer.from(parsed.rpIdHash)).toEqual(Buffer.from(await sha256(RP_ID)));
    expect(parsed.signCount).toBe(42);
    expect(parsed.flags.userPresent).toBe(true);
    expect(parsed.flags.userVerified).toBe(true);
    expect(parsed.flags.attestedCredentialData).toBe(false);
    expect(parsed.attestedCredentialData).toBeUndefined();
    expect(parsed.extensions).toBeUndefined();
  });

  it('reads the sign counter as big-endian', async () => {
    // Byte order is exactly the kind of thing that works for small counters
    // and silently breaks past 256.
    const data = await header(FLAG_UP, 0x01020304);
    expect(parseAuthenticatorData(data).signCount).toBe(0x01020304);
  });

  it('accepts a counter at the 32-bit ceiling', async () => {
    const data = await header(FLAG_UP, 0xffffffff);
    expect(parseAuthenticatorData(data).signCount).toBe(4294967295);
  });

  it.each([
    ['user present', FLAG_UP, 'userPresent'],
    ['user verified', FLAG_UV, 'userVerified'],
    ['backup eligible', FLAG_BE, 'backupEligible'],
  ] as const)('decodes the %s flag', async (_label, bit, field) => {
    expect(parseAuthenticatorData(await header(bit)).flags[field]).toBe(true);
    expect(parseAuthenticatorData(await header(0)).flags[field]).toBe(false);
  });

  it('decodes backup state only alongside eligibility', async () => {
    const parsed = parseAuthenticatorData(await header(FLAG_BE | FLAG_BS));
    expect(parsed.flags.backupEligible).toBe(true);
    expect(parsed.flags.backedUp).toBe(true);
  });

  it('exposes the raw flag byte', async () => {
    // Callers checking a flag this package does not model should not have to
    // re-parse the buffer to do it.
    const parsed = parseAuthenticatorData(await header(FLAG_UP | FLAG_UV));
    expect(parsed.rawFlags).toBe(FLAG_UP | FLAG_UV);
  });

  it('keeps the exact bytes it parsed', async () => {
    // The signature is computed over these, so a parser that returned a copy
    // with any normalisation applied would break verification.
    const data = await header(FLAG_UP, 7);
    expect(parseAuthenticatorData(data).raw).toBe(data);
  });

  it('refuses a backed-up credential that is not backup eligible', async () => {
    // §6.1: "If the BE flag is 0, the BS flag MUST be 0." No honest
    // authenticator produces this combination.
    await expect(async () => parseAuthenticatorData(await header(FLAG_BS))).rejects.toThrow(
      /not backup eligible/,
    );
  });

  it.each([36, 20, 1, 0])('refuses %i bytes of input', (length) => {
    expect(() => parseAuthenticatorData(new Uint8Array(length))).toThrow(/at least 37 bytes/);
  });

  it('accepts exactly 37 bytes', () => {
    expect(() => parseAuthenticatorData(new Uint8Array(37))).not.toThrow();
  });
});

describe('attested credential data', () => {
  it('parses what a registration produces', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const coseKey = await authenticator.coseKey();
    const data = await buildAuthenticatorData({
      rpId: RP_ID,
      flags: FLAG_UP | FLAG_UV | FLAG_AT,
      signCount: 0,
      attestedCredential: {
        aaguid: authenticator.aaguid,
        credentialId: authenticator.credentialId,
        credentialPublicKey: coseKey,
      },
    });

    const parsed = parseAuthenticatorData(data);
    const attested = parsed.attestedCredentialData;

    expect(attested).toBeDefined();
    expect(Buffer.from(attested!.aaguid)).toEqual(Buffer.from(authenticator.aaguid));
    expect(Buffer.from(attested!.credentialId)).toEqual(Buffer.from(authenticator.credentialId));
    // The key bytes must come back byte-identical: they are stored and
    // re-imported at every later authentication.
    expect(Buffer.from(attested!.credentialPublicKey)).toEqual(Buffer.from(coseKey));
  });

  it('finds the end of the public key without a length field', async () => {
    // The COSE key is self-delimiting. This is the case that proves the
    // decoder reports its own extent correctly: extension data can only be
    // located if the key ended where the parser said it did.
    const authenticator = await VirtualAuthenticator.create();
    const extensions = encodeCbor(new Map<string, Encodable>([['credProtect', 2]]));

    const data = await buildAuthenticatorData({
      rpId: RP_ID,
      flags: FLAG_UP | FLAG_AT | FLAG_ED,
      signCount: 0,
      attestedCredential: {
        aaguid: authenticator.aaguid,
        credentialId: authenticator.credentialId,
        credentialPublicKey: await authenticator.coseKey(),
      },
      extensions,
    });

    const parsed = parseAuthenticatorData(data);
    expect(parsed.extensions).toBeInstanceOf(Map);
    expect((parsed.extensions as Map<string, unknown>).get('credProtect')).toBe(2);
  });

  it.each([1, 16, 64, 1023])('accepts a %i-byte credential id', async (length) => {
    const authenticator = await VirtualAuthenticator.create();
    const credentialId = new Uint8Array(length).fill(7);
    const data = await buildAuthenticatorData({
      rpId: RP_ID,
      flags: FLAG_UP | FLAG_AT,
      signCount: 0,
      attestedCredential: {
        aaguid: authenticator.aaguid,
        credentialId,
        credentialPublicKey: await authenticator.coseKey(),
      },
    });

    expect(parseAuthenticatorData(data).attestedCredentialData?.credentialId).toHaveLength(length);
  });

  it('refuses a credential id past the 1023-byte spec limit', async () => {
    // The length field can express 65535, so the spec's limit is the one that
    // has to be enforced rather than the encoding's.
    const authenticator = await VirtualAuthenticator.create();
    const data = await buildAuthenticatorData({
      rpId: RP_ID,
      flags: FLAG_UP | FLAG_AT,
      signCount: 0,
      attestedCredential: {
        aaguid: authenticator.aaguid,
        credentialId: new Uint8Array(1024),
        credentialPublicKey: await authenticator.coseKey(),
      },
    });

    expect(() => parseAuthenticatorData(data)).toThrow(/exceeds the 1023-byte maximum/);
  });

  it('refuses an empty credential id', async () => {
    const data = concat(
      await sha256(RP_ID),
      new Uint8Array([FLAG_UP | FLAG_AT, 0, 0, 0, 0]),
      new Uint8Array(16),
      new Uint8Array([0x00, 0x00]),
      encodeCbor(new Map<number, Encodable>([[1, 2]])),
    );
    expect(() => parseAuthenticatorData(data)).toThrow(/credential id is empty/);
  });

  it('refuses a credential id length that runs past the buffer', async () => {
    // The attacker-controlled length that drives the read. A parser that
    // trusts it reads whatever follows in memory.
    const data = concat(
      await sha256(RP_ID),
      new Uint8Array([FLAG_UP | FLAG_AT, 0, 0, 0, 0]),
      new Uint8Array(16),
      new Uint8Array([0x03, 0xff]), // claims 1023 bytes
      new Uint8Array(4), // provides 4
    );
    expect(() => parseAuthenticatorData(data)).toThrow(/runs past the end/);
  });

  it('refuses attested credential data truncated before the length field', async () => {
    const data = concat(
      await sha256(RP_ID),
      new Uint8Array([FLAG_UP | FLAG_AT, 0, 0, 0, 0]),
      new Uint8Array(10), // an aaguid needs 16
    );
    expect(() => parseAuthenticatorData(data)).toThrow(/truncated/);
  });

  it('refuses a public key that is not valid CBOR', async () => {
    const data = concat(
      await sha256(RP_ID),
      new Uint8Array([FLAG_UP | FLAG_AT, 0, 0, 0, 0]),
      new Uint8Array(16),
      new Uint8Array([0x00, 0x04]),
      new Uint8Array([1, 2, 3, 4]),
      new Uint8Array([0xff, 0xff]), // not a CBOR value
    );
    expect(() => parseAuthenticatorData(data)).toThrow(/not valid CBOR/);
  });

  it('refuses attested data when the AT flag is clear', async () => {
    // The bytes are present but the flags say they are not. Believing the
    // bytes over the flags would let an attacker attach a credential to an
    // assertion that never claimed to carry one.
    const authenticator = await VirtualAuthenticator.create();
    const data = concat(
      await sha256(RP_ID),
      new Uint8Array([FLAG_UP, 0, 0, 0, 0]),
      authenticator.aaguid,
      new Uint8Array([0x00, 0x20]),
      authenticator.credentialId,
      await authenticator.coseKey(),
    );
    expect(() => parseAuthenticatorData(data)).toThrow(/trailing bytes/);
  });
});

describe('extensions', () => {
  it('refuses extension data when the ED flag is clear', async () => {
    const data = concat(
      await header(FLAG_UP),
      encodeCbor(new Map<string, Encodable>([['credProtect', 2]])),
    );
    expect(() => parseAuthenticatorData(data)).toThrow(/trailing bytes/);
  });

  it('refuses a missing extension map when the ED flag is set', async () => {
    expect(() => parseAuthenticatorData(new Uint8Array(37).fill(0).map((v, i) => (i === 32 ? FLAG_ED : v))))
      .toThrow(AuthDataError);
  });

  it('refuses extension data that is not a map', async () => {
    const data = concat(await header(FLAG_UP | FLAG_ED), encodeCbor([1, 2, 3]));
    expect(() => parseAuthenticatorData(data)).toThrow(/not a CBOR map/);
  });
});

describe('trailing data', () => {
  it('refuses bytes after a bare header', async () => {
    const data = concat(await header(FLAG_UP), new Uint8Array([0xaa]));
    expect(() => parseAuthenticatorData(data)).toThrow(/1 unexpected trailing bytes/);
  });

  it('refuses bytes after attested credential data', async () => {
    const authenticator = await VirtualAuthenticator.create();
    const valid = await buildAuthenticatorData({
      rpId: RP_ID,
      flags: FLAG_UP | FLAG_AT,
      signCount: 0,
      attestedCredential: {
        aaguid: authenticator.aaguid,
        credentialId: authenticator.credentialId,
        credentialPublicKey: await authenticator.coseKey(),
      },
    });

    expect(() => parseAuthenticatorData(concat(valid, new Uint8Array(3)))).toThrow(/trailing/);
  });
});

describe('hostile input', () => {
  it('refuses every truncation of a valid registration', async () => {
    // Each prefix must be refused cleanly rather than reading past the end or
    // producing a half-populated result.
    const authenticator = await VirtualAuthenticator.create();
    const valid = await buildAuthenticatorData({
      rpId: RP_ID,
      flags: FLAG_UP | FLAG_UV | FLAG_AT,
      signCount: 1,
      attestedCredential: {
        aaguid: authenticator.aaguid,
        credentialId: authenticator.credentialId,
        credentialPublicKey: await authenticator.coseKey(),
      },
    });

    for (let cut = 0; cut < valid.length; cut += 1) {
      expect(() => parseAuthenticatorData(valid.subarray(0, cut)), `prefix of ${cut}`).toThrow(
        AuthDataError,
      );
    }
    expect(() => parseAuthenticatorData(valid)).not.toThrow();
  });

  it('never throws anything but AuthDataError on random input', () => {
    for (let i = 0; i < 3000; i += 1) {
      // Sized around the header boundary so the fuzzer spends its time in the
      // optional sections rather than bouncing off the length check.
      const bytes = new Uint8Array(37 + Math.floor(Math.random() * 60));
      crypto.getRandomValues(bytes);

      try {
        parseAuthenticatorData(bytes);
      } catch (error) {
        if (!(error instanceof AuthDataError)) {
          throw new Error(
            `uncontrolled ${(error as Error).constructor.name} for ` +
              `${Buffer.from(bytes).toString('hex')}: ${(error as Error).message}`,
          );
        }
      }
    }
  });

  it('is not confused by a Uint8Array with a non-zero byteOffset', async () => {
    // A subarray shares its buffer with the original. A DataView built over
    // the whole buffer instead of the view would read the wrong bytes — and
    // would do it silently.
    const valid = await header(FLAG_UP | FLAG_UV, 99);
    const padded = new Uint8Array(valid.length + 16);
    padded.set(valid, 8);

    const parsed = parseAuthenticatorData(padded.subarray(8, 8 + valid.length));
    expect(parsed.signCount).toBe(99);
    expect(parsed.flags.userVerified).toBe(true);
  });
});
