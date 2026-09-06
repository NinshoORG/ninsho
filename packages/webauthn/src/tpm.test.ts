import { describe, it, expect } from 'vitest';
import {
  TpmError,
  parseTpmAttest,
  parseTpmPublic,
  verifyAttestedName,
  verifyPublicKeyMatches,
} from './tpm.js';
import { buildTpmCertInfo, buildTpmPublic } from './testing.js';

/**
 * The TPM structure parsers, on their own.
 *
 * `attestation.test.ts` drives these through a whole ceremony, which is the
 * right place to check that the format *verifies*. It is the wrong place to
 * check that the parsers survive rubbish, because the ceremony rejects most
 * rubbish long before it reaches them — so almost every random input would be
 * testing the CBOR decoder again.
 *
 * These structures are packed big-endian binary with length prefixes and no
 * framing, arriving from a browser. Every length drives a read, which is the
 * classic shape of an out-of-bounds bug, and the RSA branch of both parsers is
 * not reachable from the ECC fixture the ceremony tests use at all.
 */

const hex = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, 'hex'));
const toHex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

const u16 = (value: number): string => value.toString(16).padStart(4, '0');
const u32 = (value: number): string => value.toString(16).padStart(8, '0');
const sized = (payload: string): string => u16(payload.length / 2) + payload;

const P256_X = 'aa'.repeat(32);
const P256_Y = 'bb'.repeat(32);

/** A `TPMT_PUBLIC` for an RSA key, which the ECC fixture cannot produce. */
function rsaPublic(options: { exponent?: number; modulus?: string } = {}): Uint8Array {
  const modulus = options.modulus ?? 'cd'.repeat(256);
  return hex(
    u16(0x0001) + // type: TPM_ALG_RSA
      u16(0x000b) + // nameAlg: SHA-256
      u32(0x00050472) + // objectAttributes
      sized('') + // authPolicy
      u16(0x0010) + // symmetric: TPM_ALG_NULL
      u16(0x0014) + // scheme: RSASSA
      u16(0x0800) + // keyBits: 2048
      u32(options.exponent ?? 0) + // exponent, 0 meaning the default
      sized(modulus),
  );
}

describe('parseTpmPublic — ECC', () => {
  it('reads a P-256 key the fixture built', () => {
    const parsed = parseTpmPublic(buildTpmPublic(hex(P256_X), hex(P256_Y)));

    expect(parsed.type).toBe(0x0023);
    expect(parsed.nameAlg).toBe(0x000b);
    expect(parsed.curveId).toBe(0x0003);
    expect(toHex(parsed.x as Uint8Array)).toBe(P256_X);
    expect(toHex(parsed.y as Uint8Array)).toBe(P256_Y);
    // `unique` is the concatenation, which is what a name digest covers.
    expect(toHex(parsed.unique)).toBe(P256_X + P256_Y);
  });

  it('refuses trailing bytes after the structure', () => {
    // A structure with something appended is not the structure it claims to
    // be, and skipping the tail is how a parser ends up disagreeing with the
    // one that produced it.
    const valid = buildTpmPublic(hex(P256_X), hex(P256_Y));
    const padded = new Uint8Array(valid.length + 3);
    padded.set(valid, 0);

    expect(() => parseTpmPublic(padded)).toThrow(/trailing bytes/);
  });

  it('refuses a coordinate longer than the bytes that follow', () => {
    const valid = toHex(buildTpmPublic(hex(P256_X), hex(P256_Y)));
    // The x coordinate's length prefix sits after type, nameAlg,
    // objectAttributes, authPolicy, symmetric, scheme, curveID and kdf.
    const prefixAt = (2 + 2 + 4 + 2 + 2 + 2 + 2 + 2) * 2;
    const overstated = valid.slice(0, prefixAt) + 'ffff' + valid.slice(prefixAt + 4);

    expect(() => parseTpmPublic(hex(overstated))).toThrow(TpmError);
  });
});

describe('parseTpmPublic — RSA', () => {
  /**
   * Unreachable from the ceremony tests, which build ECC keys. Windows Hello
   * can and does present RSA ones, so a branch nobody exercises is a branch
   * that gets to be wrong.
   */
  it('reads a 2048-bit key', () => {
    const parsed = parseTpmPublic(rsaPublic());

    expect(parsed.type).toBe(0x0001);
    expect(parsed.unique).toHaveLength(256);
    expect(parsed.exponent).toBe(65537);
  });

  it('reads a zero exponent as the 65537 default', () => {
    // TPM 2.0 Part 2 §12.2.3.5. A parser that took the zero literally would
    // compare 0 against a credential's real exponent and refuse every RSA
    // registration.
    expect(parseTpmPublic(rsaPublic({ exponent: 0 })).exponent).toBe(65537);
  });

  it('keeps a non-default exponent as stated', () => {
    expect(parseTpmPublic(rsaPublic({ exponent: 3 })).exponent).toBe(3);
  });

  it('refuses trailing bytes', () => {
    const valid = rsaPublic();
    const padded = new Uint8Array(valid.length + 1);
    padded.set(valid, 0);

    expect(() => parseTpmPublic(padded)).toThrow(/trailing bytes/);
  });
});

describe('parseTpmPublic — refusals', () => {
  it.each([
    ['an empty input', ''],
    ['a truncated header', '0023'],
    ['a key type nobody uses', u16(0x0008) + u16(0x000b) + u32(0) + sized('')],
  ])('refuses %s', (_label, encoded) => {
    expect(() => parseTpmPublic(hex(encoded))).toThrow(TpmError);
  });

  it('names the unsupported type rather than failing vaguely', () => {
    const encoded = u16(0x0008) + u16(0x000b) + u32(0) + sized('');
    expect(() => parseTpmPublic(hex(encoded))).toThrow(/unsupported TPM key type: 0x8/);
  });

  it('never throws anything but TpmError on random input', () => {
    for (let i = 0; i < 3000; i += 1) {
      const bytes = new Uint8Array(Math.floor(Math.random() * 90));
      crypto.getRandomValues(bytes);

      try {
        parseTpmPublic(bytes);
      } catch (error) {
        if (!(error instanceof TpmError)) {
          throw new Error(
            `uncontrolled ${(error as Error).constructor.name} for ` +
              `${toHex(bytes)}: ${(error as Error).message}`,
          );
        }
      }
    }
  });

  it.each([
    ['an ECC structure', () => buildTpmPublic(hex(P256_X), hex(P256_Y))],
    ['an RSA structure', () => rsaPublic()],
  ])('never throws anything but TpmError on a mutated %s', (_label, build) => {
    // Every single-byte mutation must parse or be refused cleanly. Mutating a
    // length prefix is the interesting case, and it is the one a random-bytes
    // fuzzer almost never reaches, because random bytes rarely form a header
    // the parser gets past.
    const valid = build();

    for (let index = 0; index < valid.length; index += 1) {
      for (const delta of [1, 0x7f, 0xff]) {
        const mutated = Uint8Array.from(valid);
        mutated[index] = ((mutated[index] as number) + delta) & 0xff;

        try {
          parseTpmPublic(mutated);
        } catch (error) {
          if (!(error instanceof TpmError)) {
            throw new Error(
              `uncontrolled ${(error as Error).constructor.name} at byte ${index} ` +
                `(+${delta}): ${(error as Error).message}`,
            );
          }
        }
      }
    }
  });
});

describe('parseTpmAttest', () => {
  const validCertInfo = async (): Promise<Uint8Array> =>
    buildTpmCertInfo(buildTpmPublic(hex(P256_X), hex(P256_Y)), new TextEncoder().encode('ceremony'));

  it('reads the two fields the binding rests on', async () => {
    const pubArea = buildTpmPublic(hex(P256_X), hex(P256_Y));
    const attToBeSigned = new TextEncoder().encode('ceremony');
    const parsed = parseTpmAttest(await buildTpmCertInfo(pubArea, attToBeSigned));

    expect(parsed.magic).toBe(0xff544347);
    expect(parsed.type).toBe(0x8017);

    const expectedExtra = new Uint8Array(await crypto.subtle.digest('SHA-256', attToBeSigned));
    expect(toHex(parsed.extraData)).toBe(toHex(expectedExtra));

    // `nameAlg || digest(pubArea)` — two bytes then a SHA-256.
    expect(parsed.attestedName).toHaveLength(34);
  });

  it('refuses a structure without TPM_GENERATED_VALUE', async () => {
    const certInfo = Uint8Array.from(await validCertInfo());
    certInfo[0] = 0x00;

    expect(() => parseTpmAttest(certInfo)).toThrow(/TPM_GENERATED_VALUE/);
  });

  it('refuses an attestation type that is not a key certification', async () => {
    const certInfo = Uint8Array.from(await validCertInfo());
    certInfo[4] = 0x80;
    certInfo[5] = 0x18; // TPM_ST_ATTEST_QUOTE

    expect(() => parseTpmAttest(certInfo)).toThrow(/not a TPM_ST_ATTEST_CERTIFY/);
  });

  it('tolerates the qualifiedName it does not read', async () => {
    // The field follows the attested name and is not consulted, so trailing
    // bytes are expected here — unlike TPMT_PUBLIC, where they are not.
    const certInfo = await validCertInfo();
    const padded = new Uint8Array(certInfo.length + 8);
    padded.set(certInfo, 0);

    expect(() => parseTpmAttest(padded)).not.toThrow();
  });

  it('never throws anything but TpmError on random input', () => {
    for (let i = 0; i < 3000; i += 1) {
      const bytes = new Uint8Array(Math.floor(Math.random() * 120));
      crypto.getRandomValues(bytes);

      try {
        parseTpmAttest(bytes);
      } catch (error) {
        if (!(error instanceof TpmError)) {
          throw new Error(
            `uncontrolled ${(error as Error).constructor.name} for ` +
              `${toHex(bytes)}: ${(error as Error).message}`,
          );
        }
      }
    }
  });

  it('never throws anything but TpmError on a mutated structure', async () => {
    const valid = await validCertInfo();

    for (let index = 0; index < valid.length; index += 1) {
      const mutated = Uint8Array.from(valid);
      mutated[index] = ((mutated[index] as number) ^ 0xff) & 0xff;

      try {
        parseTpmAttest(mutated);
      } catch (error) {
        if (!(error instanceof TpmError)) {
          throw new Error(
            `uncontrolled ${(error as Error).constructor.name} at byte ${index}: ` +
              `${(error as Error).message}`,
          );
        }
      }
    }
  });
});

describe('verifyAttestedName', () => {
  const pubArea = buildTpmPublic(hex(P256_X), hex(P256_Y));

  const nameFor = async (algorithm: string, alg: number): Promise<Uint8Array> => {
    const digest = new Uint8Array(await crypto.subtle.digest(algorithm, pubArea));
    const name = new Uint8Array(2 + digest.length);
    name[0] = (alg >> 8) & 0xff;
    name[1] = alg & 0xff;
    name.set(digest, 2);
    return name;
  };

  it.each([
    ['SHA-256', 0x000b],
    ['SHA-384', 0x000c],
    ['SHA-512', 0x000d],
  ])('accepts a %s name', async (algorithm, alg) => {
    await expect(verifyAttestedName(await nameFor(algorithm, alg), pubArea)).resolves.toBeUndefined();
  });

  it('refuses SHA-1, which TPM 2.0 permits', async () => {
    // A name is a hash whose only job is to identify one key, which makes it
    // exactly where a collision would pay.
    const name = await nameFor('SHA-1', 0x0004);
    await expect(verifyAttestedName(name, pubArea)).rejects.toThrow(/SHA-1 name algorithm/);
  });

  it('refuses an algorithm it does not recognise', async () => {
    const name = await nameFor('SHA-256', 0x0027);
    await expect(verifyAttestedName(name, pubArea)).rejects.toThrow(/unsupported name algorithm/);
  });

  it('refuses a name too short to carry an algorithm', async () => {
    await expect(verifyAttestedName(new Uint8Array([0x00]), pubArea)).rejects.toThrow(
      /too short/,
    );
  });

  it('refuses a digest of something else', async () => {
    const name = await nameFor('SHA-256', 0x000b);
    name[10] = (name[10] as number) ^ 0xff;

    await expect(verifyAttestedName(name, pubArea)).rejects.toThrow(/does not describe/);
  });

  it('refuses a right-length name for a different pubArea', async () => {
    const other = buildTpmPublic(hex('cc'.repeat(32)), hex('dd'.repeat(32)));
    const name = await nameFor('SHA-256', 0x000b);

    await expect(verifyAttestedName(name, other)).rejects.toThrow(/does not describe/);
  });
});

describe('verifyPublicKeyMatches', () => {
  const ecc = parseTpmPublic(buildTpmPublic(hex(P256_X), hex(P256_Y)));
  const rsa = parseTpmPublic(rsaPublic());

  it('accepts an EC key that matches', () => {
    expect(() =>
      verifyPublicKeyMatches(ecc, { kty: 'EC', x: hex(P256_X), y: hex(P256_Y) }),
    ).not.toThrow();
  });

  it.each([
    ['a different x', { kty: 'EC', x: hex('11'.repeat(32)), y: hex(P256_Y) }, /x coordinate/],
    ['a different y', { kty: 'EC', x: hex(P256_X), y: hex('11'.repeat(32)) }, /y coordinate/],
    ['a truncated x', { kty: 'EC', x: hex('aa'.repeat(31)), y: hex(P256_Y) }, /x coordinate/],
    ['an RSA credential', { kty: 'RSA', n: hex('cd'.repeat(256)), e: 65537 }, /not EC/],
  ])('refuses %s', (_label, credential, message) => {
    expect(() => verifyPublicKeyMatches(ecc, credential)).toThrow(message);
  });

  it('refuses a curve other than P-256', () => {
    // The only curve §8.3's fixture path produces, and the only one this
    // comparison is written for. Silently accepting another would compare
    // coordinates of different widths.
    expect(() => verifyPublicKeyMatches({ ...ecc, curveId: 0x0004 }, {
      kty: 'EC',
      x: hex(P256_X),
      y: hex(P256_Y),
    })).toThrow(/unsupported TPM curve/);
  });

  it('accepts an RSA key that matches', () => {
    expect(() =>
      verifyPublicKeyMatches(rsa, { kty: 'RSA', n: hex('cd'.repeat(256)), e: 65537 }),
    ).not.toThrow();
  });

  it.each([
    ['a different modulus', { kty: 'RSA', n: hex('ce'.repeat(256)), e: 65537 }, /RSA modulus/],
    ['a different exponent', { kty: 'RSA', n: hex('cd'.repeat(256)), e: 3 }, /RSA exponent/],
    ['an EC credential', { kty: 'EC', x: hex(P256_X), y: hex(P256_Y) }, /not RSA/],
  ])('refuses %s', (_label, credential, message) => {
    expect(() => verifyPublicKeyMatches(rsa, credential)).toThrow(message);
  });

  it('refuses an RSA credential with no modulus at all', () => {
    // A credential key that parsed but carries nothing to compare must not be
    // treated as a match by omission.
    expect(() => verifyPublicKeyMatches(rsa, { kty: 'RSA' })).toThrow(/not RSA/);
  });

  it('accepts an RSA key whose exponent the credential does not state', () => {
    // The exponent is compared only when the credential has one; a COSE key
    // without `e` is not evidence of a mismatch.
    expect(() =>
      verifyPublicKeyMatches(rsa, { kty: 'RSA', n: hex('cd'.repeat(256)) }),
    ).not.toThrow();
  });
});
