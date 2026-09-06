import { describe, it, expect } from 'vitest';
import {
  AndroidKeyError,
  KM_ORIGIN_GENERATED,
  KM_PURPOSE_SIGN,
  parseKeyDescription,
  verifyAuthorizations,
  type KeyDescription,
} from './android-key.js';

/**
 * Android's `KeyDescription`, on its own.
 *
 * `attestation.test.ts` drives this through a ceremony, which is where the
 * *verification* belongs. This is where the parser belongs, for two reasons.
 *
 * The DER here is written by hand rather than by `x509-fixtures.ts`, so the
 * encoder that produces the test data is not the encoder under test — if both
 * agreed on a wrong tag encoding, a fixture-driven test would happily confirm
 * it. And the extension is attacker-supplied DER whose authorization lists are
 * a long run of optional fields at tag numbers in the hundreds, which is the
 * shape where a parser reading by position instead of by tag quietly returns
 * the wrong field.
 */

const hex = (value: string): Uint8Array => new Uint8Array(Buffer.from(value, 'hex'));

/** DER length, short form or long form as the length requires. */
function len(byteLength: number): string {
  if (byteLength < 0x80) return byteLength.toString(16).padStart(2, '0');
  const bytes: string[] = [];
  let value = byteLength;
  while (value > 0) {
    bytes.unshift((value & 0xff).toString(16).padStart(2, '0'));
    value >>>= 8;
  }
  return (0x80 | bytes.length).toString(16).padStart(2, '0') + bytes.join('');
}

const tlv = (tag: string, content: string): string => tag + len(content.length / 2) + content;

const sequence = (...parts: string[]): string => tlv('30', parts.join(''));
const set = (...parts: string[]): string => tlv('31', parts.join(''));
const octetString = (content: string): string => tlv('04', content);
const enumerated = (value: number): string => tlv('0a', value.toString(16).padStart(2, '0'));
const nullValue = (): string => '0500';

/** A positive INTEGER, minimally encoded. */
function integer(value: number): string {
  let digits = value.toString(16);
  if (digits.length % 2 === 1) digits = `0${digits}`;
  if (parseInt(digits.slice(0, 2), 16) & 0x80) digits = `00${digits}`;
  return tlv('02', digits);
}

/** `[n] EXPLICIT` for a tag number under 31. */
const context = (number: number, content: string): string =>
  tlv((0xa0 | number).toString(16), content);

/**
 * `[n] EXPLICIT` for a tag number of 31 or more.
 *
 * Written out here rather than reused from the fixture builder: 600 and 702
 * are the whole reason the DER reader gained multi-byte tag support, and a
 * test that encoded them with the same code that decodes them would not be
 * checking the encoding at all.
 */
function highContext(number: number, content: string): string {
  const groups: number[] = [];
  let value = number;
  while (value > 0) {
    groups.unshift(value & 0x7f);
    value >>>= 7;
  }
  const tag = ['bf'];
  for (let i = 0; i < groups.length - 1; i += 1) {
    tag.push(((groups[i] as number) | 0x80).toString(16).padStart(2, '0'));
  }
  tag.push((groups[groups.length - 1] as number).toString(16).padStart(2, '0'));
  return tlv(tag.join(''), content);
}

interface ListSpec {
  purposes?: readonly number[];
  allApplications?: boolean;
  origin?: number;
  /** Extra encoded fields, for the shapes a well-formed builder will not make. */
  extra?: string;
}

const authorizationList = (spec: ListSpec = {}): string =>
  sequence(
    spec.purposes === undefined ? '' : context(1, set(...spec.purposes.map(integer))),
    spec.allApplications === true ? highContext(600, nullValue()) : '',
    spec.origin === undefined ? '' : highContext(702, integer(spec.origin)),
    spec.extra ?? '',
  );

const CHALLENGE = 'ab'.repeat(32);

function keyDescription(options: {
  challenge?: string;
  software?: ListSpec;
  tee?: ListSpec;
  /** Replaces the whole encoded field list, for malformed shapes. */
  fields?: readonly string[];
} = {}): Uint8Array {
  const fields = options.fields ?? [
    integer(200),
    enumerated(1),
    integer(41),
    enumerated(1),
    octetString(options.challenge ?? CHALLENGE),
    octetString(''),
    authorizationList(options.software ?? {}),
    authorizationList(options.tee ?? { purposes: [KM_PURPOSE_SIGN], origin: KM_ORIGIN_GENERATED }),
  ];
  return hex(sequence(...fields));
}

describe('parseKeyDescription', () => {
  it('reads the challenge and both authorization lists', () => {
    const parsed = parseKeyDescription(keyDescription());

    expect(Buffer.from(parsed.attestationChallenge).toString('hex')).toBe(CHALLENGE);
    expect(parsed.teeEnforced.purposes).toEqual([KM_PURPOSE_SIGN]);
    expect(parsed.teeEnforced.origin).toBe(KM_ORIGIN_GENERATED);
    expect(parsed.teeEnforced.allApplications).toBe(false);
    expect(parsed.softwareEnforced.purposes).toBeUndefined();
    expect(parsed.softwareEnforced.origin).toBeUndefined();
  });

  it('decodes the multi-byte tag numbers Android uses', () => {
    // `allApplications` is [600] and `origin` is [702]. Both need the
    // high-tag-number form, which the DER reader refused outright until this
    // format needed it — so this is the assertion that the support is real
    // rather than merely present.
    const parsed = parseKeyDescription(
      keyDescription({ tee: { purposes: [2], allApplications: true, origin: 7 } }),
    );

    expect(parsed.teeEnforced.allApplications).toBe(true);
    expect(parsed.teeEnforced.origin).toBe(7);
  });

  it('reads several purposes', () => {
    const parsed = parseKeyDescription(keyDescription({ tee: { purposes: [2, 3], origin: 0 } }));
    expect(parsed.teeEnforced.purposes).toEqual([2, 3]);
  });

  it('reads allApplications by presence, whatever it holds', () => {
    // Android encodes it as NULL. A verifier that only refused `NULL` would
    // accept the same claim wearing a different tag.
    const parsed = parseKeyDescription(
      keyDescription({ software: { extra: highContext(600, integer(1)) } }),
    );
    expect(parsed.softwareEnforced.allApplications).toBe(true);
  });

  it('ignores the many fields it does not consult', () => {
    // A real list carries dozens of entries. Skipping them by tag rather than
    // counting is what keeps one unfamiliar field from shifting every reading
    // that follows.
    const parsed = parseKeyDescription(
      keyDescription({
        tee: {
          purposes: [2],
          origin: 0,
          extra: context(2, set(integer(3))) + context(3, integer(256)) + highContext(701, integer(9)),
        },
      }),
    );

    expect(parsed.teeEnforced.purposes).toEqual([2]);
    expect(parsed.teeEnforced.origin).toBe(0);
  });

  it.each([
    ['a structure that is not a SEQUENCE', () => hex(octetString(CHALLENGE)), /must be a SEQUENCE/],
    [
      'a structure with fewer than eight fields',
      () => keyDescription({ fields: [integer(200), enumerated(1), integer(41)] }),
      /has 8 fields, not 3/,
    ],
    [
      'a challenge that is not an OCTET STRING',
      () =>
        keyDescription({
          fields: [
            integer(200),
            enumerated(1),
            integer(41),
            enumerated(1),
            integer(5),
            octetString(''),
            authorizationList(),
            authorizationList(),
          ],
        }),
      /attestationChallenge is not an OCTET STRING/,
    ],
    [
      'an authorization list that is not a SEQUENCE',
      () =>
        keyDescription({
          fields: [
            integer(200),
            enumerated(1),
            integer(41),
            enumerated(1),
            octetString(CHALLENGE),
            octetString(''),
            octetString('00'),
            authorizationList(),
          ],
        }),
      /softwareEnforced is not a SEQUENCE/,
    ],
    [
      'a list field that is not context-tagged',
      () => keyDescription({ tee: { extra: integer(1) } }),
      /not context-tagged/,
    ],
    [
      'a purpose that is not a SET',
      () => keyDescription({ tee: { extra: context(1, integer(2)) } }),
      /purpose is not a SET/,
    ],
    [
      'a purpose entry that is not an INTEGER',
      () => keyDescription({ tee: { extra: context(1, set(octetString('02'))) } }),
      /is not an INTEGER/,
    ],
    [
      'a negative origin',
      () => keyDescription({ tee: { extra: highContext(702, tlv('02', 'ff')) } }),
      /is negative/,
    ],
    [
      'an origin too wide to compare safely',
      () => keyDescription({ tee: { extra: highContext(702, tlv('02', '00ffffffffff')) } }),
      /implausibly large/,
    ],
    [
      'an empty origin',
      () => keyDescription({ tee: { extra: highContext(702, '') } }),
      /origin is empty/,
    ],
  ])('refuses %s', (_label, build, message) => {
    expect(() => parseKeyDescription(build())).toThrow(message);
  });

  it('never throws anything but AndroidKeyError on random input', () => {
    for (let i = 0; i < 3000; i += 1) {
      const bytes = new Uint8Array(Math.floor(Math.random() * 90));
      crypto.getRandomValues(bytes);

      try {
        parseKeyDescription(bytes);
      } catch (error) {
        if (!(error instanceof AndroidKeyError)) {
          throw new Error(
            `uncontrolled ${(error as Error).constructor.name} for ` +
              `${Buffer.from(bytes).toString('hex')}: ${(error as Error).message}`,
          );
        }
      }
    }
  });

  it('never throws anything but AndroidKeyError on a mutated structure', () => {
    // The mutations that matter are to lengths and tags, and random bytes
    // almost never form a structure the parser gets far enough into to reach
    // them.
    const valid = keyDescription({
      tee: { purposes: [2, 3], allApplications: false, origin: 0 },
      software: { purposes: [2] },
    });

    for (let index = 0; index < valid.length; index += 1) {
      for (const delta of [1, 0x7f, 0xff]) {
        const mutated = Uint8Array.from(valid);
        mutated[index] = ((mutated[index] as number) + delta) & 0xff;

        try {
          parseKeyDescription(mutated);
        } catch (error) {
          if (!(error instanceof AndroidKeyError)) {
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

describe('verifyAuthorizations', () => {
  const describeKey = (options: Parameters<typeof keyDescription>[0] = {}): KeyDescription =>
    parseKeyDescription(keyDescription(options));

  it('accepts a hardware-enforced signing key generated in the keystore', () => {
    expect(() => verifyAuthorizations(describeKey(), false)).not.toThrow();
  });

  it.each([
    ['teeEnforced', { tee: { purposes: [2], origin: 0, allApplications: true } }],
    ['softwareEnforced', { software: { allApplications: true } }],
  ])('refuses allApplications in %s', (_where, options) => {
    // A key every application on the device can sign with is not scoped to
    // one relying party — and the OS asserting the key is scoped while the
    // hardware does not is not a disagreement to resolve in the caller's
    // favour.
    expect(() => verifyAuthorizations(describeKey(options), false)).toThrow(
      /usable by every application/,
    );
  });

  it('refuses allApplications even under the looser reading', () => {
    expect(() =>
      verifyAuthorizations(describeKey({ software: { allApplications: true } }), true),
    ).toThrow(/usable by every application/);
  });

  it('refuses a key the keystore did not generate', () => {
    expect(() => verifyAuthorizations(describeKey({ tee: { purposes: [2], origin: 1 } }), false))
      .toThrow(/not generated in the keystore \(origin 1\)/);
  });

  it('refuses a key not authorized for signing', () => {
    expect(() => verifyAuthorizations(describeKey({ tee: { purposes: [3], origin: 0 } }), false))
      .toThrow(/not authorized for signing/);
  });

  it('refuses a key with no purposes stated at all', () => {
    expect(() => verifyAuthorizations(describeKey({ tee: { origin: 0 } }), false)).toThrow(
      /not authorized for signing/,
    );
  });

  it('refuses properties asserted only by software, by default', () => {
    // The default reading, and the reason for it: a software-enforced list is
    // the operating system vouching for itself.
    expect(() =>
      verifyAuthorizations(describeKey({ software: { purposes: [2], origin: 0 }, tee: {} }), false),
    ).toThrow(/no hardware-enforced origin/);
  });

  it('accepts them when the caller opts in', () => {
    expect(() =>
      verifyAuthorizations(describeKey({ software: { purposes: [2], origin: 0 }, tee: {} }), true),
    ).not.toThrow();
  });

  it('still refuses a bad software-enforced origin under the looser reading', () => {
    // Opting in widens where the properties may be stated, not what they may
    // say.
    expect(() =>
      verifyAuthorizations(describeKey({ software: { purposes: [2], origin: 2 }, tee: {} }), true),
    ).toThrow(/not generated in the keystore/);
  });

  it('prefers the hardware list when both state a property', () => {
    // Under the looser reading the software list is a fallback, never an
    // override: hardware saying "imported" must not be talked out of by the OS
    // saying "generated".
    expect(() =>
      verifyAuthorizations(
        describeKey({ software: { purposes: [2], origin: 0 }, tee: { purposes: [2], origin: 1 } }),
        true,
      ),
    ).toThrow(/not generated in the keystore \(origin 1\)/);
  });
});
