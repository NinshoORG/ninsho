/**
 * Android Keystore key attestation — WebAuthn §8.4, Android `KeyDescription`.
 *
 * ─── What this format proves, and why the extension matters ───────────────
 * The signature in an `android-key` statement is over the ceremony, the way
 * `packed`'s is, and the attestation certificate's key is the credential key.
 * On its own that would say only that whoever holds the credential also holds
 * a certificate — which is what any self-signed chain can say.
 *
 * The proof lives in an extension Android's Keystore puts in the certificate
 * it issues (`1.3.6.1.4.1.11129.2.1.17`), and reading it is the whole job:
 *
 *   - `attestationChallenge` must equal this ceremony's `clientDataHash`. The
 *     challenge is chosen when the key is *generated*, so a certificate
 *     carrying this ceremony's hash is one Keystore minted for this
 *     registration and could not have minted earlier.
 *   - `allApplications` must be absent from both authorization lists. A key
 *     marked usable by every application on the device is not scoped to this
 *     relying party, and a credential another app can sign with is not a
 *     credential.
 *   - `origin` must be `KM_ORIGIN_GENERATED` and `purpose` must include
 *     `KM_PURPOSE_SIGN` — the key was generated in the keystore rather than
 *     imported into it, and it is a signing key.
 *
 * ─── The list the checks are read from ────────────────────────────────────
 * Those properties appear twice: once in `softwareEnforced`, which is the
 * Android OS's word, and once in `teeEnforced`, which is the secure hardware's.
 * WebAuthn §8.4 lets a relying party use either. This reads `teeEnforced` by
 * default, because a software-enforced authorization list is the operating
 * system vouching for itself — and if the OS's word were enough there would be
 * no reason to be doing attestation at all. `allowSoftwareEnforcedAndroidKey`
 * opts into the looser reading for callers who need emulators or
 * TEE-less devices to register.
 *
 * The extension is attacker-supplied DER, so every field is located by tag
 * rather than by position, and anything that is not the structure it claims to
 * be is refused rather than guessed at.
 * ──────────────────────────────────────────────────────────────────────────
 */

import { Asn1Error, children, readTlv, type Tlv } from './asn1.js';

/** Raised for a `KeyDescription` this parser will not accept. */
export class AndroidKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AndroidKeyError';
  }
}

/** `id-attestation` — where Android Keystore puts the key description. */
export const ANDROID_KEY_ATTESTATION_OID = '1.3.6.1.4.1.11129.2.1.17';

/** `KM_ORIGIN_GENERATED`: the key was created inside the keystore. */
export const KM_ORIGIN_GENERATED = 0;

/** `KM_PURPOSE_SIGN`. */
export const KM_PURPOSE_SIGN = 2;

/** Context tag numbers inside an `AuthorizationList`. */
const TAG_PURPOSE = 1;
const TAG_ALL_APPLICATIONS = 600;
const TAG_ORIGIN = 702;

const TAG_INTEGER = 0x02;
const TAG_OCTET_STRING = 0x04;
const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;

/** The fields of an `AuthorizationList` this verification consults. */
export interface AuthorizationList {
  /** `purpose [1] SET OF INTEGER`, when present. */
  readonly purposes: readonly number[] | undefined;
  /** Whether `allApplications [600]` is present at all. Its value is irrelevant. */
  readonly allApplications: boolean;
  /** `origin [702] INTEGER`, when present. */
  readonly origin: number | undefined;
}

/** The parsed key attestation extension. */
export interface KeyDescription {
  readonly attestationChallenge: Uint8Array;
  readonly softwareEnforced: AuthorizationList;
  readonly teeEnforced: AuthorizationList;
}

/**
 * Reads a small non-negative INTEGER.
 *
 * Keystore's enumerations are all small. A field wide enough to lose precision
 * in a JavaScript number is refused rather than truncated, because a truncated
 * comparison against `KM_ORIGIN_GENERATED` could succeed by accident.
 */
function readSmallInteger(bytes: Uint8Array, tlv: Tlv, what: string): number {
  if (tlv.tag !== TAG_INTEGER) {
    throw new AndroidKeyError(`${what} is not an INTEGER`);
  }

  const content = bytes.subarray(tlv.start, tlv.end);
  if (content.length === 0) throw new AndroidKeyError(`${what} is an empty INTEGER`);
  if (content.length > 4) throw new AndroidKeyError(`${what} is implausibly large`);
  if ((content[0] as number) & 0x80) throw new AndroidKeyError(`${what} is negative`);

  let value = 0;
  for (const byte of content) value = value * 256 + byte;
  return value;
}

/**
 * Parses the fields of an `AuthorizationList` that §8.4 consults.
 *
 * Every DER read below can fail on a malformed list, and `Asn1Error` escaping
 * here would be an uncontrolled throw out of a parser whose contract is
 * `AndroidKeyError`. Wrapped in one place rather than at each call site: the
 * walk has half a dozen reads and adding a `try` to each is how one gets
 * missed.
 */
function parseAuthorizationList(bytes: Uint8Array, tlv: Tlv, what: string): AuthorizationList {
  try {
    return readAuthorizationList(bytes, tlv, what);
  } catch (error) {
    if (error instanceof AndroidKeyError) throw error;
    throw new AndroidKeyError(
      error instanceof Asn1Error ? `${what}: ${error.message}` : `${what} could not be read`,
    );
  }
}

function readAuthorizationList(bytes: Uint8Array, tlv: Tlv, what: string): AuthorizationList {
  if (tlv.tag !== TAG_SEQUENCE) {
    throw new AndroidKeyError(`${what} is not a SEQUENCE`);
  }

  let purposes: number[] | undefined;
  let allApplications = false;
  let origin: number | undefined;

  // Located by tag, never by position: the list is a long run of optional
  // fields, and counting through it would make one absent entry shift every
  // reading that follows.
  for (const field of children(bytes, tlv, 6)) {
    // Every entry is context-specific and constructed — `[n] EXPLICIT`, so the
    // real value is the single child inside.
    if ((field.tag & 0xc0) !== 0x80) {
      throw new AndroidKeyError(`${what} holds a field that is not context-tagged`);
    }

    if (field.number === TAG_ALL_APPLICATIONS) {
      // Present is all that matters. Android encodes it as NULL, but a
      // relying party that only refused `NULL` would accept the same claim
      // wearing a different tag.
      allApplications = true;
      continue;
    }

    if (field.number === TAG_PURPOSE) {
      const inner = children(bytes, field, 7)[0];
      if (inner === undefined || inner.tag !== TAG_SET) {
        throw new AndroidKeyError(`${what}.purpose is not a SET`);
      }
      purposes = children(bytes, inner, 8).map((entry) =>
        readSmallInteger(bytes, entry, `${what}.purpose entry`),
      );
      continue;
    }

    if (field.number === TAG_ORIGIN) {
      const inner = children(bytes, field, 7)[0];
      if (inner === undefined) throw new AndroidKeyError(`${what}.origin is empty`);
      origin = readSmallInteger(bytes, inner, `${what}.origin`);
    }
  }

  return {
    purposes,
    allApplications,
    origin,
  };
}

/**
 * Parses the Android key attestation extension.
 *
 * `attestationChallenge` sits at a fixed position in `KeyDescription` — unlike
 * the authorization lists, the outer sequence has no optional fields, so the
 * index is stable across every schema version Android has published. The count
 * is checked first so a short structure cannot read past its end.
 */
export function parseKeyDescription(extension: Uint8Array): KeyDescription {
  let root: Tlv;
  try {
    root = readTlv(extension, 0);
  } catch (error) {
    throw new AndroidKeyError(
      error instanceof Asn1Error ? error.message : 'the key description could not be read',
    );
  }

  if (root.tag !== TAG_SEQUENCE) {
    throw new AndroidKeyError('a KeyDescription must be a SEQUENCE');
  }

  let fields: Tlv[];
  try {
    fields = children(extension, root, 5);
  } catch (error) {
    throw new AndroidKeyError(
      error instanceof Asn1Error ? error.message : 'the key description could not be read',
    );
  }

  if (fields.length < 8) {
    throw new AndroidKeyError(`a KeyDescription has 8 fields, not ${fields.length}`);
  }

  const challenge = fields[4] as Tlv;
  if (challenge.tag !== TAG_OCTET_STRING) {
    throw new AndroidKeyError('attestationChallenge is not an OCTET STRING');
  }

  return {
    attestationChallenge: extension.subarray(challenge.start, challenge.end),
    softwareEnforced: parseAuthorizationList(extension, fields[6] as Tlv, 'softwareEnforced'),
    teeEnforced: parseAuthorizationList(extension, fields[7] as Tlv, 'teeEnforced'),
  };
}

/**
 * Checks the authorization properties §8.4 requires.
 *
 * `allApplications` is refused wherever it appears — a key every application
 * can use is not scoped to a relying party, and the OS asserting the key is
 * scoped while the hardware does not is not a disagreement worth resolving in
 * the caller's favour. The remaining checks read the list named by
 * `useSoftwareEnforced`.
 */
export function verifyAuthorizations(
  description: KeyDescription,
  useSoftwareEnforced: boolean,
): void {
  if (description.softwareEnforced.allApplications || description.teeEnforced.allApplications) {
    throw new AndroidKeyError(
      'the attested key is marked usable by every application, so it is not scoped to this relying party',
    );
  }

  const tee = description.teeEnforced;
  const software = description.softwareEnforced;

  // The union, when the caller opted into it: §8.4 permits reading either
  // list, and a property asserted by hardware still counts when the looser
  // reading is in force.
  const origin = useSoftwareEnforced ? (tee.origin ?? software.origin) : tee.origin;
  const purposes = useSoftwareEnforced ? (tee.purposes ?? software.purposes) : tee.purposes;

  if (origin === undefined) {
    throw new AndroidKeyError(
      useSoftwareEnforced
        ? 'the key description states no origin'
        : 'the key description states no hardware-enforced origin; the key may not be in secure hardware',
    );
  }
  if (origin !== KM_ORIGIN_GENERATED) {
    throw new AndroidKeyError(
      `the attested key was not generated in the keystore (origin ${origin})`,
    );
  }

  if (purposes === undefined || !purposes.includes(KM_PURPOSE_SIGN)) {
    throw new AndroidKeyError('the attested key is not authorized for signing');
  }
}
