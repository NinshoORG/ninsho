/**
 * Authenticator data — WebAuthn Level 3, §6.1.
 *
 * ─── The layout, and why it needs careful parsing ─────────────────────────
 * Authenticator data is a packed binary structure with no framing:
 *
 *     rpIdHash        32 bytes
 *     flags            1 byte
 *     signCount        4 bytes, big-endian
 *   [ attestedCredentialData ]   present only when the AT flag is set
 *       aaguid                  16 bytes
 *       credentialIdLength       2 bytes, big-endian
 *       credentialId       (that many) bytes
 *       credentialPublicKey     CBOR, self-delimiting — no length field
 *   [ extensions ]               present only when the ED flag is set, CBOR
 *
 * Two things make this worth writing carefully. The public key has no length
 * prefix, so the only way to find where it ends is to decode it — which is why
 * `decodeCborPrefix` exists. And `credentialIdLength` is a two-byte
 * attacker-controlled number that drives a read, which is the classic shape of
 * an out-of-bounds bug.
 *
 * Every field is bounds-checked before use, and the parse must consume the
 * buffer exactly. Leftover bytes would mean the structure was not what it
 * claimed, and a parser that shrugs at that is one half of a request-smuggling
 * pair.
 * ──────────────────────────────────────────────────────────────────────────
 */

import { CborError, decodeCborPrefix, type CborValue } from './cbor.js';

/** Raised for authenticator data this module will not accept. */
export class AuthDataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthDataError';
  }
}

/** Flag bits, WebAuthn §6.1. */
export const FLAG_USER_PRESENT = 0x01;
export const FLAG_RESERVED_1 = 0x02;
export const FLAG_USER_VERIFIED = 0x04;
export const FLAG_BACKUP_ELIGIBLE = 0x08;
export const FLAG_BACKUP_STATE = 0x10;
export const FLAG_RESERVED_2 = 0x20;
export const FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;
export const FLAG_EXTENSION_DATA = 0x80;

const RP_ID_HASH_BYTES = 32;
const FLAGS_BYTES = 1;
const SIGN_COUNT_BYTES = 4;
const AAGUID_BYTES = 16;

/** The fixed header: everything before the optional sections. */
const HEADER_BYTES = RP_ID_HASH_BYTES + FLAGS_BYTES + SIGN_COUNT_BYTES;

/**
 * Longest credential id accepted, from WebAuthn §5.8.3: "credential IDs [...]
 * MUST be at most 1023 bytes". The field itself can express 65535, so the
 * spec's own limit is the bound to enforce.
 */
const MAX_CREDENTIAL_ID_BYTES = 1023;

/** Decoded flags, as booleans rather than bit arithmetic at every call site. */
export interface AuthenticatorFlags {
  /** The user interacted with the authenticator — a touch, typically. */
  readonly userPresent: boolean;
  /** The user was verified — a PIN, a biometric. Stronger than presence. */
  readonly userVerified: boolean;
  /** The credential may be backed up (a multi-device passkey). */
  readonly backupEligible: boolean;
  /** The credential is currently backed up. */
  readonly backedUp: boolean;
  readonly attestedCredentialData: boolean;
  readonly extensionData: boolean;
}

export interface AttestedCredentialData {
  /** Identifies the authenticator model. All zeroes when not disclosed. */
  readonly aaguid: Uint8Array;
  readonly credentialId: Uint8Array;
  /** COSE-encoded, kept as bytes: the relying party stores and re-imports it. */
  readonly credentialPublicKey: Uint8Array;
}

export interface ParsedAuthenticatorData {
  readonly rpIdHash: Uint8Array;
  readonly flags: AuthenticatorFlags;
  readonly rawFlags: number;
  readonly signCount: number;
  readonly attestedCredentialData: AttestedCredentialData | undefined;
  readonly extensions: CborValue | undefined;
  /** The exact bytes parsed — the signature is computed over these. */
  readonly raw: Uint8Array;
}

function parseFlags(rawFlags: number): AuthenticatorFlags {
  return {
    userPresent: (rawFlags & FLAG_USER_PRESENT) !== 0,
    userVerified: (rawFlags & FLAG_USER_VERIFIED) !== 0,
    backupEligible: (rawFlags & FLAG_BACKUP_ELIGIBLE) !== 0,
    backedUp: (rawFlags & FLAG_BACKUP_STATE) !== 0,
    attestedCredentialData: (rawFlags & FLAG_ATTESTED_CREDENTIAL_DATA) !== 0,
    extensionData: (rawFlags & FLAG_EXTENSION_DATA) !== 0,
  };
}

/** Parses authenticator data, requiring it to be exactly well-formed. */
export function parseAuthenticatorData(bytes: Uint8Array): ParsedAuthenticatorData {
  if (bytes.length < HEADER_BYTES) {
    throw new AuthDataError(
      `authenticator data must be at least ${HEADER_BYTES} bytes, got ${bytes.length}`,
    );
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const rpIdHash = bytes.subarray(0, RP_ID_HASH_BYTES);
  const rawFlags = bytes[RP_ID_HASH_BYTES] as number;
  const signCount = view.getUint32(RP_ID_HASH_BYTES + FLAGS_BYTES, false);
  const flags = parseFlags(rawFlags);

  // A backed-up credential that is not eligible for backup is a contradiction
  // the spec forbids outright (§6.1): "If the BE flag is 0, the BS flag MUST
  // be 0." Accepting it would mean trusting a state no honest authenticator
  // produces.
  if (!flags.backupEligible && flags.backedUp) {
    throw new AuthDataError('backup state is set on a credential that is not backup eligible');
  }

  let offset = HEADER_BYTES;
  let attestedCredentialData: AttestedCredentialData | undefined;

  if (flags.attestedCredentialData) {
    if (bytes.length < offset + AAGUID_BYTES + 2) {
      throw new AuthDataError('attested credential data is truncated');
    }

    const aaguid = bytes.subarray(offset, offset + AAGUID_BYTES);
    offset += AAGUID_BYTES;

    const credentialIdLength = view.getUint16(offset, false);
    offset += 2;

    // Checked against the spec limit *and* against what is actually present.
    // The first stops an authenticator claiming an id longer than a credential
    // id may be; the second stops the read running off the end.
    if (credentialIdLength > MAX_CREDENTIAL_ID_BYTES) {
      throw new AuthDataError(
        `credential id of ${credentialIdLength} bytes exceeds the ` +
          `${MAX_CREDENTIAL_ID_BYTES}-byte maximum`,
      );
    }
    if (credentialIdLength === 0) {
      throw new AuthDataError('credential id is empty');
    }
    if (offset + credentialIdLength > bytes.length) {
      throw new AuthDataError('credential id runs past the end of the authenticator data');
    }

    const credentialId = bytes.subarray(offset, offset + credentialIdLength);
    offset += credentialIdLength;

    // The public key carries no length, so its extent comes from decoding it.
    // The bytes are kept rather than the decoded value: the relying party
    // stores exactly what it was given and re-imports it every time.
    let bytesRead: number;
    try {
      ({ bytesRead } = decodeCborPrefix(bytes.subarray(offset)));
    } catch (error) {
      throw new AuthDataError(
        `credential public key is not valid CBOR: ${
          error instanceof CborError ? error.message : 'unknown error'
        }`,
      );
    }

    const credentialPublicKey = bytes.subarray(offset, offset + bytesRead);
    offset += bytesRead;

    attestedCredentialData = { aaguid, credentialId, credentialPublicKey };
  }

  let extensions: CborValue | undefined;

  if (flags.extensionData) {
    try {
      const decoded = decodeCborPrefix(bytes.subarray(offset));
      extensions = decoded.value;
      offset += decoded.bytesRead;
    } catch (error) {
      throw new AuthDataError(
        `extension data is not valid CBOR: ${
          error instanceof CborError ? error.message : 'unknown error'
        }`,
      );
    }

    if (!(extensions instanceof Map)) {
      throw new AuthDataError('extension data is not a CBOR map');
    }
  }

  // The parse must land exactly on the end. Trailing bytes mean the structure
  // was not what its flags described, and treating the remainder as padding is
  // how one parser comes to disagree with another about the same message.
  if (offset !== bytes.length) {
    throw new AuthDataError(
      `${bytes.length - offset} unexpected trailing bytes in authenticator data`,
    );
  }

  return {
    rpIdHash,
    flags,
    rawFlags,
    signCount,
    attestedCredentialData,
    extensions,
    raw: bytes,
  };
}
