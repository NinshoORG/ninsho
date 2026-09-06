/**
 * A minimal X.509 certificate builder, for tests only.
 *
 * ─── Why build certificates rather than commit them ───────────────────────
 * Attestation verification needs real certificate chains to test against.
 * Three ways to get them, and two are worse:
 *
 *   Committed fixtures expire. A test that starts failing in 2035 because a
 *   fixture aged out is a test nobody will diagnose quickly.
 *
 *   Shelling out to `openssl` makes the suite depend on a CLI that differs by
 *   platform — on this project's own Windows checkout `req -x509` mangles the
 *   subject through mingw path conversion, while CI's Linux openssl does not.
 *   Tests that pass on one machine and not another are worse than no tests.
 *
 *   So: build them here. Deterministic, cross-platform, no external tool, and
 *   every certificate produced is cross-checked by Node's own
 *   `X509Certificate` parser in the tests — if this encoder were wrong, that
 *   parser would reject its output.
 *
 * This is a test fixture generator and nothing more. It is not a certificate
 * authority, it does not belong anywhere near production, and it lives in the
 * `testing` entry point so it never reaches the verifier's bundle.
 * ──────────────────────────────────────────────────────────────────────────
 */

import { createSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { encodeOid } from './asn1.js';

// ─── DER encoding primitives ───────────────────────────────────────────────

function encodeLength(length: number): Uint8Array {
  if (length < 0x80) return new Uint8Array([length]);

  const bytes: number[] = [];
  let value = length;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value >>>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, c) => sum + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** Wraps content in a tag and its length. */
function tlv(tag: number, content: Uint8Array): Uint8Array {
  return concat([new Uint8Array([tag]), encodeLength(content.length), content]);
}

const sequence = (...parts: Uint8Array[]): Uint8Array => tlv(0x30, concat(parts));
const set = (...parts: Uint8Array[]): Uint8Array => tlv(0x31, concat(parts));
const octetString = (content: Uint8Array): Uint8Array => tlv(0x04, content);
const boolean_ = (value: boolean): Uint8Array => tlv(0x01, new Uint8Array([value ? 0xff : 0x00]));
const oid = (dotted: string): Uint8Array => tlv(0x06, encodeOid(dotted));
const utf8String = (value: string): Uint8Array => tlv(0x0c, new TextEncoder().encode(value));

/** EXPLICIT context-specific tag, constructed. */
const context = (number: number, content: Uint8Array): Uint8Array => tlv(0xa0 | number, content);

/**
 * EXPLICIT context-specific tag, constructed, for tag numbers of 31 or more.
 *
 * Android's authorization lists put fields at numbers like 600 and 702, which
 * DER writes as base-128 groups after a leading `0xbf`.
 */
function highContext(number: number, content: Uint8Array): Uint8Array {
  if (number < 0x1f) throw new Error('use `context` for tag numbers under 31');

  const groups: number[] = [];
  let value = number;
  while (value > 0) {
    groups.unshift(value & 0x7f);
    value >>>= 7;
  }
  const tag = [0xbf];
  for (let i = 0; i < groups.length - 1; i += 1) tag.push((groups[i] as number) | 0x80);
  tag.push(groups[groups.length - 1] as number);

  return concat([new Uint8Array(tag), encodeLength(content.length), content]);
}

/** ENUMERATED, which is how Keystore writes its security levels. */
const enumerated = (value: number): Uint8Array => tlv(0x0a, new Uint8Array([value]));

/**
 * A positive INTEGER, encoded minimally.
 *
 * Both halves of the rule matter, and only one of them is obvious. A set high
 * bit needs a leading zero, or the value reads as negative — that half is easy
 * to remember. The other half is that a leading zero which is *not* needed is
 * invalid DER, and a random serial number begins with one about once in every
 * 256 certificates. Encoders that skip the trim produce a certificate that
 * looks fine until a real X.509 parser refuses it, and the failure surfaces
 * somewhere else entirely — as a chain that would not verify.
 */
function integer(value: Uint8Array | number): Uint8Array {
  let digits: Uint8Array;
  if (typeof value === 'number') {
    const bytes: number[] = [];
    let n = value;
    do {
      bytes.unshift(n & 0xff);
      n >>>= 8;
    } while (n > 0);
    digits = new Uint8Array(bytes);
  } else {
    digits = value;
  }

  // Drop leading zeros that carry no sign information.
  let start = 0;
  while (
    start < digits.length - 1 &&
    digits[start] === 0 &&
    ((digits[start + 1] as number) & 0x80) === 0
  ) {
    start += 1;
  }
  digits = digits.subarray(start);

  if ((digits[0] as number) & 0x80) {
    const padded = new Uint8Array(digits.length + 1);
    padded.set(digits, 1);
    digits = padded;
  }
  return tlv(0x02, digits);
}

/** A BIT STRING with no unused trailing bits. */
const bitString = (content: Uint8Array): Uint8Array =>
  tlv(0x03, concat([new Uint8Array([0x00]), content]));

/** UTCTime, `YYMMDDHHMMSSZ`. Valid for 1950–2049, which covers every fixture. */
function utcTime(date: Date): Uint8Array {
  const pad = (n: number): string => String(n).padStart(2, '0');
  const text =
    pad(date.getUTCFullYear() % 100) +
    pad(date.getUTCMonth() + 1) +
    pad(date.getUTCDate()) +
    pad(date.getUTCHours()) +
    pad(date.getUTCMinutes()) +
    pad(date.getUTCSeconds()) +
    'Z';
  return tlv(0x17, new TextEncoder().encode(text));
}

/** A Name carrying a single CN. Enough to distinguish fixtures from each other. */
const name = (commonName: string): Uint8Array =>
  commonName.length === 0
    ? // An empty Name — no RDNs at all. WebAuthn 8.3.1 requires it of an AIK
      // certificate, so that the certificate does not itself become a device
      // identifier.
      sequence()
    : sequence(set(sequence(oid('2.5.4.3'), utf8String(commonName))));

// ─── Certificate construction ──────────────────────────────────────────────

/** `ecdsa-with-SHA256`. */
const ECDSA_SHA256 = sequence(oid('1.2.840.10045.4.3.2'));

/** FIDO's AAGUID extension (`id-fido-gen-ce-aaguid`). */
export const FIDO_AAGUID_OID = '1.3.6.1.4.1.45724.1.1.4';

/** Apple's ceremony-nonce extension (`id-apple-anonymous-attestation`). */
export const APPLE_NONCE_OID = '1.2.840.113635.100.8.2';

/** Android Keystore's key attestation extension. */
export const ANDROID_KEY_OID = '1.3.6.1.4.1.11129.2.1.17';
const BASIC_CONSTRAINTS_OID = '2.5.29.19';
const EKU_OID = '2.5.29.37';

function extension(oidText: string, value: Uint8Array, critical = false): Uint8Array {
  return sequence(
    oid(oidText),
    ...(critical ? [boolean_(true)] : []),
    octetString(value),
  );
}

/** The `AuthorizationList` fields WebAuthn §8.4 reads. */
export interface AndroidAuthorizations {
  /** `purpose [1]`. `2` is `KM_PURPOSE_SIGN`. */
  readonly purposes?: readonly number[];
  /** `allApplications [600]`. Its presence alone is what §8.4 refuses. */
  readonly allApplications?: boolean;
  /** `origin [702]`. `0` is `KM_ORIGIN_GENERATED`. */
  readonly origin?: number;
}

/** Encodes an `AuthorizationList`, fields ascending by tag as Keystore writes them. */
function authorizationList(list: AndroidAuthorizations): Uint8Array {
  const parts: Uint8Array[] = [];
  if (list.purposes !== undefined) {
    parts.push(context(1, set(...list.purposes.map((p) => integer(p)))));
  }
  if (list.allApplications === true) {
    parts.push(highContext(600, tlv(0x05, new Uint8Array(0))));
  }
  if (list.origin !== undefined) {
    parts.push(highContext(702, integer(list.origin)));
  }
  return sequence(...parts);
}

/** Encodes a `KeyDescription`, the payload of Android's attestation extension. */
function keyDescription(options: {
  challenge: Uint8Array;
  softwareEnforced?: AndroidAuthorizations;
  teeEnforced?: AndroidAuthorizations;
  fieldCount?: number;
}): Uint8Array {
  const fields = [
    integer(200), // attestationVersion
    enumerated(1), // attestationSecurityLevel — TrustedEnvironment
    integer(41), // keymasterVersion
    enumerated(1), // keymasterSecurityLevel
    octetString(options.challenge),
    octetString(new Uint8Array(0)), // uniqueId
    authorizationList(options.softwareEnforced ?? {}),
    authorizationList(options.teeEnforced ?? { purposes: [2], origin: 0 }),
  ];

  return sequence(...fields.slice(0, options.fieldCount ?? fields.length));
}

export interface CertificateKeyPair {
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
}

/** A generated certificate and the key that signs things on its behalf. */
export interface GeneratedCertificate extends CertificateKeyPair {
  /** DER bytes, ready for `new X509Certificate(...)` or an `x5c` entry. */
  readonly der: Uint8Array;
  readonly subject: string;
}

export interface CreateCertificateOptions {
  readonly subject: string;
  /** Omit to self-sign, which is how a root is made. */
  readonly issuer?: GeneratedCertificate;
  readonly isCa?: boolean;
  /** Embeds the FIDO AAGUID extension carrying these 16 bytes. */
  readonly aaguid?: Uint8Array;
  /**
   * Embeds Apple's nonce extension, `SEQUENCE { [1] { OCTET STRING nonce } }`.
   *
   * Apple's format has no signature field: this nonce, equal to
   * `SHA-256(authData || clientDataHash)`, is the entire binding between the
   * certificate and one ceremony.
   */
  readonly appleNonce?: Uint8Array;
  /**
   * Extended key usages, as dotted OIDs.
   *
   * A TPM attestation identity key must declare `tcg-kp-AIKCertificate`
   * (2.23.133.8.3); §8.3.1 also wants an empty subject, which `subject: ''`
   * produces.
   */
  readonly extendedKeyUsage?: readonly string[];
  /**
   * Embeds Android Keystore's key attestation extension.
   *
   * `challenge` is what the verifier compares against `clientDataHash`, and
   * the two authorization lists are what it reads the key's properties from.
   * Both default to the shape a real device produces: nothing software
   * enforced, and a hardware-enforced signing key generated in the keystore.
   */
  readonly androidKey?: {
    readonly challenge: Uint8Array;
    readonly softwareEnforced?: AndroidAuthorizations;
    readonly teeEnforced?: AndroidAuthorizations;
    /** Truncates the outer SEQUENCE to fewer than its eight fields. */
    readonly fieldCount?: number;
  };
  /**
   * Serial number bytes. Random when omitted.
   *
   * Settable so the encoding edge cases — a leading zero byte, a set high bit
   * — can be exercised on purpose rather than waited for.
   */
  readonly serialNumber?: Uint8Array;
  readonly notBefore?: Date;
  readonly notAfter?: Date;
  /** Reuse an existing key instead of generating one. */
  readonly keyPair?: CertificateKeyPair;
  /** Sign with the wrong key, to produce a chain that must fail to verify. */
  readonly signWith?: KeyObject;
}

/** Builds a P-256 X.509 v3 certificate. */
export function createCertificate(options: CreateCertificateOptions): GeneratedCertificate {
  const keyPair =
    options.keyPair ?? (generateKeyPairSync('ec', { namedCurve: 'P-256' }) as CertificateKeyPair);

  const spki = new Uint8Array(
    keyPair.publicKey.export({ type: 'spki', format: 'der' }) as Buffer,
  );

  const notBefore = options.notBefore ?? new Date('2020-01-01T00:00:00Z');
  const notAfter = options.notAfter ?? new Date('2040-01-01T00:00:00Z');

  const extensions: Uint8Array[] = [
    // basicConstraints. A leaf encodes an empty SEQUENCE, which means cA is
    // absent and therefore false — the shape a real attestation certificate
    // has, and the one the verifier insists on.
    extension(
      BASIC_CONSTRAINTS_OID,
      options.isCa === true ? sequence(boolean_(true)) : sequence(),
      true,
    ),
  ];

  if (options.aaguid) {
    // FIDO wraps the AAGUID in its own OCTET STRING inside the extension's
    // OCTET STRING value.
    extensions.push(extension(FIDO_AAGUID_OID, octetString(options.aaguid)));
  }

  if (options.extendedKeyUsage && options.extendedKeyUsage.length > 0) {
    extensions.push(
      extension(EKU_OID, sequence(...options.extendedKeyUsage.map((usage) => oid(usage)))),
    );
  }

  if (options.appleNonce) {
    extensions.push(
      extension(APPLE_NONCE_OID, sequence(context(1, octetString(options.appleNonce)))),
    );
  }

  if (options.androidKey) {
    extensions.push(extension(ANDROID_KEY_OID, keyDescription(options.androidKey)));
  }

  let serial: Uint8Array;
  if (options.serialNumber === undefined) {
    serial = new Uint8Array(8);
    crypto.getRandomValues(serial);
  } else {
    serial = options.serialNumber;
  }

  const issuerName = options.issuer ? options.issuer.subject : options.subject;

  const tbs = sequence(
    context(0, integer(2)), // version v3
    integer(serial),
    ECDSA_SHA256,
    name(issuerName),
    sequence(utcTime(notBefore), utcTime(notAfter)),
    name(options.subject),
    spki,
    context(3, sequence(...extensions)),
  );

  const signingKey = options.signWith ?? options.issuer?.privateKey ?? keyPair.privateKey;
  const signature = new Uint8Array(createSign('SHA256').update(tbs).sign(signingKey));

  return {
    der: sequence(tbs, ECDSA_SHA256, bitString(signature)),
    subject: options.subject,
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
  };
}

/** A root and a leaf beneath it — the usual shape of an attestation chain. */
export interface CertificateChain {
  readonly root: GeneratedCertificate;
  readonly leaf: GeneratedCertificate;
}

export function createChain(options: { aaguid?: Uint8Array; subject?: string } = {}): CertificateChain {
  const root = createCertificate({ subject: 'Ninsho Test Root CA', isCa: true });
  const leaf = createCertificate({
    subject: options.subject ?? 'Ninsho Test Authenticator',
    issuer: root,
    ...(options.aaguid ? { aaguid: options.aaguid } : {}),
  });
  return { root, leaf };
}
