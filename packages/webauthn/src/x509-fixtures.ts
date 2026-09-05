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

/** A positive INTEGER, with a leading zero when the high bit would read as negative. */
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
  sequence(set(sequence(oid('2.5.4.3'), utf8String(commonName))));

// ─── Certificate construction ──────────────────────────────────────────────

/** `ecdsa-with-SHA256`. */
const ECDSA_SHA256 = sequence(oid('1.2.840.10045.4.3.2'));

/** FIDO's AAGUID extension (`id-fido-gen-ce-aaguid`). */
export const FIDO_AAGUID_OID = '1.3.6.1.4.1.45724.1.1.4';

/** Apple's ceremony-nonce extension (`id-apple-anonymous-attestation`). */
export const APPLE_NONCE_OID = '1.2.840.113635.100.8.2';
const BASIC_CONSTRAINTS_OID = '2.5.29.19';

function extension(oidText: string, value: Uint8Array, critical = false): Uint8Array {
  return sequence(
    oid(oidText),
    ...(critical ? [boolean_(true)] : []),
    octetString(value),
  );
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

  if (options.appleNonce) {
    extensions.push(
      extension(APPLE_NONCE_OID, sequence(context(1, octetString(options.appleNonce)))),
    );
  }

  const serial = new Uint8Array(8);
  crypto.getRandomValues(serial);

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
