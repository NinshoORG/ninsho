/**
 * A minimal DER reader, for the one thing X.509 parsing is still needed for.
 *
 * ─── Why this is so small ─────────────────────────────────────────────────
 * Node's `X509Certificate` already parses certificates, verifies signatures,
 * checks issuance and reports `ca` — all of it vetted code that has seen far
 * more scrutiny than anything written here would. Hand-rolling an X.509 parser
 * to duplicate that would be inventing exactly the kind of primitive this
 * project refuses to invent.
 *
 * What `X509Certificate` does not expose is an arbitrary extension by OID, and
 * FIDO puts the AAGUID in one (`1.3.6.1.4.1.45724.1.1.4`). So this file does
 * the smallest possible thing: walk a certificate's DER far enough to find one
 * extension, and stop.
 *
 * The input is an attestation certificate supplied by the browser, so every
 * length is bounds-checked before it is used and the walk refuses anything it
 * does not recognise rather than guessing.
 * ──────────────────────────────────────────────────────────────────────────
 */

/** Raised for any DER this reader will not accept. */
export class Asn1Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'Asn1Error';
  }
}

/** DER tags this reader needs to recognise. */
const TAG_BOOLEAN = 0x01;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
/** Context-specific, constructed, tag number 3 — `extensions [3]` in a TBSCertificate. */
const TAG_EXTENSIONS = 0xa3;

/**
 * How deep the walk may go.
 *
 * Certificates are shallow. A bound stops a crafted structure from driving the
 * recursive descent into a stack overflow, which costs an attacker nothing to
 * attempt.
 */
const MAX_DEPTH = 12;

/** One tag-length-value triple, with absolute offsets into the buffer. */
export interface Tlv {
  /**
   * The leading identifier byte — class, constructed bit and, for tag numbers
   * under 31, the number itself. Comparisons against constants like `0x30`
   * read against this.
   */
  readonly tag: number;
  /**
   * The decoded tag number.
   *
   * Equal to `tag & 0x1f` for the usual single-byte form. Android's key
   * attestation extension uses tag numbers in the hundreds, which DER encodes
   * across several bytes, and those are only legible here.
   */
  readonly number: number;
  /** First byte of the content. */
  readonly start: number;
  /** One past the last byte of the content. */
  readonly end: number;
  /** One past the last byte of the whole TLV, including its header. */
  readonly next: number;
}

/**
 * Reads one TLV at `offset`.
 *
 * Only definite lengths are accepted. BER's indefinite form is not valid DER,
 * and accepting it would mean supporting a second encoding of the same
 * certificate — the classic route to two implementations disagreeing about
 * what a document said.
 */
export function readTlv(bytes: Uint8Array, offset: number): Tlv {
  if (offset + 2 > bytes.length) {
    throw new Asn1Error(`truncated TLV header at offset ${offset}`);
  }

  const tag = bytes[offset] as number;
  let cursor = offset + 1;
  let number = tag & 0x1f;

  if (number === 0x1f) {
    // High-tag-number form: base-128 groups, continuation bit set on all but
    // the last. Android's key attestation extension puts its authorization
    // fields at tag numbers like 600 and 702, so refusing this form would mean
    // refusing to read a structure that is perfectly valid DER.
    number = 0;
    for (let seen = 0; ; seen += 1) {
      if (cursor >= bytes.length) throw new Asn1Error('truncated multi-byte tag');
      // Three groups reach 2,097,151. Nothing here uses a tag number remotely
      // that large, and an unbounded loop over attacker input is not something
      // to leave open.
      if (seen >= 3) throw new Asn1Error('tag number is implausibly large');

      const byte = bytes[cursor] as number;
      cursor += 1;
      // DER requires the shortest encoding, so the first group cannot be zero.
      if (seen === 0 && (byte & 0x7f) === 0) throw new Asn1Error('non-minimal tag encoding');
      number = (number << 7) | (byte & 0x7f);
      if ((byte & 0x80) === 0) break;
    }
    if (number < 0x1f) throw new Asn1Error('non-minimal tag encoding');
  }

  if (cursor >= bytes.length) {
    throw new Asn1Error(`truncated TLV header at offset ${offset}`);
  }

  const first = bytes[cursor] as number;
  const lengthStart = cursor;
  let length: number;
  let contentStart: number;

  if (first < 0x80) {
    length = first;
    contentStart = lengthStart + 1;
  } else {
    if (first === 0x80) throw new Asn1Error('indefinite length is not valid DER');
    if (first === 0xff) throw new Asn1Error('reserved length form');

    const count = first & 0x7f;
    // A certificate field longer than 16 MB is not a certificate field.
    if (count > 3) throw new Asn1Error(`length encoded in ${count} bytes is implausible`);
    if (lengthStart + 1 + count > bytes.length) throw new Asn1Error('truncated length');

    length = 0;
    for (let i = 0; i < count; i += 1) {
      length = (length << 8) | (bytes[lengthStart + 1 + i] as number);
    }
    // DER requires the shortest encoding.
    if (length < 0x80) throw new Asn1Error('non-minimal length encoding');
    if ((bytes[lengthStart + 1] as number) === 0x00) {
      throw new Asn1Error('non-minimal length encoding');
    }

    contentStart = lengthStart + 1 + count;
  }

  const end = contentStart + length;
  if (end > bytes.length) {
    throw new Asn1Error(`TLV of ${length} bytes runs past the end of the input`);
  }

  return { tag, number, start: contentStart, end, next: end };
}

/** Reads the immediate children of a constructed TLV. */
export function children(bytes: Uint8Array, parent: Tlv, depth: number): Tlv[] {
  if (depth > MAX_DEPTH) {
    throw new Asn1Error(`nesting deeper than ${MAX_DEPTH} is not accepted`);
  }

  const out: Tlv[] = [];
  let offset = parent.start;
  while (offset < parent.end) {
    const tlv = readTlv(bytes, offset);
    if (tlv.next > parent.end) {
      throw new Asn1Error('a child TLV runs past the end of its parent');
    }
    out.push(tlv);
    offset = tlv.next;
  }
  return out;
}

/**
 * Encodes a dotted OID string as DER content bytes.
 *
 * Done once per lookup and compared against the certificate's bytes, rather
 * than decoding every OID in the certificate into a string. Comparing bytes
 * avoids a decoder that could disagree with an encoder about, say, a
 * non-minimal component.
 */
export function encodeOid(dotted: string): Uint8Array {
  const parts = dotted.split('.').map((p) => {
    const value = Number(p);
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Asn1Error(`invalid OID component: ${p}`);
    }
    return value;
  });

  if (parts.length < 2) throw new Asn1Error('an OID needs at least two components');

  const first = parts[0] as number;
  const second = parts[1] as number;
  const bytes: number[] = [first * 40 + second];

  for (const part of parts.slice(2)) {
    if (part === 0) {
      bytes.push(0);
      continue;
    }
    // Base-128, most significant group first, continuation bit on all but the
    // last byte.
    const group: number[] = [];
    let value = part;
    while (value > 0) {
      group.unshift(value & 0x7f);
      value >>>= 7;
    }
    for (let i = 0; i < group.length - 1; i += 1) {
      bytes.push((group[i] as number) | 0x80);
    }
    bytes.push(group[group.length - 1] as number);
  }

  return new Uint8Array(bytes);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Finds an X.509 extension's value by OID.
 *
 * Walks `Certificate → TBSCertificate → extensions [3] → Extension`, exactly
 * as RFC 5280 §4.1 lays it out, and returns the contents of the extension's
 * OCTET STRING — the `extnValue`, still DER-encoded.
 *
 * @returns the extension value, or `undefined` if the certificate has no such
 *   extension. A certificate with no extensions at all is not an error: plenty
 *   of legitimate certificates have none.
 */
export function findExtension(certificate: Uint8Array, oid: string): Uint8Array | undefined {
  const target = encodeOid(oid);

  const cert = readTlv(certificate, 0);
  if (cert.tag !== TAG_SEQUENCE) {
    throw new Asn1Error('a certificate must be a SEQUENCE');
  }

  const tbs = children(certificate, cert, 1)[0];
  if (tbs === undefined || tbs.tag !== TAG_SEQUENCE) {
    throw new Asn1Error('a certificate must begin with a TBSCertificate SEQUENCE');
  }

  // `extensions` is the last field and is context-tagged [3]. Scanning for the
  // tag rather than counting fields means an optional field being present or
  // absent cannot shift the index and silently read the wrong thing.
  const extensionsHolder = children(certificate, tbs, 2).find((c) => c.tag === TAG_EXTENSIONS);
  if (extensionsHolder === undefined) return undefined;

  const extensionsSeq = children(certificate, extensionsHolder, 3)[0];
  if (extensionsSeq === undefined || extensionsSeq.tag !== TAG_SEQUENCE) {
    throw new Asn1Error('extensions [3] must contain a SEQUENCE');
  }

  for (const extension of children(certificate, extensionsSeq, 4)) {
    if (extension.tag !== TAG_SEQUENCE) {
      throw new Asn1Error('each extension must be a SEQUENCE');
    }

    const fields = children(certificate, extension, 5);
    const oidField = fields[0];
    if (oidField === undefined || oidField.tag !== TAG_OID) {
      throw new Asn1Error('an extension must begin with an OID');
    }

    if (!bytesEqual(certificate.subarray(oidField.start, oidField.end), target)) continue;

    // The `critical` BOOLEAN is optional and sits between the OID and the
    // value, so the value is whichever OCTET STRING follows.
    const valueField = fields.find((f, index) => index > 0 && f.tag === TAG_OCTET_STRING);
    if (valueField === undefined) {
      throw new Asn1Error('an extension must carry an OCTET STRING value');
    }
    // A `critical` field, if present, must be a BOOLEAN — anything else means
    // this is not the structure it claims to be.
    const middle = fields[1];
    if (middle !== undefined && middle !== valueField && middle.tag !== TAG_BOOLEAN) {
      throw new Asn1Error('unexpected field between an extension OID and its value');
    }

    return certificate.subarray(valueField.start, valueField.end);
  }

  return undefined;
}
