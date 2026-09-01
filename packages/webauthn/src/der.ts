/**
 * DER decoding for ECDSA signatures.
 *
 * ─── Why this exists ──────────────────────────────────────────────────────
 * WebAuthn authenticators emit ECDSA signatures in the ASN.1 DER form that
 * X.509 uses: `SEQUENCE { INTEGER r, INTEGER s }`. WebCrypto's ECDSA verify
 * expects the IEEE P1363 form instead: `r || s`, each left-padded to the
 * curve's field size. Something has to translate, and that something parses
 * attacker-controlled bytes.
 *
 * The parser below is strict — it accepts only the minimal DER encoding and
 * refuses everything else. Strictness here is not about forgery: a malformed
 * signature would fail the cryptographic check anyway. It is about the parser
 * itself. Length fields drive reads, and a lenient length parser is how a
 * signature decoder turns into an out-of-bounds read or an allocation the
 * attacker chose the size of.
 * ──────────────────────────────────────────────────────────────────────────
 */

/** Raised for any signature encoding this parser will not accept. */
export class DerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DerError';
  }
}

const SEQUENCE = 0x30;
const INTEGER = 0x02;

/**
 * Reads a DER length.
 *
 * Only the short form and the minimal long form are accepted. Long form with a
 * redundant leading zero, or with more length bytes than a signature could
 * possibly need, is refused rather than normalised — two encoders disagreeing
 * about what a length means is not a problem worth inheriting.
 */
function readLength(bytes: Uint8Array, offset: number): { length: number; next: number } {
  const first = bytes[offset];
  if (first === undefined) throw new DerError('truncated length');

  // Short form: the byte is the length.
  if (first < 0x80) return { length: first, next: offset + 1 };

  if (first === 0x80) throw new DerError('indefinite length is not valid DER');
  if (first === 0xff) throw new DerError('reserved length form');

  const count = first & 0x7f;
  // An ECDSA signature over any curve WebAuthn permits fits in two bytes of
  // length. Anything longer is not a signature we are going to accept.
  if (count > 2) throw new DerError(`length encoded in ${count} bytes is implausible`);
  if (offset + 1 + count > bytes.length) throw new DerError('truncated length');

  let length = 0;
  for (let i = 0; i < count; i += 1) {
    length = (length << 8) | (bytes[offset + 1 + i] as number);
  }

  // DER requires the shortest encoding: a value below 0x80 must use the short
  // form, and a multi-byte length must not begin with a zero byte.
  if (length < 0x80) throw new DerError('non-minimal length encoding');
  if (count === 2 && (bytes[offset + 1] as number) === 0x00) {
    throw new DerError('non-minimal length encoding');
  }

  return { length, next: offset + 1 + count };
}

/**
 * Reads one DER INTEGER and returns it as a fixed-width, unsigned big-endian
 * field element.
 */
function readInteger(bytes: Uint8Array, offset: number, size: number): {
  value: Uint8Array;
  next: number;
} {
  if (bytes[offset] !== INTEGER) {
    throw new DerError(`expected an INTEGER tag, found 0x${(bytes[offset] ?? 0).toString(16)}`);
  }

  const { length, next } = readLength(bytes, offset + 1);
  if (length === 0) throw new DerError('INTEGER of zero length');
  if (next + length > bytes.length) throw new DerError('INTEGER runs past the end of the input');

  let digits = bytes.subarray(next, next + length);
  const first = digits[0] as number;

  // DER INTEGERs are signed two's complement. A field element is never
  // negative, so a set high bit means the encoder should have prefixed a zero
  // byte; if it did not, this is not the signature we were promised.
  if (first & 0x80) throw new DerError('negative INTEGER in a signature');

  if (first === 0x00) {
    // A leading zero is legal only to clear the sign bit of the next byte.
    // Anything else is non-minimal, and a decoder that accepts padding accepts
    // an unbounded number of spellings of the same signature.
    if (length === 1) throw new DerError('INTEGER is zero');
    if (!((digits[1] as number) & 0x80)) throw new DerError('non-minimal INTEGER encoding');
    digits = digits.subarray(1);
  }

  if (digits.length > size) {
    throw new DerError(`INTEGER of ${digits.length} bytes is too large for a ${size}-byte field`);
  }

  // Left-pad into the fixed width P1363 requires.
  const value = new Uint8Array(size);
  value.set(digits, size - digits.length);
  return { value, next: next + length };
}

/**
 * Converts a DER `SEQUENCE { INTEGER r, INTEGER s }` into the raw `r || s`
 * form WebCrypto verifies, with each value left-padded to `fieldSize` bytes.
 *
 * @param fieldSize byte width of the curve's field — 32 for P-256.
 */
export function derToRawSignature(der: Uint8Array, fieldSize: number): Uint8Array {
  if (der[0] !== SEQUENCE) throw new DerError('signature is not a DER SEQUENCE');

  const { length, next: contentStart } = readLength(der, 1);

  // The declared length must describe the input exactly. Trailing bytes would
  // let one implementation read a signature another did not.
  if (contentStart + length !== der.length) {
    throw new DerError('declared SEQUENCE length does not match the input');
  }

  const r = readInteger(der, contentStart, fieldSize);
  const s = readInteger(der, r.next, fieldSize);

  if (s.next !== der.length) throw new DerError('unexpected data after the signature');

  const raw = new Uint8Array(fieldSize * 2);
  raw.set(r.value, 0);
  raw.set(s.value, fieldSize);
  return raw;
}
