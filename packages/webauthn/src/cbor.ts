/**
 * A minimal CBOR decoder — RFC 8949, restricted to what WebAuthn uses.
 *
 * ─── Why a subset, and why written here ───────────────────────────────────
 * WebAuthn encodes attestation objects and COSE public keys in CBOR, so
 * parsing it is unavoidable. What *is* avoidable is parsing all of it.
 *
 * This decoder handles definite-length integers, byte strings, text strings,
 * arrays, maps and simple values. It rejects everything else — tags,
 * indefinite lengths, floats, streaming. That is not laziness: indefinite
 * lengths and tag handling are where CBOR implementations historically grow
 * their vulnerabilities, and WebAuthn's own encoding rules (CTAP2 canonical
 * CBOR) forbid them anyway. A parser that cannot express a construct cannot be
 * attacked through it.
 *
 * The input is attacker-controlled — it arrives from a browser, and a hostile
 * one can send anything — so every length is bounds-checked before it is used,
 * and nesting is bounded.
 * ──────────────────────────────────────────────────────────────────────────
 */

/** Raised for any input this decoder will not accept. */
export class CborError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CborError';
  }
}

/** What a decoded value can be. Maps use a Map because CBOR keys may be integers. */
export type CborValue =
  | number
  | bigint
  | string
  | Uint8Array
  | boolean
  | null
  | CborValue[]
  | Map<string | number, CborValue>;

/**
 * How deeply nested a structure may be.
 *
 * A few hundred bytes of nested arrays can otherwise drive a recursive decoder
 * into a stack overflow — a denial of service that costs the attacker nothing
 * to send.
 */
const MAX_DEPTH = 16;

/** Major types, RFC 8949 §3.1. */
const MAJOR_UNSIGNED = 0;
const MAJOR_NEGATIVE = 1;
const MAJOR_BYTES = 2;
const MAJOR_TEXT = 3;
const MAJOR_ARRAY = 4;
const MAJOR_MAP = 5;
const MAJOR_SIMPLE = 7;

class Reader {
  #offset = 0;
  readonly #view: DataView;

  constructor(readonly bytes: Uint8Array) {
    this.#view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  get offset(): number {
    return this.#offset;
  }

  get remaining(): number {
    return this.bytes.length - this.#offset;
  }

  #require(count: number): void {
    if (this.remaining < count) {
      throw new CborError(
        `truncated input: needed ${count} more bytes at offset ${this.#offset}`,
      );
    }
  }

  u8(): number {
    this.#require(1);
    return this.bytes[this.#offset++] as number;
  }

  u16(): number {
    this.#require(2);
    const value = this.#view.getUint16(this.#offset, false);
    this.#offset += 2;
    return value;
  }

  u32(): number {
    this.#require(4);
    const value = this.#view.getUint32(this.#offset, false);
    this.#offset += 4;
    return value;
  }

  u64(): bigint {
    this.#require(8);
    const value = this.#view.getBigUint64(this.#offset, false);
    this.#offset += 8;
    return value;
  }

  slice(length: number): Uint8Array {
    this.#require(length);
    const out = this.bytes.subarray(this.#offset, this.#offset + length);
    this.#offset += length;
    return out;
  }
}

/**
 * Reads the argument that follows a major type.
 *
 * Additional-information values 28–30 are reserved and 31 means indefinite
 * length; both are refused rather than guessed at.
 */
function readArgument(reader: Reader, additional: number): number | bigint {
  if (additional < 24) return additional;

  switch (additional) {
    case 24:
      return reader.u8();
    case 25:
      return reader.u16();
    case 26:
      return reader.u32();
    case 27:
      return reader.u64();
    case 31:
      throw new CborError('indefinite-length items are not accepted');
    default:
      throw new CborError(`reserved additional information: ${additional}`);
  }
}

/** Narrows an argument to a usable length, refusing anything implausible. */
function asLength(value: number | bigint, what: string, available: number): number {
  const length = typeof value === 'bigint' ? Number(value) : value;

  if (!Number.isSafeInteger(length) || length < 0) {
    throw new CborError(`invalid ${what} length`);
  }
  // Checked against what is actually present before any allocation, so a
  // declared length of four billion cannot make the decoder reserve memory.
  if (length > available) {
    throw new CborError(`${what} length ${length} exceeds the ${available} bytes available`);
  }
  return length;
}

/**
 * `fatal` so malformed UTF-8 is rejected rather than silently replaced. A
 * replacement character would change the string's meaning with nothing to
 * indicate it had happened.
 *
 * The rethrow is not decoration. TextDecoder signals a bad sequence with a
 * `TypeError`, which would escape this module's error contract — a caller
 * writing `catch (e) { if (e instanceof CborError) ... }` would see a hostile
 * payload become an unhandled 500 rather than a clean refusal.
 */
const UTF8 = new TextDecoder('utf-8', { fatal: true });

function decodeUtf8(bytes: Uint8Array): string {
  try {
    return UTF8.decode(bytes);
  } catch {
    throw new CborError('text string is not valid UTF-8');
  }
}

function decodeValue(reader: Reader, depth: number): CborValue {
  if (depth > MAX_DEPTH) {
    throw new CborError(`nesting deeper than ${MAX_DEPTH} is not accepted`);
  }

  const initial = reader.u8();
  const major = initial >> 5;
  const additional = initial & 0x1f;

  switch (major) {
    case MAJOR_UNSIGNED: {
      const value = readArgument(reader, additional);
      return typeof value === 'bigint' && value <= BigInt(Number.MAX_SAFE_INTEGER)
        ? Number(value)
        : value;
    }

    case MAJOR_NEGATIVE: {
      const value = readArgument(reader, additional);
      // CBOR encodes -1 - n, so COSE's negative label -1 arrives as 0.
      if (typeof value === 'bigint') {
        const negated = -1n - value;
        return negated >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(negated) : negated;
      }
      return -1 - value;
    }

    case MAJOR_BYTES:
      return reader.slice(
        asLength(readArgument(reader, additional), 'byte string', reader.remaining),
      );

    case MAJOR_TEXT: {
      const bytes = reader.slice(
        asLength(readArgument(reader, additional), 'text string', reader.remaining),
      );
      return decodeUtf8(bytes);
    }

    case MAJOR_ARRAY: {
      // Each element is at least one byte, so the count cannot exceed what
      // remains — this bounds the allocation before the loop begins.
      const count = asLength(readArgument(reader, additional), 'array', reader.remaining);
      const items: CborValue[] = [];
      for (let i = 0; i < count; i += 1) items.push(decodeValue(reader, depth + 1));
      return items;
    }

    case MAJOR_MAP: {
      const count = asLength(readArgument(reader, additional), 'map', reader.remaining);
      const map = new Map<string | number, CborValue>();

      for (let i = 0; i < count; i += 1) {
        const key = decodeValue(reader, depth + 1);
        if (typeof key !== 'string' && typeof key !== 'number') {
          throw new CborError('map keys must be text strings or integers');
        }
        // A repeated key is ambiguous, and which one "wins" differs between
        // implementations — exactly the kind of disagreement an attacker uses
        // to make two systems read the same bytes differently.
        if (map.has(key)) {
          throw new CborError(`duplicate map key: ${String(key)}`);
        }
        map.set(key, decodeValue(reader, depth + 1));
      }
      return map;
    }

    case MAJOR_SIMPLE:
      switch (additional) {
        case 20:
          return false;
        case 21:
          return true;
        case 22:
          return null;
        case 23:
          throw new CborError('undefined is not accepted');
        default:
          // Floats (25–27) and other simple values have no place in WebAuthn's
          // encoding, so accepting them would only widen the parser.
          throw new CborError(`unsupported simple value: ${additional}`);
      }

    default:
      // Major type 6 is tags, which CTAP2 canonical CBOR forbids.
      throw new CborError(`unsupported major type: ${major}`);
  }
}

/**
 * Decodes a single CBOR value, requiring it to consume the whole input.
 *
 * Trailing bytes are refused. Ignoring them would let an attacker append data
 * that one parser reads and another does not — the classic route to two
 * systems disagreeing about what a message said.
 */
export function decodeCbor(bytes: Uint8Array): CborValue {
  const reader = new Reader(bytes);
  const value = decodeValue(reader, 0);

  if (reader.remaining !== 0) {
    throw new CborError(`${reader.remaining} trailing bytes after the CBOR value`);
  }
  return value;
}

/**
 * Decodes one value and reports how many bytes it used.
 *
 * Needed for attested credential data, where a COSE key is embedded in a
 * larger buffer with no length prefix — the only way to find where it ends is
 * to decode it.
 */
export function decodeCborPrefix(bytes: Uint8Array): {
  value: CborValue;
  bytesRead: number;
} {
  const reader = new Reader(bytes);
  const value = decodeValue(reader, 0);
  return { value, bytesRead: reader.offset };
}
