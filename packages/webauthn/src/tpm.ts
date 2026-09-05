/**
 * TPM attestation structures — WebAuthn §8.3, TPM 2.0 Part 2.
 *
 * ─── Why this format takes more code than the others ──────────────────────
 * `packed` signs `authData || clientDataHash` directly, and `apple` carries a
 * nonce over the same bytes. A TPM signs neither. It signs a `TPMS_ATTEST`
 * structure describing a key it certifies, and the tie to the ceremony runs
 * through two indirections:
 *
 *   - `certInfo.extraData` holds a hash of `authData || clientDataHash`, which
 *     is what binds the attestation to this registration; and
 *   - `certInfo.attested.name` holds a hash of `pubArea`, which is what binds
 *     it to a particular key.
 *
 * So verifying it means parsing both structures and checking that the key the
 * TPM certified is the credential key the browser sent. Skip the second and a
 * genuine TPM attestation vouches for a key nobody attested to — the same
 * class of gap the `apple` subject-key check closes.
 *
 * Both structures are packed big-endian binary with length-prefixed fields and
 * no framing, and both arrive from a browser. Every length is bounds-checked
 * before use, and anything the parser does not recognise is refused rather
 * than skipped.
 * ──────────────────────────────────────────────────────────────────────────
 */

/** Raised for a TPM structure this parser will not accept. */
export class TpmError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TpmError';
  }
}

/** `TPM_GENERATED_VALUE` — the marker only a TPM may place. */
const TPM_GENERATED = 0xff544347;

/** `TPM_ST_ATTEST_CERTIFY`. The only attestation type WebAuthn uses. */
const TPM_ST_ATTEST_CERTIFY = 0x8017;

/** Algorithm identifiers, TPM 2.0 Part 2 §6.3. */
const TPM_ALG_RSA = 0x0001;
const TPM_ALG_SHA1 = 0x0004;
const TPM_ALG_SHA256 = 0x000b;
const TPM_ALG_SHA384 = 0x000c;
const TPM_ALG_SHA512 = 0x000d;
const TPM_ALG_ECC = 0x0023;

/** `TPM_ECC_NIST_P256`. */
const TPM_ECC_NIST_P256 = 0x0003;

/** Which digest a `nameAlg` selects. SHA-1 is refused: it is not collision-resistant. */
const NAME_ALGORITHMS: Record<number, string> = {
  [TPM_ALG_SHA256]: 'SHA-256',
  [TPM_ALG_SHA384]: 'SHA-384',
  [TPM_ALG_SHA512]: 'SHA-512',
};

/**
 * Reads packed big-endian fields, refusing to run past the end.
 *
 * The TPM structures are a sequence of sizes that drive reads, which is the
 * classic shape of an out-of-bounds bug — so the bound is checked in one place
 * rather than at each call site.
 */
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
      throw new TpmError(`truncated: needed ${count} more bytes at offset ${this.#offset}`);
    }
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

  slice(length: number): Uint8Array {
    this.#require(length);
    const out = this.bytes.subarray(this.#offset, this.#offset + length);
    this.#offset += length;
    return out;
  }

  /** A `TPM2B_*`: a two-byte size followed by that many bytes. */
  sized(what: string): Uint8Array {
    const length = this.u16();
    if (length > this.remaining) {
      throw new TpmError(`${what} declares ${length} bytes, more than the ${this.remaining} left`);
    }
    return this.slice(length);
  }
}

// ─── TPMT_PUBLIC ───────────────────────────────────────────────────────────

/** The key a TPM certified, as described in `pubArea`. */
export interface TpmPublic {
  readonly type: number;
  readonly nameAlg: number;
  /** RSA modulus, or the concatenated EC point coordinates. */
  readonly unique: Uint8Array;
  /** RSA only: the public exponent, defaulted to 65537 when the TPM sends zero. */
  readonly exponent?: number;
  /** ECC only. */
  readonly curveId?: number;
  /** EC point halves, when the key is ECC. */
  readonly x?: Uint8Array;
  readonly y?: Uint8Array;
}

/** Parses `TPMT_PUBLIC` — TPM 2.0 Part 2 §12.2.4. */
export function parseTpmPublic(bytes: Uint8Array): TpmPublic {
  const reader = new Reader(bytes);

  const type = reader.u16();
  const nameAlg = reader.u16();
  reader.u32(); // objectAttributes — not consulted; the checks that matter are below.
  reader.sized('authPolicy');

  if (type === TPM_ALG_RSA) {
    reader.u16(); // symmetric
    reader.u16(); // scheme
    reader.u16(); // keyBits
    const rawExponent = reader.u32();
    // TPM 2.0 Part 2 §12.2.3.5: zero means the default, 65537.
    const exponent = rawExponent === 0 ? 65537 : rawExponent;
    const unique = reader.sized('RSA modulus');

    if (reader.remaining !== 0) {
      throw new TpmError(`${reader.remaining} trailing bytes after TPMT_PUBLIC`);
    }
    return { type, nameAlg, unique, exponent };
  }

  if (type === TPM_ALG_ECC) {
    reader.u16(); // symmetric
    reader.u16(); // scheme
    const curveId = reader.u16();
    reader.u16(); // kdf

    const x = reader.sized('EC x coordinate');
    const y = reader.sized('EC y coordinate');

    if (reader.remaining !== 0) {
      throw new TpmError(`${reader.remaining} trailing bytes after TPMT_PUBLIC`);
    }

    const unique = new Uint8Array(x.length + y.length);
    unique.set(x, 0);
    unique.set(y, x.length);
    return { type, nameAlg, unique, curveId, x, y };
  }

  throw new TpmError(`unsupported TPM key type: 0x${type.toString(16)}`);
}

// ─── TPMS_ATTEST ───────────────────────────────────────────────────────────

/** The statement a TPM signed. */
export interface TpmAttest {
  readonly magic: number;
  readonly type: number;
  /** Hash of `authData || clientDataHash`. The tie to this ceremony. */
  readonly extraData: Uint8Array;
  /** `nameAlg || hash(pubArea)`. The tie to a particular key. */
  readonly attestedName: Uint8Array;
}

/** Parses `TPMS_ATTEST` — TPM 2.0 Part 2 §10.12.8. */
export function parseTpmAttest(bytes: Uint8Array): TpmAttest {
  const reader = new Reader(bytes);

  const magic = reader.u32();
  const type = reader.u16();

  // Checked here rather than by the caller: a structure that is not a TPM
  // attestation should not be parsed as one and then judged.
  if (magic !== TPM_GENERATED) {
    throw new TpmError('certInfo does not carry TPM_GENERATED_VALUE');
  }
  if (type !== TPM_ST_ATTEST_CERTIFY) {
    throw new TpmError(`certInfo is not a TPM_ST_ATTEST_CERTIFY (0x${type.toString(16)})`);
  }

  reader.sized('qualifiedSigner');
  const extraData = reader.sized('extraData');

  // clockInfo (17) and firmwareVersion (8) are fixed-width and not consulted.
  reader.slice(17);
  reader.slice(8);

  const attestedName = reader.sized('attested name');
  // `qualifiedName` follows and is not consulted, so trailing bytes are fine.

  return { magic, type, extraData, attestedName };
}

// ─── Binding checks ────────────────────────────────────────────────────────

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/**
 * Verifies that `attested.name` really names `pubArea`.
 *
 * The name is `nameAlg || digest(pubArea)`. Without this check the TPM's
 * signature vouches for whatever key the attacker named, rather than the one
 * whose description they sent.
 *
 * SHA-1 is refused. It is a permitted `nameAlg` in TPM 2.0 and is not
 * collision-resistant, and a name is exactly the place a collision would be
 * useful.
 */
export async function verifyAttestedName(
  attestedName: Uint8Array,
  pubArea: Uint8Array,
): Promise<void> {
  if (attestedName.length < 2) {
    throw new TpmError('attested name is too short to carry an algorithm');
  }

  const nameAlg = (attestedName[0] as number) * 256 + (attestedName[1] as number);
  if (nameAlg === TPM_ALG_SHA1) {
    throw new TpmError('SHA-1 name algorithm is not accepted');
  }

  const digestName = NAME_ALGORITHMS[nameAlg];
  if (digestName === undefined) {
    throw new TpmError(`unsupported name algorithm: 0x${nameAlg.toString(16)}`);
  }

  const expected = new Uint8Array(await crypto.subtle.digest(digestName, pubArea));
  if (!bytesEqual(attestedName.subarray(2), expected)) {
    throw new TpmError('the attested name does not describe the supplied pubArea');
  }
}

/**
 * Verifies that the key a TPM certified is the credential key.
 *
 * The comparison is on the raw key material rather than on a re-encoding,
 * because the two arrive in different shapes: the TPM describes its key in
 * `TPMT_PUBLIC`, the browser sends the same key as COSE. Anything that lets
 * these disagree lets a genuine attestation vouch for a key nobody attested
 * to.
 */
export function verifyPublicKeyMatches(
  pub: TpmPublic,
  credential: { readonly kty: string; readonly n?: Uint8Array; readonly e?: number; readonly x?: Uint8Array; readonly y?: Uint8Array },
): void {
  if (pub.type === TPM_ALG_RSA) {
    if (credential.kty !== 'RSA' || credential.n === undefined) {
      throw new TpmError('pubArea describes an RSA key but the credential is not RSA');
    }
    if (!bytesEqual(pub.unique, credential.n)) {
      throw new TpmError('the RSA modulus in pubArea is not the credential key');
    }
    if (credential.e !== undefined && pub.exponent !== credential.e) {
      throw new TpmError('the RSA exponent in pubArea is not the credential key');
    }
    return;
  }

  if (credential.kty !== 'EC' || credential.x === undefined || credential.y === undefined) {
    throw new TpmError('pubArea describes an EC key but the credential is not EC');
  }
  if (pub.curveId !== TPM_ECC_NIST_P256) {
    throw new TpmError(`unsupported TPM curve: 0x${(pub.curveId ?? 0).toString(16)}`);
  }
  if (!bytesEqual(pub.x ?? new Uint8Array(0), credential.x)) {
    throw new TpmError('the EC x coordinate in pubArea is not the credential key');
  }
  if (!bytesEqual(pub.y ?? new Uint8Array(0), credential.y)) {
    throw new TpmError('the EC y coordinate in pubArea is not the credential key');
  }
}

export { TPM_ALG_ECC, TPM_ALG_RSA, TPM_ALG_SHA256, TPM_ECC_NIST_P256, TPM_GENERATED, TPM_ST_ATTEST_CERTIFY };
