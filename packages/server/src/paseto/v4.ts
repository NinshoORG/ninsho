import { sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto';

/**
 * PASETO v4.public — sign and verify.
 *
 * ─── Why this is implemented here rather than pulled from a package ───────
 * This file contains no cryptography. Ed25519 signing and verification come
 * entirely from `node:crypto`; what is implemented here is PASETO's
 * Pre-Authentication Encoding (PAE) — a length-prefixed concatenation — plus
 * base64url framing. That is serialization, not a primitive, and it is
 * verified against the specification's own test vectors in `v4.test.ts`.
 *
 * Three reasons this beat taking a dependency:
 *
 *   1. The reference package (`paseto` on npm) has not been published since
 *      April 2023. An unmaintained dependency in the signing path of an
 *      authentication library is a supply-chain cost that ~120 lines does not
 *      justify.
 *
 *   2. The predecessor's most subtle defect came from depending on that
 *      package's *error strings*: it decided whether a token was "expired" or
 *      "invalid" by substring-matching the message, and then let the expired
 *      branch skip signature validation. Owning the failure modes removes
 *      that class of bug rather than documenting around it.
 *
 *   3. `@ninsho/core` is dependency-free and this keeps the signing path
 *      equally auditable.
 *
 * The decision is contained: `TokenEngine` is the seam, so swapping this for a
 * package later touches one file and no callers.
 *
 * SECURITY: v4.public tokens are **signed, not encrypted**. Anyone holding a
 * token can read every claim. Never place personal data in a payload.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * @see https://github.com/paseto-standard/paseto-spec — Version4.md
 */

/** The only header this module produces or accepts. There is no negotiation. */
export const V4_PUBLIC_HEADER = 'v4.public.';

/** Ed25519 signatures are fixed-width. */
const SIGNATURE_BYTES = 64;

/** Raised for any structural or signature failure. Carries no attacker-visible text. */
export class PasetoFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PasetoFormatError';
  }
}

// ─── Encoding helpers ───────────────────────────────────────────────────────

function b64uEncode(data: Buffer): string {
  return data.toString('base64url');
}

/**
 * Decodes base64url, rejecting input that is not canonical.
 *
 * Node's decoder is lenient: it ignores stray characters and accepts padding
 * variants, so several distinct strings can decode to the same bytes. For a
 * token that is a security boundary, that is a liability — it invites parser
 * mismatches between systems. Re-encoding and comparing forces exactly one
 * accepted spelling per value.
 */
function b64uDecode(value: string): Buffer {
  const decoded = Buffer.from(value, 'base64url');
  if (b64uEncode(decoded) !== value) {
    throw new PasetoFormatError('non-canonical base64url');
  }
  return decoded;
}

/**
 * 64-bit unsigned little-endian, most significant bit cleared.
 *
 * The PASETO specification mandates that the MSB must be 0 and requires
 * implementations to reject any integer with bit 63 set.
 */
export function le64(value: number | bigint): Buffer {
  const b = BigInt(value);
  if (b < 0n || b > 0x7fffffffffffffffn || (b & 0x8000000000000000n) !== 0n) {
    throw new PasetoFormatError('integer MSB is set or out of range');
  }
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(b);
  return buf;
}

/**
 * Pre-Authentication Encoding.
 *
 * Encodes the piece count, then each piece prefixed by its length. The
 * length prefixes are the entire point: without them, `["ab", "c"]` and
 * `["a", "bc"]` would produce identical bytes, and an attacker could shift
 * content between the payload and the footer while keeping the signature
 * valid — a canonicalization attack.
 */
export function pae(pieces: readonly Buffer[]): Buffer {
  const parts: Buffer[] = [le64(pieces.length)];
  for (const piece of pieces) {
    parts.push(le64(piece.length), piece);
  }
  return Buffer.concat(parts);
}

// ─── Sign / verify ──────────────────────────────────────────────────────────

/**
 * Signs a payload, producing a `v4.public.` token.
 *
 * @param payload - Claims, serialized by the caller. Signed, not encrypted.
 * @param privateKey - An Ed25519 private key.
 * @param footer - Optional, authenticated but readable without the key. Ninsho
 *   puts the key id here so a verifier can select a key before verifying.
 * @param implicit - Optional implicit assertion. Authenticated but not
 *   transmitted; both parties must supply the same value. Ninsho does not use
 *   it, and it is present for spec completeness and test-vector coverage.
 */
export function signV4Public(
  payload: string,
  privateKey: KeyObject,
  footer = '',
  implicit = '',
): string {
  const m = Buffer.from(payload, 'utf8');
  const f = Buffer.from(footer, 'utf8');
  const i = Buffer.from(implicit, 'utf8');
  const h = Buffer.from(V4_PUBLIC_HEADER, 'utf8');

  // The header, footer and implicit assertion are all inside the signed
  // preimage, so none of them can be swapped after the fact.
  const signature = edSign(null, pae([h, m, f, i]), privateKey);

  const body = b64uEncode(Buffer.concat([m, signature]));
  return footer === ''
    ? `${V4_PUBLIC_HEADER}${body}`
    : `${V4_PUBLIC_HEADER}${body}.${b64uEncode(f)}`;
}

/** A token split into its parts, before signature verification. */
export interface ParsedToken {
  readonly payload: string;
  readonly footer: string;
}

/**
 * Reads a token's footer without verifying the signature.
 *
 * This exists for exactly one purpose: selecting which key to verify with,
 * from the `kid` the footer carries. That is a chicken-and-egg the spec
 * resolves by making the footer readable up front while still covering it with
 * the signature.
 *
 * SECURITY: the return value is attacker-controlled and must never influence
 * an authorization decision. Use it to look up a key, then let
 * {@link verifyV4Public} decide whether anything here was genuine — a footer
 * naming an unknown key simply fails verification.
 */
export function readFooterUnverified(token: string): string {
  if (typeof token !== 'string' || !token.startsWith(V4_PUBLIC_HEADER)) {
    throw new PasetoFormatError('not a v4.public token');
  }
  const rest = token.slice(V4_PUBLIC_HEADER.length);
  const parts = rest.split('.');
  if (parts.length === 1) return '';
  if (parts.length !== 2) throw new PasetoFormatError('malformed token structure');
  return b64uDecode(parts[1] as string).toString('utf8');
}

/**
 * Verifies a `v4.public.` token and returns its payload.
 *
 * Verifies the Ed25519 signature over the header, payload, footer and implicit
 * assertion. It performs **no claim validation** — expiry, issuer and audience
 * are the caller's concern, and keeping the split sharp is deliberate: this
 * function answers "is this authentic?" and nothing else.
 *
 * @throws {PasetoFormatError} Malformed, non-canonical, or bad signature.
 */
export function verifyV4Public(
  token: string,
  publicKey: KeyObject,
  implicit = '',
): ParsedToken {
  if (typeof token !== 'string') {
    throw new PasetoFormatError('token must be a string');
  }
  // Exact prefix match. There is no algorithm field to confuse, and no other
  // version or purpose is accepted — a `v4.local` or `v2.public` token is
  // rejected here rather than being coerced into this code path.
  if (!token.startsWith(V4_PUBLIC_HEADER)) {
    throw new PasetoFormatError('not a v4.public token');
  }

  const rest = token.slice(V4_PUBLIC_HEADER.length);
  const parts = rest.split('.');
  if (parts.length > 2) {
    throw new PasetoFormatError('malformed token structure');
  }

  const body = b64uDecode(parts[0] as string);
  const footer = parts.length === 2 ? b64uDecode(parts[1] as string) : Buffer.alloc(0);

  if (body.length < SIGNATURE_BYTES) {
    throw new PasetoFormatError('token too short to contain a signature');
  }

  const m = body.subarray(0, body.length - SIGNATURE_BYTES);
  const signature = body.subarray(body.length - SIGNATURE_BYTES);

  const h = Buffer.from(V4_PUBLIC_HEADER, 'utf8');
  const i = Buffer.from(implicit, 'utf8');

  const ok = edVerify(null, pae([h, m, footer, i]), publicKey, signature);
  if (!ok) {
    throw new PasetoFormatError('signature verification failed');
  }

  return { payload: m.toString('utf8'), footer: footer.toString('utf8') };
}
