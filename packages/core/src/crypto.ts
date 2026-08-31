/**
 * Cryptographic primitives for Ninsho.
 *
 * Everything here delegates to Node's `node:crypto`. Ninsho implements no
 * cryptography of its own — the only original code in this file is encoding
 * and length selection.
 *
 * ─── Zero dependencies is a security property ─────────────────────────────
 * This package has no runtime dependencies at all. Identifier generation uses
 * `randomBytes` directly rather than a third-party id library, which removes a
 * supply-chain link from the most security-sensitive path in the system: the
 * generation of session and token identifiers.
 *
 * The previous implementation used `nanoid` here, which as of this writing
 * carries two published high-severity advisories. Neither was exploitable as
 * it was called, but a vulnerable package in the dependency tree of an
 * authentication library trips every downstream consumer's audit, and the
 * dependency was buying roughly four lines of code.
 * ──────────────────────────────────────────────────────────────────────────
 */

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

// ─── Identifiers ────────────────────────────────────────────────────────────

/** Entropy for identifiers: 128 bits. Collision-free at any realistic scale. */
const ID_BYTES = 16;

/** Entropy for credentials: 256 bits. Not brute-forceable. */
const TOKEN_BYTES = 32;

/**
 * Generates a URL-safe random identifier.
 *
 * Used for session ids and token ids — values that appear in logs, URLs and
 * audit trails but are not themselves secrets.
 *
 * base64url is used rather than a custom alphabet because it is a standard
 * encoding with no modulo bias: every output character maps to exactly six
 * bits of `randomBytes` output. Hand-rolled alphabet mapping is where id
 * libraries historically introduce bias bugs.
 *
 * @param bytes - Entropy in bytes. Default 16 (128 bits) → 22 characters.
 */
export function generateId(bytes: number = ID_BYTES): string {
  return randomBytes(bytes).toString('base64url');
}

/**
 * Generates a URL-safe random credential.
 *
 * Used for opaque access tokens and refresh tokens. These ARE secrets: never
 * log the return value, never place it in a URL, never return it in a response
 * body where a refresh token belongs in an httpOnly cookie.
 *
 * @param bytes - Entropy in bytes. Default 32 (256 bits) → 43 characters.
 */
export function generateToken(bytes: number = TOKEN_BYTES): string {
  return randomBytes(bytes).toString('base64url');
}

// ─── Hashing ────────────────────────────────────────────────────────────────

/** SHA-256 of a UTF-8 string, hex-encoded. */
export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Derives the store key for a raw token.
 *
 * Ninsho stores `hashToken(raw)` and never the raw value, so read access to
 * the session store yields no usable credentials. A plain SHA-256 is correct
 * here and a password hash would be wrong: these tokens carry 256 bits of
 * entropy from a CSPRNG, so there is no guessable input to slow down, and a
 * deliberately slow hash on the hot verification path would be a denial-of-
 * service vector rather than a defence.
 *
 * Named separately from `sha256` so the intent is legible at call sites and
 * the algorithm can change without hunting through generic hash calls.
 */
export function hashToken(rawToken: string): string {
  return sha256(rawToken);
}

/**
 * Hashes a weak client signal for audit records.
 *
 * Truncated to 16 hex characters because these values are only ever compared
 * for equality across a single user's sessions, and storing a full hash of an
 * IP address is more personal data than the purpose requires.
 *
 * SECURITY: the result is not a secret and not an access-control input. See
 * `SecuritySignals` in `types.ts` for why signals are never branched on.
 */
export function hashSignal(value: string): string {
  return sha256(value).slice(0, 16);
}

// ─── Comparison ─────────────────────────────────────────────────────────────

/**
 * Constant-time string comparison.
 *
 * Ordinary `===` short-circuits at the first differing byte, so the time it
 * takes reveals how many leading characters matched. Against a value an
 * attacker can submit repeatedly, that leak is enough to recover a secret one
 * character at a time.
 *
 * Returns `false` rather than throwing for non-string or differing-length
 * input. The length check is not constant-time and does reveal length, which
 * is accepted: every value compared here is a fixed-length hash or token, so
 * the length carries no information an attacker does not already have.
 *
 * Defensive typing is deliberate. Accepting `unknown` means a malformed or
 * absent value fails closed here instead of throwing an unhandled TypeError
 * somewhere further up the verification path.
 */
export function safeEqual(a: unknown, b: unknown): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;

  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  if (bufA.length !== bufB.length) return false;
  if (bufA.length === 0) return false;

  return timingSafeEqual(bufA, bufB);
}
