import {
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
  type ScryptOptions,
} from 'node:crypto';

/**
 * Promisified scrypt.
 *
 * Written out rather than using `promisify`, which collapses to the
 * three-argument overload and drops the options parameter — and the options
 * are the entire point here, since they carry the cost factors.
 */
function scrypt(
  password: string,
  salt: Buffer,
  keylen: number,
  options: ScryptOptions,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keylen, options, (error, derived) => {
      if (error !== null) reject(error);
      else resolve(derived);
    });
  });
}

/**
 * Password hashing for the example API.
 *
 * ─── Why scrypt, and why this is not part of Ninsho ───────────────────────
 * Ninsho does not hash passwords. It manages what happens *after* identity is
 * established, and owning credential verification would mean owning the user
 * model — which is the application's business, not a session library's.
 *
 * scrypt is used here because it is memory-hard, OWASP-acceptable, and built
 * into Node, so this example needs no native dependency to demonstrate the
 * correct thing. Argon2id is the current first choice if you are willing to
 * take a native module; the `argon2` package is the usual route.
 *
 * Note what is deliberately absent: bcrypt. The predecessor's example paired
 * bcryptjs with a 128-character password schema, and bcrypt silently ignores
 * everything past byte 72 — so a user choosing a long passphrase got far less
 * strength than the form implied, with nothing to indicate it. scrypt has no
 * such truncation.
 * ──────────────────────────────────────────────────────────────────────────
 */

/**
 * OWASP Password Storage Cheat Sheet minimums for scrypt (2024):
 * N = 2^17, r = 8, p = 1. `maxmem` must be raised to match — Node's default
 * is 32 MB and this configuration needs roughly 128 MB.
 */
const SCRYPT_PARAMS = {
  N: 2 ** 17,
  r: 8,
  p: 1,
  maxmem: 256 * 1024 * 1024,
} as const;

const KEY_BYTES = 32;
const SALT_BYTES = 16;

/**
 * Hashes a password into a self-describing string.
 *
 * Format: `scrypt$N$r$p$salt$hash`. Embedding the parameters means an existing
 * hash keeps verifying after the cost is raised, so parameters can be
 * increased over time without invalidating every stored password.
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const derived = await scrypt(password, salt, KEY_BYTES, SCRYPT_PARAMS);

  const { N, r, p } = SCRYPT_PARAMS;
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64url')}$${derived.toString('base64url')}`;
}

/**
 * Verifies a password against a stored hash.
 *
 * Returns `false` rather than throwing for a malformed hash: a corrupted
 * record must not authenticate anyone, and must not crash the login route
 * either.
 */
export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const N = Number.parseInt(parts[1] as string, 10);
  const r = Number.parseInt(parts[2] as string, 10);
  const p = Number.parseInt(parts[3] as string, 10);
  if (!Number.isFinite(N) || !Number.isFinite(r) || !Number.isFinite(p)) return false;

  const salt = Buffer.from(parts[4] as string, 'base64url');
  const expected = Buffer.from(parts[5] as string, 'base64url');
  if (salt.length === 0 || expected.length === 0) return false;

  let derived: Buffer;
  try {
    derived = await scrypt(password, salt, expected.length, {
      N,
      r,
      p,
      maxmem: SCRYPT_PARAMS.maxmem,
    });
  } catch {
    // Parameters outside what this process will allocate. Refuse rather than
    // fall back to something weaker.
    return false;
  }

  // Constant-time. A plain === would leak, through timing, how many leading
  // bytes matched — enough to recover a hash byte by byte given enough tries.
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

/**
 * A hash that no password matches, for the "user not found" branch.
 *
 * Without it, login returns in microseconds for an unknown address and in
 * ~100ms for a known one, and that difference is a reliable oracle for
 * enumerating which addresses have accounts. Verifying against this instead
 * makes both paths cost the same.
 *
 * Generated once at module load so the cost is not paid on the hot path.
 */
export const DUMMY_HASH_PROMISE = hashPassword(
  `unmatchable-${randomBytes(32).toString('hex')}`,
);
