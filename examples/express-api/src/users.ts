import { randomUUID } from 'node:crypto';
import { DUMMY_HASH_PROMISE, hashPassword, verifyPassword } from './passwords.js';

/**
 * An in-memory user directory, standing in for your database.
 *
 * The only parts worth copying are the shapes and the constant-time login
 * path. Everything else — where records live, how they are indexed — is
 * application concern that Ninsho has no opinion about.
 */
export interface User {
  readonly id: string;
  readonly email: string;
  readonly passwordHash: string;
  readonly roles: readonly string[];
  readonly scopes: readonly string[];
  readonly tenant: string;
}

const byEmail = new Map<string, User>();
const byId = new Map<string, User>();

/** Normalises an address so one account cannot be created twice. */
function normaliseEmail(email: string): string {
  return email.trim().toLowerCase();
}

export async function createUser(input: {
  email: string;
  password: string;
  roles?: readonly string[];
  scopes?: readonly string[];
  tenant?: string;
}): Promise<User> {
  const email = normaliseEmail(input.email);
  if (byEmail.has(email)) {
    throw new Error('email already registered');
  }

  const user: User = {
    id: `usr_${randomUUID()}`,
    email,
    passwordHash: await hashPassword(input.password),
    roles: input.roles ?? ['user'],
    scopes: input.scopes ?? ['profile:read'],
    tenant: input.tenant ?? 'default',
  };

  byEmail.set(email, user);
  byId.set(user.id, user);
  return user;
}

export function findById(id: string): User | undefined {
  return byId.get(id);
}

/**
 * Verifies credentials in constant time with respect to account existence.
 *
 * ─── Why the dummy hash is not optional ───────────────────────────────────
 * The obvious implementation returns early when no user is found, which makes
 * an unknown address answer in microseconds and a known one in ~100ms. That
 * gap is a reliable oracle: an attacker learns which addresses have accounts
 * without ever guessing a password, which is a privacy breach on its own and
 * a shortlist for credential stuffing.
 *
 * Hashing against an unmatchable value on the miss path costs the same as a
 * real check, so both answers take the same time and reveal nothing.
 * ──────────────────────────────────────────────────────────────────────────
 */
export async function verifyCredentials(
  email: string,
  password: string,
): Promise<User | null> {
  const user = byEmail.get(normaliseEmail(email));
  const hash = user?.passwordHash ?? (await DUMMY_HASH_PROMISE);

  const valid = await verifyPassword(password, hash);

  // Both conditions are evaluated; there is no early return above to shortcut
  // the expensive work.
  return valid && user !== undefined ? user : null;
}

/** Test affordance. Not something a real directory would expose. */
export function resetUsers(): void {
  byEmail.clear();
  byId.clear();
}
