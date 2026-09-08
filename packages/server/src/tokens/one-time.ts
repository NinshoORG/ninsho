/**
 * Single-use tokens — password reset, email verification, magic links.
 *
 * ─── Why this is in the library at all ────────────────────────────────────
 * Ninsho does not own your user model, and this does not change that: it
 * issues an opaque token bound to a subject and a purpose, and tells you which
 * subject presented it. What happens next — send an email, set a password,
 * mark an address verified — is yours.
 *
 * It is here because password reset is the most reliably botched flow in
 * authentication, and every way of botching it is a full account takeover:
 *
 *   - a token stored in plaintext, so a database read is a takeover
 *   - a token that works twice, so a forwarded email is a takeover
 *   - a token that never expires, so an old inbox is a takeover
 *   - a reset token accepted as an email-verification token, so the weaker
 *     flow becomes an entry point to the stronger one
 *   - a token compared with `===` against a value read by a prefix scan
 *
 * Every one of those is avoided by construction below rather than by
 * remembering to avoid it. The primitives were already here — an atomic
 * `take`, `hashToken`, TTLs — and leaving developers to assemble them
 * correctly is how the mistakes above keep happening.
 *
 * ─── What is deliberately still yours ─────────────────────────────────────
 * Sending the email. Rate-limiting the request endpoint (use `auth.rateLimit`;
 * without it this becomes an email-flooding tool aimed at your users).
 * Answering identically whether or not the address exists, so the endpoint is
 * not an account-enumeration oracle. And deciding whether consuming a reset
 * revokes the user's sessions — it usually should, and `revokeAllForUser` is
 * one call.
 * ──────────────────────────────────────────────────────────────────────────
 */

import {
  NinshoError,
  generateToken,
  hashToken,
  isExpired,
  isoFrom,
  type AuditSink,
} from '@ninshorg/core';
import type { NinshoStore } from '../store/types.js';
import { KEYS } from '../keys.js';

/**
 * A single-use token was not accepted.
 *
 * Deliberately uninformative. "Expired", "already used" and "never existed"
 * are the same answer to a client and three different hints to an attacker
 * probing which reset links were real.
 */
export class OneTimeTokenError extends NinshoError {
  readonly code = 'ONE_TIME_TOKEN_INVALID';
  readonly status = 400;
  constructor(detail?: string) {
    super('This link is no longer valid', detail);
  }
}

/** Configuration is wrong — the operator's mistake, not the caller's. */
export class OneTimeTokenConfigurationError extends NinshoError {
  readonly code = 'ONE_TIME_TOKEN_CONFIGURATION_INVALID';
  readonly status = 500;
  constructor(message: string) {
    super(message);
  }
}

export interface OneTimeTokenOptions {
  /**
   * Default lifetime, in seconds. Default 900 (fifteen minutes).
   *
   * Short on purpose: the window in which a reset link is useful to the person
   * who asked for it is also the window in which it is useful to anyone who
   * reaches their inbox.
   */
  readonly defaultTtlSeconds?: number;
  /** Bytes of randomness. Default 32 — 256 bits, unguessable. */
  readonly tokenBytes?: number;
  /**
   * Whether issuing a token invalidates the subject's outstanding ones for the
   * same purpose. Default `true`.
   *
   * OWASP's guidance, and the behaviour users expect: asking for a second
   * reset email should make the first link stop working, rather than leaving
   * both live in an inbox indefinitely.
   */
  readonly invalidatePrevious?: boolean;
}

export interface IssueOneTimeTokenInput {
  /**
   * What this token is for, e.g. `'password-reset'`. Becomes part of the
   * storage key, so tokens for different purposes cannot be interchanged.
   */
  readonly purpose: string;
  /** Who it is for — normally a user id. */
  readonly subject: string;
  /** Overrides the configured default. */
  readonly ttlSeconds?: number;
  /**
   * Small values to carry through to consumption, e.g. the new address in a
   * change-email flow.
   *
   * SECURITY: this is stored server-side and never leaves it, but it is not
   * encrypted. Do not put secrets here.
   */
  readonly metadata?: Readonly<Record<string, string>>;
}

export interface IssuedOneTimeToken {
  /**
   * The value to put in the link you email.
   *
   * SECURITY: this is the only time it exists in plaintext. Never log it,
   * never store it — the store holds only its hash.
   */
  readonly token: string;
  readonly expiresAt: string;
}

/** What was recorded when the token was issued. */
export interface OneTimeTokenClaim {
  readonly purpose: string;
  readonly subject: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly metadata: Readonly<Record<string, string>>;
  /**
   * The subject's generation when this token was issued.
   *
   * Compared at consumption. A token stamped with an older generation has been
   * superseded — by a replacement, or by an explicit revocation — and is
   * refused. This is what makes invalidation race-free; see
   * `KEYS.oneTimeTokenGeneration`.
   */
  readonly generation: number;
}

const DEFAULT_TTL_SECONDS = 900;
const MAX_TTL_SECONDS = 60 * 60 * 24 * 7;
const DEFAULT_TOKEN_BYTES = 32;
const MIN_TOKEN_BYTES = 16;

/**
 * Longest token string accepted from a caller.
 *
 * The value is hashed before it becomes a key, so length cannot reach the
 * store — but refusing an absurd input costs less than hashing it, and a token
 * this package issued is never close to this long.
 */
const MAX_TOKEN_INPUT = 512;

/**
 * How long a subject's generation counter is kept.
 *
 * Comfortably beyond the longest token so a live token's generation is still
 * there to compare against. If it does lapse, the mismatch refuses the token —
 * a failure in the safe direction.
 */
const GENERATION_TTL_SECONDS = MAX_TTL_SECONDS + 3600;

export interface OneTimeTokenManagerDeps {
  readonly store: NinshoStore;
  readonly audit: AuditSink;
}

export class OneTimeTokenManager {
  readonly #store: NinshoStore;
  readonly #audit: AuditSink;
  readonly #ttlSeconds: number;
  readonly #tokenBytes: number;
  readonly #invalidatePrevious: boolean;

  constructor(deps: OneTimeTokenManagerDeps, options: OneTimeTokenOptions = {}) {
    const ttlSeconds = options.defaultTtlSeconds ?? DEFAULT_TTL_SECONDS;
    const tokenBytes = options.tokenBytes ?? DEFAULT_TOKEN_BYTES;

    // Validated at construction. A misconfiguration that only appears when the
    // first user requests a password reset is one that reaches production.
    if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > MAX_TTL_SECONDS) {
      throw new OneTimeTokenConfigurationError(
        `defaultTtlSeconds must be a whole number between 1 and ${MAX_TTL_SECONDS}`,
      );
    }
    if (!Number.isInteger(tokenBytes) || tokenBytes < MIN_TOKEN_BYTES) {
      throw new OneTimeTokenConfigurationError(
        `tokenBytes must be a whole number of at least ${MIN_TOKEN_BYTES}`,
      );
    }

    this.#store = deps.store;
    this.#audit = deps.audit;
    this.#ttlSeconds = ttlSeconds;
    this.#tokenBytes = tokenBytes;
    this.#invalidatePrevious = options.invalidatePrevious ?? true;
  }

  /**
   * Issues a token.
   *
   * Call this whether or not the subject exists, and answer identically either
   * way — an endpoint that responds differently for a real address is an
   * account-enumeration oracle regardless of how careful the rest of the flow
   * is.
   */
  async issue(input: IssueOneTimeTokenInput): Promise<IssuedOneTimeToken> {
    this.#assertPurpose(input.purpose);
    if (typeof input.subject !== 'string' || input.subject.length === 0) {
      throw new OneTimeTokenConfigurationError('a one-time token needs a subject');
    }

    const ttlSeconds = input.ttlSeconds ?? this.#ttlSeconds;
    if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > MAX_TTL_SECONDS) {
      throw new OneTimeTokenConfigurationError(
        `ttlSeconds must be a whole number between 1 and ${MAX_TTL_SECONDS}`,
      );
    }

    // Atomic, so two concurrent issues receive distinct generations and the
    // older token stops matching. Reading without incrementing keeps every
    // outstanding token in the same generation when replacement is disabled.
    const generation = this.#invalidatePrevious
      ? await this.#store.increment(
          KEYS.oneTimeTokenGeneration(input.purpose, input.subject),
          GENERATION_TTL_SECONDS,
        )
      : await this.#readGeneration(input.purpose, input.subject);

    const token = generateToken(this.#tokenBytes);
    const tokenHash = hashToken(token);

    // One clock reading for both timestamps, so the recorded lifetime is
    // exactly the one that was asked for.
    const now = Date.now();
    const claim: OneTimeTokenClaim = {
      purpose: input.purpose,
      subject: input.subject,
      issuedAt: isoFrom(now),
      expiresAt: isoFrom(now, ttlSeconds),
      metadata: input.metadata ?? {},
      generation,
    };

    const stored = await this.#store.setIfAbsent(
      KEYS.oneTimeToken(input.purpose, tokenHash),
      JSON.stringify(claim),
      ttlSeconds,
    );

    // A collision on 256 bits of CSPRNG output does not happen. If it did, it
    // would mean the random source had failed, and reusing the value would be
    // the worst available response.
    if (!stored) {
      throw new OneTimeTokenConfigurationError(
        'one-time token collision — the random source is suspect',
      );
    }

    this.#audit.emit({
      type: 'onetime.issued',
      at: claim.issuedAt,
      userId: input.subject,
      reason: input.purpose,
    });

    return { token, expiresAt: claim.expiresAt };
  }

  /**
   * Consumes a token, or throws.
   *
   * Whatever happens, the token is gone afterwards: `take` removes it before
   * any validation runs, so a malformed record cannot leave a live token
   * behind for a second attempt.
   */
  async consume(purpose: string, token: string): Promise<OneTimeTokenClaim> {
    this.#assertPurpose(purpose);

    if (typeof token !== 'string' || token.length === 0) {
      throw new OneTimeTokenError('token was absent or not a string');
    }
    if (token.length > MAX_TOKEN_INPUT) {
      throw new OneTimeTokenError(`token of ${token.length} characters is implausible`);
    }

    const tokenHash = hashToken(token);

    // Atomic. Two people clicking the same link at the same moment cannot both
    // succeed, which a read-then-delete pair would allow.
    const raw = await this.#store.take(KEYS.oneTimeToken(purpose, tokenHash));
    if (raw === null) {
      // Never issued, already used, expired, or issued for a different
      // purpose. Indistinguishable by design.
      throw new OneTimeTokenError('token was not found');
    }

    let claim: OneTimeTokenClaim;
    try {
      claim = JSON.parse(raw) as OneTimeTokenClaim;
    } catch {
      throw new OneTimeTokenError('stored token record was not valid JSON');
    }

    if (
      typeof claim.subject !== 'string' ||
      claim.subject.length === 0 ||
      typeof claim.expiresAt !== 'string'
    ) {
      throw new OneTimeTokenError('stored token record is malformed');
    }

    // The store's TTL should already have removed an expired token. Checking
    // anyway means the guarantee rests on the recorded timestamp rather than
    // on a backend expiring things promptly, and `isExpired` fails closed on a
    // timestamp it cannot parse.
    if (isExpired(claim.expiresAt)) {
      throw new OneTimeTokenError('token had expired');
    }

    // Belt and braces: the purpose is already in the key, so a mismatch cannot
    // reach here. It stays so that a future change moving the purpose out of
    // the key cannot silently remove the separation.
    if (claim.purpose !== purpose) {
      throw new OneTimeTokenError(`token was issued for ${claim.purpose}, not ${purpose}`);
    }

    // Superseded by a later issue, or by an explicit revocation. Checked at
    // consumption rather than deleted at issue, which is what makes the
    // invalidation race-free.
    const current = await this.#readGeneration(purpose, claim.subject);
    if (typeof claim.generation !== 'number' || claim.generation !== current) {
      throw new OneTimeTokenError('token was superseded by a newer one');
    }

    this.#audit.emit({
      type: 'onetime.consumed',
      at: new Date().toISOString(),
      userId: claim.subject,
      reason: purpose,
    });

    return { ...claim, metadata: claim.metadata ?? {} };
  }

  /**
   * Invalidates every outstanding token a subject holds for a purpose.
   *
   * Worth calling when the reason for the token disappears — the user changed
   * their password by another route, or an administrator disabled the account.
   */
  async revokeAllFor(purpose: string, subject: string): Promise<void> {
    this.#assertPurpose(purpose);
    // One atomic increment invalidates every outstanding token at once. The
    // records themselves are left to expire; they can no longer be redeemed,
    // and sweeping them would cost a fan-out to delete data that is already
    // inert.
    await this.#store.increment(
      KEYS.oneTimeTokenGeneration(purpose, subject),
      GENERATION_TTL_SECONDS,
    );
  }

  /** The subject's current generation. Absent counts as zero. */
  async #readGeneration(purpose: string, subject: string): Promise<number> {
    const raw = await this.#store.get(KEYS.oneTimeTokenGeneration(purpose, subject));
    if (raw === null) return 0;

    const value = Number(raw);
    // A counter that cannot be read is treated as a mismatch rather than as
    // agreement, so a corrupt value refuses tokens instead of accepting them.
    return Number.isInteger(value) ? value : Number.NaN;
  }

  #assertPurpose(purpose: string): void {
    if (typeof purpose !== 'string' || purpose.length === 0) {
      throw new OneTimeTokenConfigurationError('a one-time token needs a purpose');
    }
    // The purpose becomes part of a store key. Restricting it keeps the
    // keyspace readable and stops a caller-supplied value from introducing
    // separators that could make two different purposes collide.
    if (!/^[a-z0-9][a-z0-9._-]{0,63}$/i.test(purpose)) {
      throw new OneTimeTokenConfigurationError(
        `invalid purpose "${purpose}": use letters, digits, dot, dash or underscore`,
      );
    }
  }
}
