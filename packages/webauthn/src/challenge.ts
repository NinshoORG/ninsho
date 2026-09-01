/**
 * Challenge issuance and single-use consumption.
 *
 * ─── What a challenge is defending against ────────────────────────────────
 * A WebAuthn assertion is a signature over `authenticatorData ||
 * SHA-256(clientDataJSON)`, and the challenge is the only part of that an
 * attacker cannot predict. Everything else — the RP ID hash, the flags, the
 * origin — is the same on every ceremony. Without a server-issued,
 * server-remembered, single-use challenge, a captured assertion is a password
 * that never expires.
 *
 * So three properties have to hold, and each one is load-bearing:
 *
 *   Unpredictable — 32 bytes from a CSPRNG. The spec's floor is 16 (§13.4.3);
 *   the extra margin costs nothing on a value that lives for five minutes.
 *
 *   Single-use — consumption goes through the store's atomic `take`, so two
 *   requests presenting the same challenge cannot both succeed. A read-then-
 *   delete pair would leave exactly the window a replay needs.
 *
 *   Scoped — the ceremony type is part of the storage key, not a field
 *   compared afterwards. A registration challenge replayed at an
 *   authentication endpoint does not fail a check; it is simply not there.
 *   A check can be forgotten in a later refactor. A key that does not exist
 *   cannot be.
 * ──────────────────────────────────────────────────────────────────────────
 */

import { NinshoError, generateToken, hashToken, isExpired, isoFrom } from '@ninsho/core';

/** Which ceremony a challenge belongs to. */
export type CeremonyType = 'registration' | 'authentication';

/**
 * The storage this module needs — the two atomic operations, nothing more.
 *
 * `NinshoStore` from `@ninsho/server` satisfies this structurally, so a
 * deployment already running Redis passes its existing store straight in.
 * Declaring the narrow shape rather than importing the wide one keeps this
 * package free of a dependency it would use two methods of.
 */
export interface ChallengeStore {
  /** Stores only if absent. Atomic. Returns whether this call stored it. */
  setIfAbsent(key: string, value: string, ttlSeconds?: number): Promise<boolean>;
  /** Atomically reads and deletes. Returns `null` if absent. */
  take(key: string): Promise<string | null>;
}

/** A challenge failed to verify. Maps to 400. */
export class ChallengeError extends NinshoError {
  readonly code = 'WEBAUTHN_CHALLENGE_INVALID';
  readonly status = 400;
  constructor(detail?: string) {
    // Uninformative by design, matching the rest of Ninsho's 4xx surface:
    // "expired" and "already used" and "never issued" are the same answer to
    // a client and three different hints to an attacker.
    super('Challenge is not valid', detail);
  }
}

/** Configuration is wrong. Maps to 500 — this is the operator's mistake. */
export class ChallengeConfigurationError extends NinshoError {
  readonly code = 'WEBAUTHN_CONFIGURATION_INVALID';
  readonly status = 500;
  constructor(message: string) {
    super(message);
  }
}

export interface ChallengeOptions {
  /**
   * How long a challenge stays valid, in seconds. Default 300.
   *
   * This is the window in which a user must complete the ceremony, so it
   * cannot be tiny; it is also the window in which a captured challenge is
   * useful, so it must not be long.
   */
  readonly ttlSeconds?: number;
  /** Bytes of randomness. Default 32; the spec's minimum is 16. */
  readonly challengeBytes?: number;
  /** Key prefix, for deployments sharing a store across products. */
  readonly keyPrefix?: string;
}

/** A challenge to hand to the browser. */
export interface IssuedChallenge {
  /** base64url, ready for `PublicKeyCredentialCreationOptions.challenge`. */
  readonly challenge: string;
  readonly expiresAt: string;
}

/** What was recorded when a challenge was issued. */
export interface ChallengeContext {
  readonly type: CeremonyType;
  /**
   * The user this challenge was issued for, when it was issued for one.
   *
   * Registration always has a user. Authentication may not: a discoverable-
   * credential (usernameless) flow does not know who is signing in until the
   * authenticator answers.
   */
  readonly userId: string | undefined;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

const DEFAULT_TTL_SECONDS = 300;
const DEFAULT_CHALLENGE_BYTES = 32;
const MIN_CHALLENGE_BYTES = 16;
const MAX_TTL_SECONDS = 3600;
const DEFAULT_KEY_PREFIX = 'ninsho:webauthn:v1';

/**
 * Longest challenge string accepted from a client.
 *
 * `consume` receives an attacker-controlled string. It is hashed before it
 * becomes a key, so length cannot reach the store — but refusing an absurd
 * input before hashing it is cheaper than hashing it, and a challenge this
 * package issued is never anywhere near this long.
 */
const MAX_CHALLENGE_INPUT = 512;

export class ChallengeManager {
  readonly #store: ChallengeStore;
  readonly #ttlSeconds: number;
  readonly #challengeBytes: number;
  readonly #keyPrefix: string;

  constructor(store: ChallengeStore, options: ChallengeOptions = {}) {
    const ttlSeconds = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
    const challengeBytes = options.challengeBytes ?? DEFAULT_CHALLENGE_BYTES;

    // Validated at construction rather than at first use. A misconfiguration
    // that only surfaces under load is a misconfiguration that reaches
    // production.
    if (!Number.isInteger(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > MAX_TTL_SECONDS) {
      throw new ChallengeConfigurationError(
        `ttlSeconds must be a whole number between 1 and ${MAX_TTL_SECONDS}`,
      );
    }
    if (!Number.isInteger(challengeBytes) || challengeBytes < MIN_CHALLENGE_BYTES) {
      throw new ChallengeConfigurationError(
        `challengeBytes must be a whole number of at least ${MIN_CHALLENGE_BYTES}`,
      );
    }

    this.#store = store;
    this.#ttlSeconds = ttlSeconds;
    this.#challengeBytes = challengeBytes;
    this.#keyPrefix = options.keyPrefix ?? DEFAULT_KEY_PREFIX;
  }

  get ttlSeconds(): number {
    return this.#ttlSeconds;
  }

  /**
   * The storage key.
   *
   * The challenge is hashed rather than used directly: it bounds the key
   * length regardless of what a client sends, and it keeps the store's
   * keyspace free of caller-controlled bytes. The ceremony type is part of the
   * key so that a challenge issued for one ceremony cannot be found by the
   * other.
   */
  #key(type: CeremonyType, challenge: string): string {
    return `${this.#keyPrefix}:challenge:${type}:${hashToken(challenge)}`;
  }

  /**
   * Issues a challenge and records it.
   *
   * @param userId the user this ceremony is for, when known. Omit for a
   *   usernameless authentication flow.
   */
  async issue(type: CeremonyType, userId?: string): Promise<IssuedChallenge> {
    const challenge = generateToken(this.#challengeBytes);

    // One clock reading for both timestamps, so the recorded lifetime is
    // exactly the configured one.
    const now = Date.now();
    const context: ChallengeContext = {
      type,
      userId,
      issuedAt: isoFrom(now),
      expiresAt: isoFrom(now, this.#ttlSeconds),
    };

    const stored = await this.#store.setIfAbsent(
      this.#key(type, challenge),
      JSON.stringify(context),
      this.#ttlSeconds,
    );

    // A collision on 32 bytes of CSPRNG output is not a thing that happens; if
    // it did, it would mean the random source had failed, and reusing the
    // value would be the worst possible response.
    if (!stored) {
      throw new ChallengeConfigurationError('challenge collision — the random source is suspect');
    }

    return { challenge, expiresAt: context.expiresAt };
  }

  /**
   * Consumes a challenge, or throws.
   *
   * Whatever happens, the challenge is gone afterwards: `take` removes it
   * before any validation runs. A malformed record must not leave a live
   * challenge behind for a second attempt.
   */
  async consume(type: CeremonyType, challenge: string): Promise<ChallengeContext> {
    if (typeof challenge !== 'string' || challenge.length === 0) {
      throw new ChallengeError('challenge was absent or not a string');
    }
    if (challenge.length > MAX_CHALLENGE_INPUT) {
      throw new ChallengeError(`challenge of ${challenge.length} characters is implausible`);
    }

    const raw = await this.#store.take(this.#key(type, challenge));
    if (raw === null) {
      // Covers every case: never issued, already consumed, expired out of the
      // store, or issued for the other ceremony. They are indistinguishable to
      // the caller by design.
      throw new ChallengeError('challenge was not found');
    }

    let context: ChallengeContext;
    try {
      context = JSON.parse(raw) as ChallengeContext;
    } catch {
      throw new ChallengeError('stored challenge record was not valid JSON');
    }

    // The store's TTL should already have removed an expired challenge. This
    // checks anyway: the guarantee then rests on the recorded timestamp rather
    // than on a backend honouring expiry promptly, and `isExpired` fails
    // closed on a timestamp it cannot parse.
    if (typeof context.expiresAt !== 'string' || isExpired(context.expiresAt)) {
      throw new ChallengeError('challenge had expired');
    }

    // Belt and braces. The type is already in the key, so a mismatch cannot
    // reach here — but if a future change ever moves the type out of the key,
    // this stops that refactor from silently removing the separation.
    if (context.type !== type) {
      throw new ChallengeError(`challenge was issued for ${context.type}, not ${type}`);
    }

    return context;
  }
}
