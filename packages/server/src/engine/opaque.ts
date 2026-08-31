import {
  type AccessRecord,
  type AuthContext,
  type Principal,
  StoreUnavailableError,
  TokenExpiredError,
  TokenInvalidError,
  generateId,
  generateToken,
  hashToken,
  isExpired,
  isoFrom,
  secondsUntil,
} from '@ninsho/core';
import type { NinshoStore } from '../store/types.js';
import { KEYS } from '../keys.js';
import type {
  IssueAccessTokenInput,
  IssuedAccessToken,
  TokenEngine,
} from './types.js';

/** Configuration for {@link OpaqueEngine}. */
export interface OpaqueEngineOptions {
  /** Access token lifetime in seconds. */
  readonly accessTokenTtl: number;
  /**
   * Clock skew allowance in seconds when checking expiry.
   * Only matters if the store and the process disagree about time; the
   * authoritative expiry is the store's TTL either way.
   */
  readonly clockToleranceSeconds: number;
}

/**
 * The default strategy: access tokens are opaque random strings and all state
 * lives in the store.
 *
 * ─── Why this is the default ──────────────────────────────────────────────
 * For a single application, stateless tokens buy nothing. A signed token still
 * requires a revocation lookup on every request to be trustworthy, so the
 * round trip happens regardless — and having paid it, the signature adds cost
 * without adding a guarantee.
 *
 * Opaque tokens are strictly stronger in that setting:
 *
 *   - Revocation is immediate and native. Deleting the record IS revocation;
 *     there is no denylist to maintain and no window in which a revoked token
 *     still verifies.
 *   - There are no signing keys, so none can leak, and none need rotating.
 *     A developer's entire configuration is a store.
 *   - The token carries no claims, so a leaked token discloses nothing about
 *     the user, their roles, or the deployment.
 *   - Expiry cannot disagree with reality: the store's TTL is the expiry.
 *
 * The `paseto` strategy exists for the case this one genuinely cannot serve —
 * several services verifying independently without a shared store.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * SECURITY: the raw token is never stored. `hashToken` (SHA-256) is the store
 * key, so read access to the store yields hashes, not usable credentials. A
 * plain hash is correct here rather than a password hash — these tokens carry
 * 256 bits of CSPRNG entropy, so there is no guessable input to slow down, and
 * a deliberately slow hash on the verification hot path would be a
 * denial-of-service vector.
 */
export class OpaqueEngine implements TokenEngine {
  readonly strategy = 'opaque' as const;

  /**
   * Always false. The store holds the identity, so there is nothing to fall
   * back on — a store outage means the caller cannot be identified at all,
   * and admitting the request anyway would be admitting an anonymous one.
   */
  readonly canVerifyWithoutStore = false;

  readonly #store: NinshoStore;
  readonly #options: OpaqueEngineOptions;

  constructor(store: NinshoStore, options: OpaqueEngineOptions) {
    this.#store = store;
    this.#options = options;
  }

  async issue(input: IssueAccessTokenInput): Promise<IssuedAccessToken> {
    const token = generateToken();
    const tokenHash = hashToken(token);
    const tokenId = generateId();
    // One reading of the clock for both, so the recorded lifetime is exactly
    // the configured TTL rather than a millisecond either side of it.
    const now = Date.now();
    const issuedAt = isoFrom(now);
    const expiresAt = isoFrom(now, this.#options.accessTokenTtl);

    const record: AccessRecord = {
      tokenId,
      sessionId: input.sessionId,
      principal: input.principal,
      issuedAt,
      expiresAt,
    };

    const ttl = this.#options.accessTokenTtl;

    // Written before the token is returned, so a caller can never hold a
    // credential that is not yet verifiable.
    await this.#store.set(KEYS.accessToken(tokenHash), JSON.stringify(record), ttl);

    // Reverse index: logout has `req.auth.tokenId` but not the raw token.
    await this.#store.set(KEYS.accessTokenId(tokenId), tokenHash, ttl);

    // Session index, so terminating a session reaches every token under it.
    // Given a slightly longer life than the tokens so the set never expires
    // while a live token still points at it.
    await this.#store.sAdd(KEYS.sessionTokens(input.sessionId), tokenHash, ttl + 60);

    return { token, tokenId, issuedAt, expiresAt };
  }

  async verify(token: string): Promise<AuthContext> {
    // Reject obviously malformed input before touching the store, so garbage
    // cannot be used to generate store load.
    if (typeof token !== 'string' || token.length === 0) {
      throw new TokenInvalidError('empty or non-string token');
    }

    // A transport failure must not be mistaken for a missing record: the
    // first means "unknown", the second would mean "invalid token". Wrapping
    // keeps the distinction, and lets the caller apply its failure mode.
    let raw: string | null;
    try {
      raw = await this.#store.get(KEYS.accessToken(hashToken(token)));
    } catch (error) {
      throw new StoreUnavailableError(
        `store unreachable during token lookup: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    // Absence is the single answer to "never existed", "expired out of the
    // store", and "was revoked". The client is told only that the credential
    // is invalid; distinguishing those cases would let an attacker learn
    // whether a token had ever been real.
    if (raw === null) {
      throw new TokenInvalidError('no record for presented token');
    }

    const record = this.#parseRecord(raw);

    // Belt and braces. The store TTL should already have removed this, but a
    // store whose expiry is approximate, or a clock that moved, must not be
    // able to extend a token's life.
    if (isExpired(record.expiresAt, this.#options.clockToleranceSeconds)) {
      await this.revoke(record.tokenId);
      throw new TokenExpiredError(`token ${record.tokenId} past expiry`);
    }

    return {
      userId: record.principal.userId,
      roles: record.principal.roles,
      scopes: record.principal.scopes,
      ...(record.principal.tenant !== undefined && { tenant: record.principal.tenant }),
      tokenId: record.tokenId,
      sessionId: record.sessionId,
      issuedAt: record.issuedAt,
      expiresAt: record.expiresAt,
      strategy: this.strategy,
    };
  }

  async revoke(tokenId: string): Promise<void> {
    const tokenHash = await this.#store.get(KEYS.accessTokenId(tokenId));

    // Already gone. Idempotent by contract — the caller wanted this token not
    // to work, and it does not.
    if (tokenHash === null) {
      await this.#store.delete(KEYS.accessTokenId(tokenId));
      return;
    }

    // Read the record first so the session index can be cleaned up too;
    // a stale hash left in the set would survive until the set's own TTL.
    const raw = await this.#store.get(KEYS.accessToken(tokenHash));

    await this.#store.delete(KEYS.accessToken(tokenHash), KEYS.accessTokenId(tokenId));

    if (raw !== null) {
      const record = this.#tryParseRecord(raw);
      if (record !== null) {
        await this.#store.sRemove(KEYS.sessionTokens(record.sessionId), tokenHash);
      }
    }
  }

  async revokeSession(sessionId: string): Promise<void> {
    const sessionKey = KEYS.sessionTokens(sessionId);
    const hashes = await this.#store.sMembers(sessionKey);

    if (hashes.length > 0) {
      // Resolve each record to find its token id, so the reverse index is
      // cleaned up as well and cannot leave danglers behind.
      const records = await Promise.all(
        hashes.map(async (hash) => {
          const raw = await this.#store.get(KEYS.accessToken(hash));
          return raw === null ? null : this.#tryParseRecord(raw);
        }),
      );

      const keys = [
        ...hashes.map((hash) => KEYS.accessToken(hash)),
        ...records
          .filter((r): r is AccessRecord => r !== null)
          .map((r) => KEYS.accessTokenId(r.tokenId)),
      ];

      await this.#store.delete(...keys);
    }

    await this.#store.delete(sessionKey);
  }

  /**
   * Parses a stored record, rejecting anything that does not match the shape.
   *
   * A record can be malformed because the schema changed, because something
   * else wrote to the key, or because the value was truncated. None of those
   * are reasons to authenticate a request, so every failure raises
   * `TokenInvalidError` rather than yielding a partially-populated context.
   */
  #parseRecord(raw: string): AccessRecord {
    const record = this.#tryParseRecord(raw);
    if (record === null) {
      throw new TokenInvalidError('stored access record is malformed');
    }
    return record;
  }

  #tryParseRecord(raw: string): AccessRecord | null {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return null;
    }

    if (typeof parsed !== 'object' || parsed === null) return null;
    const r = parsed as Record<string, unknown>;

    if (
      typeof r['tokenId'] !== 'string' ||
      typeof r['sessionId'] !== 'string' ||
      typeof r['issuedAt'] !== 'string' ||
      typeof r['expiresAt'] !== 'string'
    ) {
      return null;
    }

    const principal = this.#tryParsePrincipal(r['principal']);
    if (principal === null) return null;

    return {
      tokenId: r['tokenId'],
      sessionId: r['sessionId'],
      principal,
      issuedAt: r['issuedAt'],
      expiresAt: r['expiresAt'],
    };
  }

  #tryParsePrincipal(value: unknown): Principal | null {
    if (typeof value !== 'object' || value === null) return null;
    const p = value as Record<string, unknown>;

    if (typeof p['userId'] !== 'string' || p['userId'].length === 0) return null;

    const roles = p['roles'];
    const scopes = p['scopes'];
    if (!Array.isArray(roles) || !roles.every((x) => typeof x === 'string')) return null;
    if (!Array.isArray(scopes) || !scopes.every((x) => typeof x === 'string')) return null;

    const tenant = p['tenant'];
    if (tenant !== undefined && typeof tenant !== 'string') return null;

    return {
      userId: p['userId'],
      roles: roles as string[],
      scopes: scopes as string[],
      ...(tenant !== undefined && { tenant }),
    };
  }

  /** Seconds remaining on a token, for callers setting a matching TTL elsewhere. */
  static remainingSeconds(expiresAt: string): number {
    return secondsUntil(expiresAt);
  }
}
