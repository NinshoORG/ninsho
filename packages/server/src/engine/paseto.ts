import {
  StoreUnavailableError,
  TokenExpiredError,
  TokenInvalidError,
  TokenRevokedError,
  generateId,
  isExpired,
  isNotYetValid,
  isoFrom,
  secondsUntil,
  type AuthContext,
  type PasetoClaims,
  type Principal,
} from '@ninsho/core';
import type { NinshoStore } from '../store/types.js';
import { KEYS } from '../keys.js';
import { KeyRing } from '../keys/keyring.js';
import { readFooterUnverified, signV4Public, verifyV4Public } from '../paseto/v4.js';
import type {
  IssueAccessTokenInput,
  IssuedAccessToken,
  TokenEngine,
  VerifyOptions,
} from './types.js';

export interface PasetoEngineOptions {
  readonly accessTokenTtl: number;
  readonly clockToleranceSeconds: number;
  /** Stamped into every token as `iss`, and required to match on verify. */
  readonly issuer: string;
  /** Stamped as `aud`, and required to match on verify. */
  readonly audience: string;
}

/** Footer shape. Carries only the key id — it is readable before verification. */
interface Footer {
  readonly kid: string;
}

/**
 * The `paseto` strategy: stateless, locally verifiable access tokens.
 *
 * ─── When this is the right choice ────────────────────────────────────────
 * Only when several services must verify tokens independently without sharing
 * a session store. For a single application the `opaque` strategy is strictly
 * better — see the note on {@link OpaqueEngine}.
 *
 * The trade-off this strategy makes is explicit: a signed token is valid until
 * it expires, whether or not anyone still wants it to be. Revocation therefore
 * requires a denylist lookup, and a verifier that skips that lookup is
 * trusting a token that may have been revoked minutes ago. Ninsho always
 * performs it, which is why the access token TTL defaults to five minutes —
 * that is the window in which a denylist outage matters.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * ─── What is structurally impossible here ─────────────────────────────────
 * PASETO fixes the algorithm to Ed25519 in the version string. There is no
 * `alg` header to manipulate, so JWT's algorithm-confusion family — `alg:
 * none`, HMAC-verified-against-a-public-key — cannot be expressed. This is the
 * one genuine advantage PASETO has over JWT, and it is a property of the
 * format rather than of this implementation.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * SECURITY: tokens are signed, not encrypted. Every claim is readable by
 * anyone holding the token. Never put personal data in a `Principal`.
 */
export class PasetoEngine implements TokenEngine {
  readonly strategy = 'paseto' as const;

  /**
   * True. The signature is verified locally against a key already in memory,
   * so a store outage costs only the denylist lookup. That makes
   * `onStoreError: 'open'` a coherent posture here — weakened, but coherent.
   */
  readonly canVerifyWithoutStore = true;

  readonly #store: NinshoStore;
  readonly #keys: KeyRing;
  readonly #options: PasetoEngineOptions;

  constructor(store: NinshoStore, keys: KeyRing, options: PasetoEngineOptions) {
    this.#store = store;
    this.#keys = keys;
    this.#options = options;
  }

  async issue(input: IssueAccessTokenInput): Promise<IssuedAccessToken> {
    const tokenId = generateId();
    // One reading of the clock, so iat/nbf/exp are exactly consistent.
    const now = Date.now();
    const issuedAt = isoFrom(now);
    const expiresAt = isoFrom(now, this.#options.accessTokenTtl);

    const claims: PasetoClaims = {
      jti: tokenId,
      sub: input.principal.userId,
      iss: this.#options.issuer,
      aud: this.#options.audience,
      iat: issuedAt,
      nbf: issuedAt,
      exp: expiresAt,
      sid: input.sessionId,
      roles: input.principal.roles,
      scopes: input.principal.scopes,
      ...(input.principal.tenant !== undefined && { tenant: input.principal.tenant }),
      // RFC 9449 §6.1. Inside the signed payload, so the binding cannot be
      // stripped by anyone who does not hold the signing key.
      ...(input.confirmationKey !== undefined && {
        cnf: { jkt: input.confirmationKey },
      }),
    };

    const footer: Footer = { kid: this.#keys.signingKid };
    const token = signV4Public(
      JSON.stringify(claims),
      this.#keys.privateKey,
      JSON.stringify(footer),
    );

    // Tracked so a session can be terminated. Unlike the opaque strategy this
    // index is the *only* way to reach a token again — the token itself is not
    // stored anywhere, so without this, "sign out this device" could not
    // revoke the access tokens it had already issued.
    await this.#store.sAdd(
      KEYS.sessionTokens(input.sessionId),
      tokenId,
      this.#options.accessTokenTtl + 60,
    );

    return { token, tokenId, issuedAt, expiresAt };
  }

  async verify(token: string, options: VerifyOptions = {}): Promise<AuthContext> {
    if (typeof token !== 'string' || token.length === 0) {
      throw new TokenInvalidError('empty or non-string token');
    }

    // ── Select a key from the footer, then prove the footer was genuine ────
    // The footer is attacker-controlled until the signature verifies. It is
    // used only to look up a candidate key; a fabricated kid resolves to
    // nothing, and a swapped one fails verification a few lines below.
    let kid: string;
    try {
      kid = this.#readKid(readFooterUnverified(token));
    } catch {
      throw new TokenInvalidError('token footer is missing or malformed');
    }

    const publicKey = this.#keys.resolve(kid);
    if (publicKey === null) {
      // A retired key removed from the set and a key an attacker invented are
      // the same thing from here: neither can authenticate anything.
      throw new TokenInvalidError(`unknown key id: ${kid}`);
    }

    let payload: string;
    try {
      payload = verifyV4Public(token, publicKey).payload;
    } catch (error) {
      // The whole string is `detail` — server-side only. TokenInvalidError's
      // client-facing message is a fixed constant and is never built from this.
      throw new TokenInvalidError(
        `signature verification failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }

    // ── Everything below runs on authenticated bytes ──────────────────────
    const claims = this.#parseClaims(payload);
    if (claims === null) {
      throw new TokenInvalidError('token claims are malformed');
    }

    // Issuer and audience are checked before expiry so a token minted for a
    // different service is rejected as invalid rather than reported as
    // expired, which would invite a pointless refresh.
    if (claims.iss !== this.#options.issuer) {
      throw new TokenInvalidError(
        `issuer mismatch: expected ${this.#options.issuer}, got ${claims.iss}`,
      );
    }
    if (claims.aud !== this.#options.audience) {
      // The check the predecessor lacked entirely: without it, any service
      // holding the public key accepts tokens minted for any other service.
      throw new TokenInvalidError(
        `audience mismatch: expected ${this.#options.audience}, got ${claims.aud}`,
      );
    }

    const tolerance = this.#options.clockToleranceSeconds;
    if (isNotYetValid(claims.nbf, tolerance)) {
      throw new TokenInvalidError('token is not yet valid');
    }
    if (isNotYetValid(claims.iat, tolerance)) {
      throw new TokenInvalidError('token was issued in the future');
    }
    if (isExpired(claims.exp, tolerance)) {
      throw new TokenExpiredError(`token ${claims.jti} past expiry`);
    }

    // ── Proof-of-possession ───────────────────────────────────────────────
    // A bound token presented without a matching proof is refused. Accepting
    // it would silently degrade DPoP to bearer semantics the moment a caller
    // forgot to pass the proof through — and everything would keep working,
    // so nobody would notice.
    if (claims.cnf !== undefined) {
      if (options.confirmationKey === undefined) {
        throw new TokenInvalidError(`token ${claims.jti} is DPoP-bound but no proof was presented`);
      }
      if (options.confirmationKey !== claims.cnf.jkt) {
        throw new TokenInvalidError(
          `token ${claims.jti} is bound to a different key than the presented proof`,
        );
      }
    }

    // ── Revocation ────────────────────────────────────────────────────────
    // A store failure propagates as StoreUnavailableError rather than being
    // read as "not revoked". Deciding what an outage means belongs to the
    // configured failure mode; swallowing it here would take that decision
    // away and silently resurrect every revoked token.
    if (options.skipRevocationCheck !== true) {
      let revoked: boolean;
      try {
        revoked = await this.#store.exists(KEYS.revoked(claims.jti));
      } catch (error) {
        throw new StoreUnavailableError(
          `store unreachable during revocation check: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      if (revoked) {
        throw new TokenRevokedError(`token ${claims.jti} is revoked`);
      }
    }

    return {
      userId: claims.sub,
      roles: claims.roles,
      scopes: claims.scopes,
      ...(claims.tenant !== undefined && { tenant: claims.tenant }),
      tokenId: claims.jti,
      sessionId: claims.sid,
      issuedAt: claims.iat,
      expiresAt: claims.exp,
      strategy: this.strategy,
      ...(claims.cnf !== undefined && { confirmationKey: claims.cnf.jkt }),
    };
  }

  /**
   * Denylists a token id until it would have expired anyway.
   *
   * The TTL matching the token's own lifetime is what keeps the denylist
   * bounded without a cleanup job: an entry becomes redundant at precisely the
   * moment the token it blocks stops verifying.
   *
   * Idempotent, and a no-op for an unknown id — the caller's intent is that
   * the token not work, which is already true.
   */
  async revoke(tokenId: string): Promise<void> {
    // Without the issue time, assume a full lifetime. Over-retaining a
    // denylist entry is harmless; under-retaining would let a revoked token
    // come back to life.
    await this.#store.set(KEYS.revoked(tokenId), '1', this.#options.accessTokenTtl);
  }

  async revokeSession(sessionId: string): Promise<void> {
    const sessionKey = KEYS.sessionTokens(sessionId);
    const tokenIds = await this.#store.sMembers(sessionKey);

    await Promise.all(tokenIds.map((tokenId) => this.revoke(tokenId)));
    await this.#store.delete(sessionKey);
  }

  /** Extracts `kid` from a footer. Rejects anything that is not the expected shape. */
  #readKid(footer: string): string {
    if (footer === '') throw new Error('empty footer');
    const parsed: unknown = JSON.parse(footer);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error('footer is not an object');
    }
    const kid = (parsed as Record<string, unknown>)['kid'];
    if (typeof kid !== 'string' || kid.length === 0) {
      throw new Error('footer has no kid');
    }
    return kid;
  }

  /**
   * Validates the claim set.
   *
   * The signature proves these bytes came from a holder of the private key; it
   * says nothing about their shape. A token signed by an older version of this
   * library, or by a service with a different claim set, must be rejected
   * rather than yielding a half-populated context — `roles` arriving as a
   * string instead of an array would otherwise reach authorization code.
   */
  #parseClaims(payload: string): PasetoClaims | null {
    let parsed: unknown;
    try {
      parsed = JSON.parse(payload);
    } catch {
      return null;
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
    const c = parsed as Record<string, unknown>;

    const strings = ['jti', 'sub', 'iss', 'aud', 'iat', 'nbf', 'exp', 'sid'] as const;
    for (const field of strings) {
      if (typeof c[field] !== 'string' || (c[field] as string).length === 0) return null;
    }

    const roles = c['roles'];
    const scopes = c['scopes'];
    if (!Array.isArray(roles) || !roles.every((r) => typeof r === 'string')) return null;
    if (!Array.isArray(scopes) || !scopes.every((s) => typeof s === 'string')) return null;

    const tenant = c['tenant'];
    if (tenant !== undefined && typeof tenant !== 'string') return null;

    // A malformed `cnf` must reject the token rather than be ignored: dropping
    // it would turn a proof-of-possession token into a bearer one.
    const rawCnf = c['cnf'];
    let cnf: { jkt: string } | undefined;
    if (rawCnf !== undefined) {
      if (typeof rawCnf !== 'object' || rawCnf === null || Array.isArray(rawCnf)) return null;
      const jkt = (rawCnf as Record<string, unknown>)['jkt'];
      if (typeof jkt !== 'string' || jkt.length === 0) return null;
      cnf = { jkt };
    }

    return {
      jti: c['jti'] as string,
      sub: c['sub'] as string,
      iss: c['iss'] as string,
      aud: c['aud'] as string,
      iat: c['iat'] as string,
      nbf: c['nbf'] as string,
      exp: c['exp'] as string,
      sid: c['sid'] as string,
      roles: roles as string[],
      scopes: scopes as string[],
      ...(tenant !== undefined && { tenant }),
      ...(cnf !== undefined && { cnf }),
    };
  }

  /** Seconds remaining on a token, for callers setting a matching TTL. */
  static remainingSeconds(expiresAt: string): number {
    return secondsUntil(expiresAt);
  }
}

/** Re-exported so callers constructing an engine need one import. */
export { KeyRing };

/** Convenience alias so `Principal` is importable alongside the engine. */
export type { Principal };
