/**
 * Core type surface for Ninsho.
 *
 * Everything here is strategy-agnostic: nothing in this file knows whether an
 * access token is an opaque random string or a signed PASETO. That distinction
 * lives behind the `TokenStrategy` interface in `@ninsho/server`, which is what
 * lets one API serve both single-app and multi-service deployments.
 *
 * This package has no runtime dependencies and no server- or browser-specific
 * imports, so the future client SDK can share it.
 */

// ─── Strategy and mode selectors ────────────────────────────────────────────

/**
 * How access tokens are represented.
 *
 *  - `opaque`  (default) — a 256-bit random string; all state lives in the
 *    store. Verification is a store lookup. Revocation is immediate and native.
 *    No signing keys exist at all. Correct for a single application.
 *
 *  - `paseto` — a PASETO v4.public token signed with Ed25519, carrying claims
 *    that any service holding the public key can verify locally without a
 *    round trip. Requires `issuer`, `audience` and a key set. Correct when
 *    several services must verify independently.
 */
export type TokenStrategy = 'opaque' | 'paseto';

/**
 * How an access token is bound to the client presenting it.
 *
 *  - `none` (default) — bearer semantics. Anyone holding the token can use it.
 *    This is the same guarantee every mainstream bearer-token system provides,
 *    and it is stated plainly rather than dressed up as replay protection.
 *
 *  - `dpop` — proof-of-possession per RFC 9449. Tokens are bound to a key the
 *    client holds privately, and every request must carry a fresh proof signed
 *    by it. A stolen token is useless without the key, which in a browser
 *    should be a non-extractable WebCrypto key.
 *
 * Note that user-agent fingerprinting is deliberately absent. It is not a
 * binding mechanism: the User-Agent is a header the client chooses, so an
 * attacker replaying a stolen token simply sends the victim's value. It is
 * available as an audit signal (see `SecuritySignals`), never as a control.
 */
export type BindingMode = 'none' | 'dpop';

/**
 * What to do when the session store cannot be reached.
 *
 *  - `closed` (default) — reject the request. Revocation is a security
 *    guarantee; if it cannot be checked, the guarantee cannot be honoured.
 *
 *  - `open` — allow the request, skipping the revocation check. Every revoked
 *    token becomes valid again for the duration of the outage. Choosing this
 *    is legitimate for availability-critical systems, but it is a security
 *    downgrade and Ninsho logs a warning at startup when it is set.
 */
export type FailureMode = 'closed' | 'open';

// ─── Identity and authorization ─────────────────────────────────────────────

/**
 * Who a session belongs to and what it is permitted to do.
 *
 * Embedded in both access and refresh records so that authorization data
 * survives token rotation without a second lookup.
 *
 * SECURITY: everything in here may end up inside a PASETO payload, which is
 * signed but NOT encrypted. Never place email addresses, names, or any other
 * personal data in these fields — `userId` must be an opaque identifier.
 */
export interface Principal {
  /** Opaque user identifier. Becomes the `sub` claim in paseto mode. */
  readonly userId: string;
  /** Coarse-grained roles, e.g. `['admin']`. Enforced by `requireRole()`. */
  readonly roles: readonly string[];
  /** Fine-grained permissions, e.g. `['orders:read']`. Enforced by `requireScope()`. */
  readonly scopes: readonly string[];
  /** Tenant identifier for multi-tenant deployments. Enforced by `requireTenant()`. */
  readonly tenant?: string;
}

// ─── Request context ────────────────────────────────────────────────────────

/**
 * The verified identity attached to `req.auth` once `verify()` has passed.
 *
 * Field names favour clarity over claim-name fidelity: this is a developer
 * surface, not a wire format. The corresponding PASETO claims (`sub`, `jti`,
 * `sid`) are an implementation detail of the paseto strategy.
 */
export interface AuthContext extends Principal {
  /**
   * Identifier for this specific access token.
   * Maps to the `jti` claim in paseto mode; the record id in opaque mode.
   * Use it to revoke exactly this token.
   */
  readonly tokenId: string;
  /**
   * Identifier for the session (the refresh-token family) this access token
   * belongs to. Stable across every rotation, so it is the right handle for
   * "sign this device out" and for correlating audit events.
   */
  readonly sessionId: string;
  /** When this access token was issued. ISO 8601. */
  readonly issuedAt: string;
  /**
   * When the user actually authenticated, ISO 8601.
   *
   * ─── Why this is not `issuedAt` ─────────────────────────────────────────
   * `issuedAt` is when this *token* was minted, and rotation mints a new one
   * every few minutes for as long as the session lives. A session refreshed
   * for thirty days has an `issuedAt` that is always minutes old.
   *
   * So `issuedAt` cannot answer "did this person prove who they are
   * recently?", which is the question a step-up check asks before letting
   * someone change an email address or move money. This field can: it is fixed
   * when the session is created and carried unchanged through every rotation.
   *
   * Enforce it with `requireFreshAuth()`.
   * ────────────────────────────────────────────────────────────────────────
   */
  readonly authenticatedAt: string;
  /** When this access token expires. ISO 8601. */
  readonly expiresAt: string;
  /** Which strategy produced this token. Useful in logs and in mixed fleets. */
  readonly strategy: TokenStrategy;
  /**
   * Thumbprint of the DPoP key this token is bound to, when it is bound.
   *
   * Its presence means proof-of-possession was verified for this request.
   * Absent means the token was a bearer credential — anyone holding it could
   * have made this call.
   */
  readonly confirmationKey?: string;
}

// ─── Stored records ─────────────────────────────────────────────────────────

/**
 * Server-side record for an opaque access token.
 *
 * Keyed in the store by `sha256(rawToken)` — the raw token is never stored, so
 * read access to the store does not yield usable credentials.
 *
 * Not used in paseto mode, where the claims travel inside the signed token.
 */
export interface AccessRecord {
  readonly tokenId: string;
  readonly sessionId: string;
  readonly principal: Principal;
  readonly issuedAt: string;
  /** When the user authenticated. Constant across rotations — see AuthContext. */
  readonly authenticatedAt: string;
  readonly expiresAt: string;
  /**
   * RFC 7638 thumbprint of the DPoP key this token is bound to.
   *
   * Present only under `binding: 'dpop'`. When set, the token is no longer a
   * bearer credential: presenting it also requires a proof signed by the
   * matching private key, so a stolen token is useless on its own.
   */
  readonly confirmationKey?: string;
}

/**
 * Server-side record for a refresh token.
 *
 * Keyed by `sha256(rawToken)`. Used by both strategies — refresh handling is
 * identical whether access tokens are opaque or signed.
 *
 * `sessionId` identifies the *family*: every token produced by rotating this
 * one shares it. That is what makes family-wide revocation possible when reuse
 * is detected (RFC 9700 §4.14.2).
 */
export interface RefreshRecord {
  /** The family this token belongs to. Constant across rotations. */
  readonly sessionId: string;
  readonly principal: Principal;
  readonly issuedAt: string;
  /**
   * When the user authenticated, fixed at session creation.
   *
   * Carried through every rotation deliberately: a refresh is not a new proof
   * of identity, so it must not reset the clock a step-up check reads.
   */
  readonly authenticatedAt: string;
  /** When this individual token expires. Reset on each rotation. */
  readonly expiresAt: string;
  /**
   * Hard ceiling on the whole family, fixed when the session was created and
   * never extended by rotation.
   *
   * Without it, refresh rotation gives a session unlimited life: each rotation
   * pushes expiry further out, so a token stolen from an active session can be
   * kept alive indefinitely by an attacker who simply keeps refreshing. The
   * cap bounds that, and forces a genuine re-authentication on a schedule.
   */
  readonly familyExpiresAt: string;
  /**
   * RFC 7638 thumbprint of the DPoP key this family is bound to.
   *
   * RFC 9449 §5 binds refresh tokens for public clients to the same key as the
   * access token. Without it, a stolen refresh token would still be freely
   * redeemable — which would leave the longest-lived credential in the system
   * as the one piece with no proof-of-possession.
   */
  readonly confirmationKey?: string;
  /**
   * How many times this family has been rotated. Starts at 0.
   * Recorded for forensics: a reuse event reports which generation was
   * replayed, which distinguishes a stale browser tab from a replay attack.
   */
  readonly generation: number;
}

// ─── Issued credentials ─────────────────────────────────────────────────────

/** The credential pair handed back after authentication or refresh. */
export interface TokenPair {
  /**
   * Send to the client and hold in memory only.
   * Never `localStorage` — any XSS on the page can read it there.
   */
  readonly accessToken: string;
  /**
   * Delivered as an httpOnly cookie by default. Treat as a secret; never log
   * it, never place it in a URL, never return it in a response body.
   */
  readonly refreshToken: string;
  readonly accessExpiresAt: string;
  readonly refreshExpiresAt: string;
  /** The session (family) both tokens belong to. */
  readonly sessionId: string;
}

// ─── PASETO claims (paseto strategy only) ───────────────────────────────────

/**
 * The claim set carried inside a PASETO v4.public access token.
 *
 * Time claims are ISO 8601 strings, which is what the PASETO specification
 * requires — unlike JWT's numeric timestamps.
 *
 * SECURITY: signed, not encrypted. Anyone holding the token can read every
 * field here. See the warning on `Principal`.
 */
export interface PasetoClaims {
  /** Token identifier. Surfaces as `AuthContext.tokenId`. */
  readonly jti: string;
  /** Subject — the opaque user id. */
  readonly sub: string;
  /**
   * Issuer. Validated on every verify. Required, because a token minted by one
   * deployment must not be accepted by another that happens to share a key.
   */
  readonly iss: string;
  /**
   * Audience — the service this token is for. Validated on every verify.
   * Required, so a token for `orders-api` is rejected by `billing-api`.
   */
  readonly aud: string;
  readonly iat: string;
  readonly nbf: string;
  readonly exp: string;
  /**
   * When the user authenticated. Named for OIDC's `auth_time`, which carries
   * the same meaning, so the claim reads the way people expect.
   */
  readonly auth_time: string;
  /** Session (refresh family) id. Surfaces as `AuthContext.sessionId`. */
  readonly sid: string;
  readonly roles: readonly string[];
  readonly scopes: readonly string[];
  readonly tenant?: string;
  /**
   * Confirmation claim — proof-of-possession, RFC 9449 §6.1.
   *
   * `jkt` is the RFC 7638 thumbprint of the client's DPoP key. When present,
   * a verifier must additionally require a proof signed by that key, and this
   * token stops being a bearer credential.
   */
  readonly cnf?: { readonly jkt: string };
}

// ─── Key material (paseto strategy only) ────────────────────────────────────

/** An Ed25519 keypair used to sign access tokens, identified by `kid`. */
export interface SigningKey {
  /**
   * Key identifier, published in the PASETO footer so a verifier knows which
   * key to check against. The footer is authenticated by the signature, and is
   * readable before verification — which is exactly what key selection needs.
   */
  readonly kid: string;
  /** PKCS#8 DER, hex-encoded. */
  readonly privateKey: string;
  /** SPKI DER, hex-encoded. */
  readonly publicKey: string;
}

/** A public key retained so tokens signed before a rotation still verify. */
export interface VerificationKey {
  readonly kid: string;
  readonly publicKey: string;
}

/**
 * The set of keys a deployment trusts.
 *
 * Rotation is: mint a new keypair, move the old `active` into `previous`, and
 * deploy. Tokens signed by the old key keep verifying until they expire, so
 * rotation causes no forced logouts. Drop the old key from `previous` once the
 * longest access-token TTL has elapsed.
 */
export interface KeySet {
  /** Signs all new tokens; also verifies. */
  readonly active: SigningKey;
  /** Verify-only. Retired keys still inside their overlap window. */
  readonly previous?: readonly VerificationKey[];
}

// ─── Audit ──────────────────────────────────────────────────────────────────

/**
 * Security-relevant events emitted by the engine.
 *
 * Namespaced `subject.verb` so that a log pipeline can filter on prefix.
 * `refresh.reuse_detected` is the highest-signal event Ninsho produces: it
 * means a refresh token was replayed after rotation, which is the strongest
 * indication of credential theft an authentication system can observe.
 */
export type SecurityEventType =
  | 'session.created'
  | 'session.refreshed'
  | 'session.revoked'
  | 'session.revoked_all'
  | 'token.rejected'
  | 'token.revoked'
  | 'refresh.reuse_detected'
  | 'auth.failed'
  | 'authz.denied'
  | 'ratelimit.exceeded'
  | 'store.unavailable'
  | 'config.insecure';

/**
 * A structured security event.
 *
 * SECURITY: this shape is deliberately narrow. There is no free-form payload
 * field that could accidentally carry a raw token, a password, or a request
 * body. `reason` is for short, non-sensitive classifiers such as
 * `'signature_invalid'` — never for user input and never for secrets.
 */
export interface SecurityEvent {
  readonly type: SecurityEventType;
  readonly at: string;
  readonly userId?: string;
  readonly sessionId?: string;
  readonly tokenId?: string;
  /** Client address, when known and when the proxy configuration makes it trustworthy. */
  readonly ip?: string;
  /** Short non-sensitive classifier. Never user input, never a secret. */
  readonly reason?: string;
}

/**
 * Where security events go. Defaults to structured JSON on stdout; supply your
 * own to forward into an existing logging or SIEM pipeline.
 *
 * Implementations must not throw — the engine treats auditing as best-effort
 * and will not fail an authentication because a log sink was unavailable.
 */
export interface AuditSink {
  emit(event: SecurityEvent): void;
}

// ─── Non-security signals ───────────────────────────────────────────────────

/**
 * Weak client signals recorded for anomaly detection.
 *
 * These are explicitly NOT access-control inputs. Every field is
 * client-controlled and trivially forged, so nothing in Ninsho branches on
 * them. They exist so a host application can notice that a session's
 * user-agent changed and decide, with its own context, whether to step up
 * authentication.
 *
 * This is where the old device-fingerprinting feature went, and the demotion
 * is deliberate: presenting attacker-supplied data as a security boundary was
 * the most misleading claim in the previous implementation.
 */
export interface SecuritySignals {
  readonly userAgentHash?: string;
  readonly ipHash?: string;
}
