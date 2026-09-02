import type { Principal, TokenPair } from '@ninsho/core';
import { resolveConfig, type NinshoConfig, type ResolvedConfig } from './config.js';
import type { NinshoStore } from './store/types.js';
import type { TokenEngine } from './engine/types.js';
import { OpaqueEngine } from './engine/opaque.js';
import { PasetoEngine } from './engine/paseto.js';
import { KeyRing } from './keys/keyring.js';
import { SessionManager } from './session/manager.js';
import type {
  CreateSessionOptions,
  RefreshSessionOptions,
  RevocationReason,
  SessionSummary,
} from './session/types.js';
import {
  createErrorHandler,
  createRequireAllRoles,
  createRequireOwner,
  createRequireRole,
  createRequireScope,
  createRequireTenant,
  createRequireFreshAuth,
  createVerify,
} from './http/middleware.js';
import { establishProofOfPossession } from './http/dpop-middleware.js';
import type { HttpRequest, Middleware, ValueSelector } from './http/types.js';
import { DpopReplayGuard } from './dpop/replay.js';
import type { DpopContext } from './http/dpop-middleware.js';
import { RateLimiter } from './ratelimit/limiter.js';
import { createRateLimit, type RateLimitOptions } from './ratelimit/middleware.js';

/**
 * The one object an application needs.
 *
 * Wires the store, token engine, session manager, middleware and rate limiter
 * from a single configuration object, and validates that configuration
 * synchronously so a misconfigured deployment fails at boot rather than at the
 * first request.
 *
 * ─── The shortest configuration is the safest one ─────────────────────────
 * ```ts
 * const auth = new Ninsho({ store: new RedisStore(process.env.REDIS_URL!) });
 * ```
 *
 * That is the whole setup. It yields opaque tokens with no signing keys to
 * generate or rotate, fail-closed behaviour, five-minute access tokens, and
 * refresh rotation with reuse detection. Every deviation from it — stateless
 * tokens, fail-open, a longer TTL — is something the developer has to ask for
 * by name, and several of them emit a startup warning when asked for.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * Ninsho deliberately does not verify credentials. Passwords, WebAuthn and
 * federated sign-in are the application's concern; conflating them with
 * session management is how auth libraries end up dictating a user model.
 * Establish identity yourself, then call {@link createSession}.
 */
export class Ninsho {
  readonly #config: ResolvedConfig;
  readonly #engine: TokenEngine;
  readonly #sessions: SessionManager;
  readonly #limiter: RateLimiter;
  /** Present only under `binding: 'dpop'`. Its presence enables proof checking. */
  readonly #dpop: DpopContext | undefined;
  /** Overridable so a deployment can build the proof URI from configuration. */
  #requestUrl: ((req: HttpRequest) => string) | undefined;

  constructor(config: NinshoConfig) {
    this.#config = resolveConfig(config);

    this.#engine =
      this.#config.strategy === 'paseto'
        ? new PasetoEngine(
            this.#config.store,
            // resolveConfig has already proven these are present for paseto.
            new KeyRing(this.#config.keys!),
            {
              accessTokenTtl: this.#config.accessTokenTtl,
              clockToleranceSeconds: this.#config.clockToleranceSeconds,
              issuer: this.#config.issuer!,
              audience: this.#config.audience!,
            },
          )
        : new OpaqueEngine(this.#config.store, {
            accessTokenTtl: this.#config.accessTokenTtl,
            clockToleranceSeconds: this.#config.clockToleranceSeconds,
          });

    this.#sessions = new SessionManager(this.#config.store, this.#engine, {
      refreshTokenTtl: this.#config.refreshTokenTtl,
      refreshGraceSeconds: this.#config.refreshGraceSeconds,
      clockToleranceSeconds: this.#config.clockToleranceSeconds,
      audit: this.#config.audit,
    });

    this.#limiter = new RateLimiter({
      store: this.#config.store,
      onStoreError: this.#config.onStoreError,
      audit: this.#config.audit,
    });

    this.#dpop =
      this.#config.binding === 'dpop'
        ? {
            replayGuard: new DpopReplayGuard(
              this.#config.store,
              this.#config.onStoreError,
              // Remembered for at least as long as a proof stays acceptable.
              // A shorter retention would forget a proof that would still be
              // accepted, reopening the replay it exists to close.
              this.#config.dpopProofMaxAgeSeconds + this.#config.clockToleranceSeconds + 1,
            ),
            maxAgeSeconds: this.#config.dpopProofMaxAgeSeconds,
            clockToleranceSeconds: this.#config.clockToleranceSeconds,
            audit: this.#config.audit,
          }
        : undefined;

    // Surface every accepted-but-weakening choice once, at startup, where an
    // operator will see it — rather than leaving it to be discovered from an
    // incident. `config.insecure` is a distinct event type so it can be
    // alerted on separately from ordinary traffic.
    for (const warning of this.#config.warnings) {
      this.#config.audit.emit({
        type: 'config.insecure',
        at: new Date().toISOString(),
        reason: warning,
      });
    }
  }

  // ── Sessions ──────────────────────────────────────────────────────────────

  /**
   * Starts a session for an already-authenticated principal.
   * Call only after your own credential check has succeeded.
   */
  createSession(principal: Principal, options: CreateSessionOptions = {}): Promise<TokenPair> {
    if (this.#dpop !== undefined && options.confirmationKey === undefined) {
      // Fail closed. Silently issuing an unbound token here would mean a
      // deployment believed it had proof-of-possession while handing out
      // bearer credentials — and nothing downstream would reveal it, because
      // an unbound token verifies perfectly well.
      throw new Error(
        "ninsho: binding is 'dpop', so createSession() requires a confirmationKey. " +
          'Obtain it with confirmProofOfPossession(req) on the login route.',
      );
    }
    return this.#sessions.create(principal, options);
  }

  /**
   * Exchanges a refresh token for a new pair, rotating it.
   *
   * @throws {RefreshReuseError} The token was already rotated. The family is
   *   revoked before this throws — treat it as a compromise signal, not a
   *   routine failure.
   */
  refresh(
    rawRefreshToken: string,
    options: RefreshSessionOptions = {},
  ): Promise<TokenPair> {
    return this.#sessions.refresh(rawRefreshToken, options);
  }

  /** Ends one session — its refresh family and every access token under it. */
  revokeSession(sessionId: string, reason?: RevocationReason): Promise<void> {
    return this.#sessions.revoke(sessionId, reason);
  }

  /** Ends every session for a user. The response to a password change or compromise. */
  revokeAllForUser(userId: string, reason?: RevocationReason): Promise<void> {
    return this.#sessions.revokeAllForUser(userId, reason);
  }

  /** Lists a user's live sessions. Contains no credential material. */
  listSessions(userId: string, currentSessionId?: string): Promise<SessionSummary[]> {
    return this.#sessions.listSessions(userId, currentSessionId);
  }

  // ── Middleware ────────────────────────────────────────────────────────────

  /**
   * Authenticates the request and populates `req.auth`. Mount before any check
   * below.
   *
   * Under `binding: 'dpop'` this additionally requires a valid, unreplayed
   * `DPoP` proof header bound to the presented token.
   */
  verify(): Middleware {
    return createVerify({
      engine: this.#engine,
      onStoreError: this.#config.onStoreError,
      audit: this.#config.audit,
      ...(this.#dpop !== undefined && {
        dpop: {
          ...this.#dpop,
          ...(this.#requestUrl !== undefined && { requestUrl: this.#requestUrl }),
        },
      }),
    });
  }

  /**
   * Overrides how the request URI a DPoP proof must match is reconstructed.
   *
   * The default derives it from the request, which trusts the `Host` header.
   * Behind a proxy that sets `Host` reliably — the normal deployment — that is
   * correct. Elsewhere, supply a builder that uses configuration instead, or
   * an attacker who controls `Host` controls both sides of the comparison.
   */
  setRequestUrlBuilder(build: (req: HttpRequest) => string): void {
    this.#requestUrl = build;
  }

  /**
   * Verifies a DPoP proof outside the middleware, returning the key thumbprint
   * to bind a new session to.
   *
   * Needed on the login route, which runs *before* any token exists: the client
   * sends its first proof there, and the thumbprint it yields is what
   * {@link createSession} binds the session to.
   *
   * @throws {TokenMissingError} No proof header, or more than one.
   * @throws {TokenInvalidError} The proof failed verification or was replayed.
   */
  async confirmProofOfPossession(req: HttpRequest, accessToken?: string): Promise<string> {
    if (this.#dpop === undefined) {
      throw new Error(
        "ninsho: confirmProofOfPossession() requires binding: 'dpop'. " +
          'Under bearer semantics there is no proof to confirm.',
      );
    }
    return establishProofOfPossession(req, accessToken, {
      ...this.#dpop,
      ...(this.#requestUrl !== undefined && { requestUrl: this.#requestUrl }),
    });
  }

  /** Requires any one of the given roles. */
  requireRole(roles: string | readonly string[]): Middleware {
    return createRequireRole(this.#config.audit)(roles);
  }

  /** Requires all of the given roles. */
  requireAllRoles(roles: string | readonly string[]): Middleware {
    return createRequireAllRoles(this.#config.audit)(roles);
  }

  /** Requires any one of the given scopes. */
  requireScope(scopes: string | readonly string[]): Middleware {
    return createRequireScope(this.#config.audit)(scopes);
  }

  /**
   * Requires that the caller owns the resource being addressed — the check
   * that closes OWASP API Security #1.
   */
  requireOwner(selector: ValueSelector): Middleware {
    return createRequireOwner(this.#config.audit)(selector);
  }

  /** Requires that the caller's tenant matches the tenant being addressed. */
  requireTenant(selector: ValueSelector): Middleware {
    return createRequireTenant(this.#config.audit)(selector);
  }

  /**
   * Requires that the user authenticated within the last `maxAgeSeconds` — a
   * step-up check, for operations where a live session is not enough.
   *
   * Mount it on the routes where being signed in should not be sufficient:
   * changing an email address, adding a passkey, moving money.
   *
   * ```ts
   * app.post('/account/email', auth.verify(), auth.requireFreshAuth(300), handler);
   * ```
   *
   * This reads the *authentication* time, not the token's issue time. A
   * refresh mints a new token but is not a new proof of identity, so refreshing
   * will never satisfy this check — only re-authenticating and starting a new
   * session will.
   */
  requireFreshAuth(maxAgeSeconds: number): Middleware {
    return createRequireFreshAuth(this.#config.audit)(maxAgeSeconds);
  }

  /**
   * Rate-limits an endpoint across a per-address bucket and, when configured,
   * a per-account bucket.
   *
   * `trustProxy` has no default and must be stated: keying on the wrong
   * address either locks out everyone behind a shared proxy or lets one
   * attacker bypass the limit by rotating a header.
   */
  rateLimit(options: RateLimitOptions): Middleware {
    return createRateLimit(this.#limiter, this.#config.audit, options);
  }

  /** Terminal error handler for frameworks that route errors to middleware. */
  errorHandler(): ReturnType<typeof createErrorHandler> {
    return createErrorHandler();
  }

  // ── Operations ────────────────────────────────────────────────────────────

  /** Whether the store is reachable. For a health endpoint. */
  health(): Promise<boolean> {
    return this.#config.store.ping();
  }

  /** Releases store connections. */
  close(): Promise<void> {
    return this.#config.store.close();
  }

  /**
   * The resolved configuration, with defaults applied.
   * Read-only; exposed for diagnostics and for tests that assert on defaults.
   */
  get config(): ResolvedConfig {
    return this.#config;
  }

  /** The underlying store. Escape hatch for advanced use. */
  get store(): NinshoStore {
    return this.#config.store;
  }

  /** The underlying token engine. Escape hatch for advanced use. */
  get engine(): TokenEngine {
    return this.#engine;
  }
}
