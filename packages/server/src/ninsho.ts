import type { Principal, TokenPair } from '@ninsho/core';
import { resolveConfig, type NinshoConfig, type ResolvedConfig } from './config.js';
import type { NinshoStore } from './store/types.js';
import type { TokenEngine } from './engine/types.js';
import { OpaqueEngine } from './engine/opaque.js';
import { PasetoEngine } from './engine/paseto.js';
import { KeyRing } from './keys/keyring.js';
import { SessionManager } from './session/manager.js';
import type { RevocationReason, SessionSummary } from './session/types.js';
import {
  createErrorHandler,
  createRequireAllRoles,
  createRequireOwner,
  createRequireRole,
  createRequireScope,
  createRequireTenant,
  createVerify,
} from './http/middleware.js';
import type { Middleware, ValueSelector } from './http/types.js';
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
  createSession(principal: Principal): Promise<TokenPair> {
    return this.#sessions.create(principal);
  }

  /**
   * Exchanges a refresh token for a new pair, rotating it.
   *
   * @throws {RefreshReuseError} The token was already rotated. The family is
   *   revoked before this throws — treat it as a compromise signal, not a
   *   routine failure.
   */
  refresh(rawRefreshToken: string): Promise<TokenPair> {
    return this.#sessions.refresh(rawRefreshToken);
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

  /** Authenticates the request and populates `req.auth`. Mount before any check below. */
  verify(): Middleware {
    return createVerify({
      engine: this.#engine,
      onStoreError: this.#config.onStoreError,
      audit: this.#config.audit,
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
