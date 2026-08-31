/**
 * Error taxonomy for Ninsho.
 *
 * Every error carries three things the transport layer needs:
 *   - `code`   — a stable, machine-readable identifier for clients
 *   - `status` — the HTTP status to respond with
 *   - `message`— a fixed, safe string
 *
 * ─── Why `detail` is separate from `message` ──────────────────────────────
 * `message` is a constant defined in this file. It never interpolates a value
 * from a request, a dependency, or a stack trace. Anything diagnostic goes in
 * the optional `detail` field, which `toResponse()` does not read.
 *
 * That separation is structural rather than a convention to remember: there is
 * no code path that can place internal information into a client response,
 * because the response builder only ever reads `code` and `message`. The
 * previous implementation interpolated raw library error text into a 401 body,
 * which leaked dependency internals to unauthenticated callers.
 * ──────────────────────────────────────────────────────────────────────────
 */

/** Shape of every error body Ninsho sends to a client. */
export interface ErrorResponse {
  readonly error: {
    readonly code: string;
    readonly message: string;
  };
}

/**
 * Base class for everything Ninsho throws.
 *
 * Subclasses fix `code`, `status` and `message`; callers may attach `detail`
 * for logs. Use `instanceof NinshoError` to distinguish Ninsho's own failures
 * from unexpected exceptions — the middleware maps the former to their status
 * and the latter to a generic 500, never leaking either.
 */
export abstract class NinshoError extends Error {
  /** Stable machine-readable identifier. Safe to expose. */
  abstract readonly code: string;
  /** HTTP status this error maps to. */
  abstract readonly status: number;

  /**
   * Server-side diagnostic context. NEVER sent to a client.
   * Safe to include dependency messages, key ids, or configuration values.
   */
  readonly detail: string | undefined;

  constructor(message: string, detail?: string) {
    super(message);
    this.name = new.target.name;
    this.detail = detail;
    // Restores the prototype chain so `instanceof` works when this package is
    // consumed as compiled CommonJS from a TypeScript ES2022 target.
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * The client-facing body for this error.
   * Reads only `code` and `message` — `detail` cannot escape through here.
   */
  toResponse(): ErrorResponse {
    return { error: { code: this.code, message: this.message } };
  }
}

// ─── 401 — authentication failures ──────────────────────────────────────────
// All four share a deliberately uninformative message set. A client learns
// that its credential was not accepted, not why — distinguishing "expired"
// from "revoked" from "malformed" would help an attacker probe the system.
// The precise cause is always available server-side via `detail` and the
// audit log.

/** No credential was presented, or the Authorization header was malformed. */
export class TokenMissingError extends NinshoError {
  readonly code = 'TOKEN_MISSING';
  readonly status = 401;
  constructor(detail?: string) {
    super('Authentication required', detail);
  }
}

/**
 * The token failed verification: bad signature, wrong key, structurally
 * invalid, unknown `kid`, or a claim that did not check out.
 *
 * SECURITY: `detail` is where the actual reason belongs. Never widen this
 * message to explain which check failed.
 */
export class TokenInvalidError extends NinshoError {
  readonly code = 'TOKEN_INVALID';
  readonly status = 401;
  constructor(detail?: string) {
    super('Invalid authentication credentials', detail);
  }
}

/** The token's `exp` has passed. Distinct from invalid so clients know to refresh. */
export class TokenExpiredError extends NinshoError {
  readonly code = 'TOKEN_EXPIRED';
  readonly status = 401;
  constructor(detail?: string) {
    super('Authentication credentials have expired', detail);
  }
}

/** The token was explicitly revoked before its natural expiry. */
export class TokenRevokedError extends NinshoError {
  readonly code = 'TOKEN_REVOKED';
  readonly status = 401;
  constructor(detail?: string) {
    super('Authentication credentials are no longer valid', detail);
  }
}

/** The refresh token was absent, expired, or not found in the store. */
export class RefreshInvalidError extends NinshoError {
  readonly code = 'REFRESH_INVALID';
  readonly status = 401;
  constructor(detail?: string) {
    super('Session could not be renewed', detail);
  }
}

/**
 * A refresh token was presented after it had already been rotated, outside the
 * grace window. Per RFC 9700 §4.14.2 this is treated as evidence of theft:
 * the entire token family is revoked and a `refresh.reuse_detected` event is
 * emitted before this error is thrown.
 *
 * The client-facing message is identical in effect to `RefreshInvalidError` —
 * an attacker learns nothing from the response about whether detection fired.
 * The distinct `code` exists so host applications can react (notify the user,
 * raise an alert) without parsing logs.
 */
export class RefreshReuseError extends NinshoError {
  readonly code = 'REFRESH_REUSE_DETECTED';
  readonly status = 401;
  constructor(detail?: string) {
    super('Session could not be renewed', detail);
  }
}

// ─── 403 — authorization failures ───────────────────────────────────────────

/**
 * The caller authenticated successfully but lacks the required role, scope, or
 * tenant. Deliberately 403, not 404: the request was understood and refused.
 *
 * Callers that need to avoid confirming a resource exists should catch this
 * and respond 404 themselves — that is an application-level decision about a
 * specific resource, not one Ninsho can make correctly on its own.
 */
export class ForbiddenError extends NinshoError {
  readonly code = 'FORBIDDEN';
  readonly status = 403;
  constructor(detail?: string) {
    super('Insufficient permissions', detail);
  }
}

// ─── 429 — abuse control ────────────────────────────────────────────────────

/** The caller exceeded a rate limit. `retryAfter` is in seconds. */
export class RateLimitError extends NinshoError {
  readonly code = 'RATE_LIMIT_EXCEEDED';
  readonly status = 429;
  readonly retryAfter: number;

  constructor(retryAfter: number, detail?: string) {
    super('Too many requests', detail);
    this.retryAfter = retryAfter;
  }
}

// ─── 503 — dependency failure ───────────────────────────────────────────────

/**
 * The session store was unreachable and `onStoreError` is `'closed'` (the
 * default). Ninsho refuses the request rather than serving it without a
 * revocation check.
 *
 * Reaching this means revocation could not be verified — never downgrade it to
 * a pass. That downgrade, as a silent default, was the behaviour this design
 * deliberately reverses.
 */
export class StoreUnavailableError extends NinshoError {
  readonly code = 'SERVICE_UNAVAILABLE';
  readonly status = 503;
  constructor(detail?: string) {
    super('Service temporarily unavailable', detail);
  }
}

// ─── 500 — startup and programming errors ───────────────────────────────────
// These indicate a misconfigured or misused server, not a bad request. They
// are thrown synchronously during construction wherever possible, so a broken
// deployment fails at boot instead of at the first authentication attempt.

/**
 * The configuration passed to `new Ninsho()` is invalid or unsafe.
 *
 * Thrown at construction time. `message` is developer-facing here — it is
 * surfaced in server logs and never reaches an end user, because a server that
 * throws this never starts serving.
 */
export class ConfigurationError extends NinshoError {
  readonly code = 'CONFIGURATION_ERROR';
  readonly status = 500;
  constructor(message: string, detail?: string) {
    super(message, detail);
  }
}

/** Key material could not be parsed, or is not the required Ed25519 type. */
export class KeyError extends NinshoError {
  readonly code = 'KEY_ERROR';
  readonly status = 500;
  constructor(message: string, detail?: string) {
    super(message, detail);
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Narrows an unknown caught value to a Ninsho error. */
export function isNinshoError(value: unknown): value is NinshoError {
  return value instanceof NinshoError;
}

/**
 * Builds a safe client response for any thrown value.
 *
 * Ninsho errors map to their own code and status. Anything else — a bug, a
 * dependency throwing, a rejected promise carrying arbitrary data — collapses
 * to a generic 500 with no detail, because an unrecognised value cannot be
 * assumed safe to describe.
 */
export function toErrorResponse(error: unknown): {
  status: number;
  body: ErrorResponse;
} {
  if (isNinshoError(error)) {
    return { status: error.status, body: error.toResponse() };
  }
  return {
    status: 500,
    body: { error: { code: 'INTERNAL_ERROR', message: 'Internal server error' } },
  };
}
