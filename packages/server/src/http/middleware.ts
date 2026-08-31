import {
  ForbiddenError,
  NinshoError,
  StoreUnavailableError,
  TokenMissingError,
  toErrorResponse,
  type AuditSink,
  type AuthContext,
  type FailureMode,
} from '@ninsho/core';
import type { TokenEngine } from '../engine/types.js';
import type {
  HttpRequest,
  HttpResponse,
  Middleware,
  NextFunction,
  ValueSelector,
} from './types.js';

export interface MiddlewareOptions {
  readonly engine: TokenEngine;
  readonly onStoreError: FailureMode;
  readonly audit: AuditSink;
}

/** `Bearer <token>`, case-insensitive scheme per RFC 7235 §2.1. */
const BEARER = /^Bearer[ ]+(.+)$/i;

/**
 * Reads the credential from the Authorization header.
 *
 * Only the `Authorization` header is consulted. Ninsho deliberately does not
 * accept tokens from query strings: URLs land in server logs, browser history,
 * `Referer` headers and analytics pipelines, and a credential that leaks into
 * any of those is a credential that has leaked.
 */
function extractBearer(req: HttpRequest): string {
  const header = req.headers['authorization'] ?? req.headers['Authorization'];

  // A repeated Authorization header is ambiguous — different proxies resolve
  // it differently, so two systems can disagree about which credential was
  // presented. Refuse rather than pick.
  if (Array.isArray(header)) {
    throw new TokenMissingError('multiple Authorization headers');
  }
  if (typeof header !== 'string' || header.length === 0) {
    throw new TokenMissingError('no Authorization header');
  }

  const match = BEARER.exec(header.trim());
  if (match === null) {
    throw new TokenMissingError('Authorization header is not a Bearer credential');
  }

  const token = match[1]?.trim() ?? '';
  if (token.length === 0) {
    throw new TokenMissingError('empty Bearer credential');
  }
  return token;
}

/** Writes a Ninsho error as a JSON response, never leaking `detail`. */
function sendError(res: HttpResponse, error: unknown): void {
  const { status, body } = toErrorResponse(error);
  if (status === 429 && res.setHeader !== undefined) {
    const retryAfter = (error as { retryAfter?: number }).retryAfter;
    if (typeof retryAfter === 'number') res.setHeader('Retry-After', retryAfter);
  }
  res.status(status).json(body);
}

/**
 * Wraps an async handler so a rejected promise becomes a response rather than
 * an unhandled rejection.
 *
 * Express 4 does not await middleware, so without this an async throw escapes
 * into `process.on('unhandledRejection')` and the client waits until timeout.
 * A hung request on an auth route is worse than a 401: it looks like a network
 * fault rather than a refusal.
 */
function guard(handler: (req: HttpRequest, res: HttpResponse) => Promise<boolean>): Middleware {
  return (req: HttpRequest, res: HttpResponse, next: NextFunction): void => {
    handler(req, res)
      .then((shouldContinue) => {
        if (shouldContinue) next();
      })
      .catch((error: unknown) => {
        sendError(res, error);
      });
  };
}

/**
 * Returns the verified identity for a request.
 *
 * Throws if `verify()` has not run, rather than returning `undefined`. That
 * turns a middleware-ordering mistake into a loud failure at the first
 * request, instead of `req.auth?.userId` quietly evaluating to `undefined` and
 * an authorization check comparing against nothing.
 */
export function getAuth(req: HttpRequest): AuthContext {
  const auth = req.auth;
  if (auth === undefined) {
    throw new Error(
      'ninsho: req.auth is not set. Mount verify() before this handler — ' +
        'authorization cannot run on an unauthenticated request.',
    );
  }
  return auth;
}

/**
 * Authenticates the request and populates `req.auth`.
 *
 * ─── Failure mode (audit finding H3) ──────────────────────────────────────
 * When the store is unreachable, behaviour follows `onStoreError`:
 *
 *   - `closed` (default) — respond 503. Revocation could not be checked, so
 *     the guarantee cannot be honoured, so the request is refused.
 *
 *   - `open` — proceed *only if the engine can establish identity without the
 *     store*. That is true for `paseto`, where the signature verifies locally
 *     and only the denylist lookup was lost. It is false for `opaque`, where
 *     the store holds the identity itself: there, failing open would mean
 *     admitting an unidentified request, so the outage is fatal regardless of
 *     configuration. Config rejects that combination up front; this is the
 *     runtime backstop.
 *
 * Every fail-open admission emits `store.unavailable`, because a period during
 * which revoked tokens were accepted must be reconstructible afterwards.
 * ──────────────────────────────────────────────────────────────────────────
 */
export function createVerify(options: MiddlewareOptions): Middleware {
  const { engine, onStoreError, audit } = options;

  return guard(async (req, _res) => {
    const token = extractBearer(req);

    let auth: AuthContext;
    try {
      auth = await engine.verify(token);
    } catch (error) {
      if (!(error instanceof StoreUnavailableError)) throw error;

      if (onStoreError !== 'open' || !engine.canVerifyWithoutStore) {
        audit.emit({
          type: 'store.unavailable',
          at: new Date().toISOString(),
          reason: 'refused',
        });
        throw error;
      }

      // Fail open: accept on signature and time claims alone. This admits
      // tokens that may have been revoked — the trade-off the operator chose.
      auth = await engine.verify(token, { skipRevocationCheck: true });
      audit.emit({
        type: 'store.unavailable',
        at: new Date().toISOString(),
        userId: auth.userId,
        sessionId: auth.sessionId,
        tokenId: auth.tokenId,
        reason: 'admitted_without_revocation_check',
      });
    }

    req.auth = auth;
    return true;
  });
}

// ─── Authorization ──────────────────────────────────────────────────────────
// Everything below assumes verify() has already run. Each returns 403 rather
// than 401: the caller is authenticated, and simply not permitted.

/** Emits an authz denial and throws. Shared so every refusal is auditable. */
function deny(audit: AuditSink, auth: AuthContext, reason: string): never {
  audit.emit({
    type: 'authz.denied',
    at: new Date().toISOString(),
    userId: auth.userId,
    sessionId: auth.sessionId,
    reason,
  });
  throw new ForbiddenError(reason);
}

/** Normalises a single value or list into an array. */
function toList(value: string | readonly string[]): readonly string[] {
  return typeof value === 'string' ? [value] : value;
}

/**
 * Requires **any** of the given roles.
 *
 * @example
 * ```ts
 * app.get('/admin', auth.verify(), auth.requireRole('admin'), handler);
 * app.get('/staff', auth.verify(), auth.requireRole(['admin', 'support']), handler);
 * ```
 */
export function createRequireRole(audit: AuditSink) {
  return (roles: string | readonly string[]): Middleware => {
    const required = toList(roles);
    if (required.length === 0) {
      // An empty list would permit everyone while reading as a restriction.
      throw new Error('ninsho: requireRole() needs at least one role');
    }

    return guard(async (req) => {
      const auth = getAuth(req);
      if (!required.some((role) => auth.roles.includes(role))) {
        deny(audit, auth, `requires one of role: ${required.join(', ')}`);
      }
      return true;
    });
  };
}

/** Requires **all** of the given roles. */
export function createRequireAllRoles(audit: AuditSink) {
  return (roles: string | readonly string[]): Middleware => {
    const required = toList(roles);
    if (required.length === 0) {
      throw new Error('ninsho: requireAllRoles() needs at least one role');
    }

    return guard(async (req) => {
      const auth = getAuth(req);
      const missing = required.filter((role) => !auth.roles.includes(role));
      if (missing.length > 0) {
        deny(audit, auth, `missing role: ${missing.join(', ')}`);
      }
      return true;
    });
  };
}

/** Requires **any** of the given scopes. */
export function createRequireScope(audit: AuditSink) {
  return (scopes: string | readonly string[]): Middleware => {
    const required = toList(scopes);
    if (required.length === 0) {
      throw new Error('ninsho: requireScope() needs at least one scope');
    }

    return guard(async (req) => {
      const auth = getAuth(req);
      if (!required.some((scope) => auth.scopes.includes(scope))) {
        deny(audit, auth, `requires one of scope: ${required.join(', ')}`);
      }
      return true;
    });
  };
}

/**
 * Requires that the caller owns the resource being addressed.
 *
 * ─── The check most often missing ─────────────────────────────────────────
 * Broken object-level authorization is OWASP API Security #1. The shape is
 * always the same: a route reads `/users/:id/orders`, the handler trusts `:id`
 * because the request was authenticated, and any signed-in user can read any
 * other user's data by changing a number.
 *
 * Authentication says *who is calling*. It says nothing about *what they may
 * address*. That gap is what this closes, and the predecessor offered nothing
 * for it at all.
 * ──────────────────────────────────────────────────────────────────────────
 *
 * @param selector Extracts the owner id the request is addressing.
 *
 * @example
 * ```ts
 * app.get(
 *   '/users/:id/orders',
 *   auth.verify(),
 *   auth.requireOwner((req) => req.params?.id),
 *   handler,
 * );
 * ```
 *
 * Note the deliberate absence of a "but admins may bypass this" flag.
 * Overriding an ownership check is a policy decision specific to each route,
 * and a general escape hatch here would be reached for reflexively. Compose
 * instead — for example, route admins to a separate handler guarded by
 * `requireRole('admin')`.
 */
export function createRequireOwner(audit: AuditSink) {
  return (selector: ValueSelector): Middleware =>
    guard(async (req) => {
      const auth = getAuth(req);

      let resourceOwner: string | undefined;
      try {
        resourceOwner = selector(req);
      } catch {
        // A throwing selector must not be read as permission.
        resourceOwner = undefined;
      }

      // Absent is not allowed. A selector pointing at a renamed route
      // parameter returns undefined, and treating that as a pass would
      // silently disable the check across every route using it.
      if (typeof resourceOwner !== 'string' || resourceOwner.length === 0) {
        deny(audit, auth, 'ownership could not be determined');
      }
      if (resourceOwner !== auth.userId) {
        // The reason is deliberately vague — naming the owner would confirm
        // the resource exists and belongs to someone else.
        deny(audit, auth, 'caller does not own the requested resource');
      }
      return true;
    });
}

/**
 * Requires that the caller's tenant matches the tenant being addressed.
 *
 * A token with no tenant claim never passes. In a multi-tenant deployment an
 * absent tenant is a token that predates tenanting or was issued by a
 * misconfigured path, and neither should reach tenant-scoped data.
 */
export function createRequireTenant(audit: AuditSink) {
  return (selector: ValueSelector): Middleware =>
    guard(async (req) => {
      const auth = getAuth(req);

      if (typeof auth.tenant !== 'string' || auth.tenant.length === 0) {
        deny(audit, auth, 'token carries no tenant');
      }

      let resourceTenant: string | undefined;
      try {
        resourceTenant = selector(req);
      } catch {
        resourceTenant = undefined;
      }

      if (typeof resourceTenant !== 'string' || resourceTenant.length === 0) {
        deny(audit, auth, 'tenant could not be determined');
      }
      if (resourceTenant !== auth.tenant) {
        deny(audit, auth, 'caller does not belong to the requested tenant');
      }
      return true;
    });
}

/**
 * Terminal error handler, for frameworks that route errors to middleware.
 *
 * Ninsho errors map to their own status; anything else collapses to a generic
 * 500 with no detail, because an unrecognised value cannot be assumed safe to
 * describe to a client.
 */
export function createErrorHandler(): (
  error: unknown,
  req: HttpRequest,
  res: HttpResponse,
  next: NextFunction,
) => void {
  return (error, _req, res, next) => {
    if (!(error instanceof NinshoError)) {
      next(error);
      return;
    }
    sendError(res, error);
  };
}
