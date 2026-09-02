import type { AuthContext } from '@ninsho/core';

/**
 * Minimal HTTP shapes.
 *
 * ─── Why these are declared rather than imported ──────────────────────────
 * Express's `Request` and `Response` are structurally compatible with the
 * interfaces below, so `app.get('/x', auth.verify(), handler)` type-checks and
 * runs — without Ninsho depending on Express, or on `@types/express`, at all.
 *
 * These are Express *shapes*, not a universal HTTP abstraction. Anything
 * matching them works. Fastify's reply uses `send()` rather than `json()`, so
 * it needs a translation — `@ninsho/server/fastify` provides one, tested
 * against real Fastify. Hono's model differs more than that and has no adapter
 * here, so none is claimed.
 *
 * The predecessor took Express as a peer dependency and augmented
 * `express-serve-static-core` globally to add `req.auth`. That forces the
 * framework choice on every consumer and leaks a global type change into
 * unrelated code. Structural typing gets the same ergonomics with neither
 * cost.
 * ──────────────────────────────────────────────────────────────────────────
 */

/** The parts of a request Ninsho reads. */
export interface HttpRequest {
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  /** Route parameters, when the framework provides them. */
  readonly params?: Readonly<Record<string, string | undefined>>;
  readonly query?: Readonly<Record<string, unknown>>;
  readonly body?: unknown;
  /**
   * Populated by `verify()`. Prefer {@link getAuth} for type-safe access —
   * reading this directly gives you `AuthContext | undefined` and invites a
   * non-null assertion at exactly the point where being wrong matters.
   */
  auth?: AuthContext;
}

/** The parts of a response Ninsho writes. */
export interface HttpResponse {
  status(code: number): HttpResponse;
  json(body: unknown): unknown;
  setHeader?(name: string, value: string | number): unknown;
}

/** Express-style continuation. */
export type NextFunction = (error?: unknown) => void;

/** A middleware in the Express calling convention. */
export type Middleware = (
  req: HttpRequest,
  res: HttpResponse,
  next: NextFunction,
) => void | Promise<void>;

/**
 * Derives the value an authorization check compares against — a tenant id
 * from a route parameter, an owner id from a body field.
 *
 * Returning `undefined` fails the check. That is deliberate: a selector that
 * cannot find its value has not proved anything, and treating "absent" as
 * "allowed" is how ownership checks silently stop working when a route is
 * renamed.
 */
export type ValueSelector = (req: HttpRequest) => string | undefined;
