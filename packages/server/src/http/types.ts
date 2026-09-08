import type { AuthContext } from '@ninshorg/core';

/**
 * Minimal HTTP shapes.
 *
 * ─── Why these are declared rather than imported ──────────────────────────
 * Express's `Request` and `Response` are structurally compatible with the
 * interfaces below, so `app.get('/x', auth.verify(), handler)` type-checks and
 * runs — without Ninsho depending on Express, or on `@types/express`, at all.
 *
 * These are Express *shapes*, not a universal HTTP abstraction. Anything
 * matching them works. Fastify's reply uses `send()` rather than `json()`, and
 * Hono differs more still — one context object, headers behind functions, and
 * halting by returning a `Response`. Both have adapters here
 * (`@ninshorg/server/fastify`, `@ninshorg/server/hono`), each tested against the
 * real framework. Koa has none, so none is claimed.
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
  /**
   * Node's flat `[name, value, name, value, …]` header list, when the
   * framework exposes it.
   *
   * `headers` is not enough to tell a repeated header from a single one. Node's
   * HTTP server keeps only the *first* `Authorization` it receives and silently
   * discards the rest — measured, not assumed — so by the time a request
   * reaches `headers`, a second credential has already vanished. This is the
   * only place the duplicate is still visible.
   *
   * Optional because not every runtime has it. Where it is absent the checks
   * fall back to what `headers` can show, which is less.
   */
  readonly rawHeaders?: readonly string[];
  /**
   * Route parameters, when the framework provides them.
   *
   * A value can be an array. Express 5's path-to-regexp supports repeatable
   * segments — `/files/*splat` puts every matched segment in one parameter —
   * and its types say so, which is why an Express 5 request does not
   * structurally satisfy a `params` typed as `string` alone.
   *
   * Widening it is not only about compiling. A selector reading
   * `req.params.id` on such a route really can receive an array, and a type
   * that promised otherwise meant the case was never considered. `requireOwner`
   * refuses one rather than picking an element: several matched segments are
   * not one owner, and choosing among them would be inventing an answer.
   */
  readonly params?: Readonly<Record<string, string | readonly string[] | undefined>>;
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
export type ValueSelector = (req: HttpRequest) => string | readonly string[] | undefined;
