/**
 * Hono adapter.
 *
 * ─── Why this one is real work and the Fastify one was not ────────────────
 * A Fastify request already satisfies `HttpRequest` structurally, so that
 * adapter only had to translate the reply. Hono's model differs more: one
 * `Context` carries both sides, headers and params arrive through *functions*
 * rather than properties, and a middleware halts by returning a `Response`
 * instead of by writing to an object.
 *
 * So this builds a small `HttpRequest` view over the context, and turns "the
 * middleware wrote a response" into "return a Response".
 *
 * As with Fastify, nothing here imports Hono. The types below are declared
 * structurally, so Ninsho gains no dependency and neither does your bundle.
 *
 * ─── One honest limitation ────────────────────────────────────────────────
 * `@ninsho/server` depends on `ioredis` and Node's crypto, so it runs on Node.
 * This adapter therefore targets Hono on Node (`@hono/node-server`), not Hono
 * on Workers or Deno. Saying so is better than letting someone discover it at
 * deploy time.
 * ──────────────────────────────────────────────────────────────────────────
 */

import type { AuthContext } from '@ninsho/core';
import type { HttpRequest, HttpResponse, Middleware } from './http/types.js';

/** The parts of a Hono context this adapter uses. */
export interface HonoLikeContext {
  readonly req: {
    /** All request headers, lowercased, when called with no argument. */
    header(): Record<string, string | undefined>;
    /** All matched route parameters. */
    param(): Record<string, string>;
    /** All query parameters. */
    query(): Record<string, string>;
    /** Parsed JSON body. Hono caches this, so reading it here is not destructive. */
    json(): Promise<unknown>;
  };
  json(body: unknown, status?: number): Response;
  header(name: string, value: string): void;
  set(key: string, value: unknown): void;
  get(key: string): unknown;
}

/** A Hono middleware handler. */
export type HonoMiddleware = (
  c: HonoLikeContext,
  next: () => Promise<void>,
) => Promise<Response | void>;

/**
 * Where the verified identity is stored on the context.
 *
 * Namespaced rather than plain `auth`, because a context variable is shared
 * with every other middleware in the application and a collision here would
 * silently replace an identity rather than fail.
 */
export const AUTH_CONTEXT_KEY = 'ninshoAuth';

export interface HonoAdapterOptions {
  /**
   * Await and expose the JSON request body.
   *
   * Off by default: most guards need only headers and route parameters, and
   * parsing a body that nothing reads costs time on every request and fails on
   * bodies that are not JSON.
   *
   * Turn it on for the guards that do need it — a rate limit keyed on an email
   * in the body, or `requireOwner` reading a body field. Hono caches the parse,
   * so the route handler can still read the body afterwards.
   */
  readonly parseJsonBody?: boolean;
}

/**
 * Returns the verified identity for a Hono request.
 *
 * Throws rather than returning `undefined` when `verify()` has not run, so a
 * middleware-ordering mistake fails loudly at the first request instead of an
 * authorization check quietly comparing against nothing.
 */
export function getAuth(c: HonoLikeContext): AuthContext {
  const auth = c.get(AUTH_CONTEXT_KEY);
  if (auth === undefined || auth === null) {
    throw new Error(
      'ninsho: no auth context on this request. Mount toHono(auth.verify()) before this handler.',
    );
  }
  return auth as AuthContext;
}

/** Builds the `HttpRequest` view Ninsho's middleware reads. */
async function toHttpRequest(
  c: HonoLikeContext,
  options: HonoAdapterOptions,
): Promise<HttpRequest> {
  let body: unknown;
  if (options.parseJsonBody === true) {
    try {
      body = await c.req.json();
    } catch {
      // A malformed or absent body is not this adapter's error to raise. The
      // guard sees `undefined`, and a selector that finds nothing fails its
      // check — which is the fail-closed outcome already specified for
      // `ValueSelector`.
      body = undefined;
    }
  }

  return {
    headers: c.req.header(),
    params: c.req.param(),
    query: c.req.query(),
    ...(body !== undefined && { body }),
  };
}

/** What running one middleware produced. */
interface Outcome {
  readonly responded: boolean;
  readonly status: number;
  readonly payload: unknown;
}

/**
 * Runs one Ninsho middleware against a request view.
 *
 * The two signals to reconcile: Express middleware continues by calling
 * `next()` and halts by writing a response, so the promise settles on either.
 */
async function runOne(
  middleware: Middleware,
  req: HttpRequest,
  c: HonoLikeContext,
): Promise<Outcome> {
  let status = 200;
  let payload: unknown;
  let responded = false;

  const res: HttpResponse = {
    status(code: number): HttpResponse {
      status = code;
      return res;
    },
    json(value: unknown): unknown {
      responded = true;
      payload = value;
      return value;
    },
    setHeader(name: string, value: string | number): unknown {
      c.header(name, String(value));
      return res;
    },
  };

  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = (error?: unknown): void => {
      if (settled) return;
      settled = true;
      if (error !== undefined) reject(error);
      else resolve();
    };

    const originalJson = res.json.bind(res);
    res.json = (value: unknown): unknown => {
      const out = originalJson(value);
      finish();
      return out;
    };

    void Promise.resolve(middleware(req, res, finish)).catch(finish);
  });

  return { responded, status, payload };
}

/**
 * Adapts Ninsho middleware into a single Hono middleware, run in order.
 *
 * Stops at the first that answers, so a denial short-circuits the rest exactly
 * as it does in an Express chain.
 *
 * @example
 * ```ts
 * import { toHono, getAuth } from '@ninsho/server/hono';
 *
 * app.use('/me', toHono(auth.verify()));
 * app.get('/me', (c) => c.json({ userId: getAuth(c).userId }));
 *
 * app.use('/admin/*', toHono([auth.verify(), auth.requireRole('admin')]));
 * ```
 */
export function toHono(
  middleware: Middleware | readonly Middleware[],
  options: HonoAdapterOptions = {},
): HonoMiddleware {
  const chain = Array.isArray(middleware) ? [...middleware] : [middleware as Middleware];

  if (chain.length === 0) {
    // An empty chain would read as a guard and permit every request.
    throw new Error('ninsho: toHono() needs at least one middleware');
  }

  return async (c, next) => {
    const req = await toHttpRequest(c, options);

    for (const one of chain) {
      const outcome = await runOne(one, req, c);

      if (outcome.responded) {
        // Returning a Response is how a Hono middleware says "answered".
        // Calling next() here would run the route handler for a request that
        // was just denied.
        return c.json(outcome.payload, outcome.status);
      }

      // `verify()` writes the identity onto the request view, so it is copied
      // where a Hono handler — and any later guard — can reach it.
      if (req.auth !== undefined) c.set(AUTH_CONTEXT_KEY, req.auth);
    }

    await next();
    return undefined;
  };
}
