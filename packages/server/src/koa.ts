/**
 * Koa adapter.
 *
 * ─── What differs from the others ─────────────────────────────────────────
 * Fastify's request already satisfies `HttpRequest` structurally, so that
 * adapter only had to translate the reply. Hono needed a request view built
 * from functions. Koa needs both, plus one thing neither of those has: a body
 * it does not parse for you.
 *
 * Koa ships no body parser. `ctx.request.body` exists only if something like
 * `koa-bodyparser` put it there, so this reads it if present and does not
 * pretend otherwise — a guard whose selector finds nothing fails its check,
 * which is the fail-closed outcome `ValueSelector` already specifies.
 *
 * Koa also halts differently again: a middleware answers by *not* calling
 * `next()` and setting `ctx.status` and `ctx.body`. There is no return value
 * to distinguish the two, so the adapter simply does not await `next()` when a
 * Ninsho middleware answered.
 *
 * Nothing here imports Koa. The types below are declared structurally, so
 * Ninsho gains no dependency and neither does your bundle.
 * ──────────────────────────────────────────────────────────────────────────
 */

import type { AuthContext } from '@ninshorg/core';
import type { HttpRequest, HttpResponse, Middleware } from './http/types.js';

/** The parts of a Koa context this adapter uses. */
export interface KoaLikeContext {
  /** Node's own request object, which is where `rawHeaders` lives. */
  readonly req?: { readonly rawHeaders?: readonly string[] };
  readonly request: {
    /** Incoming headers, lowercased by Node. */
    readonly headers: Record<string, string | string[] | undefined>;
    /** Parsed query parameters. */
    readonly query: Record<string, string | string[] | undefined>;
    /** Present only when a body parser ran. Koa ships none. */
    readonly body?: unknown;
  };
  /** Route parameters, when a router put them here. `@koa/router` does. */
  readonly params?: Record<string, string>;
  status: number;
  body: unknown;
  set(name: string, value: string): void;
  /** Koa's own per-request bag, which is where an identity belongs. */
  state: Record<string, unknown>;
}

/** A Koa middleware handler. */
export type KoaMiddleware = (ctx: KoaLikeContext, next: () => Promise<void>) => Promise<void>;

/**
 * Where the verified identity is stored on `ctx.state`.
 *
 * Namespaced rather than plain `auth`, because `state` is shared with every
 * other middleware in the application and a collision here would silently
 * replace an identity rather than fail.
 */
export const AUTH_STATE_KEY = 'ninshoAuth';

/**
 * Returns the verified identity for a Koa request.
 *
 * Throws rather than returning `undefined` when `verify()` has not run, so a
 * middleware-ordering mistake fails loudly at the first request instead of an
 * authorization check quietly comparing against nothing.
 */
export function getAuth(ctx: KoaLikeContext): AuthContext {
  const auth = ctx.state[AUTH_STATE_KEY];
  if (auth === undefined || auth === null) {
    throw new Error(
      'ninsho: no auth context on this request. Mount toKoa(auth.verify()) before this handler.',
    );
  }
  return auth as AuthContext;
}

/** Builds the `HttpRequest` view Ninsho's middleware reads. */
function toHttpRequest(ctx: KoaLikeContext): HttpRequest {
  const body = ctx.request.body;

  // Seeded from `ctx.state` so that separate `toKoa()` calls compose:
  //
  //     app.use(toKoa(auth.verify()));
  //     router.get('/admin', toKoa(auth.requireRole('admin')), handler);
  //
  // Each call builds its own request view, so without this the second one sees
  // no identity, `getAuth` throws, and a correctly written application gets a
  // 500. The Hono adapter needed the same seeding, for the same reason.
  const established = ctx.state[AUTH_STATE_KEY];

  return {
    // Koa's headers and query are already the shapes `HttpRequest` declares —
    // Node lowercases header names, and the middleware reads duplicates as
    // arrays, which is what makes the repeated-Authorization-header check work
    // here as it does on Express.
    headers: ctx.request.headers,
    // Passed through so a repeated Authorization header is still visible:
    // Node drops all but the first before `headers` is built.
    ...(ctx.req?.rawHeaders !== undefined && { rawHeaders: ctx.req.rawHeaders }),
    params: ctx.params ?? {},
    query: ctx.request.query,
    ...(body !== undefined && { body }),
    ...(established !== undefined && established !== null
      ? { auth: established as AuthContext }
      : {}),
  };
}

/** What running one middleware produced. */
interface Outcome {
  readonly responded: boolean;
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
  ctx: KoaLikeContext,
): Promise<Outcome> {
  let responded = false;

  const res: HttpResponse = {
    status(code: number): HttpResponse {
      ctx.status = code;
      return res;
    },
    json(value: unknown): unknown {
      responded = true;
      ctx.body = value;
      return value;
    },
    setHeader(name: string, value: string | number): unknown {
      ctx.set(name, String(value));
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

  return { responded };
}

/**
 * Adapts Ninsho middleware into a single Koa middleware, run in order.
 *
 * Stops at the first that answers, so a denial short-circuits the rest exactly
 * as it does in an Express chain — and, crucially, does not call `next()`,
 * which is the only way a Koa middleware can decline to run what follows.
 *
 * @example
 * ```ts
 * import { toKoa, getAuth } from '@ninshorg/server/koa';
 *
 * router.get('/me', toKoa(auth.verify()), (ctx) => {
 *   ctx.body = { userId: getAuth(ctx).userId };
 * });
 *
 * app.use(toKoa([auth.verify(), auth.requireRole('admin')]));
 * ```
 */
export function toKoa(middleware: Middleware | readonly Middleware[]): KoaMiddleware {
  const chain = Array.isArray(middleware) ? [...middleware] : [middleware as Middleware];

  if (chain.length === 0) {
    // An empty chain would read as a guard and permit every request.
    throw new Error('ninsho: toKoa() needs at least one middleware');
  }

  return async (ctx, next) => {
    const req = toHttpRequest(ctx);

    for (const one of chain) {
      const outcome = await runOne(one, req, ctx);

      if (outcome.responded) {
        // Not calling next() is how a Koa middleware says "answered". Calling
        // it here would run the route handler for a request just denied.
        return;
      }

      // `verify()` writes the identity onto the request view, so it is copied
      // where a Koa handler — and any later guard — can reach it.
      if (req.auth !== undefined) ctx.state[AUTH_STATE_KEY] = req.auth;
    }

    await next();
  };
}
