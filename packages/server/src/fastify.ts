/**
 * Fastify adapter.
 *
 * ─── Why this is so small, and why it is a separate entry point ───────────
 * Ninsho's middleware is typed structurally against Express shapes. A Fastify
 * *request* already satisfies `HttpRequest` — it has `headers`, `params`,
 * `query` and `body`, and `verify()` attaches `auth` to the same object, so
 * `getAuth()` works on it unchanged.
 *
 * Only the reply differs: Fastify uses `code()` and `send()` where Express uses
 * `status()` and `json()`. So that is all this file translates.
 *
 * It lives at `@ninsho/server/fastify` rather than in the main entry so that an
 * Express application never carries it, and it imports nothing from Fastify —
 * the types below are declared structurally, exactly as the Express ones are.
 * Ninsho gains no dependency, and neither does your bundle.
 *
 * ─── The part that is easy to get wrong ───────────────────────────────────
 * Express middleware signals "continue" by calling `next()` and "stop" by
 * writing a response. Fastify hooks signal "stop" by returning the reply after
 * sending. Translating the first into the second is the whole job, and getting
 * it wrong in the direction of "continue" means a denied request reaches the
 * route handler anyway — an authorization check that logs a denial and then
 * serves the resource.
 *
 * So the adapter tracks whether a response was written and returns the reply
 * when it was. The tests assert the handler does not run.
 * ──────────────────────────────────────────────────────────────────────────
 */

import type { AuthContext } from '@ninsho/core';
import type { HttpRequest, HttpResponse, Middleware } from './http/types.js';

/**
 * The parts of a Fastify request this adapter reads.
 *
 * Declared rather than imported: Ninsho takes no dependency on Fastify, and a
 * structural type means any version whose request looks like this works.
 */
export interface FastifyLikeRequest {
  readonly headers: Readonly<Record<string, string | string[] | undefined>>;
  /**
   * Node's request, which is the only place a repeated `Authorization` header
   * is still visible — Node's HTTP server keeps the first and discards the
   * rest before `headers` is built.
   */
  readonly raw?: { readonly rawHeaders?: readonly string[] };
  /** Copied from `raw` by this adapter, so `extractBearer` can see it. */
  rawHeaders?: readonly string[];
  readonly params?: unknown;
  readonly query?: unknown;
  readonly body?: unknown;
  /** Populated by `verify()`. Read it with `getAuth()`. */
  auth?: AuthContext;
}

/** The parts of a Fastify reply this adapter writes. */
export interface FastifyLikeReply {
  code(statusCode: number): FastifyLikeReply;
  send(payload?: unknown): unknown;
  header(name: string, value: string | number): unknown;
}

/**
 * A Fastify `preHandler` hook.
 *
 * Returning the reply tells Fastify the request has been answered and the
 * route handler must not run; returning `undefined` lets it continue.
 */
export type FastifyPreHandler = (
  request: FastifyLikeRequest,
  reply: FastifyLikeReply,
) => Promise<FastifyLikeReply | undefined>;

/**
 * Adapts one Ninsho middleware into a Fastify `preHandler`.
 *
 * @example
 * ```ts
 * import { toFastify } from '@ninsho/server/fastify';
 *
 * app.get('/me', { preHandler: toFastify(auth.verify()) }, async (req) => {
 *   return { userId: getAuth(req).userId };
 * });
 *
 * app.get('/admin', {
 *   preHandler: [toFastify(auth.verify()), toFastify(auth.requireRole('admin'))],
 * }, handler);
 * ```
 */
export function toFastify(middleware: Middleware): FastifyPreHandler {
  return async (request, reply) => {
    let responded = false;

    // Decorating the request rather than wrapping it, for the same reason
    // `auth` is set on it: the object is passed straight through, and a copy
    // would not survive to the next preHandler in the chain.
    if (request.rawHeaders === undefined && request.raw?.rawHeaders !== undefined) {
      request.rawHeaders = request.raw.rawHeaders;
    }

    // Bridges the two response surfaces. `status`/`json` are what Ninsho's
    // middleware calls; `code`/`send` are what Fastify provides.
    const res: HttpResponse = {
      status(statusCode: number): HttpResponse {
        reply.code(statusCode);
        return res;
      },
      json(body: unknown): unknown {
        responded = true;
        return reply.send(body);
      },
      setHeader(name: string, value: string | number): unknown {
        return reply.header(name, value);
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

      // A guard that denies writes the response rather than calling `next`, so
      // the promise has to settle on either signal.
      const originalJson = res.json.bind(res);
      res.json = (body: unknown): unknown => {
        const out = originalJson(body);
        finish();
        return out;
      };

      void Promise.resolve(
        middleware(request as unknown as HttpRequest, res, finish),
      ).catch(finish);
    });

    // Returning the reply is how a Fastify hook says "already answered". Get
    // this wrong and a denied request reaches the route handler anyway.
    return responded ? reply : undefined;
  };
}

/**
 * Adapts several middlewares into one `preHandler`, run in order.
 *
 * Stops at the first that answers, so a denial short-circuits the rest exactly
 * as it does in an Express chain.
 */
export function toFastifyChain(middlewares: readonly Middleware[]): FastifyPreHandler {
  if (middlewares.length === 0) {
    // An empty chain would silently permit everything while reading as a
    // guard, which is the same trap as an empty role list.
    throw new Error('ninsho: toFastifyChain() needs at least one middleware');
  }

  const handlers = middlewares.map(toFastify);

  return async (request, reply) => {
    for (const handler of handlers) {
      const answered = await handler(request, reply);
      if (answered !== undefined) return answered;
    }
    return undefined;
  };
}
