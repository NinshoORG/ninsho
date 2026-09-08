# Framework adapters

Express, Fastify, Hono and Koa — none of which `@ninshorg/server` imports.

## How this works

Middleware is typed **structurally** against `HttpRequest` and `HttpResponse` in
`packages/server/src/http/types.ts`. Those are hand-written interfaces describing
the shape a request has, not types borrowed from a framework. An Express request
satisfies them because it happens to have those properties, not because anything
declared a relationship.

So the library has no framework dependency, no peer dependency, and no version
matrix to maintain — and CI enforces that:

> **Bundle purity** › *Assert the framework adapters carry no framework
> dependency*

Each adapter is tested against the real framework over real HTTP, with the
framework as a devDependency of `@ninshorg/server` only.

---

## Express

No adapter. Ninsho middleware **is** Express middleware.

```ts
import express from 'express';
import { Ninsho, RedisStore, getAuth } from '@ninshorg/server';

const auth = new Ninsho({ store: new RedisStore(process.env.REDIS_URL!) });
const app = express();

app.use(express.json({ limit: '16kb' }));

app.get('/me', auth.verify(), (req, res) => res.json(getAuth(req)));

app.get('/users/:id/orders',
  auth.verify(),
  auth.requireOwner((req) => req.params?.id),
  handler);

app.use(auth.errorHandler());
```

Express 4 and 5 both work. Two notes on 5:

- Express 5 forwards rejections from `async` handlers itself. On Express 4 you
  need a wrapper, and [`examples/express-api`](../examples/express-api) keeps one
  so a route pasted into an Express 4 application does not inherit that bug
  silently.
- Express 5 route parameters can be **repeatable** — `/files/*splat` collects
  every matched segment into one parameter — so a selector can receive an array.
  The guards refuse arrays. See [Authorization](./authorization.md#requireownerselector--object-level-access).

*Evidence: `examples/express-api/src/*.test.ts` — 100 tests over real HTTP.*

---

## Fastify

```ts
import Fastify from 'fastify';
import { Ninsho, RedisStore, getAuth, type HttpRequest } from '@ninshorg/server';
import { toFastify, toFastifyChain } from '@ninshorg/server/fastify';

const auth = new Ninsho({ store: new RedisStore(process.env.REDIS_URL!) });
const app = Fastify();

app.get('/me', { preHandler: toFastify(auth.verify()) }, async (request) =>
  getAuth(request as unknown as HttpRequest));

app.get('/admin/users', {
  preHandler: toFastifyChain([auth.verify(), auth.requireRole('admin')]),
}, handler);
```

Fastify is the one adapter with no `getAuth` of its own. The identity is set on
the Fastify request object itself, so the ordinary `getAuth` from
`@ninshorg/server` reads it straight back.

An array of separate `toFastify()` preHandlers works as well as one
`toFastifyChain()`:

```ts
{ preHandler: [toFastify(auth.verify()), toFastify(auth.requireScope('orders:write'))] }
```

`toFastify` adapts one middleware; `toFastifyChain` adapts several into a single
`preHandler` that runs them in order. An empty chain throws at construction — it
would otherwise permit everything while reading as a guard.

The adapter decorates the request rather than wrapping it, because the object is
passed straight through and a copy would not survive to the next `preHandler`.

*Evidence: `fastify.test.ts` — against real Fastify, over real HTTP.*

---

## Hono

```ts
import { Hono } from 'hono';
import { Ninsho, RedisStore } from '@ninshorg/server';
import { toHono, getAuth, type HonoLikeContext } from '@ninshorg/server/hono';

const auth = new Ninsho({ store: new RedisStore(process.env.REDIS_URL!) });
const app = new Hono();

app.use('/me', toHono(auth.verify()));
app.get('/me', (c) =>
  c.json({ userId: getAuth(c as unknown as HonoLikeContext).userId }));

app.use('/admin', toHono([auth.verify(), auth.requireRole('admin')]));
app.get('/admin/users', handler);
```

`toHono` takes one middleware or an array. Import `getAuth` **from
`@ninshorg/server/hono`**, not from the package root — the Hono adapter stores the
identity in the Hono context (under `ninshoAuth`), so it needs its own accessor.

Separate `toHono()` calls over the same route compose:

```ts
app.use('/admin', toHono(auth.verify()));
app.use('/admin', toHono(auth.requireRole('admin')));   // sees the identity
```

That is asserted rather than assumed. Each `toHono()` builds its own request
view, and an earlier version rebuilt it empty — so the second call saw no
identity, `getAuth` threw, and a correctly written application got a 500.

### `parseJsonBody`

Off by default. Most guards need only headers and route parameters, and parsing
a body nothing reads costs time on every request and fails on bodies that are not
JSON.

Turn it on for the guards that do need it — a rate limit keyed on an email in the
body, or a `requireOwner` reading a body field:

```ts
app.post('/auth/login',
  toHono(auth.rateLimit({ /* ... */ identify: (req) => req.body?.email }),
         { parseJsonBody: true }),
  handler);
```

Hono caches the parse, so the route handler can still read the body afterwards.

### One known limitation

**A repeated `Authorization` header is not caught on Hono.**

Node's HTTP server keeps the first `Authorization` header and silently discards
the rest, so `req.headers.authorization` looks like a single clean credential
even when two were sent. The ambiguity — which a proxy in front might resolve the
other way — survives only in `rawHeaders`.

Express, Fastify and Koa all reach `rawHeaders` and refuse the request. Hono
hands headers over already collapsed and exposes no equivalent, so on
`@hono/node-server` the first credential is what the application reads.

If you terminate TLS behind a proxy that forwards duplicate headers rather than
normalising them, prefer one of the other three, or normalise at the edge. This
is recorded in [`SECURITY.md`](../SECURITY.md#a-repeated-authorization-header-is-not-caught-on-hono)
rather than left to be discovered.

*Evidence: `hono.test.ts`.*

---

## Koa

```ts
import Koa from 'koa';
import Router from '@koa/router';
import { Ninsho, RedisStore } from '@ninshorg/server';
import { toKoa, getAuth, type KoaLikeContext } from '@ninshorg/server/koa';

const auth = new Ninsho({ store: new RedisStore(process.env.REDIS_URL!) });
const app = new Koa();
const router = new Router();

router.get('/me', toKoa(auth.verify()) as Koa.Middleware, (ctx) => {
  ctx.body = getAuth(ctx as unknown as KoaLikeContext);
});

router.get('/admin/users',
  toKoa([auth.verify(), auth.requireRole('admin')]) as Koa.Middleware,
  handler);

app.use(router.routes());
```

`toKoa` takes one middleware or an array, and — as with Hono — `getAuth` comes
**from `@ninshorg/server/koa`**, because the identity lives on the Koa context
(under `ninshoAuth`). Two separate `toKoa()` calls over one route compose, which
is how a real application usually mounts them.

An empty array throws at construction — it would read as a guard and permit
every request.

Route parameters come from `ctx.params`, which is where `@koa/router` puts them
and where the adapter looks.

**A denied request never reaches the route handler.** The adapter declines to
call `next()` rather than setting a status and continuing, which is the
distinction that matters: a handler that runs after a refusal has already
touched whatever it was guarding.

*Evidence: `koa.test.ts` — asserted against real Koa over real HTTP.*

---

## Writing your own adapter

Copy the shape of `packages/server/src/koa.ts`. The whole job is reconciling two
signals:

- the middleware **answered** — it called `res.status().json()`
- the middleware **continued** — it called `next()`

Exactly one of those happens. The adapter observes which and translates it into
whatever the host framework expects. It must import nothing from that framework;
type the host's objects structurally, the way `HttpRequest` is typed.

Then test it against the real framework as a devDependency of
`@ninshorg/server`, and assert the case that actually matters: **that a denied
request does not reach the handler.** Every other assertion is about status
codes; that one is about whether the guard guards.
