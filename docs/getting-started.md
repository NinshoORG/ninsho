# Getting started

From a clone to a working sign-in route.

## Install

Ninsho is not on npm yet, so today you build from source. That is a real
inconvenience and it is stated plainly rather than papered over — see
[the release checklist](../CONTRIBUTING.md#releasing) for what has to happen
first.

```bash
git clone https://github.com/NinshoORG/ninsho.git
cd ninsho

npm ci
npm run build      # before anything else — see below
npm run test
```

**`npm run build` comes before `npm run typecheck` and before the tests.**
`@ninsho/server` resolves `@ninsho/core` through its built output, so a fresh
checkout that typechecks first reports several hundred errors that mean nothing.

To see the whole library working before you write any code:

```bash
npm run dev --workspace @ninsho/playground   # → http://localhost:4000
```

## The smallest thing that works

```ts
import express from 'express';
import { Ninsho, MemoryStore, getAuth } from '@ninsho/server';

const auth = new Ninsho({ store: new MemoryStore() });

const app = express();
app.use(express.json({ limit: '16kb' }));

app.get('/me', auth.verify(), (req, res) => {
  res.json(getAuth(req));
});

app.use(auth.errorHandler());
```

That is the entire configuration. There are no keys to generate and no algorithm
to choose, because the default strategy is opaque tokens: the token is random
bytes, and its meaning lives in the store rather than in the token.

`MemoryStore` is for development. It refuses to construct under
`NODE_ENV=production`, deliberately and with no override flag — per-process
session state that vanishes on restart would silently break revocation and rate
limiting. Use `RedisStore` for anything real:

```ts
import { Ninsho, RedisStore } from '@ninsho/server';

const auth = new Ninsho({ store: new RedisStore(process.env.REDIS_URL!) });
```

## Signing someone in

**Ninsho does not verify credentials.** Passwords, WebAuthn ceremonies and
federated sign-in belong to your application, because owning them would mean
owning your user model. You establish who somebody is; Ninsho takes it from
there.

```ts
app.post('/auth/login', async (req, res) => {
  // Your code. Ninsho has no opinion about how you do this.
  const user = await authenticate(req.body.email, req.body.password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const pair = await auth.createSession({
    userId: user.id,          // Opaque. Never an email address — see below
    roles: user.roles,        // e.g. ['user']
    scopes: user.scopes,      // e.g. ['orders:read']
  });

  res.json({
    accessToken: pair.accessToken,
    expiresAt: pair.accessExpiresAt,
  });
});
```

`createSession` returns a `TokenPair`: a short-lived `accessToken` (five minutes
by default), a `refreshToken` (seven days), both expiry timestamps, and the
`sessionId` the pair belongs to.

> **`userId` must be opaque.** Under the `paseto` strategy the principal ends up
> inside a signed — but *not encrypted* — token. Anyone holding it can read
> every field. Never put an email address, a name, or anything else personal in
> `userId`, `roles`, `scopes` or `tenant`.

## Where to put the tokens

- **Access token** — send it to the client and keep it in memory only. Never
  `localStorage`: any XSS on the page can read it there.
- **Refresh token** — an `httpOnly`, `Secure`, `SameSite=Strict` cookie, scoped
  to the refresh path. Treat it as a secret; never log it, never put it in a
  URL.

[`examples/express-api`](../examples/express-api) does this properly and is
meant to be copied rather than read.

## Rotating

```ts
app.post('/auth/refresh', async (req, res) => {
  const pair = await auth.refresh(req.cookies.refresh_token);
  res.json({ accessToken: pair.accessToken });
});
```

Every refresh mints a new pair and invalidates the old refresh token. If the old
one is ever presented again, Ninsho treats that as theft: the **entire token
family is revoked**, including the legitimate client's live session, and a
`refresh.reuse_detected` event is emitted. That is RFC 9700 §4.14.2, and it is
deliberately aggressive — one of the two parties holding that token is an
attacker and the server cannot tell which.

Rotation is atomic. Of any number of callers presenting the same token, exactly
one receives the record. There is no lock and no Lua script; it falls out of the
store contract.

*Evidence: `session.test.ts`, `concurrency.test.ts`.*

## Ending a session

```ts
// This device
await auth.revokeSession(getAuth(req).sessionId, 'logout');

// Every device — what a password change must do
await auth.revokeAllForUser(userId, 'credential_changed');

// What an account settings page shows
const sessions = await auth.listSessions(userId, currentSessionId);
```

Revocation takes effect on the **next request**, not at the next expiry. A
revoked access token is refused while it is still unexpired and its signature
still verifies, because `verify()` consults the store on every request. That one
read is the whole reason the architecture is shaped this way — a self-contained
token that nothing consults is valid until it expires, whatever the settings
page claims.

`listSessions` returns summaries containing no token, no hash a token could be
recognised from, and no user agent or IP address — only truncated signal hashes,
which support grouping and correlation but cannot be rendered back into "Chrome
on macOS". Keep your own record if you want to show that.

## Authorization

Authentication says who someone is. It says nothing about what they may reach.

```ts
import { getAuth } from '@ninsho/server';

app.get('/admin/users',
  auth.verify(),
  auth.requireRole('admin'),
  handler);

app.get('/users/:id/orders',
  auth.verify(),
  auth.requireOwner((req) => req.params?.id),   // OWASP API Security #1
  handler);

app.post('/account/email',
  auth.verify(),
  auth.requireFreshAuth(300),                   // signed in is not enough
  handler);
```

`verify()` must be mounted before any guard. If it is not, `getAuth()` throws
loudly rather than returning `undefined` — a middleware-ordering mistake becomes
a failure on the first request instead of `req.auth?.userId` quietly evaluating
to nothing and a check comparing against it.

See **[Authorization](./authorization.md)** for all six guards and how each
one fails.

## Rate limiting

```ts
app.post('/auth/login',
  auth.rateLimit({
    action: 'login',
    perIp: { limit: 20, windowMs: 60_000 },
    perAccount: { limit: 5, windowMs: 900_000 },
    identify: (req) => req.body?.email,
    trustProxy: 1,          // no default: you must state this
  }),
  handler);
```

Two dimensions, because one is not enough in either direction. A per-IP limit
alone does not stop credential stuffing — a botnet spreads attempts so no single
address approaches it. A per-account limit alone punishes shared NAT, where one
colleague's bad memory signs a whole office out.

`trustProxy` has **no default beyond `false`** and the library refuses to guess,
because guessing wrong is a security bug in both directions: too high trusts a
forged `X-Forwarded-For`, too low puts every visitor behind your load balancer
in one bucket where any of them can rate-limit everybody.

*Evidence: `ratelimit.test.ts`.*

## Errors

```ts
app.use(auth.errorHandler());
```

Every Ninsho error carries two separate things: a `message` the client sees,
which is fixed and uninformative, and a `detail` the server knows, which
`toErrorResponse()` does not read. Authentication failures deliberately share a
message set — a client learns its credential was not accepted, not why.
Distinguishing "expired" from "revoked" from "never existed" would hand an
attacker an oracle.

If you catch errors yourself:

```ts
import { isNinshoError, toErrorResponse } from '@ninsho/server';

if (isNinshoError(error)) {
  const { status, body } = toErrorResponse(error);
  return res.status(status).json(body);
}
```

## What to read next

- **[Configuration](./configuration.md)** — the three decisions that matter, and
  every option
- **[Deployment](./deployment.md)** — before this goes in front of real users
- **[`SECURITY.md`](../SECURITY.md)** — what this library does not defend against
