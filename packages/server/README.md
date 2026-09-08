# @ninshorg/server

**認証** — an authentication engine for Node.js.

Sessions, refresh-token rotation with reuse detection, authorization, and rate
limiting. Secure by default, with one dependency (`ioredis`) and no framework
coupling.

```bash
npm install @ninshorg/server
```

## Setup

```ts
import { Ninsho, RedisStore } from '@ninshorg/server';

const auth = new Ninsho({ store: new RedisStore(process.env.REDIS_URL!) });
```

That is the complete configuration. No keys to generate, no algorithm to choose.
It yields opaque tokens, fail-closed behaviour on a store outage, five-minute
access tokens, and refresh rotation with reuse detection.

```ts
import { getAuth } from '@ninshorg/server';

// After verifying credentials yourself — Ninsho does not own your user model.
const pair = await auth.createSession({ userId, roles: ['user'], scopes: [] });

app.get('/me', auth.verify(), (req, res) => res.json(getAuth(req)));
app.get('/admin', auth.verify(), auth.requireRole('admin'), handler);

// Authenticated is not the same as entitled. Without this, any signed-in user
// reads anyone's orders by changing the URL — OWASP API Security #1.
app.get('/users/:id/orders',
  auth.verify(),
  auth.requireOwner((req) => req.params?.id),
  handler);
```

Express `Request` and `Response` satisfy the middleware types structurally, so
there is no Express dependency and no global type augmentation.

## Two token strategies, one API

**`opaque`** (default) — a 256-bit random token with all state in the store.
Revocation is native and immediate, there are no signing keys to leak or rotate,
and the token carries no claims to disclose. Correct for a single application,
and [~15× faster to verify](https://github.com/NinshoORG/ninsho/blob/main/PERFORMANCE.md)
than the alternative.

**`paseto`** — PASETO v4.public, Ed25519, for services that must verify
independently without a shared store. Requires `issuer`, `audience` and a key
set; supports rotation with an overlap window so no one is signed out.

```ts
const auth = new Ninsho({
  store,
  strategy: 'paseto',
  issuer: 'https://id.example.com',
  audience: 'orders-api',
  keys: { active: generateKeyPair('2026-08') },
});
```

## Refresh reuse is treated as theft

Replaying a rotated refresh token revokes the **entire session family** and
emits `refresh.reuse_detected`, per RFC 9700 §4.14.2. Rejecting the replay and
stopping there — the common implementation — leaves a thief holding a valid
rotating chain while the victim sees one failed refresh and signs in again.

## Requirements

Node 20+. Redis 6.2+ for `RedisStore` (`GETDEL` makes single-use consumption
atomic). `MemoryStore` is available for development and refuses to construct
under `NODE_ENV=production`.

## Documentation

[README](https://github.com/NinshoORG/ninsho#readme) ·
[Security model and threat model](https://github.com/NinshoORG/ninsho/blob/main/SECURITY.md) ·
[Performance](https://github.com/NinshoORG/ninsho/blob/main/PERFORMANCE.md) ·
[Example API](https://github.com/NinshoORG/ninsho/tree/main/examples/express-api)

## Status

Pre-release (0.1.0). Not independently audited. The API may change.

MIT
