# Architecture

How the pieces fit, and why they are shaped this way.

---

## The shape in one diagram

```
                    ┌─────────────────────────────────────────┐
   your app  ─────► │  Ninsho                                 │
                    │    facade over everything below         │
                    └───┬──────────────┬───────────────┬──────┘
                        │              │               │
              ┌─────────▼───┐  ┌───────▼──────┐  ┌─────▼────────┐
              │ TokenEngine │  │SessionManager│  │  Middleware  │
              │             │  │              │  │              │
              │  opaque     │  │  create      │  │  verify()    │
              │  paseto     │  │  refresh     │  │  require*()  │
              └─────────┬───┘  │  revoke      │  │  rateLimit() │
                        │      └───────┬──────┘  └─────┬────────┘
                        └──────────────┼───────────────┘
                                       │
                              ┌────────▼────────┐
                              │  NinshoStore    │
                              │                 │
                              │  MemoryStore    │
                              │  RedisStore     │
                              │  yours          │
                              └─────────────────┘
```

`Ninsho` is a facade. Everything under it is exported too, so an application
that needs to assemble the pieces differently can — but the facade is the
surface that is documented, tested as a whole, and unlikely to change shape.

---

## The one read per request

This is the decision everything else follows from.

```
GET /orders
Authorization: Bearer <token>
        │
        ▼
   verify()
        │
        ├──► hash the token ─────► ONE store read ─────► found?  ──── no ──► 401
        │                                                  │
        │                                                 yes
        │                                                  │
        │                                          store unreachable? ──► 503
        │                                                  │
        ▼                                                  ▼
   req.auth = { userId, roles, scopes, tenant,       populate context
                sessionId, tokenId,
                issuedAt, authenticatedAt }
        │
        ▼
   requireRole / requireScope / requireOwner / …    ── in-memory only ──► 403
        │
        ▼
   your handler
```

**Why not a stateless token?** Because a self-contained token that nothing
consults is valid until it expires. Every "sign out everywhere" button on top of
one is either a lie or a denylist — and if you are keeping a denylist, you are
already paying for the read.

So Ninsho pays it once, deliberately, and gets:

- revocation that takes effect on the **next request** rather than the next
  expiry
- a token that can be refused while it is still unexpired and its signature
  still verifies
- a genuine session list, because sessions actually exist somewhere

And it costs: an unreachable store means an unanswerable question, and Ninsho
answers **503** rather than guessing. See
[`onStoreError`](./configuration.md#failure-behaviour).

*Evidence: `store-invariants.test.ts`, `session.test.ts`.*

---

## Token engines

Two implementations of the same `TokenEngine` interface. The session manager,
middleware and store contract do not know which is in use.

### `OpaqueEngine` — the default

The access token is 32 bytes of CSPRNG output, base64url-encoded. It carries no
meaning; the store holds the record.

- No signing keys. No algorithm. Nothing for an algorithm-confusion attack to
  reach, because there is no algorithm field.
- **The raw token is never stored.** What goes into the store is
  `SHA-256(token)` as a key. A stolen database dump yields no usable credential.
- Revocation is deletion — the strongest form, with no denylist to keep.

*Evidence: `opaque-engine.test.ts` › *never stores the raw token*.*

### `PasetoEngine` — for independent verification

PASETO v4.public: Ed25519 over a payload with `iss`, `aud`, `sub`, `jti`, `sid`
and the principal, plus the Pre-Authentication Encoding that binds the header and
footer into the signature.

Choose it only when several services must verify without sharing this store.
Those services verify locally with the public key; **this** service still does
the store read, because that is where revocation lives.

There is no `alg` header. PASETO puts the version and purpose in the token's
prefix (`v4.public.`), which is not a negotiable field.

*Evidence: `paseto-v4.test.ts` — the specification's own 4-S-* vectors, verified
and reproduced.*

---

## Sessions and rotation

A **session** is a family of refresh tokens. It has one `sessionId`, stable
across every rotation, which is why it is the right handle for "sign this device
out" and for correlating audit events.

```
createSession ──► rt₀  ──refresh──► rt₁ ──refresh──► rt₂  ──►  …
                   │                 │                │
                   └── consumed ─────┴── consumed ────┘
                                                       all one sessionId
```

### Rotation is atomic

Redemption begins with `take()` — read and delete in one operation. Of any number
of callers presenting the same token, **exactly one receives the record**. There
is no lock, no Lua script, and no window in which two callers both mint a
replacement. It falls out of the store contract rather than being layered on top.

### Reuse detection

If a consumed refresh token is presented again, one of the two parties holding it
is an attacker and the server cannot tell which. So Ninsho revokes **the entire
family**, including the legitimate client's live session, and emits
`refresh.reuse_detected`. That is RFC 9700 §4.14.2.

The event carries a `signalMatch` field comparing the replay's client signals
against the family's — which is the difference between "a token was replayed" and
"a token was replayed from somewhere else". Signals are hashed on the way in and
are **never** used to accept or reject; a forged header must not be able to end
someone's session.

### The grace window

Two browser tabs refreshing at the same instant is not an attack. For
`refreshGraceSeconds` (30 by default) the just-rotated token still resolves to
its replacement, so the losing tab gets the new pair rather than being signed
out. This is the one place a raw token is stored — the receiving tab needs the
literal value — and it is held for the grace period only. Recorded in
[`SECURITY.md`](../SECURITY.md#one-raw-token-is-stored-briefly) rather than left
implicit.

*Evidence: `session.test.ts`, `concurrency.test.ts`.*

---

## The store contract

Twelve methods. `store.contract.test.ts` **is** the specification: if an
implementation passes it, the engine works on it.

| | |
| --- | --- |
| `get` `set` `delete` `exists` | The ordinary ones |
| `take` | **Read and delete atomically.** Rotation depends on it |
| `setIfAbsent` | **Set only if the key is free, atomically.** Single-use tokens depend on it |
| `increment` | Atomic counter with a TTL. Rate limiting |
| `sAdd` `sRemove` `sMembers` | Sets, for tracking a user's sessions |
| `ping` `close` | Health and lifecycle |

**`take` and `setIfAbsent` carry the load.** A store that gets their atomicity
subtly wrong produces a race that only appears under production concurrency —
which is exactly why there is no mock Redis in this repository. A mock would
pass.

### The keyspace

Every key this library writes is defined in one file, `packages/server/src/keys.ts`,
namespaced and versioned:

```
ninsho:v1:at:<sha256>          access token record
ninsho:v1:rt:<sha256>          refresh token record
ninsho:v1:rtc:<sha256>         consumed refresh token (reuse detection)
ninsho:v1:rtg:<sha256>         grace record
ninsho:v1:rtx:<sha256>         revoked refresh token
ninsho:v1:sess:<id>:meta       session metadata
ninsho:v1:sess:<id>:dead       revocation tombstone
ninsho:v1:user:<id>:sess       a user's sessions
ninsho:v1:rev:<tokenId>        revoked access token
ninsho:v1:dpop:<jkt>:<jti>     DPoP proof replay guard
ninsho:v1:ott:<purpose>:<hash> one-time token
ninsho:v1:rl:<bucket>:<window> rate-limit counter
```

The version segment is there so a future schema change runs alongside this one
rather than being misread. Every token appears only as a SHA-256 hash.

The playground's *keyspace* panel shows this live, with a search box — paste any
token it has shown you and watch it not be found.

---

## The HTTP layer

`packages/server/src/http/types.ts` defines `HttpRequest` and `HttpResponse` as
plain structural interfaces. Nothing imports a framework; a framework's request
satisfies the interface by having the right shape.

Two consequences worth knowing:

- **`rawHeaders`.** Node collapses duplicate headers before you see them — it
  keeps the first `Authorization` and *joins* duplicate `DPoP` headers with a
  comma. Both are ambiguity an attacker can create, and both are refused rather
  than resolved. `rawHeaders` is the only place the truth survives, so the
  middleware consults it first. (Hono is the exception; see
  [frameworks](./frameworks.md#one-known-limitation).)
- **`params` can hold arrays.** Express 5 supports repeatable route segments. The
  guards refuse them rather than picking one.

---

## DPoP

Under `binding: 'dpop'`, three things change.

```
  browser                                   server
     │                                         │
     ├─ generate P-256 key, non-extractable    │
     │                                         │
     ├─ sign a proof over {htu, htm, jti} ────►│
     │                                         ├─ verify signature
     │                                         ├─ check htu/htm match this request
     │                                         ├─ check jti unused  (single use)
     │                                         └─ bind session to jkt
     │                                         │
     ├─ every later request:                   │
     │    Authorization: DPoP <token>          │
     │    DPoP: <fresh proof, incl. ath> ─────►│
     │                                         └─ token's cnf.jkt must match
                                                  the proof's key thumbprint
```

The private key is generated in the browser with `extractable: false`. An XSS
that can read a bearer token and copy it anywhere **cannot** copy this — the
browser refuses, and `crypto.subtle.exportKey()` throws.

`htu` is reconstructed server-side from the request. That reconstruction takes
client-supplied input (the `Host` header and the request target), so it reduces
the target to path and query before building the URL — `new URL('//evil.example/orders', base)`
discards the base entirely, which would make both sides of the `htu` comparison
attacker-controlled.

*Evidence: `dpop-integration.test.ts`, `dpop-request.test.ts`,
`packages/client/src/keys.test.ts`.*

---

## Rate limiting

A sliding window over `increment` with a TTL, in two dimensions:

```
        per-IP bucket                 per-account bucket
   ninsho:v1:rl:<ip>:<window>    ninsho:v1:rl:<account>:<window>
              │                             │
              └──────────── both always consumed ─────────────►  429
```

Both dimensions are consumed on every request, so an attacker cannot keep one
counter low by tripping the other first.

`clientIp` resolves the address from the **trusted end of the chain inwards, by
hop count** — never by taking the leftmost `X-Forwarded-For` entry. Anything the
client prepends sits beyond the hop it is entitled to, so inventing hops cannot
mint a fresh bucket.

*Evidence: `ratelimit.test.ts`. Writing the playground panel for this is what
found a real off-by-one in the resolution — before the fix, five forged chains
produced five separate buckets while the panel's own prose said otherwise.*

---

## What is deliberately not here

- **Credential verification.** Passwords, WebAuthn ceremonies and federated
  sign-in belong to the application. Owning them would mean owning the user
  model, and every application's is different.
- **A user table.** Ninsho stores sessions, not people.
- **Cryptographic primitives.** Ed25519, SHA-256 and the CSPRNG come from
  `node:crypto`.
- **A policy engine.** Six guards, mounted at the route. See
  [Authorization](./authorization.md#what-ninsho-does-not-do-here).
- **A framework.** See [Framework adapters](./frameworks.md).
