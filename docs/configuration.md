# Configuration

Everything Ninsho takes, what it defaults to, and what changing it costs.

```ts
const auth = new Ninsho({ store: new RedisStore(process.env.REDIS_URL!) });
```

One required option. Every other default was chosen to be the safe answer, so a
configuration you did not write is not a configuration that quietly weakened
something.

**Configuration is validated at construction, not at first use.** A bad value
throws a `ConfigurationError` when the process starts, rather than producing a
401 under load six weeks later. Choices that are legal but weaker emit a
`config.insecure` audit event at startup — the library will let you make them
and will not let you make them silently.

---

## The three decisions that actually matter

Everything else has a default you can leave alone. These three change the shape
of your deployment.

### 1. Which store

| | |
| --- | --- |
| `MemoryStore` | Development only. **Refuses to construct under `NODE_ENV=production`**, with no override flag. Per-process state that vanishes on restart would silently break revocation and rate limiting |
| `RedisStore` | Production. Needs `take` and `setIfAbsent` to be genuinely atomic, which Redis provides |
| Your own | Implement `NinshoStore` and run `store.contract.test.ts` against it. That suite is the specification |

There is deliberately **no mock Redis** in this repository. A mock that got
atomicity subtly wrong would hide exactly the race the contract suite exists to
catch.

### 2. `strategy` — opaque or PASETO

**Default: `'opaque'`.** The access token is random bytes and its meaning lives
in the store. No signing keys, no algorithm choice, nothing to confuse.

Choose `'paseto'` **only** when several services must verify tokens
independently without sharing this store. It then requires `issuer`, `audience`
and a key set — all three, and the library will not start without them.

- `issuer` is required because a token minted by one deployment must not be
  accepted by another that happens to share a key. A staging token working in
  production is not a theoretical concern.
- `audience` is required because a token for `orders-api` must be refused by
  `billing-api`. The predecessor omitted this, so any service holding the public
  key accepted tokens minted for any other.

PASETO v4.public is Ed25519 with no `alg` header, so the entire
algorithm-confusion family has nothing to attack. Implementation is proven
against the specification's own 4-S-* test vectors.

> Under `paseto` the principal is inside a token that is **signed but not
> encrypted**. Anyone holding it reads every field. `userId`, `roles`, `scopes`
> and `tenant` must contain no personal data.

*Evidence: `paseto-v4.test.ts`, `paseto-engine.test.ts`, `config.test.ts`.*

### 3. `binding` — bearer or DPoP

**Default: `'none'`** (bearer semantics). A bearer token is a string; whoever
holds it can use it, from anywhere, until it expires or is revoked.

`'dpop'` enables proof-of-possession (RFC 9449). The token is bound to a key the
client holds privately and never exports, and every request carries a fresh
signature. **A stolen token is then useless on its own** — which is the point,
because an XSS that can read a token cannot read a non-extractable key.

It is opt-in because it is a breaking change for clients: they have to generate
a key and send a `DPoP` header on every request. `@ninsho/client` does that in
about ten lines.

*Evidence: `dpop-integration.test.ts` › *a stolen token is useless without the
key*.*

---

## Every option

### Required

| Option | Type | |
| --- | --- | --- |
| `store` | `NinshoStore` | Where sessions, revocations and rate-limit counters live |

### Lifetimes

| Option | Default | |
| --- | --- | --- |
| `accessTokenTtl` | `300` (5 min) | Access token lifetime, in seconds. Above 3,600 emits a warning — a token that long has stopped being short-lived. Hard ceiling 86,400 |
| `refreshTokenTtl` | `604800` (7 days) | Refresh token lifetime, in seconds |
| `clockToleranceSeconds` | `5` | Skew allowance when checking time claims |

Five minutes, not the fifteen the predecessor used. Fail-closed revocation
bounds a stolen token's blast radius already; a shorter window is still the
cheapest additional defence, and with rotation it costs a legitimate client one
extra round trip every five minutes.

### Failure behaviour

| Option | Default | |
| --- | --- | --- |
| `onStoreError` | `'closed'` | What to do when the store is unreachable |

`'closed'` responds **503**. Revocation could not be checked, so the guarantee
cannot be honoured, so the request is refused. A check that could not be
performed is not a check that passed.

`'open'` lets requests through without the revocation check — which means
**every revoked token works again for the duration of the outage**. It is a
legitimate availability trade-off for some systems and an explicit security
downgrade in all of them. Selecting it emits `config.insecure` at startup.

It also has no meaning under the `opaque` strategy, where the store *is* the
token's meaning rather than a denylist beside it; configuring it there is
refused rather than silently ignored.

*Evidence: `store-invariants.test.ts` › *fail-closed when Redis is unreachable*.*

### Rotation

| Option | Default | |
| --- | --- | --- |
| `refreshGraceSeconds` | `30` | Window in which a just-rotated refresh token still resolves to its replacement |

Without a grace window, two browser tabs refreshing at the same moment race: one
wins and the other presents a token that was valid microseconds earlier, and
gets signed out. Thirty seconds is long enough to absorb a multi-tab race and a
slow mobile round trip, short enough that a genuine replay from elsewhere is
almost always outside it.

Set it to `0` to disable the window and treat every replay as reuse. Above 120
emits a warning.

### DPoP

| Option | Default | |
| --- | --- | --- |
| `dpopProofMaxAgeSeconds` | `60` | How old a proof may be. RFC 9449 §11.1's suggestion |

Bounds how long a captured proof stays replayable before the single-use guard
even matters, and how much replay state the store holds. Too short and clients
on slow links are refused. Above 300 emits a warning.

Setting it under `binding: 'none'` is refused outright, because a proof
lifetime under bearer semantics suggests a proof is being checked when none is.

### PASETO only

| Option | | |
| --- | --- | --- |
| `issuer` | required under `paseto` | Stamped as `iss`, and required to match on every verify |
| `audience` | required under `paseto` | Stamped as `aud`, and required to match |
| `keys` | required under `paseto` | The active key signs; every key verifies, which is what lets a rotation happen without signing everyone out |

Setting any of them under `opaque` **throws a `ConfigurationError`** rather than
being ignored. A developer who sets an audience expects it to be enforced
somewhere, and a setting that appears to do something and does not is its own
kind of bug.

`KeyRing` verifies at construction that the halves you gave it belong together:
it signs a probe and verifies it. Mismatched halves used to construct fine and
then reject every token they issued.

### Audit

| Option | Default | |
| --- | --- | --- |
| `audit` | `ConsoleAuditSink` | Where security events go. JSON lines on stdout |

Also available: `NullAuditSink`, `MemoryAuditSink` (for tests), or your own
`AuditSink`. Whatever you pass is wrapped in `safeSink` — a sink that throws
must not be able to fail a request that otherwise succeeded.

The event shape is deliberately narrow. There is no free-form payload that could
accidentally carry a token, a password, or a request body.

See [`SECURITY.md`](../SECURITY.md#audit-events-worth-alerting-on) for which
events deserve an alert.

### One-time tokens

| Option | Default | |
| --- | --- | --- |
| `oneTimeTokens.defaultTtlSeconds` | `900` (15 min) | Lifetime for reset links, verification links, magic links |
| `oneTimeTokens.tokenBytes` | `32` | 256 bits of randomness |
| `oneTimeTokens.invalidatePrevious` | `true` | Issuing a new token kills the subject's outstanding ones for the same purpose |

Fifteen minutes on purpose: the window in which a reset link is useful to the
person who asked for it is also the window in which it is useful to anyone who
reaches their inbox.

`invalidatePrevious` is OWASP's guidance and what users expect — asking for a
second reset email should make the first link stop working, rather than leaving
both live in an inbox indefinitely. It holds **under concurrency**: two requests
arriving at the same instant still leave exactly one usable link.

*Evidence: `one-time-token.test.ts`, `ott-race-probe.test.ts`.*

---

## Rate limiting

Configured per route rather than globally, because different endpoints deserve
different allowances.

```ts
auth.rateLimit({
  action: 'login',                                  // namespace for the counters
  perIp: { limit: 20, windowMs: 60_000 },
  perAccount: { limit: 5, windowMs: 900_000 },
  identify: (req) => req.body?.email,
  trustProxy: 1,
})
```

| Option | | |
| --- | --- | --- |
| `action` | required | Namespace. Keeps a busy public route from exhausting sign-in's allowance |
| `perIp` | required | `{ limit, windowMs }` |
| `perAccount` | optional | Same shape. Omit only where there is no account identity to key on |
| `identify` | required with `perAccount` | Extracts the account identifier. **Return an identifier, never a password** — it becomes part of a store key and may appear in audit records |
| `trustProxy` | **required, no default** | How much of `X-Forwarded-For` to believe |

`trustProxy` is `false`, a hop count, or `'all'`. There is no default because
guessing is unsafe in both directions:

- **Too low**, behind a proxy: every visitor shares one bucket, and any one of
  them can rate-limit everybody.
- **Too high**: a visitor mints a fresh bucket per request by prepending
  invented hops to `X-Forwarded-For`.

The address is counted from the *trusted end of the chain inwards, by hop
count* — never by taking the leftmost entry. Anything the client prepends sits
beyond the hop it is entitled to.

Both dimensions are always consumed, so an attacker cannot keep one counter low
by tripping the other first.

*Evidence: `ratelimit.test.ts`. The `X-Forwarded-For` case is worth reading —
writing the playground panel for it is what found a real off-by-one in the
address resolution.*

---

## Reading the resolved configuration

```ts
auth.config          // ResolvedConfig — every default applied
auth.config.warnings // what startup complained about, if anything
await auth.health()  // is the store reachable?
```

`warnings` is worth logging at startup. It is the list of things the library
would have refused if they were unambiguously wrong, and settled for warning
about instead.
