# Deployment

Before this goes in front of real users.

> **Read this first.** Ninsho is `0.1.0`, unpublished, and **has not been
> independently audited**. The entire project exists because a library's claims
> outran its evidence, so it will not make an exception for itself: run your own
> review before you depend on this. Everything below assumes you have decided to
> anyway.

---

## The checklist

### Must

- [ ] **`RedisStore`, not `MemoryStore`.** `MemoryStore` refuses to construct
      under `NODE_ENV=production` and there is no override flag. Per-process
      session state that vanishes on restart silently breaks revocation and rate
      limiting.
- [ ] **`NODE_ENV=production` is actually set.** It is what makes the guard
      above fire.
- [ ] **`trustProxy` is stated on every rate limiter**, and matches your
      topology. There is no safe default — see below.
- [ ] **Refresh tokens in an `httpOnly`, `Secure`, `SameSite=Strict` cookie**,
      scoped to the refresh path. Never in a response body you also log.
- [ ] **Access tokens in memory only** on the client. Never `localStorage` —
      any XSS on the page reads it there.
- [ ] **`userId`, `roles`, `scopes` and `tenant` contain no personal data.**
      Under `paseto` they sit inside a token that is signed but not encrypted.
      Even under `opaque` they reach your audit log.
- [ ] **HTTPS everywhere.** DPoP, `Secure` cookies and everything else assume it.
- [ ] **`auth.errorHandler()` is mounted**, or you translate `NinshoError`
      yourself with `toErrorResponse()`. Never send `error.detail` to a client.
- [ ] **`auth.close()` on shutdown**, so Redis connections drain rather than
      being severed.

### Should

- [ ] **Log `auth.config.warnings` at startup.** It is the list of things the
      library would have refused if they were unambiguously wrong, and settled
      for warning about instead.
- [ ] **Alert on the audit events that matter** — see below.
- [ ] **Rate-limit sign-in, refresh, password reset and any passkey ceremony.**
      Two dimensions on each.
- [ ] **Consider `binding: 'dpop'`.** It is the difference between a stolen
      token being useful and being inert. It is a breaking change for clients,
      which is why it is not the default.
- [ ] **`/health` calls `auth.health()`**, so an unreachable store shows up as
      unhealthy rather than as a wall of 503s.

---

## `trustProxy`, in detail

This is the setting most likely to be wrong, and wrong in a way nothing tells
you about.

`clientIp` resolves the caller's address by counting hops **inward from the
trusted end** of `X-Forwarded-For` — never by taking the leftmost entry, which
is fully attacker-controlled.

| Your topology | Value |
| --- | --- |
| Process directly exposed to the internet | `false` |
| One load balancer / reverse proxy in front | `1` |
| CDN → load balancer → process | `2` |
| Behind a proxy chain you fully control and terminate | `'all'` |

**Too low, behind a proxy:** every visitor resolves to the proxy's address. They
all share one bucket, and any one of them can rate-limit everybody.

**Too high:** a visitor mints a fresh bucket per request by prepending invented
hops. The rate limiter is then decorative.

Count the hops that will actually be in front of the process in *this*
environment. It is frequently different between staging and production, and that
difference is not visible in a log.

*The playground's rate-limiting panel demonstrates both failure modes against
the real middleware.*

---

## Redis

`RedisStore` needs `take` and `setIfAbsent` to be genuinely atomic. Redis
provides that. What to watch:

- **Do not point it at a Redis you also use as a cache with `maxmemory-policy
  allkeys-lru`.** Session records are not cache entries; evicting one signs a
  user out, and evicting a one-time token generation counter fails closed but
  confusingly.
- **Persistence is your call.** Losing the store signs everyone out. That is a
  safe failure, and for some deployments an acceptable one.
- **Give it its own database or key prefix if it is shared.** Every key is
  already namespaced `ninsho:v1:`, so a collision needs deliberate effort — but
  a `FLUSHDB` from a neighbouring service does not care about namespaces.

Verify your setup against the contract suite rather than trusting it:

```bash
REDIS_URL=redis://your-host:6379 npm run test --workspace @ninsho/server
```

---

## Audit events worth alerting on

| Event | What it means |
| --- | --- |
| `refresh.reuse_detected` | A consumed refresh token was presented again. One of the two holders is an attacker. Check `signalMatch` — `different` means the replay came from another client, which is close to certain theft |
| `config.insecure` | A weakening choice was made at startup. Should be zero in production |
| `authz.denied` in bursts for one `userId` | What enumeration looks like from the inside |
| `token.rejected` in bursts from one address | Credential stuffing, or a client that is broken in a way worth knowing about |
| `store.unavailable` | Requests are being refused with 503 |

The event shape is deliberately narrow — there is no free-form payload that
could accidentally carry a token, a password, or a request body. Full list in
[`SECURITY.md`](../SECURITY.md#audit-events-worth-alerting-on).

Pass your own `AuditSink` to route these anywhere:

```ts
const auth = new Ninsho({
  store,
  audit: { emit: (event) => logger.info(event) },
});
```

Whatever you pass is wrapped in `safeSink`, so a sink that throws cannot fail a
request that otherwise succeeded.

---

## Deploying the playground

The demonstration is a separate thing from your application, and it ships a
container:

```bash
docker build -f examples/playground/Dockerfile -t ninsho-playground .
docker run -p 4000:4000 ninsho-playground
```

Anywhere that runs a container will host it. It keeps nothing and needs no
database.

Two environment variables matter:

- **`PLAYGROUND_TRUST_PROXY`** — the same setting as above, for the demo's own
  self-limiting. Unset means "directly exposed".
- **`PUBLIC_ORIGIN`** — the URL people actually visit. A DPoP proof is bound to
  the URI it was minted for, so the value the page signs and the value the server
  reconstructs have to agree.

**It hands out internals over HTTP on purpose** — the live keyspace, the store
operations behind every request, the audit trail, and each error's `detail`
which a real deployment never sends to a client. Give it its own host and its
own network. It has no business next to a production Redis.

Its image sets `NODE_ENV=demonstration` rather than `production`, deliberately
and with a comment explaining why: the playground *is* the demonstration, and
every visitor's throwaway world vanishing on restart is the intended behaviour.
If you copy that Dockerfile for something real, set `NODE_ENV=production` and
watch it refuse to start. That is the guard working.

---

## What you are still responsible for

Ninsho draws its boundary deliberately, and the things outside it are not
oversights:

- **Verifying credentials.** Password hashing, WebAuthn ceremony orchestration,
  federated sign-in. Ninsho takes over once you know who somebody is.
- **Your user model.** Ninsho stores sessions, not people.
- **Transport security.** TLS, HSTS, certificate management.
- **CSRF**, if you put access tokens in cookies. Ninsho's default shape —
  bearer token in memory, refresh token in a `SameSite=Strict` cookie on a
  dedicated path — avoids the class, but the choice is yours.
- **Everything else on the OWASP list** that is not authentication.

[`SECURITY.md`](../SECURITY.md#what-ninsho-is-deliberately-not-responsible-for)
states this boundary in full, and lists the known limitations on the inside of
it.
