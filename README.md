# Ninsho

**認証** — an authentication engine for Node.js.

> **Status: v0.1.0, pre-release. Not published to npm. Not ready to depend on.**
>
> Sessions, both token strategies, authorization, rate limiting, and
> proof-of-possession (RFC 9449) all work. This README documents what is built,
> not what is planned. Anything not listed under "What works today" does not
> exist.

Ninsho is a ground-up rebuild of an earlier library (SecureAuth), started after
a [security audit](#audit-lineage) found that its published release could not be
built from a clean checkout, bundled a test double into its production artifact,
and defaulted to disabling its own headline feature during a store outage.

The rebuild keeps what that audit found sound and discards what it found broken.

---

## The rule this project runs on

> **A security property stated in this README must name the test that
> demonstrates it, or it does not go in this README.**

The predecessor advertised "instant revocation", "110 tests" and "all attacks
blocked". Its CI had not run since the release commit, 8 of 9 test files failed
to import, and the attack suite tested a reimplementation rather than the
shipped middleware. None of those claims were dishonest by intent — they simply
outran the evidence, which for an authentication library is the same thing.

Every claim below links to executable proof.

---

## What works today

| Capability | Where | Proof |
| :--- | :--- | :--- |
| Strategy-agnostic type surface | `packages/core/src/types.ts` | compiles under `strict` + `exactOptionalPropertyTypes` |
| Error taxonomy with HTTP status mapping | `packages/core/src/errors.ts` | `errors.test.ts` — 11 classes, status and code asserted |
| Internal detail cannot reach a client | `errors.ts` — `detail` is separate from `message` | `errors.test.ts` › *detail never reaches the client* |
| Authentication failures are indistinguishable | fixed messages per class | `errors.test.ts` › *401 responses do not explain themselves* |
| CSPRNG identifiers and tokens, no dependency | `crypto.ts` — `node:crypto` only | `crypto.test.ts` — uniqueness over 20k draws, alphabet spread |
| Constant-time comparison that fails closed | `crypto.ts` — `safeEqual` | `crypto.test.ts` — rejects `undefined`, `null`, objects, length mismatch |
| Time predicates fail closed on bad input | `time.ts` | `time.test.ts` — unparseable timestamps read as expired |
| Issue / verify / revoke opaque access tokens | `engine/opaque.ts` | `opaque-engine.test.ts` |
| Raw tokens are never stored | keyed by `hashToken()` | `opaque-engine.test.ts` › *never stores the raw token* |
| Revoked and never-issued tokens are indistinguishable | uniform `TokenInvalidError` | `opaque-engine.test.ts` › *does not reveal … whether a token ever existed* |
| Corrupt store records are rejected, not partially trusted | `#tryParseRecord` | `opaque-engine.test.ts` — 12 malformed-record cases, incl. prototype pollution |
| Terminating a session kills all its tokens | `revokeSession()` | `opaque-engine.test.ts` › *revokeSession* |
| Store implementations cannot drift apart | one contract suite, both stores | `store.contract.test.ts` |
| Engine invariants hold against a real database, not just a Map | 16 invariants × every store | `store-invariants.test.ts` |
| An unreachable store rejects rather than admits | fail-closed, verified against a dead Redis | `store-invariants.test.ts` › *fail-closed when Redis is unreachable* |
| Single-use consumption is race-free | `take()` / `setIfAbsent()` | `store.contract.test.ts` — 25 concurrent callers, exactly one wins |
| In-memory store cannot reach production | `MemoryStore` constructor | `memory-store.test.ts` › *production guard* |
| Defaults are fail-closed and short-lived | `config.ts` | `config.test.ts` › *secure defaults* |
| Refresh rotation, race-free | `session/manager.ts` — `store.take()` | `session.test.ts` › *lets exactly one of many simultaneous callers rotate* |
| **Refresh reuse revokes the whole family** | `#resolveNonLive` | `session.test.ts` › *ends the session for both parties when a stolen token is redeemed first* |
| Reuse raises an alarm, not just a 401 | `refresh.reuse_detected` event | `session.test.ts` › *emits refresh.reuse_detected with the replayed generation* |
| **A reuse alarm says whether the replay came from elsewhere** | hashed client signals, compared at detection | `signals.test.ts` › *classifying a reuse alarm* |
| A forged header cannot end anyone's session | signals are recorded, never branched on | `signals.test.ts` › *signals are never a control* |
| Client addresses are never stored in the clear | truncated hashes only | `signals.test.ts` › *signals are stored hashed, never raw* |
| Garbage tokens cannot revoke anyone's session | tombstone required before revoking | `session.test.ts` › *does not revoke anything when an unrecognised token is presented* |
| Parallel tabs are not signed out | grace window | `session.test.ts` › *grace window* |
| Rotation extends the token, never the session | `familyExpiresAt` ceiling | `session.test.ts` › *does not extend the family ceiling on rotation* |
| Raw replacement tokens live seconds, not days | `KEYS.refreshGrace` TTL | `session.test.ts` › *stores the raw replacement only for the grace period* |
| Sign-out-everywhere ends every session | `revokeAllForUser` | `session.test.ts` › *revokeAllForUser* |
| **PASETO v4.public matches the specification byte for byte** | `paseto/v4.ts` | `paseto-v4.test.ts` — all 3 official `4-S-*` vectors, verified *and* reproduced |
| Algorithm confusion is not expressible | fixed `v4.public.` prefix | `paseto-v4.test.ts` › *algorithm confusion* |
| Footer tampering invalidates the signature | PAE covers header, payload, footer | `paseto-v4.test.ts` › *rejects a swapped footer* |
| Non-canonical base64url is rejected | `b64uDecode` re-encode check | `paseto-v4.test.ts` › *rejects non-canonical base64url* |
| Tokens are scoped by issuer and audience | `PasetoEngine.verify` | `paseto-engine.test.ts` › *issuer and audience scoping* |
| Key rotation forces no sign-outs | `KeyRing` overlap window | `paseto-engine.test.ts` › *key rotation* |
| A forged `kid` cannot select an attacker's key | signature check after key lookup | `paseto-engine.test.ts` › *does not let a swapped kid select an attacker-chosen key* |
| The session layer is genuinely strategy-agnostic | one `TokenEngine` seam | `session.test.ts` › *session layer over the paseto engine* |
| **Ownership checks close the BOLA gap** | `requireOwner()` | `middleware.test.ts` › *requireOwner* |
| An undeterminable owner is refused, not allowed | selector returning `undefined` fails | `middleware.test.ts` › *refuses when the owner cannot be determined* |
| Tenants cannot reach across each other | `requireTenant()` | `middleware.test.ts` › *requireTenant* |
| Roles and scopes are exact, never prefix or wildcard | `requireRole` / `requireScope` | `middleware.test.ts` › *not fooled by a role that is a prefix*, *does not honour a wildcard* |
| Fail-closed returns 503 and leaks no infrastructure detail | `createVerify` | `middleware.test.ts` › *store outage behaviour* |
| Fail-open cannot admit an unidentifiable caller | `canVerifyWithoutStore` | `middleware.test.ts` › *still refuses under fail-open when the engine cannot identify* |
| Credentials are never read from a URL | header-only extraction | `middleware.test.ts` › *ignores a token supplied in the query string* |
| Ambiguous duplicate auth headers are refused | `extractBearer` | `middleware.test.ts` › *refuses a repeated Authorization header* |
| **Distributed credential stuffing is caught** | per-account bucket | `ratelimit.test.ts` › *stops distributed credential stuffing against one account* |
| Shared NAT does not punish bystanders | separate per-IP and per-account buckets | `ratelimit.test.ts` › *does not punish other accounts from the same address* |
| A forged `X-Forwarded-For` cannot mint a fresh bucket | hop-counting from the trusted end | `ratelimit.test.ts` › *does not let prepended entries shift the resolved address* |
| `trustProxy` has no default and must be stated | `assertTrustProxy` | `ratelimit.test.ts` › *trustProxy validation* |
| No 2× burst at a window boundary | sliding-window counter | `ratelimit.test.ts` › *does not permit a double burst across a window boundary* |
| Rate limits hold under concurrency | atomic `increment` | `store.contract.test.ts` › *gives every concurrent caller a distinct value* |
| The limiter cannot silently stop working | fail-closed by default | `ratelimit.test.ts` › *store outage* |
| One constructor wires everything, securely | `Ninsho` | `ninsho.test.ts` › *minimal configuration* |
| Weakening choices announce themselves at startup | `config.insecure` events | `ninsho.test.ts` › *startup warnings* |
| No input produces an uncontrolled exception | every parser on the untrusted path | `fuzz.test.ts` — randomised and mutation testing |
| Every single-byte mutation of a token is rejected | Ed25519 signature | `fuzz.test.ts` › *rejects every single-byte mutation* |
| Junk submitted in bulk cannot revoke a live session | tombstone required | `fuzz.test.ts` › *leaves a live session untouched* |
| The whole system holds together over real HTTP | assembled app | `examples/express-api` — 93 end-to-end tests |
| A denied request never reaches a Fastify route handler | `toFastify()` returns the reply, not undefined | `fastify.test.ts` — asserted against real Fastify |
| A denied request never reaches a Hono route handler | `toHono()` returns a Response rather than calling `next()` | `hono.test.ts` — asserted against real Hono |
| A 401 carries a challenge, as RFC 7235 requires | `WWW-Authenticate`, scheme follows the binding | `middleware.test.ts` › *the 401 challenge* |
| A logout cannot be outrun by a concurrent rotation | session tombstone written before enumeration | `session.test.ts` › *regression: revocation racing rotation* |
| Invariants hold under parallel load | 50-way rotation, racing revocation, mixed traffic | `concurrency.test.ts` |
| **Sensitive operations can demand a recent login** | `requireFreshAuth()` reads the authentication time, not the token's | `fresh-auth.test.ts` |
| **A reset link works exactly once** | atomic `take()`, never read-then-delete | `one-time-token.test.ts` › *lets exactly one of many simultaneous clicks win* |
| A reset token is never stored in plaintext | keyed by `hashToken()` | `one-time-token.test.ts` › *the raw token never reaches the store* |
| A reset token cannot be used at a verification endpoint | purpose is part of the key, not a comparison | `one-time-token.test.ts` › *purpose scoping* |
| Requesting a new reset link kills the old one | atomic generation counter, race-free | `one-time-token.test.ts` › *leaves exactly one token valid when two issues race* |
| A password reset ends every existing session | `revokeAllForUser('credential_changed')` | `password-reset.test.ts` › *revokes every existing session* |
| The reset endpoint is not an enumeration oracle | identical answer for real and unknown addresses | `password-reset.test.ts` › *it does not reveal which accounts exist* |
| Refreshing cannot masquerade as re-authenticating | `authenticatedAt` is carried unchanged through rotation | `fresh-auth.test.ts` › *refreshing does not count as authenticating* |
| A parallel tab is not signed out under real store latency | exponential tombstone backoff, measured against Redis | `store-invariants.test.ts` › *one replacement chain from 100 concurrent callers* |
| Sign-out-everywhere scales, with bounded fan-out | `mapConcurrent` | `concurrent-util.test.ts` › *session operations at scale* |
| One bad session cannot abandon a sweep half-done | per-session isolation in `revokeAllForUser` | `concurrent-util.test.ts` › *completes the sweep even when one session fails* |
| **A stolen token is useless without the key** | `binding: 'dpop'` (RFC 9449) | `dpop-integration.test.ts` › *a stolen token is useless without the key* |
| JWK thumbprints match the specification | RFC 7638 canonical form | `dpop-proof.test.ts` — the specification's own vector |
| A DPoP proof cannot be replayed | single-use `jti`, store-backed | `dpop-integration.test.ts` › *refuses a captured proof replayed* |
| `alg: none` and HMAC confusion are refused | allowlist, not denylist | `dpop-proof.test.ts` › *algorithm confusion* |
| Refresh tokens are bound too | RFC 9449 §5 | `dpop-integration.test.ts` › *refresh tokens are bound too* |
| A rejected proof cannot destroy a session | binding checked before `take()` | `dpop-integration.test.ts` › *regression: a rejected proof must not consume* |
| Only one textual spelling of a proof is accepted | canonical base64url on every segment | `dpop-proof.test.ts` › *regression: non-canonical base64url* |
| **The browser key cannot be exfiltrated** | non-extractable WebCrypto key | `client.test.ts` › *key material cannot be exfiltrated* |
| Client and server agree on the wire format | tested against each other, not assumptions | `interop.test.ts` — thumbprints and proofs both directions |
| A refresh stampede cannot look like theft | single-flight refresh | `client.test.ts` › *collapses concurrent refreshes into one* |
| Concurrent first requests share one key | single-flight key init | `client.test.ts` › *generates a key only once* |
| **Passkeys: registration and authentication** | `@ninsho/webauthn` — WebAuthn L3 §7.1 / §7.2 | `ceremony.test.ts`, `server.test.ts` |
| A WebAuthn challenge is single-use | atomic `take()`, never read-then-delete | `challenge.test.ts` › *lets exactly one of many concurrent attempts win* |
| A registration challenge cannot authenticate | ceremony type is part of the key, not a comparison | `challenge.test.ts` › *ceremony scoping* |
| A failed ceremony still burns its challenge | consume before verify | `server.test.ts` › *burns the challenge even when verification then fails* |
| The verification algorithm never comes from the request | it comes from the stored key | `cose.test.ts` › *never lets the verify-time algorithm come from the signature* |
| An EC2 key cannot claim to be RSA | key type must match the algorithm | `cose.test.ts` › *algorithm confusion* |
| Undersized RSA keys are refused | 2048-bit floor, measured in significant bits | `cose.test.ts` › *refuses a 512-bit modulus* |
| A cloned authenticator is detected | counter regression rejects by default | `ceremony.test.ts` › *sign counter* |
| Lookalike origins are refused | exact allowlist, no suffix matching | `ceremony.test.ts` › *refuses the lookalike origin …* |
| CBOR decoding matches the specification | RFC 8949 Appendix A vectors | `cbor.test.ts` |
| DER signature conversion matches OpenSSL | differential: OpenSSL signs, WebCrypto verifies | `der.test.ts` › *converts 200 OpenSSL P-256 signatures* |
| **Approved-hardware-only enrolment** | `packed` attestation, chain verified to your roots | `attestation.test.ts` › *enforces an AAGUID allowlist* |
| Touch ID and Face ID attestation | `apple` — the ceremony nonce is carried in the certificate | `attestation.test.ts` › *apple attestation* |
| An Apple certificate cannot vouch for someone else's key | subject key must equal the credential key | `attestation.test.ts` › *refuses a certificate whose subject key is not the credential key* |
| A self-signed CA cannot forge attestation | trust anchors are mandatory | `attestation.test.ts` › *refuses a chain that does not reach a configured root* |
| An attestation lifted from another device is refused | certificate AAGUID must match the authenticator data | `attestation.test.ts` |
| Unimplemented attestation formats are refused, not rubber-stamped | allowlisting one still fails closed | `ceremony.test.ts` › *cannot be verified* |
| Generated test certificates are real certificates | cross-checked by Node's own X.509 parser | `asn1.test.ts` › *the generated certificates are real certificates* |
| Passkeys work end to end over real HTTP | assembled app, real keys, real signatures | `examples/express-api/src/passkey.test.ts` — 29 tests |
| A passkey confers identity, never authority | roles come from the directory | `passkey.test.ts` › *carries roles from the directory, not from the passkey* |
| Adding a passkey requires an existing session | `auth.verify()` on both register routes | `passkey.test.ts` › *registration requires a session* |

```
942 tests passing · typecheck clean · no flaky runs over 5 repeats
core 4.9 KB, zero dependencies · server 79 KB, ioredis only — no Express dependency
```

### Documentation

- **[SECURITY.md](./SECURITY.md)** — security model, threat model, and the
  limitations stated plainly
- **[PERFORMANCE.md](./PERFORMANCE.md)** — benchmarks, and what they say about
  the architecture
- **[CONTRIBUTING.md](./CONTRIBUTING.md)** — the rule this project runs on, and
  the design constraints that are settled
- **[examples/playground](./examples/playground)** — an interactive protocol
  explorer: run the attacks, watch them fail, and read the store underneath
- **[packages/webauthn](./packages/webauthn)** — passkeys: what is verified,
  and what deliberately is not
- **[examples/express-api](./examples/express-api)** — a complete integration
  meant to be copied
- **[CHANGELOG.md](./CHANGELOG.md)**

### What does not exist yet

**The Android attestation formats.** `@ninsho/webauthn` verifies `none`,
`packed` (most security keys), `apple` (Touch ID and Face ID), `tpm` (Windows
Hello) and `fido-u2f` (CTAP1 security keys), each against roots you supply.
`android-key` and `android-safetynet` are not implemented and are refused
rather than rubber-stamped. No root store ships
with the package, and FIDO Metadata Service integration is not implemented:
which manufacturers you trust is an operational decision, not library content.

**Koa.** The middleware is Express-shaped; `@ninsho/server/fastify` and
`@ninsho/server/hono` adapt it, each a couple of kilobytes, neither depending
on the framework it adapts, both tested against the real thing. Koa has no
adapter and is therefore not claimed.

The Hono adapter targets **Hono on Node** (`@hono/node-server`). `@ninsho/server`
depends on `ioredis` and Node's crypto, so Workers and Deno are out of reach —
better said here than discovered at deploy time.

## Quick look

```ts
import { Ninsho, RedisStore, getAuth } from '@ninsho/server';

const auth = new Ninsho({ store: new RedisStore(process.env.REDIS_URL!) });
```

That is the entire configuration. No keys to generate, no algorithm to choose.
It yields opaque tokens, fail-closed behaviour, five-minute access tokens, and
refresh rotation with reuse detection.

```ts
app.post('/login',
  auth.rateLimit({
    action: 'login',
    perIp:      { limit: 20, windowMs: 900_000 },
    perAccount: { limit: 5,  windowMs: 900_000 },
    identify: (req) => req.body?.email,
    trustProxy: false,          // no default — state it deliberately
  }),
  async (req, res) => {
    // Verify credentials yourself — Ninsho does not own your user model.
    const user = await checkPassword(req.body);
    res.json(await auth.createSession({
      userId: user.id, roles: user.roles, scopes: [],
    }));
  });

app.post('/refresh', async (req, res) => {
  // Replaying a rotated token revokes the whole session and raises an alarm.
  res.json(await auth.refresh(req.cookies.refresh_token));
});

app.get('/me', auth.verify(), (req, res) => res.json(getAuth(req)));

app.get('/admin/reports', auth.verify(), auth.requireRole('admin'), handler);

// Authenticated is not the same as entitled — this closes the BOLA gap.
app.get('/users/:id/orders',
  auth.verify(),
  auth.requireOwner((req) => req.params?.id),
  handler);
```

---

## Design commitments

These are decisions already made and encoded in the type surface, not
aspirations. The full reasoning is in the architecture document.

**Two token strategies behind one API.** `opaque` is the default: a 256-bit
random token, all state in the store, revocation immediate and native, and *no
signing keys at all* — a solo developer configures a store and nothing else.
`paseto` is opt-in for teams whose services must verify independently, and it
requires `issuer`, `audience` and a key set, because a token minted for one
service must not be accepted by another.

**PASETO v4.public is implemented here, not imported.** The cryptography is
`node:crypto`'s Ed25519; what Ninsho implements is PASETO's Pre-Authentication
Encoding and base64url framing, verified against the specification's own test
vectors — including reproducing each published token byte for byte. The
reference package has not been released since April 2023, and the
predecessor's subtlest defect came from depending on that package's *error
strings* to decide whether a token was expired or forged. The decision is
contained behind `TokenEngine` and is a one-file swap if you disagree.

**Fail closed.** If the store cannot be reached, the revocation check cannot be
performed, so the request is refused. Fail-open remains available and is
logged loudly at startup, because it is a security downgrade rather than a
neutral preference.

**No security theatre.** User-agent fingerprinting is not a binding mechanism —
the User-Agent is a header the attacker chooses. It exists here as an audit
signal only, and nothing branches on it.

Real replay resistance means proof-of-possession, so that is what
`binding: 'dpop'` implements (RFC 9449): tokens bound to a key the client holds
privately, with a fresh signed proof on every request. A stolen token alone is
useless. It is opt-in because enabling it is a breaking change for clients.

**Refresh reuse is treated as theft.** Replaying a rotated refresh token
outside the grace window revokes the entire token family and emits
`refresh.reuse_detected`, per RFC 9700 §4.14.2. Rejecting the request without
revoking the family — the predecessor's behaviour — discards the strongest
compromise signal an authentication system can observe.

**No environment variable may weaken security.** The store is injected. There
is no `USE_REDIS_MOCK`-style switch, and CI fails the build if a test double or
env kill-switch appears in the bundle.

**Authentication is not authorization.** Verifying a token says who is calling
and nothing about what they may address. `requireOwner()` and `requireTenant()`
exist because broken object-level authorization is OWASP API Security #1, and
because the shape is always the same: a route reads `/users/:id/orders`, the
handler trusts `:id` since the request was authenticated, and any signed-in
user reads anyone's data by changing a number. A selector that cannot determine
an owner **refuses** — treating "absent" as "allowed" is how these checks
silently stop working when a route is renamed.

**No framework dependency.** The middleware is typed structurally, so Express
`Request`/`Response` satisfy it without Ninsho depending on Express or
`@types/express`. The predecessor took Express as a peer dependency and
augmented `express-serve-static-core` globally to add `req.auth`; this gets the
same ergonomics with neither cost.

To be precise about what that does and does not mean: the shapes are
**Express-shaped**, not universal. Anything matching them works — Connect,
Restify, most Express-compatible routers. Fastify's reply uses `send()` rather
than `json()`, so it needs a translation; `@ninsho/server/fastify` is that
translation. Hono's model differs more — one context object, headers and params
behind functions, and halting by returning a `Response` — so
`@ninsho/server/hono` does more work. Both are tested against the real
framework rather than a stub.

---

## Repository layout

```
packages/
  client/        @ninsho/client — browser DPoP client. Zero dependencies.
  core/          @ninsho/core — types, errors, primitives. Zero dependencies.
  webauthn/      @ninsho/webauthn — passkeys. Zero third-party dependencies.
    cbor.ts      RFC 8949 decoder, definite lengths only
    der.ts       strict DER → P1363 for ECDSA signatures
    asn1.ts      X.509 extension lookup (AAGUID)
    attestation.ts  packed attestation, chain verified to your roots
    cose.ts      COSE key import, algorithm allowlist
    authdata.ts  WebAuthn §6.1 authenticator data
    challenge.ts single-use challenges, scoped by ceremony
    ceremony.ts  §7.1 / §7.2 verification
  server/        @ninsho/server — store, engines, config, audit.
    fastify.ts   @ninsho/server/fastify — adapter, no Fastify dependency
    hono.ts      @ninsho/server/hono — adapter, no Hono dependency
    store/       NinshoStore interface · RedisStore · MemoryStore
    engine/      TokenEngine interface · OpaqueEngine · PasetoEngine
    session/     SessionManager — rotation, families, reuse detection
    keys/        KeyRing — kid resolution, rotation overlap
    paseto/      v4.public sign/verify on node:crypto
    http/        verify + authorization middleware (Express-shaped)
    ratelimit/   sliding-window counter, per-IP and per-account buckets
    tokens/      single-use tokens — reset, verification, magic links
    dpop/        RFC 9449 proof verification, JWK thumbprints, replay guard
```

### Testing against Redis

The store contract suite runs against `MemoryStore` by default and adds
`RedisStore` when `REDIS_URL` is set, skipping it visibly otherwise:

```bash
docker run -d --rm -p 6379:6379 redis:7-alpine
REDIS_URL=redis://localhost:6379 npm run test
```

There is deliberately **no mock Redis**. Substituting a test double for the
store is the failure this project was rebuilt to avoid, and a mock that merely
resembles Redis would defeat the purpose of a contract suite. CI runs it
against a real Redis 7 and fails if the suite silently skips.

## Development

```bash
npm ci          # lockfile-enforced; fails loudly if manifests drift
npm run test
npm run typecheck
npm run build
```

Node 20+. CI runs on 20 and 22.

### CI gates

Four independent jobs, so a failure in one cannot silently disable the others —
which is precisely how the predecessor's audit gate stopped running.

- **verify** — `npm ci`, typecheck, test, build on Node 20 and 22
- **lockfile** — regenerates the lockfile and fails on any drift
- **audit** — `npm audit --audit-level=moderate`
- **bundle** — fails if a test double or env kill-switch reaches `dist/`, or if
  `@ninsho/core` acquires any dependency beyond `node:crypto`

**Known accepted advisory:** `GHSA-g7r4-m6w7-qqqr` (esbuild, **low**). Reachable
only via `esbuild serve`, which nothing here invokes — tsup uses esbuild as a
bundler API. No patched version exists in tsup's supported range. Tracked, not
silently ignored.

---

## Audit lineage

Ninsho supersedes `@secureauth/server@1.0.2`. That package remains on npm,
unmaintained; it should not be used. The audit that motivated this rebuild
found 3 critical and 5 high issues, each of which is addressed by design here
rather than patched:

| Audit finding | How Ninsho addresses it |
| :--- | :--- |
| C1 — lockfile desync disabled all CI | `npm ci` first, plus a dedicated drift gate |
| C2 — env var swapped the store for a fake | store is injected; bundle purity enforced in CI |
| C3 — refresh reuse undetected | family revocation + `refresh.reuse_detected` — **closed** |
| H1 — expired-token path used an unsigned decoder | that code path does not exist |
| H2 — UA fingerprint sold as replay protection | demoted to audit signal; DPoP seam reserved |
| H3 — fail-open default | fail-closed default; fail-open rejected where it could never take effect — **closed** |
| H4 — no key rotation, no `iss`/`aud` | `KeyRing` overlap window; both claims required — **closed** |
| H5 — rate limiting keyed on spoofable IP | per-account bucket + mandatory `trustProxy` decision — **closed** |
| M3 — no authorization primitives | role / scope / tenant / **owner** middleware — **closed** |
| M4 — vulnerable id dependency | zero dependencies; `node:crypto` directly |
| M8 — library errors leaked to clients | `detail` is structurally separate from `message` |

The audit's one remaining accepted limitation — that bearer tokens can be
replayed — is now addressable: `binding: 'dpop'` makes a stolen access token
useless without the client's key.

## License

MIT — see [LICENSE](./LICENSE).
