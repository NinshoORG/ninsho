# AGENTS.md

Context for an AI agent — or a new human contributor — working on Ninsho.

Read this before touching anything. It is written to save you the hours that
were already spent finding out these things the hard way. Everything in it is
verified against the code in this repository; where it names a file or a test,
that file and that test exist.

**Companion documents.** [`CONTRIBUTING.md`](./CONTRIBUTING.md) is the human
contribution guide and the two agree by design. [`SECURITY.md`](./SECURITY.md)
is the threat model and the list of things this library deliberately does not
defend against. [`docs/`](./docs/) is the reference material. This file is the
orientation the other three assume you already have.

---

## 1. What this is, in one paragraph

Ninsho (認証 — *ninshō*, "certification") is an authentication and
authorization engine for Node.js, published as a monorepo of four packages. It
issues and rotates sessions, verifies passkeys, binds tokens to a browser key
under DPoP, rate-limits in two dimensions, and enforces authorization at the
route. It does **not** verify credentials — passwords, WebAuthn ceremonies and
federated sign-in stay in the application, because owning them would mean owning
the user model. It has no framework dependency: middleware is typed
structurally, so Express, Fastify, Hono and Koa are supported without importing
any of them.

---

## 2. The rule this project runs on

> **A security property stated in the documentation must name the test that
> demonstrates it, or it does not get stated.**

This is the whole reason the repository exists. Ninsho is a ground-up rebuild of
a predecessor whose audit found that its release could not be built from a clean
checkout, that it bundled a test double into production, and that it disabled
its own headline feature during an outage — while advertising "instant
revocation" and "all attacks blocked". The claims were not dishonest by intent.
They outran the evidence, which for an authentication library amounts to the
same thing.

**What this means for you, concretely:**

- Do not add a sentence to a README, a doc page or a code comment asserting that
  something is safe unless you can point at the test that shows it. If the test
  does not exist, write it first.
- Do not remove or weaken a test to make a change pass. If a test is wrong, say
  so explicitly in the commit body and explain why.
- A test that has never failed proves nothing. For a security-relevant change,
  write the test, watch it fail, then make it pass.
- "It works on my machine" is not evidence. It has been wrong here repeatedly —
  see §8.

---

## 3. Repository map

```
packages/
  core/       Types, errors, crypto helpers, time. ZERO runtime dependencies.
  server/     The engine: sessions, stores, middleware, DPoP, rate limiting.
  webauthn/   Passkey verification, all seven attestation formats, FIDO MDS.
  client/     Browser DPoP client. Zero dependencies, browser-only.
examples/
  express-api/  A complete integration meant to be copied.
  playground/   The interactive demonstration. Ten panels, real library.
docs/           Reference documentation.
manualtest/     Attacker's-eye HTTP tests, run by hand against a local server.
benchmarks/     Supplementary performance suites, plus their recorded results.
.github/        CI, issue and PR templates.
```

Neither `manualtest/` nor `benchmarks/` is a workspace and neither ships
anything, but both **are** type-checked — `npm run typecheck` compiles them via
their own `tsconfig.json`. That is because the scripts in both are cited as
evidence: `manualtest/TEST-RESULTS.md` and the cryptographic audit for the
first, `BENCHMARK-REPORT.md` for the second. Evidence that silently stops
compiling is the failure this project exists to avoid.

Adding those checks found a broken file in each. The benchmark one is the
better illustration: `dpop-bench.ts` called `verifyDpopProof` without the
required `maxAgeSeconds` and `clockToleranceSeconds`, which at runtime made
both freshness checks compare against `NaN` and never fire — so a published
figure was measuring a verification with two of its checks disabled.

### Where things actually live in `packages/server`

| Path | What it holds |
| --- | --- |
| `src/ninsho.ts` | The `Ninsho` facade — the whole public surface most callers touch |
| `src/config.ts` | `NinshoConfig`, validation, `DEFAULTS`, and the startup warnings |
| `src/engine/` | `OpaqueEngine` and `PasetoEngine` — how an access token is minted and verified |
| `src/session/manager.ts` | Session creation, refresh rotation, reuse detection, revocation |
| `src/store/` | `NinshoStore` contract, `MemoryStore`, `RedisStore` |
| `src/http/middleware.ts` | `verify()` and every authorization guard |
| `src/http/types.ts` | The structural `HttpRequest` / `HttpResponse` — no framework types |
| `src/http/dpop-middleware.ts` | Proof-of-possession on the request path |
| `src/dpop/` | Proof verification, replay guard, thumbprints |
| `src/ratelimit/` | Sliding window, two-dimensional, `clientIp` resolution |
| `src/tokens/one-time.ts` | Password reset, email verification, magic links |
| `src/keys/` | `KeyRing`, key loading, key generation |
| `src/fastify.ts`, `src/hono.ts`, `src/koa.ts` | Adapters, published as subpath exports |
| `src/keys.ts` | `KEYS` — every store key this library writes, in one place |

### Where things live in `packages/webauthn`

| Path | What it holds |
| --- | --- |
| `src/server.ts` | `WebAuthnServer` — registration and authentication ceremonies |
| `src/attestation.ts` | Format dispatch, chain building, trust anchors, `modelAnchors` |
| `src/tpm.ts`, `src/android-key.ts`, `src/safetynet.ts` | The hard formats, each with its own parser |
| `src/asn1.ts`, `src/cbor.ts`, `src/der.ts`, `src/cose.ts` | Bounds-checked parsers. Every one of them takes attacker-controlled bytes |
| `src/mds.ts` | FIDO Metadata Service BLOB verification |
| `src/testing.ts` | `VirtualAuthenticator` and certificate fixtures. **Published as `@ninshorg/webauthn/testing` and kept out of the main bundle by a CI gate** |

---

## 4. Commands

```bash
npm ci                # Never `npm install` on a clean checkout — the lockfile is a gate
npm run build         # MUST run before typecheck or tests. See §8.1
npm run test
npm run typecheck
```

The full store contract suite needs a real Redis. There is deliberately **no
mock Redis** — a mock that got atomicity subtly wrong would hide exactly the bug
the suite exists to catch.

```bash
docker run -d --rm -p 6379:6379 --name ninsho-redis redis:7-alpine
REDIS_URL=redis://localhost:6379 npm run test
```

Test counts differ depending on whether Redis is present. Both are correct:

| | Tests |
| --- | --- |
| Without `REDIS_URL` | 1,992 passing, 5 skipped |
| With `REDIS_URL` (what CI runs) | **2,056 passing, 0 skipped** |

Run one package, or one test:

```bash
npm run test --workspace @ninshorg/server
cd packages/server && npx vitest run -t "requireOwner"
```

Start the demonstration:

```bash
npm run dev --workspace @ninshorg/playground   # → http://localhost:4000
```

---

## 5. Non-negotiables

Each of these is enforced by a CI job, not by convention. Changing one is not a
matter of taste; it will fail the build, and the build is right.

| Invariant | Enforced by |
| --- | --- |
| `@ninshorg/core` has zero third-party runtime dependencies | **Bundle purity** › *Assert core has no third-party runtime dependencies* |
| `@ninshorg/client` has no dependencies at all | **Bundle purity** › *Assert the client has no dependencies at all* |
| `@ninshorg/webauthn` has no third-party dependencies | **Bundle purity** › *Assert webauthn has no third-party dependencies* |
| No test double or env kill-switch reaches `dist/` | **Bundle purity** › *Assert no test doubles or env kill-switches in dist* |
| The `VirtualAuthenticator` is not in the verifier bundle | **Bundle purity** › *Assert the virtual authenticator is not in the verifier bundle* |
| The framework adapters import no framework | **Bundle purity** › *Assert the framework adapters carry no framework dependency* |
| Every file a package declares actually exists in the tarball | **Bundle purity** › *Assert every declared package file exists* |
| The packed tarballs work for a real consumer (ESM and CJS) | **Bundle purity** › *Assert the packed tarballs work for a real consumer* |
| The lockfile matches the manifests | **Lockfile is in sync** |
| Consumers install nothing with a known vulnerability | **Dependency audit** › *Audit what consumers install* |
| The Redis contract suite genuinely ran, not silently skipped | **Verify** › *Assert the Redis contract suite actually ran* |

### And these, which are design decisions rather than build gates

1. **No cryptographic primitives are implemented here.** Ed25519, SHA-256 and
   the CSPRNG come from `node:crypto`. PASETO's Pre-Authentication Encoding is
   serialization, not a primitive, and is proven against the specification's own
   test vectors in `paseto-v4.test.ts`.
2. **No environment variable may weaken security.** The store is injected.
   `MemoryStore` reading `NODE_ENV` is the sole exception, and it can only ever
   make the library stricter — it refuses to construct under
   `NODE_ENV=production`.
3. **Fail closed.** A check that could not be performed is not a check that
   passed. When the store is unreachable, `verify()` responds 503 rather than
   accepting a token whose revocation status is unknown.
4. **No framework dependency.** Middleware is typed structurally against
   `HttpRequest` / `HttpResponse` in `src/http/types.ts`. If you find yourself
   wanting to `import type { Request } from 'express'` in `packages/server`,
   widen the structural type instead.
5. **Ninsho does not verify credentials.** If a change starts to look like
   password hashing or a user table, it belongs in the application.

---

## 6. Conventions

### Errors

Every error extends `NinshoError` and carries two separate things:

- `message` — fixed, uninformative, and the only thing a client sees.
- `detail` — what the server knows. `toErrorResponse()` **does not read it**.

**Never interpolate a caught value into a client-facing `message`.** The
separation is structural precisely so it cannot be forgotten. Authentication
failures share a deliberately uninformative message set: a client learns its
credential was not accepted, not why. Do not widen one to be helpful —
distinguishing "expired" from "revoked" from "never existed" hands an attacker
an oracle.

### Tests

**Name the attack, not the mechanism.**

```ts
// Good — survives a refactor, and explains why the assertion matters
it('refuses a caller addressing someone else’s resource', ...)

// Bad — describes the implementation, not the property
it('returns 403', ...)
```

Tests carry prose. A comment above a test says what the property is and, where
the test is a regression, what the bug was and how it was found. This is not
decoration — it is the citation half of §2. Read a few of the existing ones
before writing your first; `dpop-request.test.ts` and `middleware.test.ts` are
representative.

Mark regressions explicitly:

```ts
it('does not let an absolute-form target replace the authority', () => {
  // REGRESSION. `new URL(target, base)` discards the base entirely for any of
  // these, so the reconstruction became whatever origin the client named.
  ...
});
```

### TypeScript

Strict, plus `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess`. Two
consequences you will hit immediately:

- `obj.maybe = undefined` is not the same as omitting `maybe`. Build optional
  properties with a conditional spread: `...(value !== undefined && { value })`.
- `array[0]` is `T | undefined`. Handle it; do not `!` it away.

### Comments

The codebase explains *why*, at length, in prose. Match that. A comment that
restates the code is noise; a comment that records the decision, the attack it
defends against, or the alternative that was rejected and why, is the reason
this codebase can be reviewed at all. When you change behaviour, update the
comment that explains it — a stale explanation is worse than none.

### Commits

Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `ci:`,
`build:`. For a security-relevant change, the body says what the attack was and
which test now covers it.

---

## 7. Recipes

**Adding a store.** Implement `NinshoStore` and add it to the candidate list in
`store.contract.test.ts`. That suite *is* the specification — if an
implementation passes it, the engine works on it. Two methods carry the load:
`take` and `setIfAbsent` must be genuinely atomic. Refresh rotation depends on
exactly one concurrent caller winning, and a store that gets this subtly wrong
produces a race that only appears under production concurrency.

**Adding an authorization guard.** Write it in `src/http/middleware.ts` using
the `guard()` helper, call `getAuth(req)` (which throws loudly if `verify()` was
not mounted first), and call `deny(audit, auth, reason)` on refusal so an
`authz.denied` event is emitted. Expose it on the `Ninsho` facade. Add it to the
playground's authorization panel so it is demonstrable, not just tested.

**Adding an attestation format.** Add a parser module with its own error type
and bounds-checked reads, register it in the dispatch in `attestation.ts`, add
it to `VERIFIABLE_FORMATS`, and fuzz it — every parser here takes
attacker-controlled bytes. Then add it to the playground's format dropdown with
its four scenarios (genuine, no anchors, wrong root, tampered).

**Adding a framework adapter.** Copy the shape of `src/koa.ts`. It must import
nothing from the framework: the adapter reconciles "the middleware answered"
against "the middleware continued" by observing which of the two signals
arrives. Test it against the real framework as a devDependency of
`packages/server` only.

**Adding a playground panel.** Route in `examples/playground/src/server.ts`,
button in `public/index.html`, renderer in `public/app.js` if the response
shape is new, and a test in `src/playground.test.ts`. The panel must state in
advance what each outcome *should* be — a demonstration that stopped
demonstrating would look exactly like one that still works.

---

## 8. Traps

Every one of these has already cost someone hours. They are listed in the order
you are most likely to hit them.

### 8.1 Typecheck before build fails with hundreds of errors

`npm run typecheck` on a fresh checkout produces 227 errors, because
`@ninshorg/server` resolves `@ninshorg/core` through its built `dist/`. **Build
first.** CI orders the steps this way for the same reason. This was found only
when CI first ran on a clean machine; every local run had a stale `dist/` lying
around and passed.

### 8.2 `npm run clean` needs a shell that expands globs

`rimraf --glob "packages/*/dist"` is quoted so `rimraf` does its own expansion.
Run it from a shell that does not mangle the quotes. On Windows `cmd.exe` it
silently deletes nothing and reports success, which is worse than failing.

### 8.3 The lockfile gate is npm-version-sensitive

`npm install --package-lock-only` is not stable across npm versions. npm 11.6
writes `"peer": true` markers; npm 11.19 strips them; npm 10 strips them too. CI
regenerates on Node 24 with a current npm and asserts no drift.

**If the drift job fails and the diff is only `"peer"` lines, your npm is
behind.** Fix it with `npx npm@latest install --package-lock-only` and commit
the result. Do not hand-edit the lockfile.

### 8.4 Node version differences are real, and CI runs a matrix

CI runs Node 20 and 22. An API available on your machine may not exist on 20.
This is not hypothetical: `X509Certificate.validFromDate` / `validToDate` are
Node 22.10+, and using them made **the entire attestation verifier inert on Node
20** — it silently treated every certificate as invalid. Parse
`cert.validFrom` / `cert.validTo` with `Date.parse` instead.

### 8.5 Duplicate HTTP headers behave differently per header

Measured, not assumed:

- Node keeps the **first** `Authorization` header and discards the rest. An
  `Array.isArray` check on it is unreachable.
- Node **joins** duplicate `DPoP` headers with a comma.

Both are ambiguity an attacker can create, and both must be refused rather than
resolved. `req.rawHeaders` is the only place the truth survives; the middleware
consults it first. See `dpop-request.test.ts` › *refuses a duplicate only
rawHeaders can see*.

### 8.6 A request target can replace the authority

`new URL('//evil.example/orders', base)` **discards the base entirely** — as do
absolute-form targets. DPoP's `htu` comparison exists to scope a proof to one
endpoint; if the reconstruction trusts the target, both sides of the comparison
are attacker-controlled. `defaultRequestUrl` reduces the target to path + query
before reconstructing.

### 8.7 Express 5 route parameters can be arrays

`path-to-regexp` v8 supports repeatable segments, so a selector reading
`req.params.id` really can receive `['a', 'b']`. Guards test
`typeof === 'string'` rather than truthiness, and refuse arrays. **Do not add a
"convenience" that joins or indexes one** — several matched segments are not one
owner, and picking an element invents an answer the route never asked for.

### 8.8 The playground's CSP forbids inline styles

`style-src 'self'`, no `unsafe-inline`. A `style="..."` attribute in
`public/app.js` renders nothing and fills the console with violations. Use a
class. A demonstration that relaxed its own policy to indent a table would be
arguing against itself. `playground.test.ts` asserts no inline styles ship.

### 8.9 Local test runs are not CI

The recurring lesson. Local passes because of stale artifacts, one Node version,
a warm `node_modules`, or an absent Redis. Findings that only CI could produce
include §8.1, §8.3 and §8.4. If a change touches build order, dependencies,
Node APIs or the packaged surface, **push it and read CI** rather than
concluding from a green local run.

### 8.10 `--workspaces` does not reach everything

`npm run typecheck --workspaces` only visits `packages/*` and `examples/*`,
because that is what the root manifest declares. A directory outside those
globs is compiled by nothing, and nothing warns you — `manualtest/` accumulated
~4,500 lines of TypeScript that way, one file of which no longer compiled.

The root `typecheck` script now names `manualtest/tsconfig.json` and
`benchmarks/tsconfig.json` explicitly after the workspace pass. **If you add
another top-level directory of TypeScript, it needs the same treatment or it is
unchecked.** This has now happened twice, with a real defect found both times.

### 8.11 DER integers must be minimal

Non-minimal leading zeros in a generated certificate produce "an x5c entry is
not a valid certificate" at a rate of roughly 9 in 4,000 — often enough to look
like flakiness, rare enough to be dismissed as it. Fixture generation trims
them; see `x509-fixtures.ts`.

---

## 9. Do not

- **Do not publish to npm.** Nothing in this repository publishes, and release
  is the maintainer's decision. The `@ninshorg` scope is not claimed.
- **Do not weaken a default** without updating `config.test.ts` › *secure
  defaults* and saying why in the PR body. Defaults are security decisions.
- **Do not add a mock Redis.** The absence is deliberate.
- **Do not add a runtime dependency** to `core`, `client` or `webauthn`. CI
  fails the build.
- **Do not add an environment variable that turns a check off.** There is no
  precedent for one and CI looks for them.
- **Do not state a security property without a test.** See §2. This is the one
  rule that, if broken, defeats the entire point of the project.

---

## 10. Where the evidence lives

When you need to know whether something is actually true, these are the files
that answer:

| Question | File |
| --- | --- |
| What happens when a refresh token is replayed? | `session.test.ts` |
| Is the raw token ever stored? | `opaque-engine.test.ts` › *never stores the raw token* |
| Does PASETO match the spec? | `paseto-v4.test.ts` — the official 4-S-* vectors |
| What does a store have to guarantee? | `store.contract.test.ts` |
| What happens when Redis is unreachable? | `store-invariants.test.ts` |
| Do the authorization guards refuse what they should? | `middleware.test.ts` |
| Is a refresh accepted as re-authentication? | `fresh-auth.test.ts` |
| Can a parser be made to throw on hostile bytes? | `fuzz.test.ts`, plus a suite per parser |
| Do the adapters behave identically? | `fastify.test.ts`, `hono.test.ts`, `koa.test.ts` |
| Does the whole thing work over real HTTP? | `examples/express-api/src/*.test.ts` |
| Do the demonstration's claims still hold? | `examples/playground/src/playground.test.ts` |

---

## 11. Current state

- **Version** `0.1.0`, published to npm under the `@ninshorg` scope. Not
  audited by anyone independent.
- **CI** green on Node 20 and 22 against real Redis; verified from a fresh
  clone rather than a working directory.
- **Not yet done, and none of it is code:** an external security review, a
  security disclosure contact in `SECURITY.md`, a hosted demonstration, and the
  version decision. See the checklist at the end of `CONTRIBUTING.md`.

If you are an agent picking this up: the engineering is complete and verified.
The most valuable thing you can do is not to add features — it is to find code
that is only ever reached through a happy path, exercise it directly, and
measure what happens. That method produced roughly a dozen real defects here,
and every one of them looked fine until someone tried it.
