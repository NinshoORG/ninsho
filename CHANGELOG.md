# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **`@ninsho/webauthn/testing` — a virtual authenticator.** Testing a passkey
  integration otherwise means a physical authenticator and a human finger,
  which is to say it does not get tested. `VirtualAuthenticator` holds a real
  key pair and produces genuinely signed responses, so an end-to-end test
  exercises the real verifier against real signatures rather than a stub
  agreeing with itself.

  It is a separate entry point, so it never reaches an application bundle that
  only imports the verifier — asserted by test. It also refuses to construct
  under `NODE_ENV=production`, following the `MemoryStore` precedent: a test
  double may ship as long as it must be named explicitly and cannot be selected
  by an environment variable. That guard matters more here than it does for
  `MemoryStore`, because a virtual authenticator running server-side means the
  *server* holds the credential's private key — WebAuthn defeated, quietly,
  while every signature still verifies.

- **Passkeys in the reference API.** `examples/express-api` now demonstrates
  the whole flow: adding a passkey to an existing account, listing credentials,
  and usernameless sign-in that ends in an ordinary Ninsho session.

  The points worth copying are the ones easy to get wrong. Registration
  requires a session and is bound to the signed-in user, because adding a
  passkey is adding a new way into the account. The sign counter is written
  back after every success, without which clone detection silently stops
  working — the check still runs, always against the same stale number. An
  unknown credential id answers exactly as a bad signature does, so the
  endpoint does not become an oracle for which credentials exist. And roles
  come from the directory, never from the passkey: WebAuthn proves who, not
  what they may do.

  29 new end-to-end tests, 72 in the example overall.

- **`@ninsho/webauthn` — passkey registration and authentication.** No
  third-party dependencies; depends only on `@ninsho/core`, which has none
  either.

  WebAuthn establishes *who someone is* and stops there, so the package
  produces a `Principal` you hand to `createSession()`. That boundary is what
  lets a passkey, a password and an OIDC login all end at the same place, with
  one session implementation behind them rather than three.

  Everything on the untrusted path is parsed here rather than delegated: a CBOR
  decoder restricted to definite lengths (no tags, no indefinite lengths, no
  floats — the constructs where CBOR parsers historically grow their
  vulnerabilities, and which CTAP2 canonical CBOR forbids anyway), a strict DER
  reader for ECDSA signatures, COSE key import, and WebAuthn §6.1 authenticator
  data. Each bounds-checks every length before using it, and each is fuzzed to
  confirm no input escapes its own error type.

  Correctness rests on outside evidence, not self-agreement: the CBOR decoder
  is checked against **RFC 8949 Appendix A** vectors, and the DER converter
  differentially against 200 signatures produced by OpenSSL through
  `node:crypto` and verified by WebCrypto — two implementations that know
  nothing about this code.

  Three things are worth calling out specifically:

  *Algorithm confusion is closed structurally.* A COSE key states its own type,
  curve and algorithm, all of it attacker-supplied. The algorithm must be on a
  relying-party allowlist, and the key type must match it — an EC2 key labelled
  RS256 is refused rather than coerced. At assertion time the algorithm comes
  from the stored key, never from the request.

  *WebCrypto's validation is uneven, so the gaps are filled here.* It rejects an
  off-curve P-256 point but imports a 512-bit RSA modulus without complaint —
  factorable on a laptop. A 2048-bit floor is enforced, measured in significant
  bits so a padded short modulus cannot slip through. Both facts are recorded as
  tests, so if a future Node starts rejecting these on its own, the test says the
  check became redundant rather than the check quietly protecting nothing.

  *Challenges are single-use and scoped by construction.* Consumption goes
  through the store's atomic `take()`, and the ceremony type is part of the
  storage key rather than a field compared afterwards — a registration challenge
  replayed at an authentication endpoint is not rejected, it is simply not
  there. A check can be forgotten in a later refactor; a key that does not exist
  cannot be.

  `WebAuthnServer` wires the two together and consumes the challenge *before*
  verifying, so a failed attempt still burns it and cannot be ground against.
  Getting that order wrong in either direction is a real vulnerability, so it is
  written once rather than in every application.

  **Attestation is not verified, and this is stated rather than implied.** Only
  the `none` format is accepted, and adding another to
  `allowedAttestationFormats` does not change that — there is no arrangement of
  options that turns an unverified attestation into a verified one. Verifying
  `packed`/`tpm`/`android-key`/`apple` means X.509 chains and root stores, and a
  verifier that parses an attestation statement without checking it is worse
  than one that refuses it. Passkeys are unaffected.

  318 tests.

- **`@ninsho/client` — the browser half of DPoP.** Zero dependencies, Web APIs
  only.

  The key is generated **non-extractable**: `crypto.subtle.exportKey` on it
  throws, and there is no other route to the bytes — including for script an
  attacker injects. That is the whole reason browser DPoP is worth having. A
  bearer token is a string an XSS copies and uses indefinitely; a DPoP key
  cannot leave the browser, so an attacker is reduced to signing proofs while
  they still have execution. It does not make XSS harmless — it makes stolen
  credentials non-portable.

  Also handled: the access token held in memory only (never `localStorage`),
  IndexedDB persistence because it is the only browser storage that can hold a
  `CryptoKey` handle, a fresh proof per request, and automatic refresh on 401.

  Refresh and key initialisation are both **single-flight**. Six requests
  hitting an expired token would otherwise start six refreshes, and under
  rotation five of them present a token another has already rotated — which the
  server correctly reads as theft. A normal page load would look like an attack.

  Client and server are tested **against each other** rather than each against
  its own assumptions: thumbprints compared across both implementations, and
  client-generated proofs verified by the server's real verifier.

- **Proof-of-possession — `binding: 'dpop'` (RFC 9449).** Access and refresh
  tokens can now be bound to a key the client holds privately, with a fresh
  signed proof required on every request. A stolen token alone becomes useless.

  This closes the one limitation the security policy previously listed as
  unmitigated with "no configuration changes this".

  - ES256 and EdDSA proofs, on an **allowlist**. A DPoP proof is a JWT, so the
    whole algorithm-confusion family applies — the class PASETO was chosen to
    avoid for Ninsho's own tokens. `alg: none` and every symmetric algorithm
    are refused, the latter because the "public" key sits in the header and
    would otherwise serve as an HMAC secret.
  - RFC 7638 thumbprints, verified against the specification's own worked
    example.
  - Single-use proof identifiers (RFC 9449 §11.1), so a captured proof cannot
    be replayed within its acceptance window.
  - Refresh tokens bound too (RFC 9449 §5) — otherwise the longest-lived
    credential would be the one piece with no proof-of-possession.
  - `createDpopProof` / `generateDpopKeyPair` for Node clients and tests.
    Browsers should use WebCrypto with a non-extractable key, which is the
    property that makes DPoP worth having there.

  Opt-in, because enabling it is a breaking change for clients.

### Fixed

- **Every async route in the reference API dropped its errors.** Express 4 does
  not catch a rejection from an `async` handler. A failing route — a store
  outage on `/auth/logout`, a rejected passkey ceremony, a degraded `/health`
  — produced an unhandled rejection and *no response at all*: the error
  middleware never ran, and the client waited until it timed out. A monitoring
  dashboard would show a timeout rather than the 400 or 503 that actually
  happened, which is the difference between a bug you can diagnose and one you
  cannot.

  Found by the new passkey tests, which asserted a 400 on a rejected ceremony
  and got an unhandled rejection instead. It affected `/auth/login`,
  `/auth/logout`, `/auth/logout-all`, `/auth/sessions` and `/health` as well,
  all of which had the same shape and none of which had a test that made them
  throw.

  Fixed with a single `route()` wrapper applied to all eleven async handlers,
  rather than a `try`/`catch` remembered at each call site — the latter is the
  version that is correct on the day it is written and wrong after the next
  route is added.

- **Concurrent first requests each generated their own client key.** Ten
  callers arriving before a key existed each found none, each generated one, and
  each wrote it — last write wins. Requests already in flight would then sign
  proofs with a key the store no longer held, and a session bound to a discarded
  key is broken with nothing in the logs to explain it. Key initialisation is
  now single-flight, like refresh.

- **Non-canonical base64url was accepted in DPoP proofs.** The segment check
  verified only the character set, not canonicality. Node's decoder ignores the
  spare bits in a segment's final character, so a 64-byte ECDSA signature had
  sixteen distinct spellings that all decoded to identical bytes and all
  verified — one proof with many textual forms, which breaks anything treating
  the proof string as an identity. The PASETO parser already rejected this; the
  DPoP one now does too. Found by a mutation test, which surfaced it as an
  intermittent failure before the cause was understood.

- **Two flaky tests, both fixed at the source rather than by loosening them.**
  A wall-clock assertion on parallelism now observes task overlap instead of
  elapsed time, and the rate-limit window-boundary test controls the clock
  rather than racing it. A flaky test of a security property is worse than no
  test, because it trains people to re-run rather than investigate.

- **A rejected DPoP proof could destroy a session.** The binding was checked
  inside `#rotate`, which runs after the atomic `take()` that consumes the
  refresh token. An attacker holding a stolen refresh token — but not the key —
  could therefore end the session simply by presenting it: the token was
  consumed, the rotation then failed, and the legitimate client's next refresh
  found nothing. A denial of service handed to precisely the party the binding
  exists to shut out. The binding is now checked before the token is consumed.

- **Revocation could lose a race against rotation.** `#revokeFamily` worked by
  enumerating the family index and deleting what it found. A rotation running
  concurrently could add its replacement to that index *after* revocation had
  read it; revocation then deleted the index, leaving a live refresh record
  that nothing pointed to. No later revocation could find the orphan either, so
  a refresh token survived a completed logout for its full lifetime — a "sign
  out this device" button reporting success while a credential stayed usable.

  Fixed with a positive session tombstone written *before* the index is read
  and consulted by rotation, so the outcome no longer depends on which
  operation touched the index first. Found by the new concurrency suite; no
  sequential test could have surfaced it.

- **`revokeAllForUser` and `listSessions` were latency-bound.** Both walked
  their sessions serially — around 4,500 store round trips for a user with 500
  sessions, never more than one in flight, which is seconds against a real
  store. "Sign out everywhere" is what gets invoked during an incident, and one
  that slow risks timing out partway and leaving sessions live.

  Both now use bounded parallelism (pool of 16): ~282 effective serial steps
  instead of ~4,500, with fan-out capped so a user with very many sessions
  cannot exhaust the connection pool. A failure on one session no longer
  abandons the rest of the sweep.

- **Token lifetimes were off by up to a millisecond.** `issuedAt` and
  `expiresAt` were derived from two separate clock readings, so a tick between
  them made the recorded lifetime differ from the configured TTL. Both now
  derive from one captured instant.

## [0.1.0] — 2026-09-01

First release of Ninsho. **Not published to npm.** Pre-release: the API may
change, and the library has not been independently audited.

Ninsho supersedes `@secureauth/server@1.0.2`, which remains on npm unmaintained
and should not be used. It is a ground-up rebuild rather than a rename — the
package name is different, so there is no upgrade path and none is owed.

### Added

**Core** (`@ninsho/core`, zero runtime dependencies)
- Strategy-agnostic type surface, compiled under `strict` with
  `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess`.
- Error taxonomy with HTTP status mapping, where diagnostic `detail` is
  structurally separate from the client-facing `message`.
- CSPRNG identifiers and tokens, constant-time comparison, and time predicates
  that fail closed on unparseable input — all on `node:crypto`.

**Storage**
- `NinshoStore` interface, injected rather than constructed internally.
- `RedisStore` (Redis 6.2+, for `GETDEL`) and `MemoryStore`, which refuses to
  construct under `NODE_ENV=production` with no opt-out.
- One contract suite executed against both, so they cannot drift apart.

**Token strategies**
- `opaque` (default) — 256-bit random tokens, all state in the store. No signing
  keys exist. Revocation is native and immediate.
- `paseto` — PASETO v4.public, Ed25519, `kid` in the footer, required `iss` and
  `aud`. Key sets with a rotation overlap window, so rotation forces no
  sign-outs.
- PASETO v4.public implemented on `node:crypto` and verified against the
  specification's official test vectors — all three `4-S-*` cases, both verified
  and reproduced byte for byte.

**Sessions**
- Refresh-token rotation, made race-free by an atomic `take` rather than a lock.
- **Reuse detection**: replaying a rotated token revokes the entire family and
  emits `refresh.reuse_detected` (RFC 9700 §4.14.2).
- A grace window so parallel browser tabs are not signed out by a lost race.
- `familyExpiresAt`, a hard ceiling fixed at creation that rotation never
  extends.
- Session listing and sign-out-everywhere.

**HTTP and authorization**
- Framework-agnostic middleware, typed structurally — Express `Request` and
  `Response` satisfy it with no Express dependency.
- `verify`, `requireRole`, `requireAllRoles`, `requireScope`, `requireTenant`,
  and `requireOwner` — the last closing OWASP API Security #1.

**Rate limiting**
- Sliding-window counter with per-IP **and** per-account buckets, the second of
  which is what catches distributed credential stuffing.
- `trustProxy` with no default; a limiter cannot be constructed without one.

**Operations**
- `Ninsho` facade: `new Ninsho({ store })` is a complete configuration.
- Pluggable audit sink, wrapped so a throwing implementation cannot fail an
  authentication.
- Startup `config.insecure` events for every accepted-but-weakening choice.

**Project**
- 600 tests. CI gates `npm ci`, lockfile drift, typecheck, build, tests against
  real Redis, `npm audit`, and bundle purity.
- Reference Express API with end-to-end tests over real HTTP.
- Benchmarks, threat model, and security model.

### Security

Every critical and high finding from the audit of the predecessor is addressed
by design rather than patched:

| Finding | Resolution |
| :--- | :--- |
| C1 — lockfile desync disabled all CI | `npm ci` first, plus a dedicated drift gate |
| C2 — env var swapped the store for a fake | Store injected; bundle purity enforced in CI |
| C3 — refresh reuse undetected | Family revocation and an audit event |
| H1 — expired path used an unsigned decoder | That code path does not exist |
| H2 — UA fingerprint sold as replay protection | Removed; DPoP seam reserved instead |
| H3 — fail-open default | Fail-closed, and rejected where it could not take effect |
| H4 — no key rotation, no `iss`/`aud` | `KeyRing` overlap window; both claims required |
| H5 — rate limiting keyed on a spoofable IP | Per-account bucket and a mandatory `trustProxy` |
| M3 — no authorization primitives | Role, scope, tenant and owner middleware |
| M4 — vulnerable id dependency | Zero dependencies; `node:crypto` directly |
| M8 — library errors leaked to clients | `detail` separated from `message` |

### Known limitations

- **Bearer tokens can be replayed.** Anyone holding a valid access token can use
  it, and no configuration changes that. The `cnf` claim slot and `BindingMode`
  type are reserved for DPoP (RFC 9449); selecting `binding: 'dpop'` throws
  today rather than silently doing nothing.
- One raw token is stored for the grace window (30s default) so a parallel tab
  can adopt a rotated replacement. `refreshGraceSeconds: 0` removes it.
- Reuse detection has a false-positive floor: a client two or more rotations
  stale is indistinguishable from an attacker.
- One accepted low advisory: `GHSA-g7r4-m6w7-qqqr` (esbuild), reachable only via
  `esbuild serve`, which nothing here invokes.

See [SECURITY.md](./SECURITY.md) for the full threat model.
