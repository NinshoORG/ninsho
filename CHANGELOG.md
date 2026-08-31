# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

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
- Reference Express API with 43 end-to-end tests over real HTTP.
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
