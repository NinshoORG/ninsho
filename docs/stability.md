# Stability

What Ninsho promises not to break, how that promise is enforced, and what still
stands between this project and `1.0.0`.

The rule the rest of the project runs on applies here too: **every promise
below names the mechanism that enforces it.** A stability policy that relied on
maintainers remembering would be exactly the kind of claim this project was
built to stop making.

---

## Where things stand

**`0.2.0` — pre-1.0, on a stable track.**

`0.2.0` is the first release where the public API is written down and a change
to it cannot land unnoticed. It is not `1.0.0`, and that is deliberate.
`1.0.0` is a promise that the API is settled and the library has been looked at
by someone other than its authors. The first half is now true and enforced. The
second is not — see [the road to 1.0](#the-road-to-10) — and the predecessor
reached "1.0.0" in three days.

---

## What "the public API" is

Exactly what is recorded in [`api/`](../api):

| Package | Entry points | Report |
| :--- | :--- | :--- |
| `@ninshorg/core` | `.` | [`api/core.api.md`](../api/core.api.md) |
| `@ninshorg/server` | `.`, `./fastify`, `./hono`, `./koa` | [`api/server.api.md`](../api/server.api.md) |
| `@ninshorg/webauthn` | `.`, `./testing` | [`api/webauthn.api.md`](../api/webauthn.api.md) |
| `@ninshorg/client` | `.` | [`api/client.api.md`](../api/client.api.md) |

Each report is the package's declaration files as a consumer's compiler reads
them — every export of every path in the package's `exports` map. The
`./testing` subpath is included: the virtual authenticator is fixture code, but
people's test suites import it, and breaking a test suite is still breaking.

**Also part of the contract, though not visible in a type:**

- Error **classes** and their `code` values. A consumer branches on these.
- Audit event `type` values, such as `refresh.reuse_detected`. A consumer alerts
  on these.
- The **security posture of a default**: fail-closed on a store outage, token
  lifetimes, the refresh grace window, the RSA key-size floor. Making any of
  these weaker is breaking even when no type changes, because code that relied
  on the default being safe is no longer safe.

**Not part of the contract:**

- Error `message` and `detail` wording, and audit event messages. Match on the
  class and the code, never on the text.
- Anything reachable only through a path outside `exports`. The `exports` map
  makes those unreachable to a well-behaved import anyway.
- **Stored record formats — for now.** Keys are versioned (`ninsho:v1:`), and
  a schema change is designed to bump that prefix, so records written under the
  old one become invisible — a forced re-login — rather than misread under the
  new one. What is not yet covered is the case in between: a record written by
  one release, read by the next, with the prefix still `v1`. Two versions share
  one Redis during every rolling deploy, so this matters, and nothing yet tests
  it; this document therefore does not promise it. Closing that is a 1.0 gate,
  below.

---

## What counts as a breaking change

| Change | Breaking? | Why |
| :--- | :---: | :--- |
| Remove or rename an export | **Yes** | Code importing it stops compiling |
| A parameter accepts a narrower type, or a new required option appears | **Yes** | Existing calls stop compiling |
| A return type gets wider | **Yes** | Exhaustive handling of the old type misses a case |
| A method is added to the `NinshoStore` interface | **Yes** | Every custom store stops implementing it |
| An error class or `code` changes | **Yes** | `catch` blocks stop matching |
| An audit event `type` is renamed | **Yes** | Alerts stop firing, silently |
| A default becomes less safe | **Yes** | See above |
| The Node.js floor rises | **Yes** | Installs on the old line stop working |
| The store namespace version changes (`ninsho:v1:` → `v2`) | **Yes** | Every existing session becomes invisible, so everyone is signed out on upgrade — safe by design, and an operator still needs to know it is coming |
| A new export, a new optional option, a new error class | No | Nothing existing changes |
| A new audit event `type` | No | Consumers should ignore types they do not recognise |
| Error or event message wording | No | Not contract, see above |

**Security fixes are the exception.** If existing behaviour is itself a
vulnerability, it changes in a patch release, and the CHANGELOG says plainly
that it did and why. A stability promise that protected a vulnerability would
be the wrong promise to keep.

---

## Versioning

- **Before `1.0.0`:** a minor release (`0.2` → `0.3`) may break; a patch
  release (`0.2.0` → `0.2.1`) may not. This is ordinary semver for `0.x`, and
  it is why dropping Node 20 shipped as `0.2.0` rather than `0.1.1`.
- **From `1.0.0`:** breaking changes only in a major release.
- **Deprecation** comes before removal. A deprecated export is marked
  `@deprecated` in its declaration — so it appears in the API report and in
  every editor — named in the CHANGELOG, and kept for at least one further
  minor release before `1.0`, or until the next major after it.

### The four packages release together

All four share one version and are published as a set. `server` and `webauthn`
pin `core` exactly rather than by range, because two copies of `core` in one
install would each define their own `NinshoError`, and an error thrown by one
would fail `instanceof` against the other — a `catch` that looks correct and
never matches.

---

## Supported runtimes and dependencies

| | Tested in CI | Status upstream |
| :--- | :---: | :--- |
| Node.js 22 | ✓ | LTS, supported until April 2027 |
| Node.js 24 | ✓ | LTS, supported until April 2028 |
| Node.js 26 | ✓ | Current; becomes LTS in October 2026 |
| Node.js 20 | — | **Not supported.** End-of-life since 2026-04-30; dropped in `0.2.0` |
| Redis | 7 | Via `ioredis` `^6.0.0`, the one runtime dependency in the whole set |

**Policy:** every Node.js line that upstream still patches, and nothing older.
When a line reaches end-of-life, the floor rises in the next minor release
(before `1.0`) or major release (after), announced in the CHANGELOG. The
`@types/node` major moves in the same change and never on its own — types for
a newer Node than the floor let the compiler approve an API that crashes on the
floor, so Dependabot is told to leave its majors alone.

**Framework adapters** are tested against the real frameworks, over real HTTP,
at the versions the lockfile pins: Express 5, Fastify 5, Hono 4 on
`@hono/node-server`, Koa 3. None of them is a dependency of any published
package.

---

## How each promise is enforced

| Promise | Enforced by |
| :--- | :--- |
| A change to the public API is visible in review | `api/*.api.md`, and the CI step *Public API matches the recorded report* (`npm run api:check`), which fails when the built declarations no longer match the record |
| Every supported Node line is tested | The CI matrix: `['22', '24', '26']` |
| No supported line is one upstream has stopped patching | This document, the matrix above, and `engines.node` agreeing across the workspace — checked by `npm run release:check` |
| The four packages release in lockstep | `npm run release:check` › *Packages share one version* and *Internal dependencies pin the release version* |
| A published tarball holds its build and nothing else | `npm run release:check` › *tarball contents*; CI › *Assert every declared package file exists* |
| The packed tarballs work for a real consumer, ESM and CJS | CI › *Assert the packed tarballs work for a real consumer* |
| A version is never republished | `npm run release:check` › *is unpublished*, which asks the registry |

### Releasing

Publishing is manual on purpose — nothing in this repository can push to npm.
`npm run release:check` runs every check above, and if they pass, prints the
commands to run, in dependency order. It never runs them.

```bash
npm ci && npm run build
npm run release:check
```

---

## The road to 1.0

| Gate | Status |
| :--- | :--- |
| The public API is recorded, and a change to it cannot land unnoticed | ✅ **Done** in `0.2.0` |
| Every supported runtime is one upstream still patches | ✅ **Done** in `0.2.0` — Node 20 dropped |
| The release procedure is encoded, not remembered | ✅ **Done** in `0.2.0` — `release:check` |
| **A private vulnerability-reporting channel, tested end to end** | ⬜ **Open.** GitHub private vulnerability reporting is currently **disabled** on the repository, and `SECURITY.md` still carries the placeholder that says so. It needs enabling, then a test report filed and received, before `SECURITY.md` may point at it — a policy naming a channel that does not work is how the predecessor failed. |
| `.well-known/security.txt` per RFC 9116 | ⬜ **Open.** Follows the channel above; a `security.txt` pointing nowhere is worse than none. |
| **Rolling upgrades do not sign anyone out** | ⬜ **Open.** Keys carry a namespace version (`ninsho:v1:`) so an incompatible schema is made invisible rather than misread — but nothing tests that a session written by release *N* still verifies under *N + 1* while that version is unchanged. Until something does, record formats are excluded from the promise above. |
| **An external security review** | ⬜ **Open.** [`CRYPTOGRAPHIC-AUDIT.md`](./CRYPTOGRAPHIC-AUDIT.md) is a project contributor's review of the PASETO implementation — thorough and useful, and not independent. `1.0.0` needs a reviewer from outside the project, across the whole surface. |
| One minor cycle with no breaking change to the API report | ⬜ **Open.** The clock starts at `0.2.0`. |
| `main` accepts only changes that passed CI | ⬜ **Open.** Branch protection is not enabled. |

Two of the open gates are code — store-format versioning and the soak. The
rest are decisions and settings that belong to a maintainer, and none of them
can be completed by merging a pull request. That is also why this table exists:
so that "is it ready for 1.0?" has an answer someone can check.
