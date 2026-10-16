# Cross-tab session synchronization

Implemented against `d5be473` on `codex/cross-tab-session-sync`. This is opt-in
client invalidation, not a change to server token formats or revocation policy.
See the [client configuration and complete limits](../packages/client/README.md#cross-tab-session-synchronization-opt-in).

## Design and evidence

The existing client uses per-instance generation checks to ignore stale
responses. Incoming lifecycle notices advance that same generation, clear the
in-memory token and block cookie recovery until explicit identity establishment.
There is no broadcast refresh, lock, polling, retry loop or credential transfer.
`dispose()` closes the channel and permanently invalidates the instance.

Because tokens may be opaque, the client cannot identify a principal change.
Every successful token-bearing `signIn` and changed `setAccessToken` value is
therefore an explicit identity replacement. Routine `refresh` is not. Peers
are invalidated, not signed in to the sender's identity. HTTP-OK logout is the
existing endpoint's success contract; no message authenticates that claim.

Opting in retains shared persisted keys on logout. Clearing a shared database
from one tab cannot be made safe against all other writers with the existing
key-store interface. Retention is the scoped alternative; applications must
coordinate deliberate key destruction after server-side revocation. The default
mode still deletes keys as before. Do not mix modes on the same database.

`packages/client/src/session-sync.test.ts` uses explicitly drained fake channel
delivery and deferred network/body responses, without sleeps. It covers:

| Property | Test evidence (title excerpt) |
|---|---|
| Confirmed logout / context isolation | invalidates a peer only after confirmed logout |
| Failures are not logout | does not advertise failed logout; network failure |
| Credential-free, validated payload | sends only versioned lifecycle metadata; ignores malformed |
| Duplicate suppression | duplicate logout erase an explicitly established newer identity |
| Stale refresh / body / request | old refresh after peer logout; old response body; old request returns 401 |
| Stale sign-in / identity replacement | delayed sign-in overwrite a newer peer identity; older local sign-in |
| Superseded logout | old logout over a newly observed peer identity |
| Shared-key retention | retains the shared key when either tab signs out |
| Rotation concurrency | preserves single-flight per tab and the real server rotation grace across tabs |
| Fallback / cleanup | without BroadcastChannel; deny channel construction; disposal |

The rotation test runs the real server facade and MemoryStore with one bound
refresh token and a shared DPoP key, producing two server refresh attempts for
four simultaneous client calls. It does not emulate HTTP cookie delivery.
The first correctly configured pre-implementation run had **9 failures and
9 passes**; the initially added rotation test used the wrong facade method name
and was corrected before that run. No existing test was weakened.

## Browser regressions

The repository already uses optional Playwright in `browser-key-store.mjs`.
The `manualtest/browser-session-sync.mjs` uses two real browser pages,
native BroadcastChannel and IndexedDB, with controlled fetch responses. It
checks peer logout, stale refresh/sign-in rejection and shared-key retention.
It does **not** test real HTTP cookies, a production logout endpoint, suspended
tabs or physical devices. Chromium, Firefox and WebKit now share the same
scenario through a dedicated CI matrix; see the
[current setup and measured results](browser-regressions.md).

With the pinned Playwright tooling installed as documented above:

```powershell
npm run build
$env:CHROMIUM_PATH = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
node manualtest/browser-session-sync.mjs
```

Alternatively install the optional tooling outside the repository and set
`NODE_PATH` to that directory's `node_modules`; the script uses Node's standard
`createRequire` resolution. See the existing browser-test setup in
[review remediation](review-remediation.md). Use an ephemeral browser context,
not a personal authenticated profile.

## Validation results

Environment: Windows, Node **22.13.1**, npm **11.0.0**, dedicated Redis
**7.4.8**, Chromium **155.0.8059.41**. The initial sandboxed branch creation
and build were blocked by filesystem/process permissions; both succeeded when
rerun with approved execution permissions. One intermediate client typecheck
reported an unused test variable; it was corrected and typecheck rerun.

Executed commands:

```powershell
git switch -c codex/cross-tab-session-sync
npm run build
npm run test --workspace @ninshorg/client -- src/session-sync.test.ts
npm run test --workspace @ninshorg/client
npm run typecheck --workspace @ninshorg/client

# Final full build and checks:
npm run build
npm run typecheck
docker run -d --rm -p 127.0.0.1:6389:6379 --name ninsho-sync-test-redis redis:7-alpine
docker exec ninsho-sync-test-redis redis-cli ping
$env:REDIS_URL = 'redis://127.0.0.1:6389'
npm run test

# Optional tooling was installed outside the repository:
npm install --prefix "$env:TEMP\ninsho-sync-browser-tools" --no-package-lock --no-audit --no-fund playwright
$env:NODE_PATH = "$env:TEMP\ninsho-sync-browser-tools\node_modules"
$env:CHROMIUM_PATH = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
node manualtest/browser-session-sync.mjs

git diff --check
git diff --exit-code -- package.json package-lock.json packages/client/package.json packages/client/src/index.ts
```

The full test command's stdout/stderr was captured in
`$env:TEMP\ninsho-sync-full-tests.log`; its exit code was preserved. Docker
Desktop had to be started first because its engine was stopped. The test
container is dedicated to this run; no existing Redis data was used.

- Build: passed, including declarations. Client ESM output was 22.47 KB in
  tsup's report (uncompressed; not a performance benchmark).
- Repository typecheck: passed, including manualtest and benchmarks.
- Targeted new regressions: **26 passed**. Full client coverage: **117 passed**.
- Native Chromium two-tab check: passed, with the scope described above.
- Manifest/lockfile/export-list comparison: no changes. Diff whitespace check: passed.

Full `npm run test` exited **0**: **2,142 workspace tests in 53 files**, plus
**1 Node HTTP viva-demo test**, all passing with **zero skips**. Breakdown:
client 117, core 97, server 1,109, webauthn 623, Express example 101, playground
95. This includes the real-Redis contracts and revocation regressions. The
temporary container was stopped afterward with
`docker stop ninsho-sync-test-redis` (its `--rm` flag removes it).

For the original feature validation recorded here, no fresh Node 20/24 matrix,
Firefox/WebKit run, GitHub CI run, npm audit,
published-tarball check or benchmark was performed for this change.

## Files changed

| File | Purpose |
|---|---|
| `packages/client/src/client.ts` | Opt-in configuration, identity invalidation, guarded notifications, terminal disposal and shared-key retention |
| `packages/client/src/session-sync.ts` | Native channel transport, validated versioned messages, bounded duplicate cache and close |
| `packages/client/src/session-sync.test.ts` | Deterministic lifecycle/race cases and real-server rotation-grace integration |
| `packages/client/src/storage.ts` | Clarify the existing `clear()` contract for opt-in shared-key retention |
| `manualtest/browser-session-sync.mjs` | Optional two-tab native Chromium/IndexedDB check |
| `packages/client/README.md` | API, lifecycle semantics, examples, evidence and limitations |
| `README.md` | Feature pointer and measured client bundle size |
| `docs/review-remediation.md` | Replace the now-outdated absence-of-synchronization statement |
| `REMAINING-ISSUES.md` | Update browser coverage and retain outstanding interoperability work |
| `docs/cross-tab-session-sync.md` | Design, evidence, exact validation commands and limits |

The server remains authoritative. Passing tests are scoped evidence, not an
independent security audit or proof of all browser/network interleavings.

**Viva recommendation:** retain as an opt-in feature and rehearse the exact
application integration. Keep the explicit reauthentication/shared-key policy
visible. Defer claims of durable synchronization, arbitrary multi-tab cookie
ordering or production certification; those are not established by this work.
