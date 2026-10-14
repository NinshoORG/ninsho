# Browser regression matrix

Both browser regressions run unchanged scenarios on Chromium, Firefox and WebKit
through `manualtest/browser-harness.mjs`. Select an engine with `BROWSER`; omission
defaults to Chromium. Unknown engines fail instead of silently falling back.
The dedicated `browsers` CI job in `.github/workflows/ci.yml` has three independent
Ubuntu 24.04 matrix entries, each building packages and running both scripts.
Failure of one scenario does not skip the other after a successful build.

## Scope

| Script | Assertions |
|---|---|
| `manualtest/browser-key-store.mjs` | Two independent pages gate their initial IndexedDB loads before concurrent key generation; both receive the same key; reload preserves its thumbprint and non-extractable private key |
| `manualtest/browser-session-sync.mjs` | Shared IndexedDB key; peer logout invalidates state; a gated refresh cannot restore it; a gated sign-in cannot override a peer identity change; persisted shared key survives logout |

The test pages use a fresh isolated browser context and a loopback server serving
the built client. They use native IndexedDB, WebCrypto and BroadcastChannel.
Deferred operations and observed events control ordering; there are no sleeps
that advance the scenario. The 90-second scenario deadline only fails a stuck
test. `finally` closes the context, browser and HTTP server, including when
launch, assertions or a deadline fail. Closing the context also destroys page
channels and pending page evaluations.

Session network responses are controlled `fetch` stubs. These scripts do **not**
establish real HTTP refresh-cookie ordering, server-side revocation, suspended
or background-tab behavior, production endpoint integration, or physical-device
interoperability. Playwright WebKit is an automation build, not a test of shipped
Safari/iOS. Browser versions and operating systems matter; CI configuration is
not evidence that an unexecuted GitHub run passed.

## Reproducible setup

Playwright **1.64.1** is pinned in CI and checked by the harness. Its package
selects exact browser revisions. Following the existing optional-tooling
convention, it is installed outside the workspace: no published package runtime
dependency, root manifest or repository lockfile change is needed. A different
installed Playwright version fails with an explicit error. Keep the harness,
CI and setup commands in sync when intentionally upgrading.

Linux (the same installation approach as CI):

```bash
set -e
npm ci
npm run build
npm install --prefix /tmp/ninsho-browser-tools --no-package-lock --no-audit --no-fund playwright@1.64.1
node /tmp/ninsho-browser-tools/node_modules/playwright/cli.js install --with-deps chromium firefox webkit
export NODE_PATH=/tmp/ninsho-browser-tools/node_modules
for browser in chromium firefox webkit; do
  BROWSER="$browser" node manualtest/browser-key-store.mjs
  BROWSER="$browser" node manualtest/browser-session-sync.mjs
done
```

PowerShell (from an existing installed checkout; use `npm ci` on a clean one):

```powershell
npm run build
npm install --prefix "$env:TEMP\ninsho-sync-browser-tools" --no-package-lock --no-audit --no-fund playwright@1.64.1
node "$env:TEMP\ninsho-sync-browser-tools\node_modules\playwright\cli.js" install chromium firefox webkit
$env:NODE_PATH = "$env:TEMP\ninsho-sync-browser-tools\node_modules"
Remove-Item Env:CHROMIUM_PATH -ErrorAction SilentlyContinue
foreach ($browser in @('chromium', 'firefox', 'webkit')) {
  $env:BROWSER = $browser
  node manualtest/browser-key-store.mjs
  if ($LASTEXITCODE -ne 0) { throw "$browser key-store regression failed" }
  node manualtest/browser-session-sync.mjs
  if ($LASTEXITCODE -ne 0) { throw "$browser session-sync regression failed" }
}
```

`CHROMIUM_PATH` remains supported for an existing Chromium executable. It only
applies when the selected engine is Chromium; Firefox/WebKit use Playwright's
binaries. Such an override is a separate compatibility run, not evidence for
the pinned Chromium revision. `NODE_PATH` is resolved consistently by both
scripts via the shared harness's `createRequire`.

## Verification record

The starting branch is
`codex/cross-tab-session-sync`, HEAD `d5be473`, with the preceding feature changes
still uncommitted. This follow-up changes only browser testing, CI and related
documentation; the production client implementation is unchanged.

Fresh local Windows results with Node **22.13.1** and Playwright **1.64.1**:

| Engine | Version reported by browser | Key-store scenario | Session-sync scenario |
|---|---|---|---|
| Chromium | 156.0.8078.4 | PASS | PASS |
| Firefox | 157.0 | PASS | PASS |
| WebKit | 27.2 | PASS | PASS |

All six scenario processes exited 0. No unsupported engine, failed assertion or
skipped scenario occurred. These are local Windows measurements. The new Linux
GitHub Actions matrix has **not** been executed or claimed green; no push was made.

The existing external Playwright 1.64.1 install was reused. Exact browser install:

```powershell
node "$env:TEMP\ninsho-sync-browser-tools\node_modules\playwright\cli.js" install chromium firefox webkit
```

With `NODE_PATH` set as above and `CHROMIUM_PATH` removed, each of these commands
ran with `BROWSER` set to `chromium`, then `firefox`, then `webkit`:

```powershell
node manualtest/browser-key-store.mjs
node manualtest/browser-session-sync.mjs
```

Fresh `npm run build` and `npm run typecheck` passed. Syntax checks passed:

```powershell
node --check manualtest/browser-harness.mjs
node --check manualtest/browser-key-store.mjs
node --check manualtest/browser-session-sync.mjs
```

An injected scenario failure also passed cleanup checks on Chromium: the page
was closed, browser disconnected, and loopback server refused a new connection.
This checks assertion-failure teardown; launch-error and deadline teardown were
reviewed but not separately fault-injected. Reproduce with `NODE_PATH` as above:

```powershell
$env:BROWSER = 'chromium'
@'
import assert from 'node:assert/strict';
import { runBrowserRegression } from './manualtest/browser-harness.mjs';
let page, browser, base;
await assert.rejects(runBrowserRegression(async fixture => {
  page = fixture.pages[0];
  browser = page.context().browser();
  base = fixture.base;
  throw new Error('injected scenario failure');
}), /injected scenario failure/);
assert.equal(page.isClosed(), true);
assert.equal(browser.isConnected(), false);
await assert.rejects(fetch(base, { signal: AbortSignal.timeout(3000) }), error => error.cause?.code === 'ECONNREFUSED');
console.log('PASS injected failure cleanup: page closed, browser disconnected, server refused connection');
'@ | node --input-type=module
```

Repository-wide validation exited 0 with dedicated Redis **7.4.8**:
**2,142 workspace tests in 53 files plus one HTTP viva-demo test**, all passing
with zero skips (client 117, core 97, server 1,109, webauthn 623, Express 101,
playground 95). Commands executed:

```powershell
npm run build
npm run typecheck
docker run -d --rm -p 127.0.0.1:6389:6379 --name ninsho-browser-test-redis redis:7-alpine
$env:REDIS_URL = 'redis://127.0.0.1:6389'
npm run test
docker exec ninsho-browser-test-redis redis-server --version
docker stop ninsho-browser-test-redis
git diff --check
git diff --exit-code -- package.json package-lock.json packages/client/package.json
```

Full test output was redirected to `$env:TEMP\ninsho-browser-full-tests.log`
with the test process exit code preserved. The temporary Redis container was
removed after validation. Diff checks passed; manifests and lockfile have no
changes. The pre-existing `Ninsho_Complete_Fixes.patch` SHA-256 remained
`160A4DA0C64E50A8A21B7320EF0CC696296D4EC42D4C0ABC4BCE20492D0FDDA2`.

Reviewed follow-up files: the CI workflow, shared harness, both browser scripts,
this verification guide, `docs/cross-tab-session-sync.md`,
`docs/review-remediation.md`, and `REMAINING-ISSUES.md`. Existing feature changes
remain uncommitted on the same branch. No push, merge or package publication
was performed. No new Node-version matrix or physical-device coverage is claimed.
