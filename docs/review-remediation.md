# October 2026 review remediation

This change addresses the five findings reproduced against `c7e6539`. It is
not an independent security audit or a claim that no vulnerabilities remain.

## Changes and evidence

| Finding | Change | Regression |
|---|---|---|
| Initial issuance survives completed revocation | Check the session marker after issuance, revoke the late credential, clean the family, and refuse creation | `review-regressions.test.ts`: device logout and logout-all, opaque/PASETO, MemoryStore/RedisStore |
| Wrong-key replay destroys a bound family | Validate tombstone key binding before grace/reuse handling | `review-regressions.test.ts`: missing/wrong key preserves the family; correct-key reuse revokes it |
| Late responses restore a signed-out identity | Identity generations guard refresh/sign-in completions; logout waits for pending key writes; new sign-in waits for local cleanup | `lifecycle.test.ts` |
| Transient refresh errors appear as logout | Preserve client state on non-authentication errors and preserve the example cookie unless refresh is definitively invalid/reused | `lifecycle.test.ts`; `api.test.ts` › refresh outage recovery |
| Independent clients generate different persisted keys | Atomic get-or-create in built-in stores; IndexedDB chooses the winner in one readwrite transaction | `storage.test.ts`; `lifecycle.test.ts`; `manualtest/browser-key-store.mjs` |

The new server regressions were observed failing for both engines before the
fix. Seven of eight initial client regressions failed before the fix (the late
401-after-logout case already passed). The cookie-outage test also failed
before its fix. Tests use controlled scheduling, not timing luck.

## Local verification

- Full suites on Node 20, 22, and 24.19.0 with Redis 7.4.11: **2,116 passing tests, no skips**, 52 files per run.
- Build and TypeScript checks passed. Production dependency audit of the four
  library workspaces reported zero vulnerabilities. Check the associated CI run
  for verification in GitHub’s environment.
- Chromium 153: two independent pages sharing IndexedDB both observed an empty
  store, initialized concurrently, received the same key, and retained that
  non-extractable key after reload.
- `fake-indexeddb` is a root development-only dependency used for repeatable CI
  tests including transaction abort. It does not ship in the client bundle.

Run from a clean checkout:

```bash
npm ci
npm run build
npm run typecheck
REDIS_URL=redis://127.0.0.1:6379 npm run test
```

Browser regressions now share a Chromium/Firefox/WebKit harness and a dedicated
CI matrix. See [browser regression setup and measured results](browser-regressions.md)
for pinned Playwright tooling, exact commands, scenarios and known gaps.
`CHROMIUM_PATH` still supports an existing Chromium executable; the default
matrix uses Playwright's pinned binaries in fresh browser contexts.

## Boundaries that remain deliberate

- Logout-all revokes a snapshot of indexed sessions. New sessions added after
  that snapshot are not automatically revoked. The regression ensures a
  session already in the snapshot cannot issue usable credentials afterward.
  Applications must coordinate credential changes and fresh login issuance if
  they need an account-wide cutoff.
- Same-instance logout ignores stale client responses. Cross-tab invalidation is
  now available through opt-in `sessionSync: { context }`; refresh tokens and
  credentials are never broadcast. See [cross-tab synchronization](cross-tab-session-sync.md)
  for regression evidence and delivery limitations. Server revocation is authoritative.
- Custom persistent key stores should implement atomic `getOrCreate` across
  connections. The legacy fallback synchronizes only a shared object in one
  JavaScript realm. Give unrelated auth contexts different IndexedDB names.
- A 429/5xx response is not proof that a refresh token is dead. Retrying after
  partial rotation can still fail, so callers must use bounded backoff and
  handle eventual reauthentication. No unbounded automatic retry was added.
- DPoP prevents token-only reuse; hostile same-context code can still sign.
  In-memory access tokens are not an XSS boundary.
- PASETO revocation depends on retained store state. A reachable but wiped
  denylist differs from an unreachable store. See SECURITY.md.
- Private vulnerability reporting must be enabled by a repository administrator.
  A policy document alone cannot establish that setting. This change does not
  claim to enable it or to publish a new npm release.

Use the exact commit's CI results for test counts and supported-Node status.
