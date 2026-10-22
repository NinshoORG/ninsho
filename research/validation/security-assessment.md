# Ninsho — final security assessment

**Nature of this document.** This is a *model-assisted code review* carried out
by an AI coding assistant (Claude, Anthropic) in the repository owner's
workspace, together with the project's own test suites and purpose-written
probes. It is **not** an independent third-party audit, a penetration test, or a
certification, and it must not be cited as one. Coverage was selective, not
exhaustive (see §7).

| | |
|---|---|
| Date | 21 October 2026 |
| Reviewed commit | `6f8202659d8d05330bc220dbd7b6d72e76a09b41` (`main`, "feat(demo): add SecureShop viva showcase application"), version 0.1.1 |
| Working branch | `assessment/final-security-benchmark` (local only — nothing pushed, merged or published) |
| Pre-existing local state | Untracked `academic/` (blackbook DOCX/PDF, verification notes) — preserved, untouched. `Ninsho_Complete_Fixes.patch` — tracked, untouched |
| Reviewer | Claude (model-assisted), at the request of the repository owner |

---

## 1. Environment and baseline checks (before any change)

| Item | Value |
|---|---|
| OS | Windows 10 Home 10.0.19045 (x64) |
| CPU / RAM | Intel Core i5-4300U (2 cores / 4 threads), 16 GB |
| Node / npm | v22.13.1 / 11.0.0 |
| Docker | Docker Desktop 4.38.0, engine 27.5.1 (WSL2 backend) |
| Redis (dedicated) | `redis:7-alpine` → Redis **7.4.11**, container `ninsho-redis-assess`, `localhost:6379`, started with `--save "" --appendonly no` |
| Browsers | Playwright 1.64.1 (CI-pinned), Chromium 156.0.8078.4, Firefox 157.0, WebKit 27.2 |

All logs are in [`logs/`](./logs/).

| # | Command | Result | Log |
|---|---|---|---|
| B1 | `npm run build` | **Passed** (exit 0) | `logs/build.log` |
| B2 | `npm run typecheck` | **Passed** (exit 0; includes `manualtest/` and `benchmarks/` tsconfigs) | `logs/typecheck.log` |
| B3 | `REDIS_URL=redis://localhost:6379 npm run test` | **Passed** (exit 0): 2,150 tests, 0 failed, 0 skipped — see breakdown below | `logs/test-redis.log` |
| B4 | `npx vitest run src/__tests__/redis-persistence.test.ts --reporter=verbose` (server, with Docker) | **Passed**: 7/7 Docker-managed persistence scenarios executed (none skipped) | `logs/redis-persistence-verbose.log` |
| B5 | `node manualtest/browser-key-store.mjs` and `browser-session-sync.mjs`, `BROWSER=chromium|firefox|webkit` | **Passed**: 6/6 | `logs/browser.log` |
| B6 | `demo/viva-showcase`: `npx vitest run` | **Passed**: 3/3 | `logs/secureshop-test.log` |
| B7 | `npm audit --omit=dev` (whole workspace, production deps) | **1 critical advisory** — `proxy-addr` ≤ 2.0.7 via `express@5.2.1`, reached only through `examples/express-api` (finding F-06) | `logs/audit-prod.log` |
| B8 | `npm audit --audit-level=moderate --omit=dev --workspace @ninshorg/{core,server,client,webauthn}` (CI's consumer audit) | **Passed**: 0 vulnerabilities in each published package | `logs/audit-consumer.log` |

B3 breakdown (with real Redis): client 117, core 97, server 1,116, webauthn 623,
example express-api 101, playground 95 (Vitest, 2,149 total) + 1 `node:test`
(`manualtest/three-demos.test.mjs`) = **2,150**. This count belongs to this
commit and this configuration only; earlier documents quote 2,116 and 2,142 for
other working-tree states.

**One environment incident, recorded for honesty.** The first B3 run failed 3
tests in `store-invariants.test.ts › fail-closed when Redis is unreachable`.
Cause: the assessor had started Redis on port 6390, which that suite hard-codes
as its *dead* address (`DEAD_URL = 'redis://127.0.0.1:6390'`). With Redis moved
to 6379 the suite passed. Not a Ninsho defect (FP-02), but worth a comment in
the test: a reviewer choosing a non-default port can make it fail.

---

## 2. Scope and method

Read in full: `session/manager.ts`, `engine/opaque.ts`, `engine/paseto.ts`,
`store/redis.ts`, `http/middleware.ts`, `http/dpop-middleware.ts`,
`dpop/proof.ts`, `dpop/jwk.ts`, `dpop/replay.ts`, `ratelimit/limiter.ts`,
`ratelimit/client-ip.ts`, `ratelimit/middleware.ts`, `tokens/one-time.ts`,
`ninsho.ts`, `paseto/v4.ts` (sign/verify/PAE), `client/client.ts`,
`client/session-sync.ts`, `webauthn/ceremony.ts`, and the chain-walk in
`webauthn/attestation.ts`. Read in part: `config.ts` (bounds and defaults),
`koa.ts`, `store/memory.ts`, `keys/keyring.ts`, `webauthn/authdata.ts`, CI
workflow, `SECURITY.md`, `REMAINING-ISSUES.md`, `AGENTS.md`,
`academic/VERIFICATION_NOTES.md`.

Method: for each path, look for state that is only reached through a happy path,
then exercise it directly. Every confirmed finding below has a probe in
[`probes/`](./probes/) that reproduces it against the **built package**
(`packages/*/dist`), and where relevant against real Redis.

---

## 3. Confirmed defects

### F-01 — PASETO: a revoked session's access token can keep verifying (non-default configuration) — **FIXED**

| | |
|---|---|
| Severity | **High impact, low likelihood.** Defeats the "use of a revoked token" guarantee, but only with `clockToleranceSeconds > 60`, which is non-default (default 5) yet accepted by `resolveConfig` without warning |
| Affected | `packages/server/src/engine/paseto.ts` › `PasetoEngine.issue()` (session index TTL) interacting with `verify()` and `revokeSession()` |
| Preconditions | `strategy: 'paseto'`; `clockToleranceSeconds = T > 60` (config permits up to `accessTokenTtl`); a session with no token issued in the last `accessTokenTtl + 60` s (an idle session) |
| Mechanism | `verify()` accepts a token until `exp + T`. `issue()` indexed the token id under its session with TTL `accessTokenTtl + 60`. Between `exp + 60` and `exp + T` the index has expired, so `revokeSession()` — and therefore logout, `revokeAllForUser()`, and reuse-detection revocation — finds no token id and writes no denylist entry |
| Impact | The token of a revoked session is accepted for up to `T − 60` seconds. With `accessTokenTtl: 900, clockToleranceSeconds: 900` that is 14 minutes after a logout or theft response |
| Evidence | `probes/p4-paseto-index-vs-tolerance.mjs`, real Redis 7.4.11, public `Ninsho` facade, `accessTokenTtl = clockToleranceSeconds = 70`. **Before fix** (`logs/probe-p4.log`): control session revoked fresh → `TokenRevokedError`; idle session revoked at t = 134 s → **`ACCEPTED`**. **After fix** (`logs/probe-p4-after-fix.log`): same probe → `TokenRevokedError` |
| Related existing tests | `paseto-engine.test.ts` › *keeps denylist entries active throughout the clock tolerance window* (F4). F4 fixed the denylist TTL for the same tolerance window but not the session index — this is its sibling |
| Opaque strategy | Not affected: the access record's own store TTL ends at `exp`, so tolerance cannot extend acceptance (see FP-05) |
| Fix | Index TTL is now `accessTokenTtl + clockToleranceSeconds + 60`, the same bound `revoke()` already uses. One expression changed, plus a comment naming the test |
| Regression | `paseto-engine.test.ts` › *still reaches a token through its session while clock tolerance keeps it acceptable* — **observed failing before the fix** ("promise resolved … instead of rejecting"), passing after |

### F-02 — `trustProxy: false` still honours `X-Forwarded-For` when the framework trusts proxies

| | |
|---|---|
| Severity | **Medium** |
| Affected | `packages/server/src/ratelimit/client-ip.ts` › `peerAddress()` / `clientIp()` |
| Preconditions | The application enables its framework's own proxy trust (e.g. Express `app.set('trust proxy', true)`) **and** configures Ninsho `rateLimit({ trustProxy: false })` (or `0`) |
| Mechanism | `trustProxy: false` is documented as "take the peer address only, ignoring forwarding headers". `peerAddress()` prefers `req.ip` over `req.socket.remoteAddress`. Under Express proxy trust, `req.ip` is already derived from `X-Forwarded-For` |
| Impact | Rotating `X-Forwarded-For` rotates the per-IP bucket, bypassing the per-IP limit. The per-account bucket is unaffected |
| Evidence | `probes/p2-ratelimit-address-keying.mjs` (b), real HTTP, Express 5.2.1, limit 3/min: Express trust OFF → `200,200,200,429,…`; Express trust ON → **`200` × 10** |
| Related tests | `ratelimit.test.ts` › *uses the peer address when proxies are not trusted* (asserts against a fake request; does not combine with framework proxy trust). `SECURITY.md` lists "Rate-limit bypass via X-Forwarded-For" as **Mitigated**, which holds only when the framework's proxy trust is off |
| Recommended fix | Under `false`/`0`, read `req.socket.remoteAddress` first and fall back to `req.ip` only when no socket is exposed; or document that `req.ip` is used and must not be proxy-derived. Add a test that combines both settings. **Not fixed here** (medium; changing address resolution affects every adapter and needs its own review) |

### F-03 — Logout racing a rotation leaves a tombstone; the stale tab then raises a false theft alarm

| | |
|---|---|
| Severity | **Low–Medium** (alarm integrity; no credential is issued) |
| Affected | `packages/server/src/session/manager.ts` › `#rotate()` (revoked-after-publish branch) and `#awaitTombstone()` / `#resolveNonLive()` |
| Preconditions | A revocation (`revoke`, `revokeAllForUser`) completes between `#rotate()`'s first revocation check and its tombstone write. Then the old refresh token is presented again (a stale tab) |
| Mechanism | `#revokeFamily` deletes tombstones so stale tabs of an ended session do not alarm (comment above `#revokeFamily`). Here the tombstone is written *after* that deletion; the re-check at the next step throws but does not remove the tombstone it just published. A later presentation finds the tombstone before the `rtx:` revoked marker is consulted and takes the reuse path |
| Impact | `refresh.reuse_detected` is emitted and `RefreshReuseError` is thrown for a session the user deliberately ended. Applications that act on this event (notify user, force password reset) act on a false positive |
| Evidence | `probes/p3-tombstone-after-logout.mjs` — reproduced on all four of MemoryStore/Redis × opaque/PASETO: rotation → `RefreshInvalidError`, tombstone left = `true`, stale tab → **`RefreshReuseError`**, reuse alarms = **1** (expected: `RefreshInvalidError`, 0 alarms) |
| Related tests | `concurrency.test.ts` asserts no spurious `refresh.reuse_detected` under mixed load, but does not pause rotation at the tombstone write |
| Recommended fix | In `#rotate()`'s revoked-after-publish branch also delete `KEYS.refreshConsumed(oldHash)`; and/or in `#resolveNonLive()` check `KEYS.sessionRevoked(consumed.sessionId)` before revoking and alarming, answering `RefreshInvalidError` instead. Regression: pause at the `rtc:` write as the probe does. **Not fixed here** |

### F-04 — One DPoP key has several RFC 7638 thumbprints

| | |
|---|---|
| Severity | **Low** |
| Affected | `packages/server/src/dpop/jwk.ts` › `parseJwk()` / `jwkThumbprint()` |
| Mechanism | `x`/`y` are checked only against the base64url character set and decoded leniently. A 32-byte coordinate is 43 characters (258 bits), so the last character carries 2 ignored bits. Each spelling imports the same key but hashes to a different thumbprint (up to 4 for Ed25519, 16 for P-256). `proof.ts` already rejects non-canonical encodings for the signature segment for exactly this reason; the key members were missed |
| Impact | No binding bypass: a token is bound to one `jkt` and other spellings are refused. But a `jkt` is not a unique key identifier, so applications that use it as a device identifier or per-key quota can be evaded by the key holder, and the replay guard's `(jkt, jti)` namespace admits the same `jti` once per spelling (the holder can mint fresh `jti`s anyway) |
| Evidence | `probes/p1-jwk-thumbprint-malleability.mjs`: 4/4 spellings of one P-256 `x` accepted by `verifyDpopProof`, **4 distinct `jkt`** values |
| Recommended fix | Apply the existing `decodeCanonical` rule to `x`/`y` in `parseJwk` (re-encode and compare). **Not fixed here** |

### F-05 — CI's "persistence suite actually ran" guard cannot detect a skip

| | |
|---|---|
| Severity | **Low** (evidence integrity, not runtime security) |
| Affected | `.github/workflows/ci.yml` › *Assert the Redis contract suite actually ran*; `redis-persistence.test.ts` lines 294–296 and 716–717 |
| Mechanism | The guard greps for `Redis persistence and recovery`. When Docker is unavailable the file registers a placeholder `describe` with **the same name** and an `it.skip`, so the grep matches either way |
| Impact | A CI run in which the Docker-managed persistence tests were skipped would still pass this step. (Locally, B4 shows the suite did run.) Previously noted in `academic/VERIFICATION_NOTES.md` §3.6; confirmed here from the source |
| Recommended fix | Grep for a test title only the real suite emits (e.g. *preserves active opaque sessions and their revocation state*), or assert a non-zero passed count for that file from a JSON reporter |

### F-06 — Example application inherits a critical `proxy-addr` advisory

| | |
|---|---|
| Severity | **Informational** for the published packages; **Low** for anyone copying the example |
| Affected | `examples/express-api` → `express@5.2.1` → `proxy-addr@2.0.7` (GHSA-jqcg-44mw-7w3h, IPv4-mapped IPv6 trust-subnet spoofing) |
| Evidence | B7 vs B8: workspace production audit reports 1 critical; each published package audits clean |
| Reachability | The advisory concerns Express's own subnet-based proxy trust. The example does not call `app.set('trust proxy', …)` (no `app.set(` in `examples/express-api/src`) and uses Ninsho's `clientIp` with an explicit `trustProxy`. Not reachable as shipped |
| Recommended fix | Update Express (or override `proxy-addr`) in the example when a fixed version is available; the CI step already reports this audit as informational |

### F-08 — Docker persistence tests can fail on container-name reuse (test harness)

| | |
|---|---|
| Severity | **Low** (test reliability) |
| Affected | `packages/server/src/__tests__/redis-persistence.test.ts` › `restartRedis()` → `startRedis()` |
| Evidence | Post-fix run A6 (§6): two scenarios failed in `docker run` with a name conflict; immediate rerun A7 passed. Observed once in three executions of the suite |
| Recommended fix | Generate a fresh container name on restart, or poll `docker ps -a` until the old container is gone before starting |

### F-07 — Client refuses same-origin paths containing `//`

| | |
|---|---|
| Severity | **Low** (functional; fails safe) |
| Affected | `packages/client/src/client.ts` › `#resolve()` — `/^[a-zA-Z][a-zA-Z0-9+.-]*:|\/\//` matches `//` anywhere |
| Evidence | `probes/p5-client-path-resolution.mjs`: `/files/a` → sent; **`/files//a` → refused** ("invalid request URL"); cross-origin forms correctly refused |
| Recommended fix | Anchor the second branch (`^\/\/`) |

---

## 4. Potential concerns (not demonstrated as defects)

| ID | Concern | Why it is not a confirmed defect | Suggested action |
|---|---|---|---|
| C-01 | Per-IP buckets key each full IPv6 address; one host with a /64 gets a fresh allowance per address (`probes/p2…` (a): 3 addresses in one /64 → 3 buckets) | Design choice; the per-account bucket — the documented defence against distributed stuffing — is unaffected | Offer optional /64 (or configurable prefix) aggregation; document |
| C-02 | Attestation chain walk (`chainReachesAnchor`) checks issuer, signature, validity and `ca` for intermediates, but not `pathLenConstraint` or `keyUsage: keyCertSign` | Exploitation requires a CA certificate mis-issued beneath a root the relying party chose to trust | Enforce both, or document reliance on the trust anchors' issuance discipline |
| C-03 | `defaultRequestUrl` trusts `Host` and `X-Forwarded-Proto` | Documented in code and on `setRequestUrlBuilder`; an attacker still needs the private key, so only the holder can relax their own `htu` binding | Recommend `setRequestUrlBuilder` in deployment docs |
| C-04 | Inside the 30 s grace window a thief holding a just-rotated, **unbound** refresh token can obtain a fresh access token without an alarm | Documented trade-off (`SECURITY.md` › *Reuse detection has a false-positive floor*; `refreshGraceSeconds`). DPoP binding closes it | None beyond existing docs |
| C-05 | A login whose credential check preceded `revokeAllForUser` can create a session that survives it | Already listed (`REMAINING-ISSUES.md` › Account lifecycle) and pinned by an existing test that preserves sessions created after the snapshot | Application-level coordination (e.g. a per-user credential epoch) |
| C-06 | No DPoP server-nonce support (RFC 9449 §8) | Optional in the RFC; confirmed absent (`grep -i nonce` in `src/dpop`, `src/http`: no matches) | State as a limitation (already in the blackbook notes) |
| C-07 | `rateLimit` per-account identifiers are truncated to 128 characters, so two identifiers sharing a 128-char prefix share a bucket | Only affects implausibly long identifiers; fails towards stricter limiting | Hash rather than truncate |

---

## 5. Investigated and found not to be defects (false positives)

| ID | Suspicion | Finding |
|---|---|---|
| FP-01 | WebAuthn header comment promises a backup-state invariant that `verifyFlags` does not check | Enforced in the parser: `authdata.ts:127` rejects BS set without BE |
| FP-02 | Fail-closed tests failed on first run | Environment: assessor's Redis on port 6390 collided with the suite's hard-coded dead address (§1) |
| FP-03 | Access token issued during a concurrent logout escapes revocation | Covered: revoked marker is written before enumeration and re-checked after issuance in `create`, `#rotate` and `#adoptReplacement`; regression `review-regressions.test.ts` › *refuses initial credentials issued after completed …* |
| FP-04 | PASETO denylist expires before a tolerated token | Already fixed (F4) and tested; F-01 is the separate index case |
| FP-05 | F-01 also affects the opaque strategy | No: the opaque access record is stored with TTL = `accessTokenTtl`, so it disappears at `exp` regardless of tolerance |
| FP-06 | The critical `proxy-addr` advisory reaches consumers | No: published packages audit clean (B8); see F-06 |
| FP-07 | Refresh binding checked after the destructive `take()` | No: binding is peeked before `take()` (manager.ts `refresh()`), and re-checked in `#rotate` and before the reuse response; regression *does not let a thief without the bound key revoke a rotated family* |
| FP-08 | DPoP proof parsed before signature | No: only the embedded `jwk` is read pre-signature; claims are read after `cryptoVerify`, and the signature segment is canonically decoded |

---

## 6. Changes made

Only F-01 met the bar of "confirmed, high-impact, safely reproducible". Its fix
is minimal:

| File | Change |
|---|---|
| `packages/server/src/engine/paseto.ts` | Session index TTL `accessTokenTtl + 60` → `accessTokenTtl + clockToleranceSeconds + 60`; comment explaining why and naming the test |
| `packages/server/src/__tests__/paseto-engine.test.ts` | New regression in `describe('revocation')` |

F-02 to F-07 are reported with recommended fixes and left unchanged, as scoped.

### Post-fix verification

| # | Command | Result | Log |
|---|---|---|---|
| A1 | `npx vitest run src/__tests__/paseto-engine.test.ts -t "clock tolerance keeps it acceptable"` (before fix) | **Failed as intended** — revoked session's token accepted | (console; quoted in F-01) |
| A2 | `npx vitest run src/__tests__/paseto-engine.test.ts` (after fix) | **Passed** 63/63 | — |
| A3 | `npm run build` | **Passed** | `logs/build-after-fix.log` |
| A4 | `REDIS_URL=… node research/validation/probes/p4-paseto-index-vs-tolerance.mjs` | **Not reproduced** after fix (`TokenRevokedError`) | `logs/probe-p4-after-fix.log` |
| A5 | `npm run typecheck` | **Passed** | `logs/typecheck-after-fix.log` |
| A6 | `REDIS_URL=redis://localhost:6379 npm run test` | **Failed (exit 1): 2 tests** in `redis-persistence.test.ts` (*PASETO: previously revoked tokens become usable again…*, *restoring an older RDB snapshot…*). Both failed in `docker run` with *"Conflict. The container name … is already in use"* — `restartRedis()` re-creates a `--rm` container under the same name before Docker has finished removing the stopped one. Test-harness timing, not the change under test. Because the server workspace failed, the root script's final `node --test` step did not run | `logs/test-redis-after-fix.log` |
| A7 | `cd packages/server && REDIS_URL=… npx vitest run` (immediate rerun) | **Passed** 1,117/1,117 (including all 7 persistence scenarios and the new regression) | `logs/test-server-after-fix-rerun.log` |
| A8 | `REDIS_URL=… node --test manualtest/three-demos.test.mjs` | **Passed** 1/1 (a first invocation without `REDIS_URL` skipped itself, as designed, and is not counted) | `logs/three-demos-after-fix.log` |

Post-fix total, combining A6 (other workspaces: 117 + 97 + 623 + 101 + 95)
with A7 (server 1,117) and A8 (1): **2,151 passed**. The A6 flake is a new
observation worth its own fix (wait for container removal, or use a unique name
per start) and is recorded rather than discarded.

---

## 7. Limits of this assessment

- **Not exhaustive.** WebAuthn attestation formats (TPM, Android Key,
  SafetyNet, Apple, U2F), the CBOR/ASN.1/DER/COSE parsers, MDS BLOB handling,
  the Fastify and Hono adapters, and `keyring.ts` were reviewed only at the level
  noted in §2 or relied on their existing suites and fuzz tests.
- **Model-assisted.** Findings come from an AI reviewer working with the
  repository's own tests. A human expert or a specialised audit firm could find
  issues this review missed. Passing tests are not proof of the absence of
  vulnerabilities.
- **One machine, Windows.** CI targets Ubuntu on Node 20 and 22; this run used
  Node 22.13.1 on Windows 10. Node 20 and Linux were not exercised locally.
- **Not independent.** Nothing here substitutes for the external security
  review that `REMAINING-ISSUES.md` lists as outstanding.

---

## 8. Cross-check with the second review (`C:\Degree Yash\Ninsho-Independent-Audit`)

Read on 21 October 2026. What it is: a **second AI-agent session** (Claude Opus
5.5), run 14:47–15:10 on the same machine against this working tree. Its only
saved report, `audit-output/initial-findings.md`, is **Phase A — blind,
pre-probe hypotheses**; the Phase B files it references (`security-findings.md`,
`test-evidence.md`) do not exist, `probes/` holds only a helper library and
`consumer/` is empty. It states it is "not a human third-party audit or a
security certification", and discloses that this assessment's file names and the
uncommitted F-01 diff were visible to it. **It is therefore not an independent
audit and must not be described as one.**

Useful evidence from it: `work/test-full-wt-run2.log` — full suite on the same
working tree, 2,151 passed (its first run failed 4 tests, three of them the
same port-6390 collision recorded in §1 of this document).

Its hypotheses mapped against this assessment:

| Second review | This assessment | Status after cross-check |
|---|---|---|
| B-02 trustProxy:false via `req.ip` | F-02 | Same finding; reproduced here |
| B-03 IPv6 per /128 | C-01 | Same |
| B-06 thumbprint malleability | F-04 | Same |
| B-13 client `//` | F-07 | Same |
| B-18 PASETO index TTL | F-01 | Same (known to it from the diff) |
| B-04, B-10, B-11, B-16, B-08, B-09 | C-03, C-04, C-05 / documented limitations | Same or already documented |
| **B-12** SecureShop `/api/dpop/logout` passes the raw refresh token to `revokeSession()` | — (missed here) | **Confirmed by execution and FIXED.** Regression `demo/viva-showcase/src/server.test.ts` › *revokes the server session on logout, so neither the access token nor the refresh cookie still works* failed before the fix (access token still `200` after logout). The route now runs `auth.verify()` and revokes `getAuth(req).sessionId`; 4/4 demo tests pass (`logs/secureshop-test-after-fix2.log`). Demo only. |
| **B-01** `finishAuthentication` skips the owner check when `StoredCredential.userId` is omitted, then returns `context.userId` | — (missed here) | **Confirmed by execution and FIXED** — broader than described: the principal could also come from the *unsigned* `userHandle` (the assertion signature covers only authenticatorData ‖ hash(clientDataJSON)). Two regressions in `webauthn/src/server.test.ts` (*refuses a challenge issued for one user and completed with an owner-less credential*, *refuses to take the principal from an unsigned user handle*) both failed before the fix (attacker signed in as `victim`). `finishAuthentication` now refuses any credential without `userId`. **Behaviour change:** the former test *falls back to the user handle when the credential has no owner* asserted the vulnerable behaviour and was replaced. Medium–High for integrations that omitted `userId` |
| B-05 unsalted truncated IP hash reversible for IPv4 | — | Plausible by inspection (2³² space); not executed. Low (privacy) |
| B-07 DPoP-bound token accepted with `Bearer` scheme | — | Confirmed by reading `AUTH_SCHEME`; proof still mandatory. Info |
| B-14, B-15, B-17, B-19 | — | Not assessed here |


### 8.1 Verification after the B-01 / B-12 fixes

| Command | Result | Log |
|---|---|---|
| `npm run build` | Passed | `logs/build-after-fix2.log` |
| `npm run typecheck` | Passed | `logs/typecheck-after-fix2.log` |
| `REDIS_URL=redis://localhost:6379 npm run test` | **Passed, exit 0: 2,152** (client 117, core 97, server 1,117, webauthn 624, express example 101, playground 95, HTTP demo 1), 0 skipped | `logs/test-redis-after-fix2.log` |
| `demo/viva-showcase`: `npx vitest run` | Passed 4/4 | `logs/secureshop-test-after-fix2.log` |

Changed for these fixes: `demo/viva-showcase/src/server.ts`, `demo/viva-showcase/src/server.test.ts`, `packages/webauthn/src/server.ts`, `packages/webauthn/src/server.test.ts`, `packages/webauthn/src/ceremony.ts` (doc comment). Browser regressions were not re-run (client unchanged).
