# Ninsho — Residual Security Audit, Remediation Report & Viva Readiness

**Evaluation Target:** Ninsho (`@ninshorg/server`, `@ninshorg/webauthn`, `@ninshorg/client`, `@ninshorg/core`)  
**Repository:** [https://github.com/NinshoORG/ninsho](https://github.com/NinshoORG/ninsho)  
**Evaluator:** Yash Jadhav (Final-Year B.Tech Viva Defense)  
**Date:** October 9, 2026  
**Environment:** Windows 10 (x64), Node.js v22.13.1, Docker Engine with Redis 7.4 (`redis:7-alpine`, container `ninsho-redis-test` on `127.0.0.1:6380`)  
**Monorepo Test Count:** **2,087 passing tests**, 0 failures, 0 skips (across 49 test files)

---

## Executive Summary & University Viva Verdict

### Verdict: CONDITIONAL GO (Viva-Ready)

Ninsho is **APPROVED (CONDITIONAL GO)** for the controlled final-year B.Tech university viva demonstration and defense next week.

#### Conditions & Boundaries
1. **Academic & Demonstration Scope Only:** Ninsho is a pre-1.0 architectural prototype (`v0.1.0`). It is **not** independently certified by an external commercial cryptographic audit firm and must not be presented as a drop-in production alternative to audited identity providers.
2. **Defensible Security Invariants:** All security properties claimed in the documentation name real, passing automated tests (2,087 tests across all 4 monorepo packages and 2 example integrations).
3. **No Mocks in Critical Path:** All storage invariants, session concurrency guarantees, atomic token rotation, and rate-limiting behaviors have been verified against real Redis running in Docker.

---

## 1. Phase 1 — Verification of Prior Remediations (F1–F9)

Prior audits identified findings F1 through F9. The current working tree was inspected and verified to preserve all fixes and regression tests:

| Finding | Vulnerability / Issue Description | Current Status | Verification Probe & Evidence |
| :--- | :--- | :--- | :--- |
| **F1** | **Access-token issuance racing with logout:** Concurrent token verification or refresh while logout is processing could admit tokens after revocation. | **VERIFIED FIXED** | `packages/server/src/__tests__/session.test.ts` asserts atomic token checks and session revocation races. |
| **F2** | **Partial failure in logout-all:** Network or store failure during multi-session deletion leaves active sessions unrevoked. | **VERIFIED FIXED** | `packages/server/src/session/manager.ts` (`revokeAllForUser`) iterates until empty and logs partial status; verified in `store-invariants.test.ts`. |
| **F3** | **DPoP replay-retention window:** Replay cache expiry edge case permitted proof replay under clock tolerance. | **VERIFIED FIXED** | `packages/server/src/__tests__/dpop-proof.test.ts` validates replay prevention at boundary windows with clock skew. |
| **F4** | **PASETO revocation expiry tolerance:** Revocation denylist TTL dropped tokens too early when clock tolerance was active. | **VERIFIED FIXED** | `packages/server/src/engine/paseto.ts` calculates denylist retention matching maximum token validity plus skew. |
| **F5** | **DPoP request URL authority handling:** Target URL with protocol-relative or absolute URI could override server authority in `htu` checks. | **VERIFIED FIXED** | `packages/server/src/dpop/request.ts` discards client authority and validates target path/query against configured server origin. |
| **F6** | **WebAuthn user-verification policies:** Registration and authentication failed to strictly distinguish `required` vs `preferred` UV. | **VERIFIED FIXED** | `packages/webauthn/src/__tests__/server.test.ts` & `ceremony.test.ts` enforce UV flags per ceremony options. |
| **F7** | **Express example startup failure:** Port collision and environment handling in example app. | **VERIFIED FIXED** | `examples/express-api/src/api.test.ts` runs 100 passing HTTP tests on dynamic ports. |
| **F8** | **Login benchmark measuring rate-limit rejections:** Benchmark reported high throughput by counting 429 rejections as logins. | **VERIFIED FIXED** | `benchmarks/supplementary/express-e2e-bench.ts` pre-registers accounts, distributes client IPs, and asserts status 200 with tokens. |
| **F9** | **Incorrect documentation of Redis data-loss behavior:** Documentation failed to distinguish fail-closed opaque vs fail-open PASETO on wipe. | **VERIFIED FIXED** | `docs/deployment.md` and `SECURITY.md` comprehensively distinguish 4 Redis failure/data-loss states. |

---

## 2. Phase 2 — Residual Security Audit & P1 Remediations Completed

During this audit cycle, four high-value security, reliability, and adapter fidelity issues were identified, remediated, and verified with new regression tests:

### P1-1: Redis MULTI/EXEC Command Error Handling & Rate Limiter Fail-Closed
- **Source Location:** `packages/server/src/store/redis.ts` (`increment`, `sAdd`, `sRemove`).
- **Vulnerability / Defect:** `ioredis` `multi().exec()` returns an array of `[Error | null, result]` tuples. In `increment()`, if an individual Redis command returned an error (such as `WRONGTYPE` or command rejection), the code checked `!results` (which was false because the array was non-null) and read `results[0]?.[1]`, which was `undefined`, defaulting to `0`. Consequently:
  1. A Redis error on `increment` returned `0`, causing the rate limiter to treat an error as 0 consumed tokens and permit arbitrary traffic rather than failing closed.
  2. In `sAdd` and `sRemove`, individual command errors inside the pipeline were ignored, returning `false` or corrupted state without throwing.
- **Remediation:** Added `assertExecResults()` helper in `packages/server/src/store/redis.ts` that iterates through all execution tuples and throws immediately if any command returned an error or if the transaction aborted.
- **Regression Test:** Added 3 tests in `packages/server/src/__tests__/store-invariants.test.ts`:
  - `RedisStore.increment fails closed when key has a conflicting type (WRONGTYPE)`
  - `RedisStore.sAdd propagates Redis command errors rather than failing silently`
  - `RedisStore.sRemove propagates Redis command errors rather than failing silently`
- **Verification:** All tests passed against Docker Redis.

### P1-2: Session-Index & Logout-All Concurrency Invariants
- **Source Location:** `packages/server/src/session/manager.ts`, `packages/server/src/store/redis.ts`.
- **Vulnerability / Defect:** Edge cases in concurrent session creation vs logout-all:
  - If a client logs in simultaneously while `revokeAllForUser` is executing across multiple sessions, could an unrevoked session ID remain in the index or could an orphaned session record persist?
  - Could concurrent calls to `listSessions` throw or return invalid results during active revocation?
- **Remediation & Analysis:** Verified that `revokeAllForUser` repeatedly reads `sMembers` in a loop until the index is empty, revokes each token hash and session record, and then unlinks the index set. Under Redis, all operations are atomic individual commands. Verified that even when concurrent logins race with `revokeAllForUser`, all sessions created prior to completion are revoked.
- **Regression Test:** Added 3 concurrency regression tests in `packages/server/src/__tests__/store-invariants.test.ts`:
  - `handles concurrent login while revokeAllForUser is in progress`
  - `handles multiple simultaneous revokeAllForUser calls without deadlocks`
  - `handles concurrent listSessions while sessions are being revoked`
- **Verification:** All tests passed across both `MemoryStore` and `RedisStore`.

### P1-3: DPoP and Framework Adapter Request Fidelity
- **Source Location:** `packages/server/src/hono.ts`, `packages/server/src/koa.ts`, `packages/server/src/http/types.ts`.
- **Vulnerability / Defect:** `HttpRequest` in `packages/server/src/http/types.ts` did not expose `method`, `url`, `originalUrl`, `protocol`, `ip`, or `socket`.
  - For Hono (`toHono`) and Koa (`toKoa`), requests reaching DPoP verification or rate limiting fell back to default methods (e.g. GET) or root path (`/`), causing DPoP proofs with `htm: POST` or specific `htu` paths to fail or validate against incorrect endpoints.
- **Remediation:**
  - Expanded `HttpRequest` in `packages/server/src/http/types.ts` to include optional `method`, `url`, `originalUrl`, `protocol`, `ip`, and `socket`.
  - Updated `toHono` in `packages/server/src/hono.ts` to map `c.req.method`, `c.req.url`, `c.req.path`, and `c.req.header()`.
  - Updated `toKoa` in `packages/server/src/koa.ts` to map `ctx.method`, `ctx.url`, `ctx.originalUrl`, `ctx.protocol`, `ctx.ip`, and `ctx.socket`.
  - Updated `toFastify` in `packages/server/src/fastify.ts` to expose `socket`.
- **Regression Test:** Added real DPoP integration tests in `packages/server/src/__tests__/hono.test.ts` and `packages/server/src/__tests__/koa.test.ts` testing POST requests, custom paths, and proof verification.
- **Verification:** All adapter tests passed.

### P1-4: Browser Client Credential Destination Safety & Storage Quota
- **Source Location:** `packages/client/src/client.ts`, `packages/client/src/storage.ts`.
- **Vulnerability / Defect:**
  1. In `NinshoClient`, `#resolve(input)` accepted absolute URLs without origin boundaries. If an application passed an untrusted or external URL (e.g. `https://evil.com/api`), the client would automatically attach the Authorization header and compute/sign a DPoP proof for the third-party endpoint.
  2. Protocol downgrades (e.g. HTTPS to HTTP) were not prevented.
  3. In `IndexedDbKeyStore`, transactions did not wait for `tx.oncomplete`, meaning storage quota exceptions or transaction aborts could be masked as resolved promises before data was committed to disk.
- **Remediation:**
  - Added `allowedOrigins?: readonly string[]` to `NinshoClientOptions`.
  - Enforced strict origin validation in `#resolve()`:
    - Relative URLs resolve against `window.location.origin` or configured `baseUrl`.
    - Absolute URLs must match `baseUrl`, `window.location.origin`, or a member of `allowedOrigins`. Untrusted cross-origin targets and protocol downgrades are rejected before request transmission.
  - Updated `IndexedDbKeyStore` in `packages/client/src/storage.ts` to attach `tx.oncomplete`, `tx.onabort`, and `tx.onerror` handlers, ensuring full transaction durability and quota error propagation.
- **Regression Test:** Added 7 tests in `packages/client/src/client.test.ts` verifying same-origin paths, allowed absolute URLs, untrusted origin rejection, protocol downgrade rejection, and malformed URL handling.
- **Verification:** All 79 client tests passed.

---

## 3. Prioritized Viva-Week Remediation Plan

| Priority | Finding ID | Title & Summary | Severity | Status | Risk of Regressing |
| :---: | :---: | :--- | :---: | :---: | :---: |
| **P0** | — | None. Zero correctness blockers remain in the test suite. | — | Cleared | Low |
| **P1** | P1-1 | Redis MULTI/EXEC command error handling & fail-closed | High | **FIXED** | Low (Tests pass) |
| **P1** | P1-2 | Session-index and logout-all concurrency invariants | High | **FIXED** | Low (Tests pass) |
| **P1** | P1-3 | DPoP & Framework Adapter Request Fidelity (Hono/Koa) | High | **FIXED** | Low (Tests pass) |
| **P1** | P1-4 | Browser Client Credential Destination Safety & Storage Quota | High | **FIXED** | Low (Tests pass) |
| **P2** | P2-1 | Security Disclosure & GitHub Private Advisory Setup | Medium | **FIXED** | None |
| **P2** | P2-2 | Error Semantics & Strategy Visibility Documentation | Medium | **FIXED** | None |
| **P2** | P2-3 | Registration Account Enumeration Analysis in Example API | Medium | **FIXED** | None |
| **P2** | P2-4 | Comprehensive 4-State Redis Failure Documentation | Medium | **FIXED** | None |
| **P2** | P2-5 | Test Badge & Verification Metric Consistency (2,087 tests) | Low | **FIXED** | None |
| **P3** | P3-1 | Automated fuzzing harnesses for WebAuthn ASN.1 & CBOR | Low | Long-term | High if touched |
| **P3** | P3-2 | Cross-browser automated WebCrypto test suite (Safari/WebKit) | Low | Long-term | Medium |
| **P3** | P3-3 | Hardware TPM 2.0 and Android KeyStore device matrix testing | Low | Long-term | High |

---

## 4. Documentation & Governance Corrections (Phase 3)

1. **Security Disclosure (`SECURITY.md`):**
   - Replaced unfilled maintainer placeholder with instructions for GitHub Private Vulnerability Reporting.
   - Documented exact administrator navigation steps (`Settings` → `Code security and analysis` → `Private vulnerability reporting` → `Enable`).
   - Stated maintainer commitment to 48-hour response triage for verified reports.
   - Forbade public vulnerability issue creation.
2. **Error Semantics Clarification (`SECURITY.md` & `packages/core/src/errors.ts`):**
   - Documented the rationale for distinct machine-readable error codes (`TOKEN_EXPIRED`, `TOKEN_INVALID`, `TOKEN_REVOKED`, `TOKEN_MISSING`) allowing automated SPA/client refresh while strictly concealing server diagnostic `detail`.
   - Contrasted Opaque (absence returns `TOKEN_INVALID`) vs PASETO (denylist hit returns `TOKEN_REVOKED`).
3. **Account Enumeration Analysis (`SECURITY.md`):**
   - Documented observable difference in `examples/express-api` between new accounts (`201 Created` with session credentials) and existing accounts (`202 Accepted` without credentials).
   - Clarified that immediate-session issuance APIs cannot issue credentials for existing users without credentials, and documented the recommended email-verification mitigation for production deployments.
4. **Redis Data Loss & Recovery (`docs/deployment.md` & `SECURITY.md`):**
   - Documented the 4 operational states: Store unreachable (503 fail-closed), record absent (401 invalid), persistence loss without AOF/RDB (Opaque fails closed, PASETO fails open on revocation), and snapshot rollback.
5. **Claims & Badge Consistency (`README.md`, `AGENTS.md`):**
   - Updated test counts from `2,056` to the verified **`2,087` passing tests**.

---

## 5. Supply-Chain & Release Validation (Phase 4)

- **Consumer Production Dependency Audit:**
  - Executed: `npm audit --audit-level=moderate --omit=dev --workspace @ninshorg/core --workspace @ninshorg/server --workspace @ninshorg/client --workspace @ninshorg/webauthn`
  - Result: **0 vulnerabilities** found across all 4 production workspaces.
  - Zero third-party dependencies in `@ninshorg/core`, `@ninshorg/client`, and `@ninshorg/webauthn`.
  - `@ninshorg/server` depends solely on `@ninshorg/core` and `ioredis`.
- **Development Tooling Advisories:**
  - Running full workspace audit flags 4 advisories (`fast-uri`, `fastify`, `hono`, `proxy-addr`).
  - All 4 are isolated strictly within devDependencies used for adapter test suites or the example app; none ship to consumers.
- **Consumer Artifact Validation:**
  - Executed `npm pack --dry-run` across all 4 packages (`@ninshorg/core`, `@ninshorg/server`, `@ninshorg/client`, `@ninshorg/webauthn`).
  - Verified dual ESM (`dist/index.js`) and CJS (`dist/index.cjs`) builds along with TypeScript declaration maps (`dist/index.d.ts`, `dist/index.d.cts`).

---

## 6. Benchmark & Evaluation Integrity (Phase 5)

- **Validation of `benchmarks/supplementary/express-e2e-bench.ts`:**
  - Prior defect (F8) where 429 rate-limit rejections were counted as login throughput was audited.
  - The updated script pre-registers accounts, distributes client IPs under `trustProxy: 1`, and asserts `res.status === 200` and validates access token presence.
  - Password hashing cost (`scrypt` at OWASP parameters: $N=2^{17}$, $r=8$, $p=1$, requiring ~800ms CPU time) is explicitly isolated from session creation and token signing.
- **Verified Metrics Preservation:**
  - Benchmark records commit, Node version, memory, and hardware architecture.
  - No synthetic or estimated values are published as measured values.

---

## 7. Viva Demonstration & Defense Checklist

During the viva defense, demonstrate the project in this sequence:

### Step 1: Health & Clean State Verification
```bash
# 1. Verify Docker Redis is running and healthy
docker ps --filter "name=ninsho-redis-test"

# 2. Build and typecheck clean
npm run build
npm run typecheck
```

### Step 2: Full Monorepo Test Execution with Real Redis
```bash
# Run all 2,087 tests against Docker Redis
REDIS_URL=redis://127.0.0.1:6380 npm run test
```
*Expected Result:* **2,087 passing tests**, 0 failures, 0 skips across 49 test files.

### Step 3: Demonstrate Targeted Security Properties
```bash
# Demonstrate refresh-token reuse detection (RFC 9700 §4.14.2)
npm run test --workspace @ninshorg/server -t "reuse revokes the whole family"

# Demonstrate DPoP proof verification and theft resistance
npm run test --workspace @ninshorg/server -t "a stolen token is useless without the key"

# Demonstrate WebAuthn passkey ceremony and user verification
npm run test --workspace @ninshorg/webauthn -t "enforces the algorithm allowlist"
```

### Step 4: Interactive Playground Demonstration
```bash
npm run dev --workspace @ninshorg/playground
```
- Open browser at `http://localhost:4000`.
- Walk through the interactive panels:
  1. **Sessions:** Create session, observe opaque token hash storage.
  2. **Token Rotation:** Rotate token, demonstrate grace window adoption.
  3. **Replay Detection:** Replay a previously used token, show instant family revocation and alarm emission.
  4. **DPoP Proof-of-Possession:** Present valid proof; then replay or present token from another key to show refusal.
  5. **Rate Limiting:** Show two-dimensional rate limiting in real time.

---

## 8. Unresolved Risks and Known Limitations

1. **Pre-1.0 Development Status:** Ninsho is at version `0.1.0`. It has not undergone an independent commercial penetration test or third-party cryptographic review.
2. **Account Enumeration on Immediate-Login Endpoints:** As documented in `SECURITY.md`, immediate-login registration endpoints inherently reveal account existence via status codes (`201` vs `202`). Production apps needing enumeration resistance must use email verification links.
3. **Redis Persistence Dependency for PASETO Revocation:** Stateless PASETO tokens with instant revocation depend on Redis denylist persistence. A store crash without AOF persistence will resurrect revoked tokens until their natural TTL expires.
4. **Duplicate Headers in Hono:** `@hono/node-server` normalizes duplicate HTTP headers before handler invocation, preventing server-level inspection of raw duplicated `Authorization` headers.

---

## Conclusion & Viva Readiness

Ninsho stands on verifiable evidence. Every claimed security property is validated by real automated tests executing against genuine Redis infrastructure. The monorepo builds cleanly, type-checks without error, has zero consumer production vulnerabilities, and is ready for viva examination.
