# Ninsho v0.1.0 Manual Security Test Plan

This document defines the verified manual and semi-automated security test procedures for Ninsho v0.1.0. All tests have been cross-checked line-by-line against the actual runnable reference implementations (`http://localhost:3000` for `examples/express-api` and `http://localhost:4000` for `examples/playground`).

---

## Table of Contents

1. [A. Authentication Attacks](#a-authentication-attacks)
   - [MT-01: Account Enumeration Resistance on Registration](#mt-01-account-enumeration-resistance-on-registration)
   - [MT-02: Constant-Time Credential Verification Oracle Defense](#mt-02-constant-time-credential-verification-oracle-defense)
   - [MT-03: Single-Use One-Time Token Reuse Rejection](#mt-03-single-use-one-time-token-reuse-rejection)
2. [B. Token Integrity & Algorithm Confusion Attacks](#b-token-integrity--algorithm-confusion-attacks)
   - [MT-04: Opaque Access Token Bit-Flipping / Mutation](#mt-04-opaque-access-token-bit-flipping--mutation)
   - [MT-05: Playground Interactive Token Tampering Endpoint](#mt-05-playground-interactive-token-tampering-endpoint)
   - [MT-06: Algorithm Confusion Resistance (PASETO on Opaque Endpoint)](#mt-06-algorithm-confusion-resistance-paseto-on-opaque-endpoint)
3. [C. Token Replay Attacks](#c-token-replay-attacks)
   - [MT-07: Access Token Replay After Session Logout](#mt-07-access-token-replay-after-session-logout)
   - [MT-08: Single-Use Reset Link Replay & Concurrency Race](#mt-08-single-use-reset-link-replay--concurrency-race)
4. [D. Session & Revocation Attacks](#d-session--revocation-attacks)
   - [MT-09: Single Session Logout Immediate Revocation](#mt-09-single-session-logout-immediate-revocation)
   - [MT-10: Global Logout All Sessions Revocation](#mt-10-global-logout-all-sessions-revocation)
   - [MT-11: Password Reset Session Revocation Cascade](#mt-11-password-reset-session-revocation-cascade)
5. [E. Refresh Token Attacks](#e-refresh-token-attacks)
   - [MT-12: Refresh Token Reuse Detection & Automatic Session Termination](#mt-12-refresh-token-reuse-detection--automatic-session-termination)
   - [MT-13: Concurrent Refresh Token Rotation Race Condition](#mt-13-concurrent-refresh-token-rotation-race-condition)
6. [F. Authorization Attacks](#f-authorization-attacks)
   - [MT-14: Broken Object Level Authorization (BOLA/IDOR) on Orders](#mt-14-broken-object-level-authorization-bolaidor-on-orders)
   - [MT-15: Role-Based Access Control (RBAC) Privilege Escalation](#mt-15-role-based-access-control-rbac-privilege-escalation)
   - [MT-16: Multi-Tenant Boundary Crossing Attempt](#mt-16-multi-tenant-boundary-crossing-attempt)
7. [G. Rate Limiting Attacks](#g-rate-limiting-attacks)
   - [MT-17: Sliding-Window Login Brute-Force Rate Limiting](#mt-17-sliding-window-login-brute-force-rate-limiting)
   - [MT-18: Client IP Header Spoofing Bypass (`X-Forwarded-For`)](#mt-18-client-ip-header-spoofing-bypass-x-forwarded-for)
8. [H. DPoP Proof-of-Possession Attacks](#h-dpop-proof-of-possession-attacks)
   - [MT-19: DPoP Proof Replay Detection (`jti` Guard)](#mt-19-dpop-proof-replay-detection-jti-guard)
   - [MT-20: Unbound DPoP Token Theft (Omission of Proof)](#mt-20-unbound-dpop-token-theft-omission-of-proof)
   - [MT-21: Invalid / Corrupted DPoP Proof Presentation](#mt-21-invalid--corrupted-dpop-proof-presentation)
9. [I. Claims & Step-Up Attacks](#i-claims--step-up-attacks)
   - [MT-22: Step-Up Authentication Window Expiry (`requireFreshAuth`)](#mt-22-step-up-authentication-window-expiry-requirefreshauth)
   - [MT-23: OAuth Scope Insufficiency Verification (`requireScope`)](#mt-23-oauth-scope-insufficiency-verification-requirescope)
10. [J. Malformed Input Attacks](#j-malformed-input-attacks)
    - [MT-24: Oversized Request Body DoS (>16 KB Payload Limit)](#mt-24-oversized-request-body-dos-16-kb-payload-limit)
    - [MT-25: Malformed URI Cookie Header Injection (`Cookie: ninsho_rt=%`)](#mt-25-malformed-uri-cookie-header-injection-cookie-ninsho_rt)
11. [K. WebAuthn / Passkey Attacks](#k-webauthn--passkey-attacks)
    - [MT-26: WebAuthn Authentication Assertion Replay](#mt-26-webauthn-authentication-assertion-replay)
    - [MT-27: User Handle Impersonation in Passkey Login](#mt-27-user-handle-impersonation-in-passkey-login)

---

## A. Authentication Attacks

### MT-01: Account Enumeration Resistance on Registration
- **Test ID:** MT-01
- **Attack Name:** Registration Account Enumeration Probe
- **Objective:** Verify that registering an existing email address does not reveal whether the account already exists.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** `express-api` is running on port 3000. User `victim@example.com` has been registered.
- **Exact Setup:**
  ```bash
  curl -s -X POST http://localhost:3000/auth/register \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@example.com","password":"ValidPassword123!"}'
  ```
- **Exact Request / Command:**
  ```bash
  # Attempt registration with duplicate email:
  curl -i -s -X POST http://localhost:3000/auth/register \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@example.com","password":"AnotherPassword123!"}'
  ```
- **Expected Result:**
  - HTTP Status: `202 Accepted`
  - Response Body: `{"message":"If the address is available, the account has been created."}`
  - No `409 Conflict` or "User already exists" error is returned to the client.
- **Security Property Being Tested:** Account enumeration resistance. Unregistered vs. registered email addresses cannot be distinguished via registration responses.
- **Evidence to Capture:** HTTP response status, response body, response headers.

---

### MT-02: Constant-Time Credential Verification Oracle Defense
- **Test ID:** MT-02
- **Attack Name:** Login Timing & Enumeration Oracle Probe
- **Objective:** Verify that invalid logins for non-existent accounts and invalid passwords for existing accounts return identical error responses and comparable response timings.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** User `alice@example.com` exists with password `CorrectPassword123!`.
- **Exact Request / Command:**
  ```bash
  # Case 1: Existing account, wrong password
  curl -i -s -X POST http://localhost:3000/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"alice@example.com","password":"WrongPassword123!"}'

  # Case 2: Non-existent account
  curl -i -s -X POST http://localhost:3000/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"nonexistent_user@example.com","password":"RandomPassword123!"}'
  ```
- **Expected Result:**
  - Both requests return HTTP `401 Unauthorized`.
  - Both response bodies are strictly identical: `{"error":{"code":"INVALID_CREDENTIALS","message":"Invalid email or password"}}`.
  - No indication of whether the email exists in the database.
- **Security Property Being Tested:** Elimination of user enumeration oracles; constant-work password verification dummy hash execution on miss path.
- **Evidence to Capture:** HTTP status and JSON response bodies for both cases.

---

### MT-03: Single-Use One-Time Token Reuse Rejection
- **Test ID:** MT-03
- **Attack Name:** Password Reset Token Replay
- **Objective:** Verify that a password reset token can be consumed exactly once, and a second presentation is rejected with `ONE_TIME_TOKEN_INVALID`.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** A valid password reset token issued via `POST /auth/password/forgot` for an existing user.
- **Exact Setup:**
  1. Trigger forgot password for `alice@example.com`.
  2. Obtain the issued single-use token from the application's out-of-band delivery channel.
- **Exact Request / Command:**
  ```bash
  # First consumption (Legitimate):
  curl -i -s -X POST http://localhost:3000/auth/password/reset \
    -H "Content-Type: application/json" \
    -d '{"token":"<RESET_TOKEN>","password":"NewPassword1234!"}'

  # Second consumption (Replay Attack):
  curl -i -s -X POST http://localhost:3000/auth/password/reset \
    -H "Content-Type: application/json" \
    -d '{"token":"<RESET_TOKEN>","password":"AttackerPassword123!"}'
  ```
- **Expected Result:**
  - Request 1 returns HTTP `204 No Content`.
  - Request 2 returns HTTP `400 Bad Request` with:
    `{"error":{"code":"ONE_TIME_TOKEN_INVALID","message":"This link is no longer valid"}}`
- **Security Property Being Tested:** Atomic single-use token consumption (`auth.oneTimeTokens.consume()`).
- **Evidence to Capture:** First response headers, second response status and body.

---

## B. Token Integrity & Algorithm Confusion Attacks

### MT-04: Opaque Access Token Bit-Flipping / Mutation
- **Test ID:** MT-04
- **Attack Name:** Opaque Token Byte Tampering
- **Objective:** Verify that tampering with any character in an opaque access token results in rejection without leaking store keys or internal details.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** Valid user registered and logged in, holding valid `accessToken`.
- **Exact Request / Command:**
  ```bash
  # 1. Normal access:
  curl -i -s -H "Authorization: Bearer <VALID_TOKEN>" http://localhost:3000/me

  # 2. Mutate one character of the token:
  curl -i -s -H "Authorization: Bearer <MUTATED_TOKEN>" http://localhost:3000/me
  ```
- **Expected Result:**
  - Request 1 returns `200 OK` with user details.
  - Request 2 returns `401 Unauthorized` with:
    - Status: `401`
    - Header: `WWW-Authenticate: Bearer error="TOKEN_INVALID"`
    - Body: `{"error":{"code":"TOKEN_INVALID","message":"Invalid authentication credentials"}}`
- **Security Property Being Tested:** Opaque token unforgeability and constant-time SHA-256 store lookup.
- **Evidence to Capture:** Status code 401, header, and response body.

---

### MT-05: Playground Interactive Token Tampering Endpoint
- **Test ID:** MT-05
- **Attack Name:** Controlled Token Bit-Flipping on Playground Engine
- **Objective:** Verify that the playground's token tampering endpoint flips a character and proves store miss rejection.
- **Target Application:** `playground` (`http://localhost:4000`)
- **Prerequisites:** A session created via `POST /api/session/create`.
- **Exact Request / Command:**
  ```bash
  # 1. Create session:
  curl -i -s -X POST http://localhost:4000/api/session/create

  # 2. Trigger tamper attack endpoint:
  curl -i -s -X POST http://localhost:4000/api/attack/tamper-token
  ```
- **Expected Result:**
  - HTTP `200 OK` with payload:
    `{"rejected":true,"code":"TOKEN_INVALID","message":"Invalid authentication credentials",...}`
- **Security Property Being Tested:** Opaque token store miss isolation.
- **Evidence to Capture:** JSON response containing `rejected: true` and `code: TOKEN_INVALID`.

---

### MT-06: Algorithm Confusion Resistance (PASETO on Opaque Endpoint)
- **Test ID:** MT-06
- **Attack Name:** Presentation of Asymmetric PASETO Format to Opaque Endpoint
- **Objective:** Verify that presenting a structured PASETO token (`v4.public...`) to an opaque-configured endpoint does not trigger algorithm confusion or parser exploitation, but fails closed as `TOKEN_INVALID`.
- **Target Application:** `express-api` (`http://localhost:3000`) / `playground` (`http://localhost:4000`)
- **Exact Request / Command:**
  ```bash
  curl -i -s -H "Authorization: Bearer v4.public.eyJzdWIiOiJhZG1pbiJ9.fake_sig" http://localhost:3000/me
  ```
- **Expected Result:**
  - HTTP Status: `401 Unauthorized`
  - Body: `{"error":{"code":"TOKEN_INVALID","message":"Invalid authentication credentials"}}`
  - Server treats it as an opaque string, hashes it, finds no match, and rejects it without dynamic algorithm negotiation.
- **Security Property Being Tested:** Elimination of algorithm confusion (fixed token strategy at construction).
- **Evidence to Capture:** HTTP 401 response.

---

## C. Token Replay Attacks

### MT-07: Access Token Replay After Session Logout
- **Test ID:** MT-07
- **Attack Name:** Replaying Access Token Post-Logout
- **Objective:** Verify that immediately following session logout, presenting the previously valid access token is rejected.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** Authenticated session with `accessToken`.
- **Exact Request / Command:**
  ```bash
  # 1. Call logout:
  curl -i -s -X POST http://localhost:3000/auth/logout \
    -H "Authorization: Bearer <ACCESS_TOKEN>"

  # 2. Replay the same access token immediately:
  curl -i -s http://localhost:3000/me \
    -H "Authorization: Bearer <ACCESS_TOKEN>"
  ```
- **Expected Result:**
  - Logout returns `204 No Content`.
  - Protected endpoint returns `401 Unauthorized` with `{"error":{"code":"TOKEN_INVALID","message":"Invalid authentication credentials"}}`.
- **Security Property Being Tested:** Immediate server-side session revocation in the store.
- **Evidence to Capture:** HTTP 204 followed by HTTP 401 response.

---

### MT-08: Single-Use Reset Link Replay & Concurrency Race
- **Test ID:** MT-08
- **Attack Name:** Reset Link Replay & Racing Generation Invalidation
- **Objective:** Verify via the playground's attack endpoints that single-use tokens cannot be replayed, and racing reset requests invalidate older generations.
- **Target Application:** `playground` (`http://localhost:4000`)
- **Prerequisites:** Playground running on port 4000.
- **Exact Request / Command:**
  ```bash
  # 1. Test single-use replay:
  curl -i -s -X POST http://localhost:4000/api/attack/replay-reset-link

  # 2. Test concurrent race condition:
  curl -i -s -X POST http://localhost:4000/api/attack/race-reset-links
  ```
- **Expected Result:**
  - `replay-reset-link` returns: `first: "accepted"`, `second: "ONE_TIME_TOKEN_INVALID"`.
  - `race-reset-links` returns: `survivors: 1` (the newer generation supersedes the older one).
- **Security Property Being Tested:** Atomic `store.take()` single-use enforcement and atomic generation counter invalidation.
- **Evidence to Capture:** JSON response showing `first: accepted, second: ONE_TIME_TOKEN_INVALID` and `survivors: 1`.

---

## D. Session & Revocation Attacks

### MT-09: Single Session Logout Immediate Revocation
- **Test ID:** MT-09
- **Attack Name:** Single Session Termination Verification
- **Objective:** Verify that terminating session A revokes session A without terminating a distinct session B for the same user.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** Two distinct sessions for user `alice@example.com` (Session A and Session B).
- **Exact Setup:**
  1. Login from Client 1 -> Obtain `TokenA`.
  2. Login from Client 2 -> Obtain `TokenB`.
- **Exact Request / Command:**
  ```bash
  # Logout Session A:
  curl -i -s -X POST http://localhost:3000/auth/logout \
    -H "Authorization: Bearer <TokenA>"

  # Verify Session A is dead:
  curl -i -s http://localhost:3000/me \
    -H "Authorization: Bearer <TokenA>"

  # Verify Session B is still alive:
  curl -i -s http://localhost:3000/me \
    -H "Authorization: Bearer <TokenB>"
  ```
- **Expected Result:**
  - Logout returns `204 No Content`.
  - Call with `TokenA` returns `401 Unauthorized`.
  - Call with `TokenB` returns `200 OK` with Alice's user profile.
- **Security Property Being Tested:** Session isolation; targeted revocation deletes only the targeted session key.
- **Evidence to Capture:** Status codes 204, 401, and 200.

---

### MT-10: Global Logout All Sessions Revocation
- **Test ID:** MT-10
- **Attack Name:** Global User Logout Revocation Cascade
- **Objective:** Verify that `POST /auth/logout-all` revokes all existing sessions for the authenticated user across all devices.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** Two active sessions for user `alice@example.com` (`TokenA` and `TokenB`).
- **Exact Request / Command:**
  ```bash
  # Execute global logout using TokenA:
  curl -i -s -X POST http://localhost:3000/auth/logout-all \
    -H "Authorization: Bearer <TokenA>"

  # Test TokenA:
  curl -i -s http://localhost:3000/me \
    -H "Authorization: Bearer <TokenA>"

  # Test TokenB:
  curl -i -s http://localhost:3000/me \
    -H "Authorization: Bearer <TokenB>"
  ```
- **Expected Result:**
  - Global logout returns `204 No Content`.
  - `TokenA` returns `401 Unauthorized`.
  - `TokenB` returns `401 Unauthorized`.
- **Security Property Being Tested:** `auth.revokeAllForUser()` atomicity and complete user session invalidation.
- **Evidence to Capture:** Status code 204 followed by 401 for both tokens.

---

### MT-11: Password Reset Session Revocation Cascade
- **Test ID:** MT-11
- **Attack Name:** Password Reset Active Session Revocation
- **Objective:** Verify that completing a password reset immediately revokes all active sessions for that user to prevent account persistence by an attacker.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** User `alice@example.com` has an active session (`TokenA`).
- **Exact Request / Command:**
  ```bash
  # 1. Request password reset token:
  curl -s -X POST http://localhost:3000/auth/password/forgot \
    -H "Content-Type: application/json" \
    -d '{"email":"alice@example.com"}'

  # 2. Complete reset with valid token:
  curl -i -s -X POST http://localhost:3000/auth/password/reset \
    -H "Content-Type: application/json" \
    -d '{"token":"<VALID_TOKEN>","password":"BrandNewPassword123!"}'

  # 3. Attempt to access /me with the pre-existing session token:
  curl -i -s http://localhost:3000/me \
    -H "Authorization: Bearer <TokenA>"
  ```
- **Expected Result:**
  - Step 2 returns `204 No Content`.
  - Step 3 returns `401 Unauthorized`.
- **Security Property Being Tested:** Automatic session revocation on credential change (`revokeAllForUser(userId, 'credential_changed')`).
- **Evidence to Capture:** HTTP 401 on pre-existing session token.

---

## E. Refresh Token Attacks

### MT-12: Refresh Token Reuse Detection & Automatic Session Termination
- **Test ID:** MT-12
- **Attack Name:** Rotated Refresh Token Replay
- **Objective:** Verify that presenting an already-rotated refresh token is detected by Ninsho as theft, returns `401 Unauthorized`, and immediately revokes the entire session family.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** User logs in and receives refresh token `RT1` in cookie `ninsho_rt`.
- **Exact Setup:**
  ```bash
  # Step 1: Perform legitimate refresh using RT1:
  curl -i -s -X POST http://localhost:3000/auth/refresh \
    -H "Cookie: ninsho_rt=<RT1>"
  # Server returns RT2 and clears RT1.
  ```
- **Exact Request / Command:**
  ```bash
  # Step 2: Attacker replays already-spent RT1:
  curl -i -s -X POST http://localhost:3000/auth/refresh \
    -H "Cookie: ninsho_rt=<RT1>"

  # Step 3: Legitimate client tries to use new RT2:
  curl -i -s -X POST http://localhost:3000/auth/refresh \
    -H "Cookie: ninsho_rt=<RT2>"
  ```
- **Expected Result:**
  - Step 2 returns `401 Unauthorized` with:
    `{"error":{"code":"REFRESH_REUSE_DETECTED","message":"Session could not be renewed"}}`
  - Step 3 returns `401 Unauthorized` (entire session was destroyed due to reuse detection).
  - Response header includes `Set-Cookie: ninsho_rt=; ... Max-Age=0` (cookie wiped).
- **Security Property Being Tested:** Refresh token rotation with automatic reuse detection and breach containment.
- **Evidence to Capture:** Both 401 responses, cleared cookies, server log stating `refresh token reuse detected`.

---

### MT-13: Concurrent Refresh Token Rotation Race Condition
- **Test ID:** MT-13
- **Attack Name:** Concurrent Refresh Token Double-Spend Race
- **Objective:** Verify that under concurrent identical refresh requests, exactly one caller succeeds and the other is safely rejected without creating duplicate sessions.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** Active refresh token `RT_ORIG`.
- **Exact Request / Command:**
  Dispatch 2 simultaneous HTTP POST requests to `/auth/refresh` carrying `Cookie: ninsho_rt=RT_ORIG`.
- **Expected Result:**
  - Exactly one request returns `200 OK` with a new token pair.
  - The other request returns `401 Unauthorized`.
  - Atomic `store.take()` guarantees mutual exclusion.
- **Security Property Being Tested:** Atomicity of refresh token consumption (single-winner invariant).
- **Evidence to Capture:** One HTTP 200 and one HTTP 401 response status.

---

## F. Authorization Attacks

### MT-14: Broken Object Level Authorization (BOLA/IDOR) on Orders
- **Test ID:** MT-14
- **Attack Name:** Insecure Direct Object Reference on User Orders
- **Objective:** Verify that User Alice cannot access User Bob's orders by altering the route parameter `:id`.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** User Alice (`usr_alice`) and User Bob (`usr_bob`) exist. Alice holds valid `TokenAlice`.
- **Exact Request / Command:**
  ```bash
  # Alice calls her own orders route:
  curl -i -s -H "Authorization: Bearer <TokenAlice>" http://localhost:3000/users/<ALICE_ID>/orders

  # Alice attempts to access Bob's orders:
  curl -i -s -H "Authorization: Bearer <TokenAlice>" http://localhost:3000/users/<BOB_ID>/orders
  ```
- **Expected Result:**
  - Alice accessing her own orders: `200 OK` (`{"orders":[]}`).
  - Alice accessing Bob's orders: `403 Forbidden` with body:
    `{"error":{"code":"FORBIDDEN","message":"Insufficient permissions"}}`
  - Server audit log emits `authz.denied` with reason `caller does not own the requested resource`.
- **Security Property Being Tested:** `requireOwner((req) => req.params?.['id'])` resource ownership enforcement.
- **Evidence to Capture:** HTTP 200 vs HTTP 403 responses and audit denial log.

---

### MT-15: Role-Based Access Control (RBAC) Privilege Escalation
- **Test ID:** MT-15
- **Attack Name:** Unauthorized Access to Administrator Endpoint
- **Objective:** Verify that a user with the default `user` role is refused access to an administrative endpoint requiring the `admin` role.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** User Alice registered with default role `['user']`, holding `TokenAlice`.
- **Exact Request / Command:**
  ```bash
  curl -i -s -H "Authorization: Bearer <TokenAlice>" http://localhost:3000/admin/reports
  ```
- **Expected Result:**
  - HTTP Status: `403 Forbidden`
  - Response Body: `{"error":{"code":"FORBIDDEN","message":"Insufficient permissions"}}`
  - Server audit log records `authz.denied` with reason `requires one of role: admin`.
- **Security Property Being Tested:** `requireRole('admin')` role enforcement.
- **Evidence to Capture:** HTTP 403 status code and audit event log.

---

### MT-16: Multi-Tenant Boundary Crossing Attempt
- **Test ID:** MT-16
- **Attack Name:** Cross-Tenant Resource Access
- **Objective:** Verify that a caller belonging to Tenant A cannot access resources scoped to Tenant B.
- **Target Application:** `playground` (`http://localhost:4000`)
- **Prerequisites:** Playground running on port 4000.
- **Exact Request / Command:**
  ```bash
  curl -i -s -X POST http://localhost:4000/api/authz/tenant
  ```
- **Expected Result:**
  - Allowed when caller tenant matches route tenant (`expected: 'allowed'`).
  - Refused with HTTP 403 when caller tenant is `acme` and route tenant is `globex` (`auditReason: "caller belongs to tenant acme, requested globex"`).
  - Refused with HTTP 403 when caller has no tenant.
- **Security Property Being Tested:** `requireTenant((req) => req.params?.['tenant'])` isolation.
- **Evidence to Capture:** JSON checks response demonstrating tenant refusal.

---

## G. Rate Limiting Attacks

### MT-17: Sliding-Window Login Brute-Force Rate Limiting
- **Test ID:** MT-17
- **Attack Name:** Login Credential Brute-Force Attack
- **Objective:** Verify that exceeding the configured per-account or per-IP threshold on `/auth/login` results in HTTP 429 and blocks further attempts.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** User `target@example.com` exists. Login rate limit is 5 attempts per 15-minute window for a specific account.
- **Exact Request / Command:**
  Send 6 rapid failed login attempts for `target@example.com`.
  ```bash
  for i in {1..6}; do
    curl -i -s -X POST http://localhost:3000/auth/login \
      -H "Content-Type: application/json" \
      -d '{"email":"target@example.com","password":"BadPassword123!"}'
  done
  ```
- **Expected Result:**
  - Attempts 1-5 return `401 Unauthorized`.
  - Attempt 6 returns `429 Too Many Requests` with body:
    `{"error":{"code":"RATE_LIMIT_EXCEEDED","message":"Too many requests"}}`
  - Response headers include `Retry-After: <seconds>`.
- **Security Property Being Tested:** Sliding-window rate limiter in two dimensions (`perAccount` limit).
- **Evidence to Capture:** HTTP 429 response status and `Retry-After` header.

---

### MT-18: Client IP Header Spoofing Bypass (`X-Forwarded-For`)
- **Test ID:** MT-18
- **Attack Name:** Spoofed X-Forwarded-For Rate Limit Evasion
- **Objective:** Verify that when `trustProxy: false`, rotating `X-Forwarded-For` headers does not bypass the per-IP rate limit.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** `express-api` configured with `trustProxy: false` (the default in `index.ts`).
- **Exact Request / Command:**
  Send 25 login requests from the same connection while setting arbitrary random values in `X-Forwarded-For: 1.2.3.4`, `5.6.7.8`, etc.
- **Expected Result:**
  - Requests beyond the IP limit (20 requests) return HTTP `429 Too Many Requests`.
  - The server reads the actual socket remote address, ignoring the spoofed headers.
- **Security Property Being Tested:** Secure IP resolution (`clientIp()` ignores unconfigured proxy headers).
- **Evidence to Capture:** HTTP 429 response showing the spoofed header was ineffective.

---

## H. DPoP Proof-of-Possession Attacks

### MT-19: DPoP Proof Replay Detection (`jti` Guard)
- **Test ID:** MT-19
- **Attack Name:** Replay of Captured DPoP Proof
- **Objective:** Verify that a stolen DPoP proof JWT cannot be reused on a second request with the same `jti`.
- **Target Application:** `playground` (`http://localhost:4000`)
- **Prerequisites:** Active session bound to DPoP key via `POST /api/dpop/bind`.
- **Exact Request / Command:**
  ```bash
  # Send initial valid DPoP request:
  curl -i -s -X POST http://localhost:4000/api/dpop/call \
    -H "Content-Type: application/json" \
    -d '{"thumbprint":"<THUMBPRINT>","proof":"<DPOP_PROOF_JWT>"}'

  # Replay identical DPoP proof:
  curl -i -s -X POST http://localhost:4000/api/dpop/call \
    -H "Content-Type: application/json" \
    -d '{"thumbprint":"<THUMBPRINT>","proof":"<DPOP_PROOF_JWT>"}'
  ```
- **Expected Result:**
  - Request 1 succeeds (`accepted: true`).
  - Request 2 is rejected (`accepted: false`, `code: "DPOP_PROOF_REPLAYED"`, `message: "DPoP proof replayed"`).
- **Security Property Being Tested:** Replay protection using store-backed single-use `jti` thumbprints.
- **Evidence to Capture:** JSON response containing `DPOP_PROOF_REPLAYED` rejection.

---

### MT-20: Unbound DPoP Token Theft (Omission of Proof)
- **Test ID:** MT-20
- **Attack Name:** Presenting DPoP-Bound Token Without Proof
- **Objective:** Verify that presenting a DPoP-bound access token without a proof is refused.
- **Target Application:** `playground` (`http://localhost:4000`)
- **Exact Request / Command:**
  ```bash
  curl -i -s -X POST http://localhost:4000/api/dpop/call \
    -H "Content-Type: application/json" \
    -d '{"thumbprint":"<THUMBPRINT>","omitProof":true}'
  ```
- **Expected Result:**
  - Server returns `{"accepted":false,"code":"DPOP_PROOF_MISSING","message":"DPoP proof required"}`.
- **Security Property Being Tested:** DPoP proof-of-possession requirement (tokens cannot be used as bearer credentials).
- **Evidence to Capture:** Response body showing `DPOP_PROOF_MISSING`.

---

### MT-21: Invalid / Corrupted DPoP Proof Presentation
- **Test ID:** MT-21
- **Attack Name:** Corrupted DPoP Proof
- **Objective:** Verify that presenting a syntactically invalid or non-JWT DPoP proof is rejected.
- **Target Application:** `playground` (`http://localhost:4000`)
- **Exact Request / Command:**
  ```bash
  curl -i -s -X POST http://localhost:4000/api/dpop/call \
    -H "Content-Type: application/json" \
    -d '{"thumbprint":"<THUMBPRINT>","proof":"garbage.invalid.proof"}'
  ```
- **Expected Result:**
  - Server returns `{"accepted":false,"code":"DPOP_PROOF_INVALID","message":"DPoP proof invalid"}`.
- **Security Property Being Tested:** Robust DPoP proof JWT validation.
- **Evidence to Capture:** Response body showing `DPOP_PROOF_INVALID`.

---

## I. Claims & Step-Up Attacks

### MT-22: Step-Up Authentication Window Expiry (`requireFreshAuth`)
- **Test ID:** MT-22
- **Attack Name:** Stale Session Bypassing Step-Up Authentication
- **Objective:** Verify that an old session that has been refreshed cannot perform sensitive operations requiring fresh authentication.
- **Target Application:** `playground` (`http://localhost:4000`)
- **Exact Request / Command:**
  ```bash
  curl -i -s -X POST http://localhost:4000/api/authz/step-up
  ```
- **Expected Result:**
  - Initial call immediately after sign-in: allowed (`allowed: true`).
  - Call after 1-second window: refused with `403 Forbidden` (`allowed: false`, reason: `authentication is Xs old, needs to be under Ys`).
  - Refreshing session does NOT reset `authenticatedAt` freshness window.
- **Security Property Being Tested:** `requireFreshAuth(maxAgeSeconds)` enforcing `authTime` freshness rather than session refresh freshness.
- **Evidence to Capture:** JSON checks array demonstrating step-up expiry and refresh immunity.

---

### MT-23: OAuth Scope Insufficiency Verification (`requireScope`)
- **Test ID:** MT-23
- **Attack Name:** Scope Elevation Attack
- **Objective:** Verify that a token carrying `orders:read` cannot access a mutation route requiring `orders:write`.
- **Target Application:** `playground` (`http://localhost:4000`)
- **Exact Request / Command:**
  ```bash
  curl -i -s -X POST http://localhost:4000/api/authz/scopes
  ```
- **Expected Result:**
  - Reader token accessing write endpoint is refused with HTTP 403 (`requires scope: orders:write`).
  - Root admin without scopes is refused on scoped endpoints.
- **Security Property Being Tested:** Fine-grained scope verification (`requireScope`).
- **Evidence to Capture:** Response checks array in `/api/authz/scopes`.

---

## J. Malformed Input Attacks

### MT-24: Oversized Request Body DoS (>16 KB Payload Limit)
- **Test ID:** MT-24
- **Attack Name:** Large Payload Memory Exhaustion Attack
- **Objective:** Verify that the server strictly enforces the 16 KB body limit on JSON endpoints before attempting expensive parsing or cryptographic operations.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Exact Request / Command:**
  ```bash
  node -e "process.stdout.write(JSON.stringify({email:'test@example.com',password:'a'.repeat(32768)}))" | \
    curl -i -s -X POST http://localhost:3000/auth/login \
      -H "Content-Type: application/json" \
      --data-binary @-
  ```
- **Expected Result:**
  - HTTP Status: `413 Payload Too Large`
  - Response Body: `{"error":{"code":"BAD_REQUEST","message":"Request could not be processed"}}`
  - Server does not leak parser offsets or memory buffers.
- **Security Property Being Tested:** Early request body size capping (`express.json({ limit: '16kb' })`) to prevent scrypt/Argon2 memory exhaustion.
- **Evidence to Capture:** HTTP status 413 and clean error response.

---

### MT-25: Malformed URI Cookie Header Injection (`Cookie: ninsho_rt=%`)
- **Test ID:** MT-25
- **Attack Name:** Malformed Cookie URI-Encoding Server Crash Attempt
- **Objective:** Verify that an invalid URI-encoded cookie (e.g. `Cookie: ninsho_rt=%`) is handled gracefully as an absent credential (HTTP 401) rather than crashing with an unhandled `URIError: URI malformed` (HTTP 500).
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Exact Request / Command:**
  ```bash
  curl -i -s -X POST http://localhost:3000/auth/refresh \
    -H "Cookie: ninsho_rt=%"
  ```
- **Expected Result:**
  - HTTP Status: `401 Unauthorized`
  - Body: `{"error":{"code":"REFRESH_INVALID","message":"Session could not be renewed"}}`
  - Server process does not crash.
- **Security Property Being Tested:** Robust cookie parsing defending against malformed URI escape sequences.
- **Evidence to Capture:** HTTP 401 response status.

---

## K. WebAuthn / Passkey Attacks

### MT-26: WebAuthn Authentication Assertion Replay
- **Test ID:** MT-26
- **Attack Name:** Passkey Assertion Replay Attack
- **Objective:** Verify that replaying a completed WebAuthn ceremony assertion is rejected because the single-use challenge in the store has already been consumed.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Prerequisites:** A completed passkey assertion payload.
- **Exact Request / Command:**
  Send the exact same `clientDataJSON`, `authenticatorData`, and `signature` to `/auth/passkey/login/finish` a second time.
- **Expected Result:**
  - HTTP Status: `401 Unauthorized`
  - Body: `{"error":{"code":"PASSKEY_REJECTED","message":"Could not sign in with that passkey"}}`
- **Security Property Being Tested:** Single-use cryptographic challenge consumption in `finishAuthentication()`.
- **Evidence to Capture:** HTTP 401 response.

---

### MT-27: User Handle Impersonation in Passkey Login
- **Test ID:** MT-27
- **Attack Name:** Passkey User Handle Substitution Attack
- **Objective:** Verify that modifying the `userHandle` in a passkey assertion payload does not allow logging into an arbitrary user's account without a valid credential signature matching that account.
- **Target Application:** `express-api` (`http://localhost:3000`)
- **Expected Result:**
  - HTTP `401 Unauthorized`
  - Body: `{"error":{"code":"PASSKEY_REJECTED","message":"Could not sign in with that passkey"}}`
- **Security Property Being Tested:** Binding between credential public key, signature counter, and user principal.
- **Evidence to Capture:** HTTP 401 response.
