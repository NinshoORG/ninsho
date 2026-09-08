# Ninsho v0.1.0 Manual Security Testing Workspace

> **WARNING:**
> Never run these attack procedures against systems without authorization. All scripts, procedures, and payloads in this directory are designed solely for controlled security experiments against a local, isolated instance of the Ninsho reference applications (`localhost`).

---

## 1. Purpose

The `manualtest/` directory contains the manual and semi-automated security testing framework for Ninsho v0.1.0. While automated unit and integration tests (in `vitest`) verify expected function signatures and internal invariants, manual security testing validates the running application from an **external attacker's perspective over real HTTP**:

- Testing actual HTTP wire representations, headers, cookies, and TLS/cleartext boundaries.
- Verifying defensive fail-closed behavior when hostile, replayed, or mutated payloads are transmitted.
- Capturing objective HTTP evidence (response codes, response headers, audit log output) demonstrating attack prevention.

---

## 2. Separation of Concerns: Automated Tests vs. Manual Tests

| Dimension | Automated Unit Tests (`vitest`) | Manual Security Tests (`manualtest/`) |
|---|---|---|
| **Execution Point** | Internal code calling API functions (`auth.verify()`, `le64()`) | External HTTP clients sending raw TCP/HTTP requests to localhost |
| **Environment** | Test runner memory space, mocked or ephemeral fixtures | Live running Express processes (`examples/express-api`, `examples/playground`) |
| **Attacker Model** | Synthetic test assertions | Realistic attacker tools (`curl`, raw sockets, custom attack scripts) |
| **Verification** | Assertion passing | HTTP response status codes, header validation, audit event emission |

---

## 3. Local Target Services

Testing is executed against the two reference applications provided in the repository:

### Target A: `express-api` (Standard Production-style REST API)
- **Directory:** `examples/express-api`
- **Default Port:** `http://localhost:3000`
- **Features Tested:**
  - Session creation & authentication (`/auth/register`, `/auth/login`)
  - Refresh token rotation & reuse detection (`/auth/refresh`)
  - Session revocation (`/auth/logout`, `/auth/logout-all`)
  - Broken Object Level Authorization / IDOR (`/users/:id/orders` with `requireOwner`)
  - Role-Based Access Control (`/admin/reports` with `requireRole('admin')`)
  - Sliding-window two-dimensional rate limiting (`/auth/login`)
  - Malformed HTTP header / cookie handling (`Cookie: ninsho_rt=...`)
  - Password reset one-time token consumption (`/auth/password/forgot`, `/auth/password/reset`)

### Target B: `playground` (Interactive Protocol & Attack Explorer)
- **Directory:** `examples/playground`
- **Default Port:** `http://localhost:4000`
- **Features Tested:**
  - PASETO v4.public token decoding & tamper verification (`/api/anatomy/paseto`, `/api/session/verify`)
  - Proof-of-Possession DPoP key binding & replay attacks (`/api/dpop/bind`, `/api/dpop/call`)
  - Multi-tenant boundary isolation (`/api/authz/tenant`)
  - Step-up fresh authentication requirements (`/api/authz/step-up`)
  - Attestation format verification & tampered certificate rejection (`/api/attestation`)

---

## 4. How to Start Required Local Services

Before running any manual tests, start the target service(s):

### Option 1: Start `express-api` (Port 3000)
```bash
# In Terminal 1:
npm run dev --workspace @ninshorg/example-express-api
# Output: ninsho example listening on http://localhost:3000
```

*Optional with Redis:*
```bash
REDIS_URL=redis://localhost:6379 npm run dev --workspace @ninshorg/example-express-api
```

### Option 2: Start `playground` (Port 4000)
```bash
# In Terminal 2:
npm run dev --workspace @ninshorg/playground
# Output: listening on http://localhost:4000
```

---

## 5. How to Run Manual Tests & Attack Scripts

Each attack scenario in `manualtest/attacks/` includes a dedicated `README.md` detailing the manual curl/HTTP procedure and, where applicable, a safe automated script (`attack.ts`).

To execute a test script against the running local server:
```bash
node --experimental-strip-types manualtest/attacks/01-token-tampering/attack.ts
node --experimental-strip-types manualtest/attacks/05-refresh-replay/attack.ts
node --experimental-strip-types manualtest/attacks/06-cross-user-access/attack.ts
node --experimental-strip-types manualtest/attacks/07-rbac-escalation/attack.ts
node --experimental-strip-types manualtest/attacks/08-rate-limit/attack.ts
```

All scripts:
- Communicate **strictly with `http://localhost:3000` or `http://localhost:4000`**.
- Do not make external outbound network calls.
- Run controlled, non-destructive payloads.
- Print human-readable test steps, HTTP status codes, and server responses.

---

## 6. Evidence Collection & Storage

Evidence captured during manual testing must be saved under `manualtest/evidence/`:
- `manualtest/evidence/responses/`: Raw HTTP response headers and bodies (e.g. `mt-01-response.json`).
- `manualtest/evidence/logs/`: Terminal outputs and server-side audit logs (e.g. `audit-events.log`).
- `manualtest/evidence/screenshots/`: Terminal captures or UI inspection screenshots where visual confirmation is relevant.

---

## 7. Determining PASS vs. FAIL

A security test is evaluated against the principle of **failing closed and leak-free rejection**:

- **PASS:**
  1. The server rejects the hostile or invalid input with the expected HTTP status (e.g., `401 Unauthorized`, `403 Forbidden`, `429 Too Many Requests`, `400 Bad Request`).
  2. The server does NOT reveal internal debug traces, cryptographic key material, SQL/NoSQL syntax errors, or stack traces in the client-facing response body.
  3. The server logs the security event to its audit sink (e.g. `authz.denied`, `session.revoked`, `ratelimit.exceeded`).
  4. State integrity is preserved (e.g. replaying a refresh token revokes the entire session rather than minting duplicate access tokens).

- **FAIL:**
  1. The server grants unauthorized access or accepts a forged/tampered credential (HTTP 200).
  2. The server crashes (unhandled exception / process exit).
  3. The server provides an information oracle (e.g., distinguishing between non-existent user and wrong password, or revealing token decryption internals).
  4. The server fails open (e.g., accepting an unverified token during an error condition).
