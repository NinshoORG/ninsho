# SecureShop — Ninsho Viva Demonstration Showcase

**Educational demonstration application for external viva examination.**  
Demonstrates real authentication invariants, cryptographic proof-of-possession, centralized server-side revocation, and cross-tab session lifecycle synchronization against real Redis and published npm packages.

---

## 1. Executive Summary & Architecture

SecureShop is a self-contained demonstration e-commerce portal that contrasts three authentication paradigms under identical application requirements:

| Comparison | Architecture | Storage Location | Revocation Behavior | Replay Resistance |
|---|---|---|---|---|
| **Comparison A**<br>Stateless JWT Baseline | Signed HS256 JWT via `jose` library | Browser `localStorage` | **Fails open.** Server retains no state; tokens remain accepted until `exp` (5m) elapses. | **Vulnerable.** Copied bearer tokens replay without restriction. |
| **Comparison B**<br>Ninsho Opaque (Dual-Instance) | 256-bit CSPRNG token via `@ninshorg/server` | Redis store (`secureshop:opaque:`) | **Fails closed.** Centralized `revokeSession` immediately rejects across Instance A and Instance B. | **Vulnerable to bearer copy before logout**, but revoked globally upon logout. |
| **Comparison C**<br>Ninsho DPoP Browser Client | RFC 9449 Proof-of-Possession via `@ninshorg/client` | In-memory token; non-extractable key in `IndexedDB` | **Fails closed.** Server revokes session; `sessionSync` broadcasts invalidation to peer tabs. | **Protected.** Token bound to client key thumbprint (`jti` replay guard + `ath` hash). Token-only replay fails (401). |

---

## 2. Prerequisites & Installation

This directory is an independent consumer application. It installs published packages from npm (`@ninshorg/server@0.1.1` and `@ninshorg/client@0.1.1`).

### Prerequisites
- Node.js 20+ and npm 10+
- A running Redis 6.2+ instance on `redis://127.0.0.1:6379` (or set `REDIS_URL`)

### Quick Setup

```bash
# 1. Start a disposable Redis container (if not already running)
docker run -d --rm -p 127.0.0.1:6379:6379 --name secureshop-redis redis:7-alpine

# 2. Navigate to the showcase directory
cd demo/viva-showcase

# 3. Clean install published packages
npm ci

# 4. Verify types and run automated test suite
npm run typecheck
npm test

# 5. Start the showcase server
npm start
# -> Access at http://localhost:3000
```

The server listens on `127.0.0.1` only, because the seeded accounts have
published passwords. To show it to another device on your network, opt in
with `HOST=0.0.0.0 npm start` and stop it when you are done. There is no CORS
middleware: the UI is served from the same origin as the API, so nothing
cross-origin needs access.

---

## 3. Seeded Accounts

The application includes two pre-configured demonstration accounts:

- **Admin Account:** `alice@example.com` / `password123` (Name: Alice Vance, Role: admin)
- **Customer Account:** `bob@example.com` / `password123` (Name: Bob Smith, Role: customer)

*(Click the "One-Click Seeded Accounts" buttons in the UI to autofill).*

---

## 4. Examiner Walkthrough (8 Steps with Developer Tools)

Follow this 8-step walkthrough to reproduce every security property using standard browser developer tools (F12):

### Step 1: Stateless JWT Sign-In
1. In the header strategy bar, select **Stateless JWT Baseline**.
2. Click **Alice Vance (Admin)** and submit.
3. Observe successful authentication and order retrieval for Alice.

### Step 2: Inspect Application Local Storage
1. Open DevTools (F12) &rarr; **Application** tab &rarr; **Storage** &rarr; **Local Storage** &rarr; `http://localhost:3000`.
2. Locate the key `secureshop_jwt_token`. Notice the raw signed JWT string accessible to any script executing in this origin.

### Step 3: Inspect Network Bearer Header
1. Open DevTools &rarr; **Network** tab &rarr; filter `Fetch/XHR`.
2. Click **Reload Orders via API**.
3. Inspect the request to `/api/jwt/dashboard`:
   - Request Header: `Authorization: Bearer eyJhbGciOi...`
   - Response: `HTTP 200 OK`

### Step 4: Demonstrate Stateless JWT Replay Limitation
1. Navigate to the **🔬 Security Experiments Lab** tab &rarr; **Comparison A**.
2. Click **Capture Token** (copies the live JWT into a demonstration memory variable).
3. Click **Logout (Clear LocalStorage)**. The client clears its local storage.
4. Click **⚠️ Replay Token** (sends the previously captured token to `/api/jwt/dashboard`).
5. **Observed Outcome:** **`HTTP 200 OK`!** The server accepts the copied token because a pure stateless implementation has no revocation record.

### Step 5: Demonstrate Ninsho Opaque Centralized Revocation
1. In the Security Lab &rarr; **Comparison B**, click **Login Alice (Opaque)**.
2. Click **Query Inst A** &rarr; returns `HTTP 200 OK` (processed by Instance A).
3. Click **Query Inst B** &rarr; returns `HTTP 200 OK` (processed by Instance B over the shared Redis store).
4. Click **Revoke via Inst A** (simulates confirmed logout).
5. Click **Replay on Inst A** &rarr; returns **`HTTP 401 Unauthorized` (`TOKEN_INVALID`)**.
6. Click **Replay on Inst B** &rarr; returns **`HTTP 401 Unauthorized` (`TOKEN_INVALID`)** immediately.

### Step 6: Inspect Ninsho DPoP Client Protection
1. In the header strategy bar, select **Ninsho DPoP (Recommended)**.
2. Log in as **Bob Smith**.
3. Open DevTools &rarr; **Application** &rarr; **Local Storage**:
   - Verify that the access token is **absent** (held in private client memory).
4. Open DevTools &rarr; **Application** &rarr; **IndexedDB** &rarr; `secureshop-dpop-keys` &rarr; `keys`:
   - Inspect the stored CryptoKey: `extractable: false`. The raw private key bytes cannot be read by JavaScript.
5. Open DevTools &rarr; **Cookies** &rarr; `http://localhost:3000`:
   - Observe `ninsho_dpop_rt` with flags: `HttpOnly: true`, `SameSite: Lax`, `Path: /api/dpop`.
6. Open DevTools &rarr; **Network** &rarr; inspect request to `/api/dpop/orders`:
   - `Authorization: DPoP <access_token>`
   - `DPoP: <fresh_rfc9449_proof_jwt>`

### Step 7: Demonstrate DPoP Attack Resistance
1. In the Security Lab &rarr; **Comparison C**:
2. Click **Simulate Token Theft Replay**:
   - Sends the stolen access token without a DPoP proof.
   - **Outcome:** **`HTTP 401 Unauthorized`** (`token is DPoP-bound but no proof was presented`).
3. Click **Attack with Wrong Key**:
   - Sends a proof signed by an unrelated key.
   - **Outcome:** **`HTTP 401 Unauthorized`** (key thumbprint `jkt` mismatch).
4. Click **Replay Captured Proof**:
   - Replays an already-used proof header.
   - **Outcome:** **`HTTP 401 Unauthorized`** (`dpop_proof_replayed`).

### Step 8: Two-Tab Session Synchronization
1. Click **🔗 Open Second Tab for Demonstration**.
2. Position both tabs side-by-side. Both show Bob's active orders.
3. In Tab 1, click **Log Out Session**.
4. Observe Tab 2:
   - Tab 2 instantly receives the `BroadcastChannel` invalidation notice.
   - Tab 2 discards its in-memory access token and updates its UI to logged-out state.
   - No credentials or tokens were ever transmitted between tabs.

---

## 5. Five-Minute Viva Presentation Script

1. **Problem Statement (Minute 1):**  
   "Modern web applications struggle with the trade-off between stateless tokens (JWT) and stateful sessions. Stateless tokens are widely used for performance, but as we demonstrate in Comparison A, standard stateless JWTs cannot be revoked upon user logout without introducing server state. A stolen token remains valid until expiry."

2. **Ninsho Centralized Revocation (Minute 2):**  
   "In Comparison B, Ninsho demonstrates its default opaque session architecture. Using 256-bit CSPRNG tokens keyed by SHA-256 hashes in Redis, revocation is immediate across multiple application instances. When a session is revoked on Instance A, Instance B rejects replayed requests in real time with zero synchronization delay."

3. **Proof-of-Possession with DPoP (Minute 3):**  
   "In Comparison C, we demonstrate RFC 9449 DPoP using `@ninshorg/client`. The browser generates a non-extractable WebCrypto key in IndexedDB. Every HTTP request requires a fresh cryptographic signature over the method and URL. Even if an attacker intercepts the access token from a server log or network trace, they cannot replay it without holding the private key."

4. **Multi-Tab Session Sync (Minute 4):**  
   "We also demonstrate Ninsho's `sessionSync` feature. When a user logs out in one tab, an invalidation message is sent over `BroadcastChannel`. Other open tabs immediately discard their in-memory access tokens without transmitting secrets or tokens across tabs."

5. **Threat Model & Boundaries (Minute 5):**  
   "It is crucial to state the security boundaries honestly. DPoP prevents network and server-side token replay, but does not stop malicious in-origin JavaScript (XSS) from requesting signatures through the active page context. Furthermore, Ninsho is pre-release software (`0.1.1`) and has not yet undergone independent third-party commercial cryptographic audit."

---

## 6. Automated Test Suite

Run the automated verification suite:

```bash
npm test
```

The test runner (`vitest`) boots the Express server, connects to Redis, and executes:
- **Comparison A test:** Confirms JWT issuance, dashboard acceptance, and post-logout replay vulnerability.
- **Comparison B test:** Confirms dual-instance verification and immediate cross-instance revocation rejection (HTTP 401).
- **Comparison C test:** Confirms DPoP proof acceptance, token-only replay rejection (HTTP 401), wrong-key rejection (HTTP 401), and single-use JTI proof replay rejection (HTTP 401).

---

## 7. Known Limitations & Disclosures

- **Stateless Baseline Scope:** The stateless JWT baseline is an illustrative implementation. JWT specifications permit stateful denylists, session versions, and sender-constrained tokens when additional infrastructure is added.
- **XSS Threat Model:** DPoP prevents exported-key replay and token reuse across machines; it does not protect against malicious script executing within the authenticated origin.
- **Pre-Release Status:** Ninsho is published at `v0.1.1` and remains pre-1.0. It is an educational prototype and has not been certified by an external commercial cryptographic audit firm.
