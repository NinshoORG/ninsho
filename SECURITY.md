# Security

## Reporting a vulnerability

> **⚠️ MAINTAINER: fill this in before the first public release.**
>
> This section is deliberately blank rather than filled with a plausible-looking
> address. The predecessor's security policy pointed at a GitHub advisory URL
> for an organisation the repository had moved away from, and listed two
> different contact addresses. A researcher who found a real bug had no working
> way to report it privately, which is worse than having no policy at all.
>
> Before publishing, replace this block with:
> - a private reporting channel that has been tested end to end (GitHub private
>   security advisories are the low-effort option, and they work)
> - a response-time commitment you can actually keep
> - a `.well-known/security.txt` per RFC 9116, with an `Expires` date you will
>   renew

**Please do not open a public issue for a security vulnerability.**

---

## Status

Ninsho is **pre-release (v0.1.0) and not published**. It has not been
independently audited. Do not deploy it to production without your own review.

---

## What this project promises

> **A security property stated in the documentation must name the test that
> demonstrates it, or it does not get stated.**

This rule exists because of how the predecessor failed. It advertised "instant
revocation", "110 tests" and "all attacks blocked". In fact its CI had not run
since the release commit, 8 of 9 test files failed to import, and its attack
suite exercised a reimplementation of the middleware rather than the shipped
one. None of that was dishonest by intent — the claims simply outran the
evidence, which for an authentication library is the same thing.

Every property below names its test. The [README](./README.md) table maps each
claim to the file that proves it.

---

## Security model

### What Ninsho is responsible for

Everything that happens **after** identity is established: issuing session
credentials, verifying them, rotating them, revoking them, and answering
whether a caller may do a given thing.

### What Ninsho is deliberately not responsible for

- **Credential verification.** Passwords, WebAuthn, federated sign-in. Owning
  these would mean owning your user model.
- **Password hashing.** The example demonstrates scrypt at OWASP parameters;
  the library ships no hashing.
- **Transport security.** Run behind TLS. Ninsho cannot detect that you have not.
- **CSRF for your own routes.** Ninsho's credentials are bearer tokens in an
  `Authorization` header, which is not automatically attached by browsers. If
  you additionally place a session in a cookie, CSRF becomes your concern.
- **Input validation for your application.** Ninsho validates its own inputs
  and nothing else.

---

## Threat model

### Assets

Access tokens, refresh tokens, signing keys (paseto mode), session records, the
authorization data inside a `Principal`.

### Adversaries

| Adversary | Assumed capability |
| :--- | :--- |
| Unauthenticated attacker | Can send arbitrary requests, including forged tokens and headers |
| Authenticated user | Holds a valid session; will try to reach other users' data |
| Token thief | Has obtained a token via XSS, a log, a proxy, or a shared device |
| Network attacker | Can observe or modify traffic not protected by TLS |
| Store-read attacker | Has read access to Redis — a backup, a replica, an exposed instance |
| Malicious operator / bad deploy | Can set environment variables and change configuration |

### Threats and their status

| Threat | Status | Evidence |
| :--- | :--- | :--- |
| Token forgery, algorithm confusion | **Mitigated** | PASETO fixes Ed25519 in the version string; there is no `alg` field to attack. `paseto-v4.test.ts` › *algorithm confusion* |
| Signature tampering, footer swapping | **Mitigated** | PAE covers header, payload and footer. Official spec vectors reproduced byte for byte |
| Forged `kid` selecting an attacker's key | **Mitigated** | Key lookup precedes signature verification, which then fails. `paseto-engine.test.ts` |
| Cross-service token reuse | **Mitigated** | `iss` and `aud` required and validated in paseto mode |
| Use of a revoked token | **Mitigated** | Fail-closed by default; fail-open rejected where it could not take effect |
| Refresh token theft | **Detected** | Reuse revokes the whole family and emits `refresh.reuse_detected` (RFC 9700 §4.14.2) |
| Session extended indefinitely by rotation | **Mitigated** | `familyExpiresAt` is fixed at creation and never extended |
| Broken object-level authorization (BOLA) | **Mitigated where used** | `requireOwner()`. Ninsho cannot force you to mount it |
| Cross-tenant access | **Mitigated where used** | `requireTenant()`; a token with no tenant claim never passes |
| Credential stuffing, distributed | **Mitigated** | Per-account rate-limit bucket, not per-IP alone |
| Rate-limit bypass via `X-Forwarded-For` | **Mitigated** | Hop-counting from the trusted end; `trustProxy` has no default |
| Account enumeration | **Application's responsibility** | The example shows a constant-time login path; the library cannot enforce it |
| Store-read attacker replaying credentials | **Mitigated** | Only SHA-256 hashes are stored. One exception below |
| Timing side-channels on secret comparison | **Mitigated** | `safeEqual` is constant-time and fails closed on malformed input |
| Internal detail leaking to clients | **Mitigated** | `detail` is structurally separate from `message` |
| Test double reaching production | **Mitigated** | Store is injected; CI fails the build if one appears in `dist/` |
| **Access-token replay by a thief** | **NOT mitigated** | See below |
| **Signing-key compromise** | **Partially** | Rotation is possible without downtime; detection is not provided |

---

## Known limitations

Stated plainly, because a limitation you know about is manageable and one you
have been reassured about is not.

### Bearer tokens can be replayed

Anyone holding a valid access token can use it. Ninsho does not detect that the
holder is not the original recipient, and **no configuration changes this**.

This is the same guarantee every mainstream bearer-token system provides. It is
called out because the predecessor claimed otherwise: it advertised "token
replay attacks: blocked" on the strength of hashing the `User-Agent` header —
a value the attacker sets. That feature is gone rather than renamed.

Real replay resistance means proof-of-possession. The `cnf` claim slot and the
`BindingMode` type are reserved for DPoP (RFC 9449), and selecting
`binding: 'dpop'` throws today rather than silently doing nothing.

Mitigate meanwhile with short access-token lifetimes (300s by default), TLS, and
`refresh.reuse_detected` alerting.

### One raw token is stored, briefly

When a refresh token rotates, the raw replacement is written to
`ninsho:v1:rtg:*` for the grace window (30s by default) so a parallel browser
tab that lost the race can adopt it rather than being signed out.

This is the one place a raw credential exists in the store. It is bounded to
seconds rather than the token's lifetime, and setting `refreshGraceSeconds: 0`
removes it entirely at the cost of occasional multi-tab logouts.

### Reuse detection has a false-positive floor

Outside the grace window, a legitimate client that is two or more rotations
stale is indistinguishable from an attacker, and its session ends. Widening the
window trades that against how quickly a genuine replay is caught. This is
inherent to rotation-based detection, not specific to Ninsho.

### `MemoryStore` is per-process

It refuses to construct under `NODE_ENV=production`. Nothing stops you unsetting
`NODE_ENV`.

---

## Security-sensitive defaults

Every default below is chosen to be the safe option and asserted in
`config.test.ts` › *secure defaults*.

| Setting | Default | Why |
| :--- | :--- | :--- |
| `strategy` | `opaque` | No signing keys exist, so none can leak. Revocation is native and immediate |
| `onStoreError` | `closed` | If revocation cannot be checked, the guarantee cannot be honoured |
| `accessTokenTtl` | `300` (5 min) | Bounds the window in which a stolen token is useful |
| `refreshTokenTtl` | `604800` (7 days) | Hard ceiling; rotation never extends it |
| `refreshGraceSeconds` | `30` | Absorbs a multi-tab race without meaningfully blunting detection |
| `binding` | `none` | Bearer semantics, stated rather than implied |
| `clockToleranceSeconds` | `5` | Absorbs modest skew without materially extending validity |
| `trustProxy` | **none** | No safe default exists; guessing breaks the limiter in both directions |

Choices that weaken security are accepted but never silent: each emits a
`config.insecure` audit event at startup.

---

## Cryptography

| Purpose | Primitive | Source |
| :--- | :--- | :--- |
| Token signing (paseto) | Ed25519 | `node:crypto` |
| Token and id generation | CSPRNG, 256 / 128 bits | `node:crypto` `randomBytes` |
| Token storage | SHA-256 | `node:crypto` |
| Secret comparison | `timingSafeEqual` | `node:crypto` |

**Ninsho implements no cryptographic primitives.** What it does implement is
PASETO's Pre-Authentication Encoding — a length-prefixed concatenation — and
base64url framing, verified against the specification's own test vectors.

A plain SHA-256 is correct for token storage rather than a password hash: these
tokens carry 256 bits of CSPRNG entropy, so there is no guessable input to slow
down, and a deliberately slow hash on the verification hot path would be a
denial-of-service vector.

---

## Audit events worth alerting on

| Event | Meaning |
| :--- | :--- |
| `refresh.reuse_detected` | **Highest signal.** A rotated refresh token was replayed. One of the two holders is an attacker |
| `store.unavailable` | Revocation could not be checked. With `reason: admitted_without_revocation_check`, a token was accepted without one |
| `config.insecure` | A weakening configuration choice was made at startup |
| `authz.denied` | A caller was refused. A spike may indicate probing |
| `ratelimit.exceeded` | Sustained volume may indicate credential stuffing |

The audit sink is pluggable and wrapped so a throwing implementation cannot
fail an authentication.

---

## Standards referenced

- RFC 9700 — OAuth 2.0 Security Best Current Practice (§4.14.2, refresh reuse)
- RFC 9449 — DPoP (reserved, not implemented)
- RFC 8410 — Ed25519 in ASN.1
- RFC 7235 — HTTP authentication framework
- RFC 9116 — `security.txt`
- PASETO v4 specification
- OWASP ASVS v5, OWASP API Security Top 10 (2023), OWASP Password Storage Cheat Sheet
- NIST SP 800-63B — password guidance
