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

- **Passwords and federated sign-in.** Owning these would mean owning your user
  model. Ninsho issues the single-use token a reset flow needs and tells you
  which subject redeemed it; hashing the password and storing it stay yours.

  WebAuthn is the one exception, and a deliberately narrow one:
  `@ninsho/webauthn` verifies the ceremony — challenge, origin, RP ID,
  signature, counter — and returns a `Principal`. It does not store credentials,
  own a user table, or decide what a user may do. Storage stays in your database
  next to the user it identifies.
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
| Refresh token theft | **Detected** | Reuse revokes the whole family and emits `refresh.reuse_detected` (RFC 9700 §4.14.2), classified by whether the replay came from the same client |
| Device fingerprinting presented as a control | **Structurally impossible** | Signals are recorded hashed and never branched on; `signals.test.ts` › *signals are never a control* |
| Session extended indefinitely by rotation | **Mitigated** | `familyExpiresAt` is fixed at creation and never extended |
| Broken object-level authorization (BOLA) | **Mitigated where used** | `requireOwner()`. Ninsho cannot force you to mount it |
| A long-lived session performing a sensitive operation | **Mitigated where used** | `requireFreshAuth()` reads the authentication time, which rotation does not reset; `fresh-auth.test.ts` |
| Cross-tenant access | **Mitigated where used** | `requireTenant()`; a token with no tenant claim never passes |
| Credential stuffing, distributed | **Mitigated** | Per-account rate-limit bucket, not per-IP alone |
| Rate-limit bypass via `X-Forwarded-For` | **Mitigated** | Hop-counting from the trusted end; `trustProxy` has no default |
| Account enumeration | **Application's responsibility** | The example shows a constant-time login path and an indistinguishable reset response; the library cannot enforce either |
| A reset link redeemed twice | **Mitigated** | Atomic `take()`; `one-time-token.test.ts` › *lets exactly one of many simultaneous clicks win* |
| A stolen database yielding usable reset links | **Mitigated** | Only `hashToken(raw)` is stored; the raw value exists solely in the email |
| A reset token replayed at a weaker endpoint | **Mitigated** | Purpose is part of the storage key, not a comparison |
| A stale reset link in an old inbox | **Mitigated** | 15-minute default; issuing a replacement invalidates the previous token via an atomic generation counter, verified race-free |
| Sessions surviving a password change | **Mitigated where used** | `revokeAllForUser('credential_changed')`; shown in the example, and Ninsho cannot force you to call it |
| Store-read attacker replaying credentials | **Mitigated** | Only SHA-256 hashes are stored. One exception below |
| Timing side-channels on secret comparison | **Mitigated** | `safeEqual` is constant-time and fails closed on malformed input |
| Internal detail leaking to clients | **Mitigated** | `detail` is structurally separate from `message` |
| Test double reaching production | **Mitigated** | Store is injected; CI fails the build if one appears in `dist/` |
| Access-token replay by a thief | **Mitigated under `binding: 'dpop'`** | `dpop-integration.test.ts` › *a stolen token is useless without the key* |
| DPoP proof replay | **Mitigated** | Single-use `jti`, store-backed (RFC 9449 §11.1) |
| Algorithm confusion in a DPoP proof | **Mitigated** | Allowlist; `dpop-proof.test.ts` › *algorithm confusion* |
| WebAuthn assertion replay | **Mitigated** | Single-use challenge consumed via atomic `take()`; `challenge.test.ts` › *lets exactly one of many concurrent attempts win* |
| Registration response replayed as a sign-in | **Mitigated** | `clientData.type` checked, and the ceremony type is part of the challenge key |
| Algorithm confusion in a COSE key | **Mitigated** | Allowlist, plus key type must match the algorithm; `cose.test.ts` › *algorithm confusion* |
| Undersized RSA credential key | **Mitigated** | 2048-bit floor measured in significant bits — WebCrypto alone accepts 512 |
| Credential used at a different origin or RP | **Mitigated** | Exact origin allowlist; RP ID hash compared against `SHA-256(rpId)` |
| Cloned authenticator | **Detected** | Sign-counter regression rejects by default (WebAuthn §6.1.1) |
| Ceremony completed against another account | **Mitigated** | Challenge user and credential owner must agree; `server.test.ts` › *binding a ceremony to its user* |
| Memory-safety bugs in attacker-facing parsers | **Mitigated** | Every length bounds-checked before use; CBOR, DER and authenticator-data parsers each fuzzed |
| **Authenticator provenance (attestation)** | **Mitigated** | Every format WebAuthn defines verified to relying-party roots, AAGUID cross-checked where the format conveys one; `attestation.test.ts`. What each one actually proves differs — see below |
| A SafetyNet verdict from a rooted device | **Mitigated** | `ctsProfileMatch` required; `basicIntegrity` alone is not accepted, because a rooted phone still reports it; `attestation.test.ts` › *refuses a device passing basicIntegrity alone* |
| A compromised vendor impersonating another vendor's model | **Mitigated** | `modelAnchors` pins each AAGUID to the roots its metadata entry names, so a leaf carrying another vendor's AAGUID does not reach a root that vouches for it; `mds.test.ts` |
| A DPoP proof scoped to another endpoint | **Mitigated** | `htu` is compared against a URI whose authority comes from the deployment, never from the request target — an absolute-form or protocol-relative target cannot replace it; `dpop-request.test.ts` |
| Rate-limit bypass by rotating `X-Forwarded-For` | **Mitigated** | The client is read at `chain.length - trustProxy`, so prepended entries sit outside the trusted span; `trustProxy` has no default. `ratelimit.test.ts` › *does not let a prepended entry become the resolved address* |
| **Credential ambiguity from a repeated Authorization header** | **Mitigated** | `rawHeaders` is consulted, because Node's HTTP server keeps the first `Authorization` and silently discards the rest — so `req.headers` shows one clean credential and a proxy validating a different occurrence would disagree about who is calling. Express, Fastify and Koa; see the note below for Hono. `api.test.ts` › *a repeated Authorization header* |
| Algorithm confusion in a SafetyNet JWS | **Mitigated** | The header names its own `alg`; an allowlist of exactly one (RS256) leaves nothing to negotiate; `attestation.test.ts` › *refuses a JWS header naming alg …* |
| A SafetyNet response captured from an earlier session | **Mitigated** | Nonce must hash this ceremony, and the timestamp must be recent; `attestation.test.ts` › *refuses a response captured from an earlier session* |
| A TPM statement certifying a key that is not the credential | **Mitigated** | `pubArea` compared against the credential key, and `attested.name` against `pubArea`; `attestation.test.ts` › *refuses a pubArea describing a key that is not the credential* |
| An Android key usable by every app on the device | **Mitigated** | `allApplications` refused in either authorization list; authorizations read from `teeEnforced` by default; `attestation.test.ts` › *refuses allApplications* |
| A U2F attestation read as naming a device model | **Mitigated** | U2F conveys no AAGUID, so `aaguidVerified` stays false and an AAGUID allowlist is refused rather than silently unenforceable |
| Forged attestation from a self-signed CA | **Mitigated** | Trust anchors are mandatory; `attestation.test.ts` › *refuses a chain that does not reach a configured root* |
| An attestation statement lifted from another device | **Mitigated** | The certificate's AAGUID must match the authenticator data |
| A CA certificate presented as an attestation leaf | **Mitigated** | Refused per §8.2.1 — a CA leaf could sign for other authenticators too |
| **Signing-key compromise** | **Partially** | Rotation is possible without downtime; detection is not provided |

---

## Known limitations

Stated plainly, because a limitation you know about is manageable and one you
have been reassured about is not.

### Account enumeration by timing on the reset endpoint

`/auth/password/forgot` in `examples/express-api` answers identically whether or
not an address has an account — same status, same body, tested. It does not
answer in identical *time*: a known address costs a one-time-token write that an
unknown one does not.

Measured rather than assumed. 120 samples each, medians:

| Store | Known address | Unknown address | Difference |
| :--- | ---: | ---: | ---: |
| `MemoryStore` | 1.267ms | 1.219ms | 4% |
| Redis (loopback) | 3.580ms | 3.449ms | 4% |

Four percent, and the rate limiter's own store round trips are most of what is
being measured either way. What makes the oracle impractical is not that
difference but the limit in front of it: three requests per address per hour,
ten per source address. Distinguishing a 4% difference over a network at three
samples an hour is not a practical attack.

It is stated here rather than equalised because the equalisation would be worse
than the problem: issuing a token for an address with no account means writing
a record for every probe, which is a storage amplification bounded only by the
same rate limit that already closes the gap. The login route *does* equalise,
with a dummy hash — the difference is that a password hash is ~100ms and
dominates the response, so there the leak would be obvious rather than marginal.

If you copy this example and remove the rate limiter, you have removed the
defence rather than an inconvenience.

### A repeated Authorization header is not caught on Hono

Node's HTTP server keeps the first `Authorization` header it receives and
silently discards the rest. That means `req.headers.authorization` shows a
single clean credential even when two were sent, and the ambiguity — which a
proxy in front might resolve the other way — is visible only in `rawHeaders`.

Express, Fastify and Koa all reach it, and refuse the request. Hono hands over
headers already collapsed and exposes no equivalent, so on `@hono/node-server`
the first credential is what the application reads. If you terminate TLS behind
a proxy that forwards duplicate headers rather than normalising them, prefer
one of the other three, or normalise at the edge.

### WebAuthn attestation: what each format actually proves

`@ninsho/webauthn` verifies every statement format WebAuthn L3 defines —
`none`, `packed`, `apple`, `tpm`, `fido-u2f`, `android-key` and
`android-safetynet`. A format name outside that set is refused, and
allowlisting it does not change that. There is deliberately no arrangement of
options that turns an unverified attestation into a verified one.

They do not all prove the same thing, and the differences matter more than the
coverage does:

| Format | What a verified statement establishes |
| :--- | :--- |
| `packed` | The credential key lives in an authenticator whose manufacturer chain reaches a root you trust, and whose AAGUID that chain vouches for |
| `apple` | The same, through Apple's anonymisation CA — the platform, not an individual device |
| `tpm` | The key was certified by a TPM whose attestation identity key chains to a root you trust |
| `android-key` | The key was generated inside Android's keystore, is a signing key, and is not usable by other applications on the device |
| `fido-u2f` | The credential lives on hardware a trusted root vouched for — and **nothing about which model**, because U2F carries no AAGUID |
| `android-safetynet` | **Google inspected the phone** and reported it passed Android's compatibility test suite. Nothing about where the key lives, and nothing about the authenticator model |

`android-safetynet` is the weakest and should be read that way. Its chain of
trust runs through Google rather than through the device: the signature is
Google's, over a document Google composed, about a phone Google inspected, and
the only thread back to the registration is a nonce. Google has deprecated the
API behind it. Prefer `android-key`, which attests to the key itself.

`fido-u2f` and `android-safetynet` convey no AAGUID, so `aaguidVerified` stays
`false` for both and pairing either with `allowedAaguids` is refused rather
than being silently unenforceable.

`android-key` is read from the **hardware-enforced** authorization list by
default. Keystore states a key's properties twice, once as the Android OS
enforces them and once as the secure hardware does, and §8.4 permits reading
either. Reading the software-enforced list means accepting the operating
system's word about the operating system, which is the thing attestation exists
to replace. `allowSoftwareEnforcedAndroidKey: true` opts into it for emulators
and TEE-less devices; what comes back is then not a hardware claim, and should
not be recorded as one.

**Trust anchors are mandatory, not optional.** Every format but `none` is
refused unless the relying party supplies the root certificates it trusts. A chain checked against
no root proves nothing — anyone can self-sign a CA and put any AAGUID they like
in a certificate they issued to themselves — and a verifier reporting
"attestation verified" in that situation manufactures confidence.

**No root store ships with this package.** Which manufacturers you trust is an
operational decision that changes without the library changing; FIDO's Metadata
Service is where most relying parties draw those roots from. Integrating with
MDS — fetching it, verifying its signature, honouring revocations — is not
implemented.

**Self-attestation is off by default**, and reports `aaguidVerified: false`
even when enabled. It proves the credential key signed for itself, which
establishes no hardware provenance at all.

### Bearer tokens can be replayed — unless you enable DPoP

**Under the default `binding: 'none'`, anyone holding a valid access token can
use it.** Ninsho does not detect that the holder is not the original recipient.
This is the same guarantee every mainstream bearer-token system provides.

It is called out because the predecessor claimed otherwise: it advertised
"token replay attacks: blocked" on the strength of hashing the `User-Agent`
header — a value the attacker sets. That feature is gone rather than renamed.

**`binding: 'dpop'` changes this.** Tokens are bound to a key the client holds
privately (RFC 9449), and every request must carry a fresh proof signed by it.
A stolen token alone is then useless: replaying it needs the key, and in a
browser that key should be a non-extractable WebCrypto key that script cannot
read even after an XSS.

It is opt-in rather than default because enabling it is a breaking change for
clients — they must generate a key and send a `DPoP` header on every request.

What DPoP does **not** protect against: an attacker with code execution in the
client's context can still ask the key to sign proofs, even a non-extractable
one. It raises theft from "copy a string" to "maintain execution", which is a
large increase in cost but not an impossibility.

Under bearer semantics, mitigate with short access-token lifetimes (300s by
default), TLS, and `refresh.reuse_detected` alerting.

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
| `binding` | `none` | Bearer semantics, stated rather than implied. `'dpop'` for proof-of-possession |
| `dpopProofMaxAgeSeconds` | `60` | RFC 9449 §11.1. Bounds how long a captured proof is worth replaying, and the replay state retained |
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
| DPoP proof verification | ES256 (P-256) / EdDSA | `node:crypto` |
| DPoP key thumbprint | SHA-256, RFC 7638 | `node:crypto` |

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
| `token.rejected` with `dpop_proof_replayed` | A DPoP proof was presented twice. Either a broken client or a captured proof being replayed |
| `store.unavailable` | Revocation could not be checked. With `reason: admitted_without_revocation_check`, a token was accepted without one |
| `config.insecure` | A weakening configuration choice was made at startup |
| `authz.denied` | A caller was refused. A spike may indicate probing |
| `ratelimit.exceeded` | Sustained volume may indicate credential stuffing |

The audit sink is pluggable and wrapped so a throwing implementation cannot
fail an authentication.

---

## Standards referenced

- W3C WebAuthn Level 3 (§6.1 authenticator data, §7.1/§7.2 verification, §6.1.1 counters, §8.2 packed attestation)
- RFC 5280 — X.509 (extension lookup; parsing and chain checks use Node's vetted `X509Certificate`)
- RFC 9052 — COSE structures and process (key import, algorithm identifiers)
- RFC 8230 — RSA keys for COSE
- RFC 8949 — CBOR (decoder verified against Appendix A vectors)
- RFC 9700 — OAuth 2.0 Security Best Current Practice (§4.14.2, refresh reuse)
- RFC 9449 — DPoP, proof-of-possession (implemented; `binding: 'dpop'`)
- RFC 7638 — JWK thumbprint (implemented; verified against the specification's own vector)
- RFC 8410 — Ed25519 in ASN.1
- RFC 7235 — HTTP authentication framework (§3.1, the 401 `WWW-Authenticate` challenge)
- RFC 9116 — `security.txt`
- PASETO v4 specification
- OWASP ASVS v5, OWASP API Security Top 10 (2023), OWASP Password Storage Cheat Sheet
- NIST SP 800-63B — password guidance
