# Ninsho PASETO v4.public Cryptographic Audit

## Scope

This audit is an independent cryptographic verification of the PASETO (Platform-Agnostic Security Tokens) v4.public implementation in Ninsho v0.1.0. The audit covers the serialization framing, the Pre-Authentication Encoding (PAE), digital signature generation and verification over Ed25519, footer authentication, implicit assertions, key handling, base64url canonicalization, expiry and claim enforcement, cross-tenant/cross-service issuer/audience binding, and key rotation lifecycles.

Audited packages:
- `@ninshorg/server` (`packages/server/src/paseto/v4.ts`)
- `@ninshorg/server` (`packages/server/src/engine/paseto.ts`)
- `@ninshorg/server` (`packages/server/src/keys/keyring.ts`)
- `@ninshorg/core` (`packages/core/src/time.ts`, `packages/core/src/errors.ts`)

---

## Implementation Reviewed

Ninsho implements PASETO v4.public in ~220 lines of TypeScript (`packages/server/src/paseto/v4.ts`) with zero third-party dependencies, relying solely on Node's native `node:crypto` for Ed25519 signing (`sign`) and verification (`verify`).

Token framing:
```
v4.public.<payload || signature>.<optional-footer>
```
where `payload || signature` is base64url-encoded and `signature` is 64 bytes (Ed25519 signature).

Higher-level token management is provided by:
- `PasetoEngine` (`packages/server/src/engine/paseto.ts`): claims minting (`jti`, `iat`, `nbf`, `exp`, `iss`, `aud`, `sub`, `sid`, `roles`, `scopes`, `cnf`), store-backed revocation denylist, and key lookup via unverified footer `kid`.
- `KeyRing` (`packages/server/src/keys/keyring.ts`): active signing key management, previous key verification lookup, and keypair self-checks at construction.

---

## Methodology

This audit separates four categories of verification:
1. **Source Code Inspection**: Tracing every byte operation, buffer slice, string/byte conversion, integer encoding, error condition, and claim check.
2. **Official Specification Test Vectors**: Testing against the official PASETO specification vectors (`4-S-1`, `4-S-2`, `4-S-3` from `paseto-standard/test-vectors`).
3. **Independent Reference Implementations**: An independent implementation of Pre-Authentication Encoding (`independentPae`) and direct `node:crypto` Ed25519 verification that does not share code with Ninsho's internal helpers.
4. **Adversarial and Fuzz Testing**: A dedicated test suite (`packages/server/src/__tests__/paseto-independent-audit.test.ts`) executing 10,000 malformed/adversarial inputs, exhaustive single-byte mutations across all 64 signature bytes, canonical base64url spare-bit corruption tests, and the full 10-step key rotation lifecycle.

---

## Existing Tests

The repository contained 25 existing tests specifically for PASETO:
- `packages/server/src/__tests__/paseto-v4.test.ts` (19 tests): Tested official test vectors 4-S-1, 4-S-2, 4-S-3, basic PAE length prefixes, roundtrip sign/verify, tamper resistance (swapped footer, altered body, added/removed footer), and near-miss headers.
- `packages/server/src/__tests__/paseto-engine.test.ts` (26 tests): Tested claim issuance, denylist revocation, store failover behavior, and basic key lookup.

**Limitation of existing tests**: Existing tests relied on Ninsho's internal `pae()` function to test PAE properties and lacked exhaustive single-byte signature mutations, non-canonical spare-bit tests, fuzzing across adversarial distributions, and independent reference comparisons.

---

## Independent Verification

The independent verification was executed via `packages/server/src/__tests__/paseto-independent-audit.test.ts` (44 comprehensive test cases).

### PAE Construction
Result: **PASS**

- **Independent reference implementation**: Built using `Uint8Array` and `DataView` with little-endian 64-bit unsigned integers (`setBigUint64(..., true)`), completely decoupled from Ninsho's `le64` and `pae`.
- **Piece count**: Encoded as 8-byte LE integer. Empty list produces `0000000000000000` (8 zero bytes).
- **Empty piece**: Encoded as `0100000000000000` (count 1) + `0000000000000000` (length 0).
- **Length encoding**: Each piece is preceded by its exact byte length in 64-bit LE. Tested on boundary lengths `0`, `1`, `255`, `256`, `65535`, `65536`.
- **Multibyte UTF-8 handling**: Tested with Japanese characters (認証) and surrogate-pair emojis (🔐). Verified that PAE encodes raw UTF-8 byte lengths (10 bytes), NOT JavaScript string character code-unit lengths (4 code units).
- **Canonicalization resistance**: Proved that `["ab", "c"]` and `["a", "bc"]` produce completely distinct byte sequences.
- **Specification alignment**: Byte-for-byte verified against the official test vector preimages.

### Nonce and Signature Handling
Result: **PASS**

- **Absence of Token Nonce**: PASETO **v4.public** is an asymmetric digital signature format using Ed25519 (RFC 8032), NOT v4.local. It does not carry an external encryption nonce field. The token body consists strictly of `payload || signature` (64 bytes).
- **Deterministic Signatures**: Ed25519 signature generation is deterministic per RFC 8032. Signing identical `(m, f, i)` twice with the same key produces the exact same signature.
- **Token Uniqueness**: Ninsho implements token uniqueness at the claims layer in `PasetoEngine` via a 128-bit CSPRNG `jti` (`crypto.randomBytes(16)`). Fifty tokens generated with identical subject/roles yielded 50 unique tokens and 50 unique `jti` values.
- **Exhaustive Signature Mutation**: Every single byte of the 64-byte Ed25519 signature was individually bit-flipped across 64 test iterations; 100% of mutated signatures were rejected.

### Serialization
Result: **PASS**

- **Header enforcement**: Only literal `'v4.public.'` is accepted. All near-misses (`v4.local.`, `v3.public.`, `v2.public.`, `v5.public.`, `V4.public.`, `v4.PUBLIC.`, `Bearer v4.public.`) are rejected.
- **Segmentation**: Tokens must consist of 1 dot-separated body part and at most 1 dot-separated footer part. Tokens with extra segments (`v4.public.a.b.c`), trailing dots (`v4.public.a.b.`), or missing bodies (`v4.public.`) are cleanly rejected.
- **Extreme size**: 1 MB payload token processed and verified without crash or stack exhaustion.
- **Type safety**: Non-string values (`null`, `undefined`, numbers, objects, arrays) throw `PasetoFormatError` cleanly without crashing the process.

### Footer Authentication
Result: **PASS**

- The footer is included in the 4-tuple PAE preimage (`[h, m, f, i]`) during signing.
- Replacing footer A with footer B invalidates verification.
- Stripping the footer from a footered token invalidates verification.
- Adding a footer to an unfootered token invalidates verification.
- Multibyte Unicode footers (`{"kid":"認証_鍵_001","notes":"🔐✨"}`) are preserved byte-for-byte and protected against tampering.

### Implicit Assertion
Result: **PASS**

- An implicit assertion participates as the 4th piece in the PAE preimage (`[h, m, f, i]`).
- A token signed with implicit assertion `A`:
  - Verifies when `A` is supplied.
  - Rejects when `B` is supplied.
  - Rejects when empty string `""` is supplied.
  - Rejects when a prefix or substring of `A` is supplied.
- A token signed with empty assertion rejects when an unintended assertion is supplied.

### Key Format
Result: **PASS**

- Accepts raw 32-byte hex seeds (private key) and 32-byte raw hex public keys.
- Accepts 64-byte PASETO secret hex strings (`seed || public`).
- Accepts standard PKCS#8 and SPKI DER hex encodings.
- Rejects invalid hex (odd length, non-hex characters, empty string).
- Rejects non-Ed25519 keys: RSA 2048-bit keys and ECDSA P-256 keys are rejected with clear errors (`requires Ed25519`).
- `KeyRing` constructor verifies keypair coherence (`#assertPair`): mismatched private and public keys throw `KeyError`.
- Tokens signed with Key A fail verification when verified against Key B.

### Canonical Base64url
Result: **PASS**

- Ninsho enforces canonical base64url via re-encoding verification: `b64uEncode(Buffer.from(value, 'base64url')) === value`.
- Base64 padding `=` in body or footer is rejected.
- Standard Base64 characters (`+` and `/`) are rejected.
- Whitespace, newlines, and carriage returns are rejected.
- Non-canonical spare bits (e.g. non-zero bits in the unused remainder of 1-byte and 2-byte encoded values) are rejected because re-encoding clears the unused bits, triggering a mismatch.

### Malformed Token Rejection
Result: **PASS**

- Tested with 10,000 malformed/adversarial inputs across 10 mutation strategies:
  1. Random raw binary buffers
  2. Prefix corruptions
  3. Delimiter disruption (consecutive dots)
  4. Single-bit flips in valid tokens
  5. Truncation at every possible character boundary
  6. Injection of hostile strings (null bytes, newlines, SQLi, script tags, `__proto__`)
  7. Base64 padding insertions
  8. Non-string types (null, undefined, booleans, objects, numbers)
  9. Random Unicode code point injections
  10. Truncated bodies with signatures smaller than 64 bytes
- Results: 0 crashes, 0 unhandled exceptions, 0 false acceptances (10,000 rejected cleanly via `PasetoFormatError`).

### Signature Verification
Result: **PASS**

- PureEd25519 (RFC 8032) verification verified using native `node:crypto.verify(null, ...)`.
- All official test vectors verified against independent Ed25519 verification without using Ninsho's `verifyV4Public`.
- Any mutation of payload, signature, footer, or implicit assertion causes `verifyV4Public` to throw `PasetoFormatError('signature verification failed')`.

### Expiry Handling
Result: **PASS**

- Evaluated in `PasetoEngine.verify()`:
  - Expired tokens throw `TokenExpiredError`.
  - Active tokens verify successfully.
  - Expiry respects `clockToleranceSeconds`: token past TTL but within tolerance verifies; token past TTL + tolerance is rejected.
  - Future `iat` and `nbf` past clock tolerance are rejected with `TokenInvalidError`.
  - Missing, non-string, or malformed `exp` claims cause `TokenInvalidError` (fails closed).

### Issuer / Audience
Result: **PASS**

- `PasetoEngine.verify()` strictly enforces exact string equality on `claims.iss === issuer` and `claims.aud === audience`.
- A valid token signed with a shared key for `billing-service` is rejected by `orders-service` (`TokenInvalidError`, detail: `audience mismatch`).
- A valid token signed for staging is rejected by production (`TokenInvalidError`, detail: `issuer mismatch`).
- Missing or malformed `iss` / `aud` claims fail closed.

### Key Rotation
Result: **PASS**

- Key rotation is implemented via `KeyRing` and `PasetoEngine` using deployment-based key sets:
  - `keys.active`: The current signing key pair.
  - `keys.previous`: An array of retired key pairs maintained during the rotation overlap window.
- The 10-step zero-downtime rotation lifecycle was tested through the public API:
  1. Key A active: signs tokens stamped with `{"kid":"key-a"}` in footer.
  2. Key A verifies successfully.
  3. Deploy Key B as active, Key A as previous.
  4. Tokens signed by Key A continue to verify without user logout.
  5. New tokens are signed by Key B and carry `{"kid":"key-b"}` in footer.
  6. New Key B tokens verify successfully.
  7. Retire Key A (`previous: []`).
  8. Tokens signed by retired Key A are rejected (`unknown key id: key-a`).
  9. Tokens signed by Key B continue to verify.
  10. Duplicate `kid` entries in KeyRing configuration are rejected at construction.
- Footer spoofing (token signed by Key A with footer modified to point to Key B) fails signature verification.

---

## Reference Vectors

Tested against official PASETO specification vectors (`paseto-standard/test-vectors/v4.json`):

| Vector | Payload | Footer | Implicit | Verification | Regeneration |
|---|---|---|---|---|---|
| `4-S-1` | `{"data":"this is a signed message",...}` | None | None | **MATCH** | **BYTE-FOR-BYTE IDENTICAL** |
| `4-S-2` | `{"data":"this is a signed message",...}` | `{"kid":"zVh..."}` | None | **MATCH** | **BYTE-FOR-BYTE IDENTICAL** |
| `4-S-3` | `{"data":"this is a signed message",...}` | `{"kid":"zVh..."}` | `{"test-vector":"4-S-3"}` | **MATCH** | **BYTE-FOR-BYTE IDENTICAL** |

---

## Fuzzing Results

- Total inputs evaluated: **10,000**
- Test duration: **634 ms**
- Malformed inputs rejected: **10,000 / 10,000 (100%)**
- False acceptances: **0**
- Uncaught exceptions / process crashes: **0**
- Error consistency: 100% of malformed inputs raised controlled `PasetoFormatError`.

---

## Findings

### Finding 1: `le64` MSB Masking vs Strict Rejection (Remediated)
- **Severity**: Informational
- **Status**: Remediated
- **Affected Component**: `packages/server/src/paseto/v4.ts` (`le64`)
- **Evidence**: `buf.writeBigUInt64LE(BigInt(value) & 0x7fffffffffffffffn)` previously cleared the MSB with bitwise AND rather than throwing if the MSB was set.
- **Impact**: **None reachable.** In Node.js, buffer lengths and piece counts are bounded by `buffer.constants.MAX_LENGTH`, which never sets bit 63, and both are the only values `le64` receives from inside this library. No exploit is possible.
- **What the specification actually says**: the specification requires the *encoded* MSB to be zero — "The most significant bit MUST be cleared for interoperability with programming languages that do not have unsigned integer support" — and its reference implementation achieves that by **masking** (`n &= 127` on the final byte). It does **not** require implementations to reject. The change below is therefore *stricter than the reference*, by choice, and is not a conformance fix.
- **Rationale for choosing rejection over masking**: masking maps two distinct inputs — `n` and `n | 2^63` — onto one encoding. Producing distinct preimages for distinct inputs is the entire purpose of PAE, so refusing keeps that property total rather than almost-total. Both behaviours satisfy the specification's requirement that the emitted MSB be zero.
- **Remediation**: strict validation in `le64`:
  ```ts
  if (n < 0n || n > 0x7fff_ffff_ffff_ffffn) {
    throw new PasetoFormatError('length is negative or has bit 63 set');
  }
  ```
  One comparison covers both halves: every value above that bound has bit 63 set. An additional `n & (1n << 63n)` test would be unreachable, and an unreachable guard in a signing path is worse than no guard because it reads as protection to the next reviewer.

  Boundary and regression tests covering `0`, `1`, `0x7fffffffffffffff` (accepted), `0x8000000000000000` and `0xffffffffffffffff` (rejected), plus negative, fractional, `NaN`, `Infinity` and oversized inputs, are in `packages/server/src/__tests__/paseto-v4.test.ts` › *le64 MSB rejection and validation*.

### Finding 2: Manual test scripts were outside every type check (Remediated)
- **Severity**: Informational
- **Status**: Remediated
- **Affected Component**: `manualtest/`
- **Evidence**: `manualtest/` is not a workspace and had no `tsconfig.json`, so its ~4,500 lines of TypeScript were compiled by nothing — not `npm run typecheck`, not CI. A check confirmed one file already failed to compile: `retest-mt05b.ts(82,5): error TS2322`.
- **Impact**: No effect on shipped code; `manualtest/` is never packaged. The risk is to the evidence rather than to the library — a script that silently stopped compiling would still be cited as proof in `TEST-RESULTS.md`. That is the failure this project was built to avoid: the predecessor's README claimed 110 tests while 8 of 9 test files failed to import.
- **Remediation**: added `manualtest/tsconfig.json` extending the shared strict base, wired into the root `typecheck` script so CI compiles it on every push. The existing type error was fixed.

---

## Limitations

- This audit evaluated PASETO **v4.public** (Ed25519 digital signatures). It did not audit PASETO v4.local (symmetric AEAD encryption), which Ninsho does not implement (Ninsho uses opaque store-backed sessions or v4.public access tokens).
- Testing was conducted on Node.js v22.13.1 on Windows x64.
- Hardware side-channel analysis (e.g. power analysis, cache timing on the underlying OpenSSL Ed25519 implementation) was outside the scope of this software audit.

---

## Conclusion

Independent verification found no deviation from the tested PASETO v4.public properties within the tested scope. The Pre-Authentication Encoding, Ed25519 signature verification, base64url canonicalization, footer authentication, implicit assertions, claim validation, and key rotation mechanisms all behave strictly according to specification and security requirements.
