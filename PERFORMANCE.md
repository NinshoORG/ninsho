# Performance

```bash
npm run build
npm run bench --workspace @ninshorg/server
REDIS_URL=redis://localhost:6379 npm run bench --workspace @ninshorg/server
```

> **Two documents measure this project, and they disagree by design.** This
> one records figures from an Intel i7-8665U on Node v24.11.1;
> [`BENCHMARK-REPORT.md`](./BENCHMARK-REPORT.md) records a much broader
> evaluation — cryptographic primitives, DPoP, concurrency scaling, end-to-end
> HTTP — from an Intel i5-4300U on Node v22.13.1. Roughly a 3× slower machine,
> so its absolute numbers are roughly 3× lower. Neither is wrong. See
> [*The ratio is hardware-dependent*](#the-ratio-is-hardware-dependent) below,
> which is the one place the difference changes a conclusion rather than a
> number.

## Reference figures

**Intel Core i7-8665U @ 1.90GHz (4 cores / 8 threads), 16 GB, Windows,
Node v24.11.1.** 2000 iterations, `MemoryStore`. These measure **library
overhead only** — serialization, hashing, signing, claim validation — with
store latency near zero. They are not throughput figures for a deployed system.

Reproduce with `npm run bench --workspace @ninshorg/server`. Absolute figures will
track your hardware; the *relationships* between rows are the durable part.

| Operation | ops/sec | mean | p95 | p99 |
| :--- | ---: | ---: | ---: | ---: |
| `ratelimit: consume` (2 buckets) | 159,125 | 0.006ms | 0.007ms | 0.023ms |
| `opaque: verify` (hot path) | 110,355 | 0.009ms | 0.013ms | 0.025ms |
| `opaque: issue` | 49,266 | 0.020ms | 0.034ms | 0.059ms |
| `session: create` | 25,387 | 0.039ms | 0.052ms | 0.092ms |
| `session: refresh` (rotation) | 16,512 | 0.061ms | 0.083ms | 0.136ms |
| `paseto: issue` (Ed25519 sign) | 15,105 | 0.066ms | 0.103ms | 0.149ms |
| `paseto: verify` (no store check) | 8,318 | 0.120ms | 0.147ms | 0.210ms |
| `paseto: verify` (Ed25519) | 8,001 | 0.125ms | 0.160ms | 0.222ms |

p99 is reported because it, not the mean, is what shows up as user-visible
slowness under load on an auth endpoint.

## The same operations against a real store

Local Redis over loopback — the best case a network gives you, and still two to
three orders of magnitude slower than the table above.

| Operation | ops/sec | mean | p95 | p99 |
| :--- | ---: | ---: | ---: | ---: |
| `paseto: verify` (no store check) | 7,437 | 0.134ms | 0.163ms | 0.228ms |
| `opaque: verify` (hot path) | 2,805 | 0.356ms | 0.414ms | 0.473ms |
| `paseto: issue` (Ed25519 sign) | 2,102 | 0.476ms | 0.658ms | 0.954ms |
| `paseto: verify` (Ed25519) | 1,816 | 0.551ms | 0.709ms | 0.938ms |
| `ratelimit: consume` (2 buckets) | 1,141 | 0.876ms | 0.991ms | 1.153ms |
| `opaque: issue` | 837 | 1.195ms | 1.684ms | 2.365ms |
| `session: create` | 359 | 2.782ms | 3.542ms | 5.487ms |
| `session: refresh` (rotation) | 211 | 4.734ms | 5.448ms | 8.107ms |

This is the table to reason about, and the first one is the table to reason
about *changes* with. Every figure here is round trips: `session: refresh`
issues several commands, so it lands near 5ms on a loopback Redis and would be
worse across a network. Nothing in the library's own cost is visible at this
scale.

The one row worth pausing on is `paseto: verify (no store check)` at 7,437 —
four times the store-checked figure, because it is the only operation that
never leaves the process. That is the real shape of the stateless trade-off,
and the section below is about why it still usually is not worth taking.

## What the numbers say

### Opaque verification is ~15× faster than PASETO verification

110,355 vs 8,001 ops/sec, from the table above. Ed25519 verification is
genuinely expensive — around 0.12ms of pure CPU — while an opaque lookup is a
hash and a store read.

*(An earlier revision of this section quoted 122,934 vs 8,116, figures that
appear in no table here. They were left behind by a superseded run. Corrected
to the measurements this document actually publishes — a number in the prose
that its own evidence does not support is the failure this project exists
around, even when the conclusion it supports is unchanged.)*

This is the strongest evidence for making `opaque` the default. The decision was
made on security grounds (no signing keys to leak or rotate, native revocation,
no claims to disclose), and the measurement says it is also the faster path by a
wide margin for the deployment most people have.

### The ratio is hardware-dependent

The 15× above is not a property of the library alone, and saying so matters more
than the number does.

| Machine | `opaque: verify` | `paseto: verify` | Ratio |
| :--- | ---: | ---: | ---: |
| i7-8665U, Node 24.11.1 — this document | 110,355 | 8,001 | **13.8×** |
| i7-8665U, Node 24.11.1 — independent re-run | 105,748 | 6,840 | **15.5×** |
| i5-4300U, Node 22.13.1 — [`BENCHMARK-REPORT.md`](./BENCHMARK-REPORT.md) | 17,267 | 2,922 | **5.9×** |

Both machines slow down on the weaker CPU, but not equally: the opaque path
loses about 6×, Ed25519 verification only about 2.7×. That asymmetry is the
interesting part. Ed25519 is a tight, cache-friendly OpenSSL routine whose cost
tracks clock speed; the opaque path is comparatively more V8 — allocation, map
lookups, object shapes — which suffers far more on an older dual-core with a
smaller cache.

So the honest claim is **"between roughly 6× and 15× faster, depending on the
machine"**, not a single figure. It does not change the conclusion — opaque is
faster than PASETO on every machine measured, and that is the row the default
rests on — but a reader comparing the two documents deserves to know why they
report different multiples rather than being left to assume one is wrong.

### Statelessness buys almost nothing on a single application

`paseto: verify` and `paseto: verify (no store check)` are within noise of each
other — 8,001 vs 8,318 ops/sec. Removing the revocation lookup entirely does not
measurably help against `MemoryStore`, because Ed25519 verification dominates.
Against Redis the gap is real (1,816 vs 7,437), and it is a network round trip
rather than anything this library does.

That is the case against reaching for stateless tokens by reflex. Their appeal
is avoiding a round trip, and here the round trip is not what costs. PASETO
earns its place when several services must verify **without a shared store at
all** — a distribution property, not a speed one. Choosing it for performance on
a single application makes things slower and gives up native revocation.

### Verification is not the bottleneck in any realistic system

Even the slowest operation clears 8,000/sec on one core. A password hash at
OWASP scrypt parameters costs ~100ms by design — roughly **800× more than
verifying a PASETO token**. Any real deployment is bounded by password hashing,
database queries, and network latency, not by this library.

The practical reading: do not trade a security property for speed here. There is
nothing meaningful to win.

### Rate limiting is effectively free

159,125 ops/sec for both buckets, which is why the per-account dimension is
always consumed rather than skipped when the per-IP bucket has already refused.
Keeping counters consistent costs nothing worth optimising away, and skipping
would let an attacker keep their account counter low by tripping the IP one
first.

## WebAuthn

Node v24.11.1, 500 iterations. Responses are pre-built outside the timer, so
these measure verification rather than the authenticator.

| Operation | ops/sec | mean | p95 | p99 |
| :--- | ---: | ---: | ---: | ---: |
| `cbor: decode` (COSE key) | 688,610 | 0.001ms | 0.003ms | 0.008ms |
| `cose: importCoseKey` | 14,162 | 0.071ms | 0.096ms | 0.133ms |
| `register: verify` (none) | 4,970 | 0.201ms | 0.242ms | 0.279ms |
| `authenticate: verify` (RS256) | 3,959 | 0.253ms | 0.315ms | 0.605ms |
| `authenticate: verify` (EdDSA) | 3,190 | 0.313ms | 0.393ms | 0.564ms |
| `authenticate: verify` (ES256) | 2,657 | 0.376ms | 0.486ms | 0.954ms |
| `register: verify` (packed + chain) | 1,845 | 0.542ms | 0.658ms | 0.925ms |

```bash
npm run bench --workspace @ninshorg/webauthn
```

### These are per sign-in, not per request

A ceremony happens once when a session starts. `opaque: verify` above runs on
*every* authenticated call and is 22–41× faster. In practice a ceremony is
dominated by the user's finger reaching the sensor, not by any of this.

### Attestation roughly halves registration throughput

4,970 → 1,845 ops/sec, about 0.34ms extra. That is certificate chain
verification — signature checks up the chain, validity windows, the AAGUID
extension lookup — and it is the honest price of knowing which hardware a
credential lives on.

The figure is for `packed`. The other formats do more or less the same work
plus their own binding check: `tpm` parses two extra structures and hashes
them, `android-key` reads one certificate extension, `android-safetynet`
verifies an RSA signature over a JWS. None of them changes the order of
magnitude, and none is benchmarked here — measuring six formats to report the
same conclusion six times would be padding rather than evidence.

It is paid once per credential, ever. If you need approved-hardware enrolment,
0.34ms is not the reason to skip it; if you do not need it, the default already
avoids the cost.

### RS256 verification is *faster* than ES256

This surprises people, and it is correct. RSA verification with the usual
public exponent (65537) is a short modular exponentiation, while ECDSA
verification needs two point multiplications. RSA is slow to *sign* and cheap
to *verify*; the authenticator does the signing and the server does the
verifying, so the server sees the cheap half.

It is not a reason to prefer RS256. ES256 keys are far smaller, and every
modern passkey uses them.

### CBOR decoding is free

688,610 ops/sec, roughly a microsecond. That matters because the decoder is the
one piece an unauthenticated caller can reach with arbitrary bytes — the guards
on it (bounds checks before allocation, a nesting limit, no indefinite lengths)
cost nothing measurable, so there is no tension between being strict and being
fast.

## Against Redis

Set `REDIS_URL` to measure with real round trips. Those figures are dominated by
network latency rather than by anything in this codebase, and they scale with
your Redis deployment.

Operation counts per request, useful for capacity planning:

| Operation | Store round trips |
| :--- | ---: |
| `opaque: verify` | 1 read |
| `paseto: verify` | 1 read (denylist) |
| `opaque: issue` | 2 writes + 1 set-add |
| `session: create` | ~5 writes |
| `session: refresh` | ~6 (one atomic `take`, then writes) |
| `ratelimit: consume` | 2 per bucket (increment + read) |

Verification — the only operation on every authenticated request — is a single
round trip in both strategies.

## Methodology

- A warm-up pass is discarded so JIT compilation is not counted as steady state.
- WebAuthn responses and assertions are generated ahead of the timer, so the
  figures measure verification and not the virtual authenticator's signing.
- Rotation consumes its input, so the token chain is pre-built outside the
  measurement.
- Benchmarks run against the **built** output, not the source, so the numbers
  describe what actually ships.
- Single-process, single-core, no concurrency. Real throughput depends on your
  event loop, your store, and everything else in the request path.
