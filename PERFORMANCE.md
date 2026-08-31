# Performance

```bash
npm run build
npm run bench --workspace @ninsho/server
REDIS_URL=redis://localhost:6379 npm run bench --workspace @ninsho/server
```

## Reference figures

Node v24.11.1, 2000 iterations, `MemoryStore`. These measure **library overhead
only** — serialization, hashing, signing, claim validation — with store latency
near zero. They are not throughput figures for a deployed system.

| Operation | ops/sec | mean | p95 | p99 |
| :--- | ---: | ---: | ---: | ---: |
| `ratelimit: consume` (2 buckets) | 144,709 | 0.007ms | 0.008ms | 0.017ms |
| `opaque: verify` (hot path) | 122,934 | 0.008ms | 0.011ms | 0.027ms |
| `opaque: issue` | 52,485 | 0.019ms | 0.032ms | 0.051ms |
| `session: create` | 23,600 | 0.042ms | 0.065ms | 0.111ms |
| `session: refresh` (rotation) | 18,490 | 0.054ms | 0.092ms | 0.135ms |
| `paseto: issue` (Ed25519 sign) | 16,769 | 0.060ms | 0.092ms | 0.125ms |
| `paseto: verify` (Ed25519) | 8,116 | 0.123ms | 0.182ms | 0.235ms |
| `paseto: verify` (no store check) | 8,144 | 0.123ms | 0.178ms | 0.247ms |

p99 is reported because it, not the mean, is what shows up as user-visible
slowness under load on an auth endpoint.

## What the numbers say

### Opaque verification is ~15× faster than PASETO verification

122,934 vs 8,116 ops/sec. Ed25519 verification is genuinely expensive — around
0.12ms of pure CPU — while an opaque lookup is a hash and a store read.

This is the strongest evidence for making `opaque` the default. The decision was
made on security grounds (no signing keys to leak or rotate, native revocation,
no claims to disclose), and the measurement says it is also the faster path by a
wide margin for the deployment most people have.

### Statelessness buys almost nothing on a single application

`paseto: verify` and `paseto: verify (no store check)` are within noise of each
other — 8,116 vs 8,144 ops/sec. Removing the revocation lookup entirely does not
measurably help, because Ed25519 verification dominates.

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

144,709 ops/sec for both buckets, which is why the per-account dimension is
always consumed rather than skipped when the per-IP bucket has already refused.
Keeping counters consistent costs nothing worth optimising away, and skipping
would let an attacker keep their account counter low by tripping the IP one
first.

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
- Rotation consumes its input, so the token chain is pre-built outside the
  measurement.
- Benchmarks run against the **built** output, not the source, so the numbers
  describe what actually ships.
- Single-process, single-core, no concurrency. Real throughput depends on your
  event loop, your store, and everything else in the request path.
