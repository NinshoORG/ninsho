# Benchmark methodology — Ninsho final assessment

This harness produces the fresh performance evidence for the final assessment.
It replaces nothing: the figures in `BENCHMARK-REPORT.md` and `PERFORMANCE.md`
remain **historical** (v0.1.0, commit `45f8235`) and must stay labelled that way.
Only numbers produced by this harness, in a run directory under `results/`, are
fresh.

## What is being asked, and what is not

Two separate questions, deliberately not merged into one headline number.

1. **Verification cost.** What does it cost, in-process, to verify one access
   token under each configuration, and how much of that is the store round
   trip? (`verify-cost.mjs`)
2. **Comparable protected requests.** Over real HTTP, through the same Express 5
   app shape returning the same JSON body, what throughput and latency do
   configurations that **provide the same server-side revocation guarantee**
   achieve? (`http-bench.mjs`)

Not asked, and not answerable from this harness: how Ninsho compares with "JWT"
in general. The JWT baseline is one carefully specified configuration (below).
Other JWT stacks, algorithms, caches or deployment topologies would produce
different numbers.

## Configurations

| Name | Role | Per-request checks |
|---|---|---|
| `ninsho-opaque` | Comparable | SHA-256 of the token → Redis `GET` of the access record (presence is non-revocation) → record shape → expiry → DPoP binding (unbound here). 503 on store error. |
| `ninsho-paseto` | Comparable | `kid` from footer → Ed25519 PASETO v4.public signature → claim shape → `iss`, `aud`, `nbf`, `iat`, `exp` ± 5 s → `cnf` (unbound here) → Redis `EXISTS` on the `jti` denylist. 503 on store error. |
| `jwt-redis` | Comparable | `jose` `jwtVerify` (alg allowlist `[EdDSA]`, Ed25519 signature, `iss`, `aud`, `nbf`, `iat`, `exp` ± 5 s, required claims) → claim shape → Redis `EXISTS` on the `jti` denylist via ioredis. 503 on Redis error. |
| `jwt-stateless` | **Reference only** | As `jwt-redis` without the denylist lookup. **Does not provide server-side revocation**: a revoked token is accepted until it expires. Shown so the cost of the lookup is visible, never as a like-for-like competitor. |
| `no-auth` | **Reference only** | No authentication. The floor for Express + loopback HTTP + JSON on this machine. |

Why these choices make the comparable trio fair:

- **Same signature primitive.** The JWT baseline uses EdDSA/Ed25519, the
  primitive PASETO v4.public fixes, so the comparison is not RS256 against
  Ed25519 by accident.
- **Same revocation shape.** Both signed-token configurations do exactly one
  Redis `EXISTS` per request through ioredis 6.0.0 with the offline queue
  disabled. The opaque strategy does one Redis `GET`. Every comparable
  configuration therefore pays one store round trip per request.
- **Same failure posture.** All three refuse (503) when the store cannot be
  consulted. A JWT middleware that silently accepted on Redis error would be
  faster under failure and would not be comparable.
- **Same token lifetime and tolerance.** 300 s access tokens, 5 s clock
  tolerance, for all.
- **Same app, body and route.** One Express 5.2.1 app per configuration
  (`x-powered-by` and ETag disabled), `GET /api/orders`, a fixed ~1 KB JSON
  body of ten order records plus the caller's user id. Only the middleware
  differs.
- **Production semantics unchanged.** Ninsho is used through its public facade
  (`new Ninsho({...})`, `auth.verify()`), built from `packages/server/dist`.
  The only non-default setting is a no-op audit sink, applied to every
  configuration (successful verifications emit no audit events either way).

**Excluded, and why.**

- *DPoP.* A fair DPoP comparison needs the client to mint a fresh signed proof
  per request, which puts a signing operation inside the load generator on the
  same 2-core machine and couples the result to client CPU. The JWT baseline has
  no equivalent proof-of-possession, so there is no comparable counterpart.
  The historical DPoP micro-benchmark in `benchmarks/supplementary/dpop-bench.ts`
  remains the reference for proof-verification cost.
- *A JWT with a local revocation cache, or a short-TTL "no revocation" policy.*
  Each is a different security guarantee. Including one would invite exactly the
  misleading comparison this harness exists to avoid.

## Security preflight

Before any configuration is timed, in **every** trial, the harness sends five
requests and records the status codes: a valid token, no token, a tampered
token, a token whose session/`jti` was revoked, and (for signed tokens) a token
signed by the right key for the wrong audience. If a comparable configuration
does not refuse what it should, the run **aborts** rather than time a verifier
that is not doing its job. The table is reproduced in each run's `summary.md`.

## Procedure

Both comparisons:

- **Warm-up** before every measurement (JIT, connection pools, Redis caches).
- **Independent trials** (default 5). In each trial the configurations run in a
  shuffled order from a fixed seed (`20261021 + trial`), so slow drift in the
  machine (thermal throttling, background load) is spread across
  configurations rather than landing on whichever happens to run last. The
  order is printed and recorded.
- **Raw samples preserved.** Every individual latency is written, gzipped, to
  `raw/`. Every summary statistic can be recomputed from them.

Verification cost (`verify-cost.mjs`): one operation at a time, `await`ed,
timed with `process.hrtime.bigint()`. Default 500 warm-up + 3,000 measured
iterations per operation per trial. Store round trips (`GET`/`EXISTS`, through
raw ioredis and through Ninsho's `RedisStore`) are measured separately so the
store component can be read off directly.

Protected requests (`http-bench.mjs`): the server is a **separate process**
(`server.mjs`, forked per configuration per trial) so the load generator does
not share its event loop. Load is closed-loop: *N* workers, each with exactly
one request in flight over a keep-alive connection (`http.Agent`,
`maxSockets = N`). Default concurrency levels 1, 8 and 32; 3 s warm-up then 10 s
measured at each level. A pool of 64 distinct valid tokens (64 sessions) is used
round-robin. Throughput counts only `200` responses; any non-`200` during load
is reported in the summary.

## Reporting rules

- Every figure is the **median across trials** of that trial's statistic
  (throughput, p50, p95, p99), shown with the **min–max range across trials**
  and the **coefficient of variation**. A single trial is never reported alone.
- p50/p95/p99 use the nearest-rank method.
- Results apply to **this machine in this session**. They are not CI timings,
  and CI must not assert on them. Nothing in this directory runs in CI.
- Where ranges overlap, the honest reading is "no difference resolved at this
  noise level", not a ranking.

## Known confounders on the recorded machine

These are recorded in `env.json` for each run and should be quoted alongside
any figure:

- A 2-core / 4-thread laptop CPU (Intel i5-4300U), Windows 10, "Balanced"
  power plan. Load generator, server and Redis share those cores.
- Redis runs inside Docker Desktop's WSL2 VM, so every store round trip crosses
  the Windows ↔ WSL2 network boundary. This inflates store latency relative to
  a Linux host or a same-host Redis, and affects all comparable configurations
  equally.
- Other containers (an unrelated local Kubernetes workload) were running during
  the recorded run and could not be stopped without disturbing the owner's other
  project. Free RAM at start was ~1.4 GiB of 16 GiB.
- Redis persistence was disabled for the run (`save ""`, `appendonly no`) so
  disk I/O does not enter the measurement. Production Redis configurations
  differ.

## Reproducing

```bash
# repository root
npm ci
npm run build
docker run -d --rm -p 6379:6379 --name ninsho-redis redis:7-alpine redis-server --save "" --appendonly no

cd research/validation/benchmarks
npm ci                                            # installs jose 5.10.0 from package-lock.json
REDIS_URL=redis://localhost:6379 node run.mjs     # full run, ~20 minutes on the recorded machine
# PowerShell: $env:REDIS_URL='redis://localhost:6379'; node run.mjs

node run.mjs --quick      # smoke test only — too short to report
node summarize.mjs results/<run-dir>              # regenerate summary from raw files
```

Each run writes `results/<timestamp>-<commit>-<mode>/` containing `env.json`,
`verify-cost.trials.json`, `http.trials.json`, `raw/*.json.gz`, `summary.json`
and `summary.md`.

## Modes

| Mode | Verification cost | HTTP | Approx. time on recorded machine | Use |
|---|---|---|---|---|
| `--standard` | 3 trials × (200 warm-up + 1,000 iterations) | 3 trials × levels 1, 16 × (2 s warm-up + 5 s) | ~6 min | **Source of the reported figures** |
| (default, full) | 5 trials × (500 + 3,000) | 5 trials × levels 1, 8, 32 × (3 s + 10 s) | ~1 h on this machine | Stronger evidence when time allows |
| `--quick` | 2 × (50 + 300) | 2 × levels 1, 8 × (1 s + 2 s) | ~2 min | Smoke test only |

The reported run used `--standard` at the repository owner's request to keep
the run short. Three trials give a median and a range but no meaningful
confidence interval; treat differences inside the ranges as unresolved.

## Run history

- `results/2026-10-21T08-47-13-720Z-6f82026-standard/` — **the reported run.**
  Completed (exit 0), 15/15 security preflights passed, 0 non-200 responses
  under load. Log: `logs/benchmark-standard-run.log`.
- `results/2026-10-21T08-42-48-810Z-6f82026-full-STOPPED/` — full-mode run
  stopped deliberately after the owner asked for a shorter run. Partial, not
  reportable; log `logs/benchmark-full-run-STOPPED.log`.

- `results/2026-10-21T08-36-31-415Z-6f82026-full-ABORTED/` — **aborted, not
  reportable.** The first full run minted its tokens once at start-up; on this
  machine a verification-cost trial took longer than the 300 s token lifetime,
  and in trial 4 Ninsho correctly refused the expired opaque token
  (`TokenInvalidError: no record for presented token`), which stopped the run.
  Its partial raw files and `logs/benchmark-full-run-ABORTED.log` are kept as a
  record. The harness now re-mints every token immediately before each timed
  operation. No figure from the aborted run is used anywhere.

## Limitations

- Single machine, single session. No cross-machine replication was possible.
- Loopback HTTP measures server-side cost plus the Node HTTP client; it
  contains no real network latency.
- The harness is plain JavaScript and is **not** covered by
  `npm run typecheck`; it guards against API drift by using the public
  facade and by the preflight, which fails if a verifier stops refusing what it
  should.
- `jose` is a single, widely used JWT library; another library could perform
  differently. Nothing here generalises to "JWT" as a whole.
