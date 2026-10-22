# Evidence map — `ninsho-paper.tex`

Every quantitative result and security claim in the manuscript, mapped to the
file that supports it, the source state it was produced on, and the caveat that
must travel with it. Paths are relative to the repository root.

## Source states

| ID | Source state | Used for |
|---|---|---|
| **S0** | Commit `6f8202659d8d05330bc220dbd7b6d72e76a09b41` (v0.1.1 + SecureShop demo), clean tree, 21 Oct 2026 | Baseline build, typecheck, 2,150 tests, persistence, browsers, SecureShop 3/3, audits, probes P1–P5 (before fix) |
| **S1** | S0 + uncommitted F-01 fix (`packages/server/src/engine/paseto.ts`, one TTL expression; plus its test) | Benchmark run `2026-10-21T08-47-13-720Z-6f82026-standard` (`env.json` › `git.dirty` lists exactly these two files plus untracked `academic/`, `research/`); P4 after-fix |
| **S2** | S1 + uncommitted fixes in `packages/webauthn/src/server.ts`, `ceremony.ts` (doc only), `demo/viva-showcase/src/server.ts` and their tests | Final test run: 2,152; SecureShop 4/4 |
| **CI** | GitHub Actions run 38607481028 on `6f82026` (14 Oct 2026), read from GitHub's public API on 20 Oct 2026 | "CI covers Node 20 and 22 on Linux" — recorded in `academic/VERIFICATION_NOTES.md` §1, not re-read in this session |
| **NPM** | Published `@ninshorg/{core,server,client,webauthn}@0.1.1`; registry `gitHead` = `f784566a2597566a88866158b164f72baf320fff` (read with `npm view`, 21 Oct 2026). `git diff f784566 6f82026 -- packages` changes only version strings | §III-E sentence "published packages … contain the defects reported" |

HEAD at manuscript time is still `6f82026`; **S1 and S2 are uncommitted**. None
of the fixes is in the published npm release 0.1.1, whose package sources are
identical to S0's apart from version numbers. The F-01 change alters only
the session-index TTL set inside `PasetoEngine.issue()`; no verification path
timed by the benchmark is changed by it.

## Quantitative results

| Paper location | Value | Source file | State | Caveat |
|---|---|---|---|---|
| Abstract, §IV-A | 2,150 tests, 0 skipped (117/97/1,116/623/101/95/1) | `research/validation/logs/test-redis.log` | S0 | Real Redis 7.4.11; Windows, Node 22.13.1 only |
| §IV-A | 2,152 tests after fixes | `research/validation/logs/test-redis-after-fix2.log` | S2 | An intermediate run (`test-redis-after-fix.log`) had 2 Docker-harness failures (F-08); reported in `security-assessment.md` §6 |
| §IV-A | Consumer audit: 0 vulnerabilities | `research/validation/logs/audit-consumer.log` | S0 | Workspace-wide audit had 1 critical in the example only (F-06) |
| §IV-B | 7/7 persistence scenarios executed and passed | `research/validation/logs/redis-persistence-verbose.log` | S0 | Graceful shutdown only; no kill -9, AOF, failover |
| §IV-C | 6/6 browser runs (Chromium 156.0.8078.4, Firefox 157.0, WebKit 27.2) | `research/validation/logs/browser.log` | S0 | Playwright 1.64.1 automation builds |
| §IV-D, Figs. 3–4 | SecureShop JWT replay 200; DPoP attacks 401 | `research/paper/figures/fig-secureshop-*.png` (screenshots taken by the authors, 21 Oct 2026) | Demo app using published `@ninshorg/*@0.1.1` | Screenshots illustrate; the automated evidence is `demo/viva-showcase/src/server.test.ts` (`secureshop-test.log`, `secureshop-test-after-fix2.log`) |
| §IV-E F-01 | Accepted after revoke at t=134 s; control refused; after fix refused | `research/validation/logs/probe-p4.log`, `probe-p4-after-fix.log`; probe `research/validation/probes/p4-paseto-index-vs-tolerance.mjs` | S0 / S1 | `accessTokenTtl = clockToleranceSeconds = 70` s; default tolerance 5 s unaffected |
| §IV-E F-02 | 10/10 allowed vs 3 allowed then 429 | `probes/p2-ratelimit-address-keying.mjs` output quoted in `research/validation/security-assessment.md` F-02 | S0 | Requires Express `trust proxy` + Ninsho `trustProxy:false` |
| §IV-E F-03 | Reproduced 4/4 store × strategy | `probes/p3-tombstone-after-logout.mjs`; output in `security-assessment.md` F-03 | S0 | Requires a logout inside a narrow window; no credential issued |
| §IV-E F-04 | 4 spellings → 4 thumbprints | `probes/p1-jwk-thumbprint-malleability.mjs`; `security-assessment.md` F-04 | S0 | No binding bypass |
| Table IV, Fig. 5 | p50 medians 1.337, 1.357, 1.588, 2.051, 2.163, 0.323, 0.320 ms; ranges; p95 medians | `research/validation/benchmarks/results/2026-10-21T08-47-13-720Z-6f82026-standard/verify-cost.trials.json` (raw samples in `raw/verify-cost.*.json.gz`) | S1 | 3 trials × 1,000 samples, 200 warm-up; ms; concurrency 1 |
| Abstract, §V-B | "Redis round trip 1.34 to 1.59 ms" | same file: medians of `store.ioredis.exists` 1.337, `store.ninsho.get` 1.357, `store.ioredis.get` 1.376, `store.ninsho.exists` 1.585 | S1 | Range of medians, not of individual samples (trial p50s span 1.088–1.797) |
| §V-B | p99 store latency above 15 ms in some trials | same file (e.g. `store.ioredis.get` t2 p99 19.245; `store.ninsho.exists` t2 19.898) | S1 | WSL2 network boundary |
| Table V, Fig. 6 | Throughput medians and CVs | `.../http.trials.json`, `summary.md`, `raw/http.*.json.gz` | S1 | 3 trials × 5 s, 2 s warm-up; successful responses only; 0 non-200 |
| §V-A | 15/15 preflights passed | `.../http.trials.json` › `preflights` | S1 | Stateless JWT accepted the revoked token, as designed |
| §V-A | Response body 1,271 bytes | `.../http.trials.json` › `meanBytes` | S1 | — |
| §VI | Trial order: PASETO 4th, JWT+Redis 5th in all three trials | `research/validation/logs/benchmark-standard-run.log` (`order:` lines) | S1 | Confound; disclosed |
| §VI | HTTP p50 3.74 vs 1.89 ms at 1 client (JWT+Redis vs stateless) | `.../summary.md` (median of trial p50s) | S1 | Reference comparison only |
| Table II | Environment values | `.../env.json` | S1 | 2.3 GiB free RAM at start of the reported run (`freeBytesAtStart` 2,476,412,928); `METHODOLOGY.md` quotes ~1.4 GiB from an earlier smoke run — the paper uses the recorded value |

### Reported-versus-recorded reconciliation

| Value as briefed | Recorded value | Resolution in the paper |
|---|---|---|
| Opaque 1.59 / PASETO 2.05 / JWT+Redis 2.16 ms | 1.588 / 2.051 / 2.163 | Matches; three decimals in Table IV |
| Redis RTT ≈ 1.34–1.59 ms | 1.337–1.585 (medians of four store ops) | Matches; described as range of medians |
| c=16: 951 / 801 / 564 req/s | 951.4 / 801.0 / 563.5 | Matches |
| "Up to ~30% variation" | Throughput CV max 29.8% among comparable cells; 34.1% for stateless reference; verify-cost p50 CV up to 68.8% for the in-memory reference | Paper states 29.8% (comparable) and 34.1% (reference) explicitly |

## Security claims

| Claim | Support | Caveat |
|---|---|---|
| Defaults (Table I) | `packages/server/src/config.ts` `DEFAULTS` (lines ~157–172); `ninsho.ts` facade comment | Release 0.1.1 |
| 256-bit tokens, SHA-256 at rest, one raw token in grace mapping | `packages/core/src/crypto.ts` (`TOKEN_BYTES = 32`); `engine/opaque.ts`; `SECURITY.md` › *One raw token is stored, briefly* | — |
| Binding checked before destructive consume; GETDEL; write order; ~126 ms backoff | `packages/server/src/session/manager.ts` (`refresh()`, `#rotate()`, `TOMBSTONE_BACKOFF_MS` = 2+4+8+16+32+64) | — |
| Revocation marker + post-issuance re-checks; regression | `manager.ts`; `packages/server/src/__tests__/review-regressions.test.ts` | — |
| Fail-open semantics; opaque refuses fail-open | `http/middleware.ts` `createVerify`; `config.ts` | — |
| DPoP: alg allowlist ES256/EdDSA, signature before claims, `jti` single-use | `dpop/proof.ts`, `dpop/jwk.ts`, `dpop/replay.ts` | No server nonce (`grep -i nonce` in `src/dpop`, `src/http`: none) |
| Ownership guard refuses undetermined owner | `http/middleware.ts` `createRequireOwner` | — |
| PASETO revival after data loss / rollback | `redis-persistence.test.ts` (scenarios 6, 7); `redis-persistence-verbose.log` | Documented limitation |
| Fuzz tests | `packages/server/src/__tests__/fuzz.test.ts`; `packages/webauthn/src/{authdata,der,tpm}.test.ts` | Not exhaustive |
| Official PASETO vectors | `packages/server/src/__tests__/paseto-v4.test.ts` | — |
| F-01…F-08 | `research/validation/security-assessment.md` §3 | AI-assisted; F-02…F-08 open |
| Second-pass B-01 (WebAuthn owner) and B-12 (demo logout) fixed | `security-assessment.md` §8, §8.1; regressions in `packages/webauthn/src/server.test.ts`, `demo/viva-showcase/src/server.test.ts`; `test-redis-after-fix2.log`, `secureshop-test-after-fix2.log` | Hypotheses originated in a separate AI session (`C:\Degree Yash\Ninsho-Independent-Audit`, Phase A only); reproduction and fixes in S2 |
| Potential concerns (IPv6 /128, attestation path length, no DPoP nonce, grace window) | `security-assessment.md` §4 (C-01, C-02, C-06, C-04) | Not demonstrated as defects |
| "Not an independent audit" | `security-assessment.md` header and §7 | Must remain in any version of the paper |

## Figures

| Figure | File | Produced from |
|---|---|---|
| Fig. 1 architecture | `figures/fig-architecture.pdf` | Drawn by `figures/make_figures.py` from `AGENTS.md` §3 and source layout |
| Fig. 2 refresh flow | `figures/fig-refresh-flow.pdf` | Drawn from `session/manager.ts` |
| Fig. 5 latency | `figures/fig-verify-latency.pdf` | `verify-cost.trials.json` (no execution) |
| Fig. 6 throughput | `figures/fig-http-throughput.pdf` | `http.trials.json` (no execution) |
| Figs. 3–4 screenshots | `figures/fig-secureshop-*.png` | Authors' screenshots of SecureShop (also in the revised blackbook v4) |

Figure and table numbers above were confirmed in the compiled PDF
(`build/ninsho-paper.pdf`, Tectonic 0.17.0, 21 Oct 2026): Figs. 1–6 and
Tables I–V in the order listed.

## Final consistency check (21 Oct 2026)

Every benchmark value in Tables IV and V and every throughput range quoted in
§V-C was recomputed from `verify-cost.trials.json` and `http.trials.json`
(medians and min–max of per-trial statistics; CV = sample standard deviation /
mean): 18 value groups, 0 discrepancies. Also confirmed: 0 non-200 responses
under load; response body 1,271 bytes; HTTP p50 at one client 3.74 ms
(JWT + Redis) and 1.89 ms (stateless JWT). No benchmark was re-executed.
