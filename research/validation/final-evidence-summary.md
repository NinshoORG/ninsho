# Ninsho — final evidence summary

21 October 2026 · commit `6f82026` (v0.1.1) plus one uncommitted fix on local
branch `assessment/final-security-benchmark` · nothing pushed, merged or
published.

> **Read this first.** The security review behind this summary was
> *model-assisted* (an AI coding assistant working with the project's own test
> suites) and is **not an independent third-party audit or certification**. Test
> passes show that specified behaviours held under the tested conditions; they do
> not show that the software is secure.

Supporting files: [`security-assessment.md`](./security-assessment.md) ·
[`benchmarks/METHODOLOGY.md`](./benchmarks/METHODOLOGY.md) ·
[`benchmarks/results/2026-10-21T08-47-13-720Z-6f82026-standard/summary.md`](./benchmarks/results/2026-10-21T08-47-13-720Z-6f82026-standard/summary.md) ·
[`probes/`](./probes/) · [`logs/`](./logs/)

---

## 1. Confirmed findings and fixes

| ID | Finding | Severity | Status |
|---|---|---|---|
| F-01 | PASETO: a revoked session's access token keeps verifying when `clockToleranceSeconds > 60` (session index expired before the token stopped verifying) | High impact, low likelihood (non-default config) | **Fixed** (`engine/paseto.ts`, one expression) + regression observed failing first; probe on real Redis now refuses the token |
| F-02 | `trustProxy: false` honours `X-Forwarded-For` through `req.ip` when Express `trust proxy` is on — per-IP limit bypass | Medium | Reported, not fixed |
| F-03 | Logout racing a rotation leaves a tombstone → false `refresh.reuse_detected` for a stale tab | Low–Medium | Reported, not fixed |
| F-04 | One DPoP key → up to 4/16 RFC 7638 thumbprints (non-canonical base64url in JWK members) | Low | Reported, not fixed |
| F-05 | CI "persistence suite ran" guard matches the skip placeholder too | Low (evidence integrity) | Reported |
| F-06 | Example app: `proxy-addr` critical advisory via Express 5.2.1 (not in published packages; not reachable as shipped) | Informational | Reported |
| F-07 | Client refuses same-origin paths containing `//` (fails safe) | Low | Reported |
| F-08 | Docker persistence tests can fail on container-name reuse | Low (test reliability) | Reported |
| B-12 (2nd review) | SecureShop DPoP logout passes the refresh token as a session id — server session not revoked; blackbook Table 4.7 overstated it | Medium (demo only) | **Fixed** + regression (failed first); 4/4 demo tests pass |
| B-01 (2nd review) | WebAuthn `finishAuthentication` signed in as another user (challenge user or unsigned user handle) when `StoredCredential.userId` omitted | Medium–High (integration-dependent) | **Fixed** + 2 regressions (failed first); now refuses owner-less credentials — behaviour change |

Seven potential concerns and eight investigated false positives are listed in
`security-assessment.md` §4–§5. Coverage was selective (§7 there).

## 2. Checks: what passed, failed, was skipped or blocked

| Check | Before fix | After fix |
|---|---|---|
| Build | Passed | Passed |
| Typecheck (incl. `manualtest/`, `benchmarks/`) | Passed | Passed |
| Full suite after B-01/B-12 fixes | — | **Passed 2,152**, exit 0, 0 skipped |
| Full suite, real Redis 7.4.11 | **Passed 2,150**, 0 skipped | First run **failed 2** (Docker name conflict, F-08); server package rerun passed 1,117/1,117; demo test passed → **2,151 passed** |
| Docker-managed Redis persistence (7) | Passed 7/7, none skipped | Passed 7/7 in rerun |
| Browser regressions (Chromium 156, Firefox 157, WebKit 27.2) | Passed 6/6 | Not re-run (fix is server-only) |
| SecureShop (`demo/viva-showcase`) | Passed 3/3 | Not re-run (fix is server-only) |
| Consumer audit of 4 published packages | 0 vulnerabilities | — |
| Whole-workspace production audit | 1 critical (example only, F-06) | — |
| Node 20, Linux | **Not run locally** (Windows, Node 22.13.1 only); CI run 38607481028 on `6f82026` covered them before the fix | **Blocked here** — would require pushing to CI, which was out of scope |
| First baseline test run | 3 failed — assessor's Redis on port 6390 collided with the suite's hard-coded dead port. Environment error, rerun passed | — |

## 3. Fresh benchmark (single machine, `--standard` mode)

Machine: Intel Core i5-4300U (2C/4T), 16 GB, Windows 10 19045, Node 22.13.1,
Redis 7.4.11 in Docker/WSL2 with persistence off, other containers running.
Three trials, shuffled order, medians (range across trials in the summary file).

**Verification cost, concurrency 1, p50:**

| Operation | p50 ms | Checks |
|---|---|---|
| Ninsho opaque + Redis | 1.59 | hash, store GET (presence = not revoked) |
| Ninsho PASETO + Redis deny-list | 2.05 | Ed25519, claims, store EXISTS |
| jose EdDSA JWT + Redis deny-list | 2.16 | Ed25519, claims, Redis EXISTS |
| One Redis round trip alone | 1.34–1.59 | — |
| PASETO / JWT signature only (no revocation) — reference | 0.32 / 0.32 | — |

**Protected HTTP requests (Express 5, same route and body):**

| Config | Revocation | c=1 req/s | c=1 p50 ms | c=16 req/s | c=16 p50 ms |
|---|---|---|---|---|---|
| Ninsho opaque | yes | 287 (165–302) | 3.19 | 951 (933–978) | 14.93 |
| Ninsho PASETO | yes | 245 (226–275) | 3.69 | 564 (420–567) | 24.94 |
| JWT + Redis deny-list | yes | 251 (213–261) | 3.74 | 801 (577–804) | 17.61 |
| JWT stateless — reference | **no** | 488 | 1.89 | 963 | 14.11 |
| No auth — floor | n/a | 1136 | 0.83 | 1310 | 10.65 |

15/15 security preflights passed (each configuration refused missing,
tampered, revoked and wrong-audience tokens before timing; the stateless JWT
accepted the revoked token, as disclosed). Zero non-200 responses under load.

**What this supports:** on this machine, the store round trip dominates every
configuration that offers server-side revocation; verification cost of Ninsho
opaque, Ninsho PASETO and a revocation-checking JWT are of the same order.

**What it does not support:** any general "faster than JWT" claim; any ranking
where ranges overlap (all three at c=1); results on other hardware, on Linux, or
with a local Redis. CV reached ~30% for some cells. Three trials are too few for
confidence intervals.

## 4. Claims: supported vs needing work

| Claim (where) | Verdict |
|---|---|
| "No independent audit" (README, SECURITY, blackbook) | Supported; keep. This review does not change it |
| Revocation guarantee ("Use of a revoked token — Mitigated", SECURITY.md) | Supported for defaults; **was false for PASETO with tolerance > 60 s until F-01** — disclose |
| "Rate-limit bypass via X-Forwarded-For — Mitigated" (SECURITY.md) | **Qualify**: not when the framework's proxy trust is enabled with `trustProxy: false` (F-02) |
| Version "v0.1.0 — published" (README.md:153, SECURITY.md Status, AGENTS.md §11) | **Outdated**: packages and npm `latest` are 0.1.1 |
| Test counts 2,116 / 2,142 (REMAINING-ISSUES, docs/browser-regressions.md, docs/cross-tab-session-sync.md) | **Outdated** for this commit; fresh: 2,150 (2,151 with the F-01 regression) |
| "Opaque ~6×–15× faster than PASETO" (PERFORMANCE.md) | **Historical, in-memory only**; with Redis the fresh p50 difference is 1.59 vs 2.05 ms. Keep labelled historical |
| `docs/CRYPTOGRAPHIC-AUDIT.md` "independent cryptographic verification" | **Wording**: in-repository review, not independent; the blackbook already says so |
| Blackbook: "No harness comparing Ninsho with a JWT library" | **Superseded** in the revised copy by §3 above |
| Blackbook: hardware, fresh-run log, SecureShop log placeholders | **Filled** in the revised copy |
| Blackbook references [10] Bonneau (pages/DOI), [12] Fett et al. (ACM DOI), [14] PASETO v4 spec URL | **Still need manual verification** — not checked in this session |
| No DPoP server nonce | Confirmed absent (`grep -i nonce` in `src/dpop`, `src/http`: no matches) |

## 5. The "Ninsho-Independent-Audit" folder

It is a second AI-agent review, saved at Phase A (unreproduced hypotheses) only, self-described as not a human third-party audit, and partly informed by this assessment. It is **not** an independent audit; the blackbook keeps "not independently audited" and now describes both reviews accurately. Details: `security-assessment.md` §8.

## 6. Blackbook

- Original `academic/Ninsho_BTech_Project_Report.docx` — **untouched**
  (SHA-256 verified identical after the edit).
- Revised copy `academic/Ninsho_BTech_Project_Report_REVISED_2026-10-21.docx`
  — schema-validated; edits: abstract (+1 sentence), §3.5 hardware, §4.1
  paragraph and Tables 4.1/4.2, §4.2.1 fresh test counts (+1 paragraph),
  §4.2.6 SecureShop run, §4.2.7 fresh benchmark (+1 paragraph), §4.4
  limitations, Table 5.1, Future Scope.
- **Not done, needs the students:** Figures 4.2/4.3 screenshots; names,
  signatures, dates; the heading of §4.2.7 still reads "Historical benchmark
  measurements" (consider "Benchmark measurements"); press **Ctrl+A, F9** in
  Word to refresh the contents and lists. The copy could not be rendered here
  (no LibreOffice on this machine) — open it in Word and check layout.
- **v2 copy** `academic/Ninsho_BTech_Project_Report_REVISED_v2_2026-10-21.docx` (built from the 21 Oct revised copy, validated): §4.4 "No independent audit" item rewritten to describe both model-assisted reviews; two new §4.4 items (B-12 demo logout defect, B-01 WebAuthn hazard); Table 4.7 Comparison C logout cell annotated. Superseded by **v3** `academic/Ninsho_BTech_Project_Report_REVISED_v3_2026-10-21.docx`: B-01/B-12 described as fixed, counts 2,152, SecureShop 4/4, Table 4.7 restored with a fix note. Superseded by **v4** `academic/Ninsho_BTech_Project_Report_REVISED_v4_2026-10-21.docx`, built from the owner's edited v3 (screenshots added by the owner): independent-audit wording and the B-01/B-12 narrative removed from the report at the owner's request; "[insert screenshot]" removed from both captions; Figure 4.3 caption widened to the three attacks shown. The repository's own README/SECURITY.md still state the project is not independently audited, and that remains true. **Use v4.**
- Consider a short table in §4.2.7 built from §3 above if your template allows.

## 7. Remaining risks and recommended disclosures

1. Not independently audited; this review is model-assisted and selective.
2. F-02 to F-08 are open. Disclose F-02 next to the rate-limit claim.
3. The F-01 fix is **uncommitted** on a local branch; until it is merged and
   released, published 0.1.1 still has the defect (non-default config only).
4. PASETO loses revocations on Redis data loss or rollback (pre-existing,
   documented, re-confirmed by the persistence suite).
5. Benchmarks: one Windows laptop, Redis across the WSL2 boundary, three
   trials, other containers running.
6. Node 20 and Linux not re-run after the fix; CI needs to run on the fix
   commit before stating it passes there.
