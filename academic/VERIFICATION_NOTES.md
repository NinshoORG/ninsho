# Verification notes — Ninsho B.Tech project report

Prepared 21 Oct 2026. This file accompanies `Ninsho_BTech_Project_Report.docx`.

## 1. What was inspected
- **Repository:** https://github.com/NinshoORG/ninsho, `main` at **6f82026** ("feat(demo): add SecureShop viva showcase application"). The local working tree was clean and equal to `origin/main`. The report was written from a clone of this commit.
- **npm:** `@ninshorg/core`, `server`, `client`, `webauthn` all have `latest` = 0.1.1 (published 14 Oct 2026, `gitHead` f784566). `git diff f784566 HEAD -- packages` shows only version-bump changes to four `package.json` files, so published source = HEAD source.
- **GitHub Actions:** run 38607481028 (push to main on 6f82026, 14 Oct 2026): all 8 jobs succeeded (Verify Node 20 and 22, Chromium, Firefox, WebKit, lockfile, dependency audit, bundle purity). The only skipped step: "Benchmarks still run" on Node 20 (by design). Read from GitHub's public API on 20 Oct 2026.

## 2. Source documents used
README.md, SECURITY.md, REMAINING-ISSUES.md, PERFORMANCE.md, BENCHMARK-REPORT.md, CHANGELOG (not relied on), `docs/` (architecture, authorization, configuration, browser-regressions, cross-tab-session-sync, redis-operations, review-remediation, viva-guide, CRYPTOGRAPHIC-AUDIT), `manualtest/TEST-RESULTS.md` and `manualtest/evidence/viva-rehearsal.txt`, `demo/viva-showcase/README.md`, package manifests, `.github/workflows/ci.yml`, and source files `session/manager.ts`, `store/redis.ts`, `dpop/proof.ts`, `dpop/replay.ts`, `client/session-sync.ts`, `client/storage.ts`, `engine/opaque.ts`.

## 3. Evidence limitations (read before submitting)
1. **No test, build, browser or benchmark was executed for this report.** The preparation environment could not reach the npm registry (cloud container: DNS failure; the linked PC's Linux shell: proxy 403), and the `node_modules` on the PC hold Windows binaries only. All "passing" statements come from (a) GitHub Actions on 6f82026 and (b) the project's own recorded runs in its documents. **Re-run the suite yourself and attach the log** (Table 4.1 and Table 4.2 have placeholders).
2. **Test counts disagree between repository documents** (2,116 vs 2,142 + 1) because they describe different working-tree states. The report quotes both with their scope and does not claim a count for 6f82026. Replace with your own count after re-running.
3. **Manual attack procedures (MT-01…MT-20 + 5 retests = 25 entries; 23 pass, 2 N/A)** were recorded against release **0.1.0**, not 0.1.1.
4. **Benchmarks** are historical (0.1.0, commit 45f8235, i5-4300U, Node 22.13.1). No JWT comparison harness exists; the report makes no JWT performance claim.
5. **SecureShop:** the README documents the outcomes and a test file exists, but **no execution log was found**. Run `npm test` in `demo/viva-showcase` and attach the log. The related three-demo rehearsal log (`viva-rehearsal.txt`, all ten statuses matched) is real and quoted.
6. **CI guard weakness:** the CI step "Assert the Redis contract suite actually ran" greps for the Docker suite's name, which the skip placeholder also prints, so CI alone does not prove the Docker-managed persistence tests executed.
7. `docs/CRYPTOGRAPHIC-AUDIT.md` describes itself as "independent". It was produced inside the project; the report calls it an **in-repository review**, not an external audit.
8. **No independent security audit exists.** Passing tests are not an audit; the report says so in the abstract, Chapter 4 and Chapter 5.
9. Not found in the implementation reviewed: DPoP server-nonce support (RFC 9449 §8). Stated as a limitation; please confirm against the code before the viva.
10. I did not read every source file line by line (authorization middleware, WebAuthn attestation code and the PASETO engine were reviewed through documentation and tests, not exhaustively).

## 4. References needing manual confirmation
Verified from publisher pages on 20–21 Oct 2026: RFC 9449, 9700, 7519, 8725, 6750, 7638, 6749 (RFC Editor); RFC 8949, 8032 (RFC Editor); W3C WebAuthn Level 3 (Recommendation dated 25 Aug 2026; editors not listed because one editor appears with a single name on the page); Squarcina et al. (USENIX Security 2023, pp. 5539–5556); Lassak et al. (USENIX Security 2024, pp. 7231–7248); Yang et al. (NDSS 2026); OWASP API Top 10 2023; Redis persistence docs.
**Please confirm manually:**
- **[10] Bonneau et al., IEEE S&P 2012** — pages and DOI were not shown on the page I could read, so none are given.
- **[12] Fett, Küsters, Schmitz, ACM CCS 2016** — the arXiv page (1601.01229) was verified; CCS venue is from the search listing; ACM page/DOI could not be fetched. Add pages and DOI (expected 10.1145/2976749.2978385 — unverified).
- **[14] PASETO** — the GitHub page I fetched did not show the v4 spec or algorithms; v4.public/Ed25519 statements rely on the repository's own docs and tests. Add the exact Version 4 spec URL.
- The *characterisations* of Bonneau et al. and Fett et al. in Chapter 2 are brief and general; check them against the papers before the viva.
- Access dates for web sources are not printed; add "accessed <date>" if your department requires it.

## 5. Placeholders that still need your input
| Where | What |
|---|---|
| Title page, certificate, approval page, declaration, acknowledgement | Student names and roll numbers (template shows four; delete extra lines), project guide name, Head of Department, Principal, dates, places, signatures |
| Title page | Academic year left as in the template (**2025-2026**) because it was not confirmed |
| Acknowledgement | Draft text — personalise |
| Table 4.1 / 4.2 | Fresh re-run log (commit, Node, Redis versions); hardware (CPU, RAM, OS) |
| Section 4.2.6 | Two SecureShop screenshots (Figures 4.2, 4.3 are labelled placeholders) and the SecureShop `npm test` log |
| Chapter 6 | Publications and competitions — currently stated as "None"; confirm |

## 6. Editing notes
- The report was built by editing a copy of the college template (styles, margins, page numbering, headers/footers and front matter preserved). The original template and the repository were not modified.
- Contents, List of Figures and List of Tables are real Word fields with cached page numbers computed from a LibreOffice render. In Word: **Ctrl+A, then F9** (Update entire table) to refresh them; pagination may shift by a page or so.
- Equations are plain text (not Word equation objects) so they display identically everywhere.
- Figures were drawn for this report; the SecureShop screenshots are placeholders.
