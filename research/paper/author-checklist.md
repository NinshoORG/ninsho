# Author checklist — before any submission or preprint

Status of the manuscript: **draft, not submitted, not peer-reviewed.** Nothing
below has been done unless it is ticked by an author.

## 1. Authors and front matter

- [x] Author names, order and affiliation entered: Darshan Jain, Yash Jadhav,
      Chetna Padhi, Chirag Sharma — Department of Information Technology,
      Vidyalankar Institute of Technology, Wadala, Mumbai, India (2×2 layout).
- [ ] Every author confirms the spelling of their name and the order as printed
      (e.g. whether full given names are wanted, as in the blackbook's
      "Jain Darshan Arvind").
- [ ] Email or ORCID for each author — four `{[email or ORCID]}` placeholders
      in the `\author{...}` block. Keep the braces when replacing them.
- [ ] ORCID iDs registered and checked (required by Zenodo for linking; often
      requested by IEEE venues).
- [x] Project guide, Dr. Varsha Bhosale, named in the Acknowledgment as project
      guide (not as an author).
- [ ] If Dr. Bhosale agrees in writing to be a co-author, add a fifth author
      block (after `Chirag Sharma`, with `\and`) and remove the guide sentence
      from the Acknowledgment. Either way, obtain the guide's approval of the
      manuscript before submission.
- [ ] Funding line in `\thanks{}`: state the agency or delete the line.
- [ ] Acknowledgment: the guide sentence is written; add further thanks or
      delete the bracketed second sentence.
- [ ] Each co-author has read the final PDF and approved submission (keep the
      emails).

## 2. Disclosure of AI assistance

- [ ] Complete the *Disclosure of AI Assistance* section. Factual basis: the
      security assessment, probe scripts, benchmark harness, figures and a draft
      of the manuscript were produced with an AI coding assistant (Anthropic
      Claude). A second AI session produced the Phase-A hypotheses later
      reproduced as B-01/B-12.
- [ ] Check the **target venue's** AI policy (IEEE requires disclosure of
      AI-generated content in the acknowledgments section; confirm the current
      wording on the venue/IEEE author centre page) and your **institution's**
      policy, then write the statement to satisfy both.
- [ ] State which sections the authors wrote, edited and verified. Do not claim
      sole human authorship of AI-drafted text.
- [ ] Keep the sentence that the assessment is **not an independent
      third-party audit** in every version.

## 3. Evidence and claims

- [ ] Re-read `evidence-map.md`; confirm every number in the PDF matches it.
- [ ] Decide whether to keep the B-01/B-12 paragraph in §IV-E. It describes real,
      reproduced and fixed defects; removing it would leave the 2,152 count
      unexplained and would omit a WebAuthn defect present in published 0.1.1.
      (The blackbook v4 omits it at the authors' request; the paper and the
      blackbook may legitimately differ, but neither should contradict the other.)
- [ ] Commit the fixes (F-01, B-01, B-12) and the `research/` directory, push,
      and let CI run on Node 20 and 22. Until then, the paper must keep saying
      the fixes are uncommitted and unreleased, and CI coverage of them is unknown.
- [ ] `research/validation/logs/*.log` is ignored by the root `.gitignore`
      (`*.log`). Add them with `git add -f` or archive them separately, or the
      evidence map points at files nobody else can see.
- [ ] Decide the canonical repository URL: manifests say
      `https://github.com/NinshoORG/ninsho`; the local remote is
      `https://github.com/Djain912/ninsho`. Make the cited one public and
      containing the evaluated commit.
- [ ] Consider re-running the benchmark in full mode (5 trials, balanced
      configuration order) before a journal submission; the paper discloses
      the current confound either way.
- [ ] If any number changes, regenerate figures with
      `python research/paper/figures/make_figures.py` and update the text.

## 4. References (confirm on the publisher page)

| Key | Status | Action |
|---|---|---|
| `bonneau2012quest` | DOI 10.1109/SP.2012.44 and pp. 553–567 from one secondary source | Confirm on IEEE Xplore (document 6234436) |
| `fett2016oauth` | DOI 10.1145/2976749.2978385 and pp. 1204–1215 from an institutional record | Confirm on ACM DL |
| `sivakorn2016cookie` | DOI 10.1109/SP.2016.49; page range unknown; second author's given name appears as both "Iasonas" and "Jason" | Confirm pages and name form on IEEE Xplore |
| `yang2026jwt` | Authors and title from the NDSS page; no DOI found | Add DOI if NDSS assigns one |
| `webauthn3` | W3C Recommendation 25 Aug 2026 (W3C and FIDO pages) | Add editors if the venue's style requires them |
| `pasetov4` | Spec file confirmed on GitHub; year 2021 is the Version 4 announcement year | Confirm year or use access date |
| `squarcina2023cookie`, `lassak2024passkeys` | Venue and pages recorded as verified in `academic/VERIFICATION_NOTES.md` | Spot-check |
| RFCs | Titles, authors, dates per RFC Editor; DOIs follow 10.17487/RFCnnnn | Spot-check one or two |
| `jose`, `ninshorepo`, `redispersistence`, `owaspapi2023` | Web resources | Add "accessed" dates if the venue requires them |

- [ ] Every citation supports the sentence it is attached to (re-read §II).
- [ ] No claim of being "first" or "only" has been added.

## 5. Venue requirements (none checked yet)

- [ ] Choose the venue and read its **actual call for papers**: page limit,
      anonymity (double-blind would require removing the repository URL, author
      names and self-identifying text), template version, PDF eXpress /
      font-embedding rules, copyright form, artifact policy.
- [ ] Obtain the venue's `IEEEtran.cls`/`IEEEtran.bst` (or use Overleaf's).
- [ ] Do not describe the manuscript as conforming to a venue's rules until this
      is done.
- [x] Compiled with Tectonic 0.17.0 (XeTeX): 8 pages including references, no
      undefined references, no overfull boxes.
- [ ] Compile once with **pdfLaTeX** (Overleaf) and confirm the page count
      and layout match; IEEE PDF eXpress expects pdfLaTeX-style output. The
      XeTeX font block in the preamble is skipped under pdfLaTeX.
- [ ] IEEEtran.bst does not print DOIs. If the venue wants DOIs in the
      reference list, ask for its preferred style or add them manually.
- [ ] The two SecureShop screenshots (Figs. 3–4) are legible only when zoomed
      at column width. If the page limit allows, consider `figure*` (full
      width) or a tighter crop that still shows the status codes.

## 6. Zenodo preprint

- [ ] Confirm the target venue allows a preprint before or during review.
- [ ] Upload type "Publication → Preprint"; title identical to the PDF.
- [ ] Creators with ORCIDs and affiliations exactly as on the PDF.
- [ ] Licence chosen deliberately (e.g. CC BY 4.0 for the text); the software
      itself is MIT.
- [ ] Related identifiers: link the GitHub repository (and a tagged release or a
      Zenodo software deposit of the evaluated commit plus `research/`).
- [ ] Description states: preprint, not peer-reviewed; AI assistance disclosed.
- [ ] Upload the compiled PDF and, optionally, the LaTeX source and figures.
- [ ] A Zenodo DOI is permanent: proofread first. New versions get new DOIs.

## 7. Final read-through

- [ ] Search the PDF for `[` to catch remaining placeholders. As of 21 Oct
      2026 they are: funding line, four `[email or ORCID]`, the second
      Acknowledgment sentence, and the two bracketed parts of the AI disclosure.
      ("[Online]" in the references is IEEE style, not a placeholder.)
- [ ] Figures readable in greyscale and at column width; screenshot text legible.
- [x] No "??" references or undefined citations in the Tectonic build.
- [x] Benchmark values in Tables IV–V and §V-C recomputed from the run's JSON:
      0 discrepancies (see `evidence-map.md`, "Final consistency check").
