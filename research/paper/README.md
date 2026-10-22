# Ninsho research paper

**Status:** draft manuscript. Not submitted, not accepted, not peer-reviewed.
Authors: Darshan Jain, Yash Jadhav, Chetna Padhi, Chirag Sharma (Department of
Information Technology, Vidyalankar Institute of Technology, Wadala, Mumbai,
India). The project guide, Dr. Varsha Bhosale, is acknowledged, not listed as an
author; change that only after explicit co-authorship agreement. Email/ORCID,
funding, extra acknowledgments and the AI-assistance disclosure are still
placeholders (see `author-checklist.md`).

**Compiled:** 21 Oct 2026 with Tectonic 0.17.0 (XeTeX engine, BibTeX run
automatically) → `build/ninsho-paper.pdf`, 8 pages, no undefined references or
citations, no overfull boxes. Not yet compiled with pdfLaTeX; do that on
Overleaf (or TeX Live/MiKTeX) before submission, because IEEE's PDF checks are
built around pdfLaTeX output.

## Files

| File | Purpose |
|---|---|
| `ninsho-paper.tex` | Manuscript, IEEEtran conference class |
| `references.bib` | Bibliography (IEEEtran.bst). Entries still needing confirmation carry a `% VERIFY:` comment, which does not print |
| `figures/` | Figures used by the paper, plus `make_figures.py`, which regenerates the two diagrams and two plots from recorded JSON |
| `build/` | Compiler output (`ninsho-paper.pdf`, `.bbl`, `.log`, `.aux`) and page previews (`page-*.png`); disposable |
| `template/conference-template-original.tex` | The IEEE conference template exactly as supplied, preserved |
| `evidence-map.md` | Every number and claim → file, source state, caveat |
| `author-checklist.md` | What the authors must do before submission or a Zenodo preprint |

## Compiling

**Tectonic (used here; one self-contained executable, downloads packages on demand):**

```bash
# installed at %LOCALAPPDATA%\Programs\tectonic\tectonic.exe
cd research/paper
tectonic ninsho-paper.tex --outdir build --keep-logs
```

**pdfLaTeX (Overleaf, TeX Live, MiKTeX):**

```bash
cd research/paper
pdflatex ninsho-paper && bibtex ninsho-paper && pdflatex ninsho-paper && pdflatex ninsho-paper
```

On Overleaf: upload `ninsho-paper.tex`, `references.bib` and `figures/`, set the
compiler to pdfLaTeX, compile.

### Changes to the template preamble, and why

| Addition | Reason |
|---|---|
| `\usepackage[hyphens]{url}` | IEEEtran.bst prints URLs with `\url`; `hyphens` lets the long NDSS URL break instead of overflowing the column |
| `\graphicspath{{figures/}}` | Figures live in a subfolder |
| `iftex` + `\ifXeTeX … fontspec/TeX Gyre Termes … \fi` | XeTeX cannot load the Type 1 Times fonts IEEEtran selects and falls back to fonts without bold/italic. The branch is skipped entirely under pdfLaTeX, so Overleaf/IEEE output is unchanged |
| `\linebreakand` macro | Lays the four author blocks out 2×2; one row of four long affiliations overflows the page width |

## Regenerating figures (no experiments are run)

```bash
python research/paper/figures/make_figures.py   # needs matplotlib
```

Reads `research/validation/benchmarks/results/2026-10-21T08-47-13-720Z-6f82026-standard/*.json`;
executes no benchmark, test or probe. The two SecureShop screenshots are the
authors' own captures and are copied, not generated.

## Evidence provenance (summary)

- Repository HEAD: `6f8202659d8d05330bc220dbd7b6d72e76a09b41`, branch
  `assessment/final-security-benchmark`. Fixes F-01, B-01 and B-12 are
  **uncommitted** in the working tree.
- Published npm 0.1.1 (all four packages): `gitHead`
  `f784566a2597566a88866158b164f72baf320fff` (read from the registry);
  `git diff f784566 6f82026 -- packages` changes only version strings. So the
  published packages contain every defect reported, including the fixed ones.
- Baseline tests, persistence, browsers, audit, probes: clean `6f82026`.
- Benchmark: `6f82026` + the F-01 working-tree change only (`env.json`).
- Final 2,152-test run: all fixes applied.
- Every benchmark number in the manuscript was re-checked against the run's
  JSON on 21 Oct 2026 (18 groups of values, no discrepancies).
- Full mapping: `evidence-map.md`.

No test, benchmark, probe or package publication was run to write or revise
this paper.
