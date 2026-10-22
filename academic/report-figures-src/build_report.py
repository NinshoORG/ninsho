"""Build the expanded Ninsho B.Tech report from the v4 blackbook.

Reads (never modifies) academic/Ninsho_BTech_Project_Report_REVISED_v4_2026-10-21.docx
and writes a new DOCX. Figures come from academic/report-figures/ and
research/paper/figures/; Appendix F tables are computed from the recorded
benchmark JSON. No benchmark, test or probe is executed.

    python academic/report-figures-src/build_report.py <unpacked-merged-v4-dir> <output.docx>
"""
import copy
import json
import re
import statistics
import sys
import zipfile
from pathlib import Path

from lxml import etree

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from build_lib import Builder, NS, w, el, runs  # noqa: E402
import content_ch1_ch2 as c12  # noqa: E402
import content_ch3 as c3  # noqa: E402
import content_ch4_ch6 as c46  # noqa: E402
import content_appendices as ca  # noqa: E402

ROOT = HERE.parents[1]
ASSETS = ROOT / "academic" / "report-figures"
RUN = ROOT / "research/validation/benchmarks/results/2026-10-21T08-47-13-720Z-6f82026-standard"

unpacked, out_path = Path(sys.argv[1]), Path(sys.argv[2])
b = Builder(unpacked)


def after(anchor, blocks):
    return b.insert_after(anchor, b.render(blocks, ASSETS))


def set_para_text(p, text):
    """Replace a paragraph's text, keeping the first run's character formatting."""
    first_rpr = p.find("w:r/w:rPr", NS)
    for r in p.findall("w:r", NS):
        p.remove(r)
    for r in runs(text):
        if first_rpr is not None and r.find("w:rPr", NS) is None:
            r.insert(0, copy.deepcopy(first_rpr))
        p.append(r)


# ── Chapter 1 ──────────────────────────────────────────────────────────────
after(b.find_p("Authentication alone does not protect user data"), c12.CH1_BACKGROUND)
after(b.find_p("The following are outside the scope and are not claimed"), c12.CH1_AFTER_SCOPE)
set_para_text(b.find_p("The rest of the report is organized as follows"), c12.CH1_ORGANIZATION)

# ── Chapter 2 ──────────────────────────────────────────────────────────────
after(b.find_p("The WebAuthn specification [6], which became"), c12.CH2_REVIEW)
t21 = b.table_after("Summary of literature survey")
template_row = t21.findall("w:tr", NS)[-1]
for values in c12.CH2_TABLE21_ROWS:
    row = copy.deepcopy(template_row)
    for tc, v in zip(row.findall("w:tc", NS), values):
        ps = tc.findall("w:p", NS)
        for extra in ps[1:]:
            tc.remove(extra)
        p = ps[0]
        rpr = p.find("w:r/w:rPr", NS)
        for r in p.findall("w:r", NS):
            p.remove(r)
        r = el("r")
        if rpr is not None:
            r.append(copy.deepcopy(rpr))
        t = el("t"); t.text = v; r.append(t); p.append(r)
    t21.append(row)
set_para_text(b.find_p("Table 2.1 summarizes the literature reviewed."),
              "Table 2.1 summarizes the literature and specifications reviewed. The column headed “Dataset / Scope” records the subject of each work, since most are standards or analytical studies without datasets.")
after(b.find_p("Honest comparison baselines."), c12.CH2_AFTER_GAPS)

# ── Chapter 3 ──────────────────────────────────────────────────────────────
after(b.find_p("Evidence sources used in this report", style="FigureCaption"), c3.CH3_NEW)

# ── Chapter 4 ──────────────────────────────────────────────────────────────
t41 = b.table_after("Evidence categories and their status")
for tr in t41.findall("w:tr", NS):
    cells = tr.findall("w:tc", NS)
    if "SecureShop outcomes" in b.text(cells[0]):
        p = cells[2].find("w:p", NS)
        rpr = p.find("w:r/w:rPr", NS)
        for r in p.findall("w:r", NS):
            p.remove(r)
        r = el("r")
        if rpr is not None:
            r.append(copy.deepcopy(rpr))
        t = el("t"); t.text = "Re-run 21 Oct 2026: 3/3 passed; 4/4 after the B-12 fix (logs in research/validation/logs)"
        r.append(t); p.append(r)
for needle in ("A fresh, single-machine benchmark was run on 21 October 2026 with the harness",
               "Over HTTP (one Express 5 application per configuration"):
    old_p = b.find_p(needle)
    old_p.getparent().remove(old_p)
after(b.find_p("Historical verification throughput, release 0.1.0", style="FigureCaption"), c46.CH4_AFTER_BENCH)
for needle, old, new in (("SecureShop outcomes, plus a single-machine benchmark", "(Section 4.2.7)", "(Sections 4.2.11 to 4.2.13)"),
                         ("Repeat the single-machine performance comparison of Section 4.2.7", "Section 4.2.7", "Sections 4.2.11 to 4.2.13")):
    p = b.find_p(needle)
    set_para_text(p, b.text(p).replace(old, new))
last = b.find_p("Internal validity of the manual tests.")
last = b.insert_after(last, b.bullets(c46.CH4_LIMITATIONS_EXTRA))
after(last, c46.CH4_NEW_SECTIONS)

for needle, extra in (("Table 4.1 classifies the evidence used.", " Figure 3.6 summarises the sources of this evidence."),
                      ("The Security Experiments Lab in the application issues the replay requests",
                       " Figure 4.2 and Figure 4.3 show two of these experiments as captured by the authors.")):
    p = b.find_p(needle)
    set_para_text(p, b.text(p) + extra)

# ── Chapter 5 and 6 ────────────────────────────────────────────────────────
after(b.find_p("There is no DPoP server-nonce mechanism in the implementation reviewed"), c46.CH5_AFTER_CONCLUSION)
after(b.find_p("Investigate a server-nonce option for DPoP"), c46.CH5_FUTURE_TABLE)
set_para_text(b.find_p("None at the time of writing. [Students to confirm; add any paper"), c46.CH6_PUBLICATIONS)

# ── References ─────────────────────────────────────────────────────────────
refs = [p for p in b.body.iter(w("p"))
        if p.find("w:pPr/w:numPr/w:numId", NS) is not None
        and p.find("w:pPr/w:numPr/w:numId", NS).get(w("val")) == "7"]
ref_numbers = {key: len(refs) + i + 1 for i, key in enumerate(c12.NEW_REFERENCE_KEYS)}
anchor = refs[-1]
for text in c12.NEW_REFERENCES:
    p = copy.deepcopy(refs[-1])
    set_para_text(p, text)
    anchor.addnext(p); anchor = p
last_ref = anchor

# ── Abbreviations ──────────────────────────────────────────────────────────
NEW_ABBR = {"CDF": "Cumulative Distribution Function", "CV": "Coefficient of Variation",
            "FR": "Functional Requirement", "HTTPS": "Hypertext Transfer Protocol Secure",
            "IETF": "Internet Engineering Task Force", "MDS": "Metadata Service (FIDO)",
            "NFR": "Non-Functional Requirement", "OWASP": "Open Worldwide Application Security Project",
            "TB": "Trust Boundary", "W3C": "World Wide Web Consortium", "WSL": "Windows Subsystem for Linux"}
abbr = [p for p in b.body.iter(w("p")) if p.find("w:pPr/w:tabs/w:tab[@w:pos='2700']", NS) is not None]
existing = {b.text(p).split("–")[0].strip(): p for p in abbr}
for key, meaning in NEW_ABBR.items():
    if key in existing:
        continue
    p = copy.deepcopy(abbr[0])
    rs = p.findall("w:r", NS)
    rs[0].find("w:t", NS).text = key
    rs[1].find("w:t", NS).text = f"–  {meaning}"
    later = [q for k, q in sorted(existing.items()) if k.upper() > key.upper()]
    if later:
        later[0].addprevious(p)
    else:
        sorted(existing.items())[-1][1].addnext(p)
    existing[key] = p

# ── Appendices ─────────────────────────────────────────────────────────────
blocks = list(ca.APPENDIX_A) + list(ca.APPENDIX_B) + list(ca.APPENDIX_C)
blocks += [("app", "Appendix D: Test Catalogue and Evidence Register"),
           ("p", "Table {T:d-files} describes every automated test file by its focus. Package totals are given in Section 4.2; the test runner does not record per-file counts, so none are given here. Table {T:d-evidence} is the register of dated evidence used in this report, with the source state each item belongs to."),
           ("tbl", "d-files", "Automated test files (grouped, .test.ts omitted) and what they exercise", ["Workspace", "Files", "Focus"],
            ca.APPENDIX_D_FILES, [1.8, 4.6, 6.6]),
           ("tbl", "d-evidence", "Evidence register", ["ID", "Evidence", "Location", "Date", "Source state", "Result"],
            ca.APPENDIX_D_EVIDENCE, [1, 3.2, 3.6, 1.8, 2.2, 2.6]),
           ("app", "Appendix E: Threat Model and Security-Control Matrix"),
           ("p", "Table {T:e-matrix} condenses the threat table of the repository's SECURITY.md together with the findings of Section 4.5. *Mitigated where used* means the control exists but takes effect only where the application mounts it."),
           ("tbl", "e-matrix", "Threats, controls, evidence and status", ["Threat", "Control", "Evidence", "Status"],
            ca.APPENDIX_E_ROWS, [3.6, 3.6, 3.2, 2.6])]
blocks += list(ca.APPENDIX_F_TEXT)

env = json.loads((RUN / "env.json").read_text(encoding="utf-8"))
blocks.append(("tbl", "f-env", "Environment of the reported benchmark run (from env.json)", ["Item", "Value"], [
    ["Run directory", "2026-10-21T08-47-13-720Z-6f82026-standard"],
    ["Commit and tree", f"{env['git']['commit'][:12]} on {env['git']['branch']}; uncommitted: F-01 change, research/ and academic/"],
    ["Node.js / npm / V8 / OpenSSL", f"{env['runtime']['node']} / {env['runtime']['npm']} / {env['runtime']['v8']} / {env['runtime']['openssl']}"],
    ["Operating system", f"{env['os']['version']} {env['os']['release']} ({env['os']['arch']}), Balanced power plan"],
    ["Processor", f"{env['cpu']['model']}, {env['cpu']['physicalCores']} cores / {env['cpu']['logicalCores']} threads"],
    ["Memory", f"{env['memory']['totalBytes'] / 2**30:.1f} GiB total, {env['memory']['freeBytesAtStart'] / 2**30:.1f} GiB free at start"],
    ["Redis", f"{env['redis']['version']} ({env['redis']['mode']}), save=\"{env['redis']['config']['save']}\", appendonly={env['redis']['config']['appendonly']}, maxmemory-policy={env['redis']['config']['maxmemory-policy']}"],
    ["Docker", f"Server {env['docker']['server']}; {len(env['docker']['runningContainers'])} containers running (Redis and seven unrelated)"],
    ["Packages", ", ".join(f"{k} {v}" for k, v in env["packages"].items())],
    ["Settings", f"Verification: {env['settings']['verifyCost']['trials']} trials, {env['settings']['verifyCost']['warmup']} warm-up + {env['settings']['verifyCost']['iterations']} measured; HTTP: {env['settings']['http']['trials']} trials, {env['settings']['http']['warmup']} s + {env['settings']['http']['duration']} s at {', '.join(map(str, env['settings']['http']['levels']))} clients; seed {env['settings']['seed']}"]],
    [3.5, 9.5]))
vc = json.loads((RUN / "verify-cost.trials.json").read_text(encoding="utf-8"))["rows"]
order = ["store.ioredis.exists", "store.ninsho.get",
         "verify.ninsho-opaque.redis", "verify.ninsho-paseto.redis", "verify.jwt-redis.redis",
         ]
vrows = []
for key in order:
    for r in sorted((r for r in vc if r["id"] == key), key=lambda r: r["trial"]):
        vrows.append([key.replace("verify.", "").replace("store.", "store: "), str(r["trial"]),
                      f"{r['p50Ms']:.3f}", f"{r['p95Ms']:.3f}", f"{r['p99Ms']:.3f}", f"{r['meanMs']:.3f}", f"{r['opsPerSec']:.0f}"])
blocks.append(("tbl", "f-verify", "Per-trial verification cost of the operations discussed in Section 4.2 (ms; 1,000 samples per trial)",
               ["Operation", "Trial", "p50", "p95", "p99", "Mean", "Ops/s"], vrows, [4.6, 1.1, 1.4, 1.4, 1.4, 1.4, 1.5]))
hr = json.loads((RUN / "http.trials.json").read_text(encoding="utf-8"))["rows"]
hrows = []
for cfg in ["ninsho-opaque", "ninsho-paseto", "jwt-redis"]:
    for c in (1, 16):
        for r in sorted((r for r in hr if r["config"] == cfg and r["concurrency"] == c), key=lambda r: r["trial"]):
            hrows.append([cfg, str(c), str(r["trial"]), f"{r['requests']:,}", f"{r['throughputRps']:.1f}",
                          f"{r['p50Ms']:.2f}", f"{r['p95Ms']:.2f}", f"{r['p99Ms']:.2f}"])
blocks.append(("tbl", "f-http", "Per-trial HTTP results of the compared configurations (all responses HTTP 200; latency in ms; reference configurations are in http.trials.json)",
               ["Configuration", "Clients", "Trial", "Requests", "Req/s", "p50", "p95", "p99"], hrows,
               [3.3, 1.3, 1.1, 1.7, 1.6, 1.3, 1.3, 1.3]))
blocks.append(("p", "Table {T:f-env} records the environment, Table {T:f-verify} the per-trial verification results and Table {T:f-http} the per-trial HTTP results of the compared configurations."))
blocks += list(ca.APPENDIX_F_METHOD) + list(ca.APPENDIX_G) + list(ca.APPENDIX_H)
blocks += [("app", "Appendix I: Glossary"),
           ("p", "Table {T:i-glossary} defines the terms used in this report."),
           ("tbl", "i-glossary", "Glossary of terms used in this report", ["Term", "Meaning"], ca.GLOSSARY, [3.5, 9.5])]
# Appendices are built above but deliberately not inserted (report without appendices).
# after(last_ref, blocks)

# ── Renumber captions and resolve placeholders ─────────────────────────────
chapter, appendix = 0, None
counters = {}
labels = {}       # key -> "Table 3.4"
old_to_new = {}   # "Table 4.8" -> "Table 4.15"
for p in b.body.iter(w("p")):
    st = p.find("w:pPr/w:pStyle", NS)
    style = st.get(w("val")) if st is not None else None
    txt = b.text(p)
    if style == "Heading1":
        chapter += 1; appendix = None
    elif style == "FrontMatterTitleinTOC":
        m = re.match(r"Appendix ([A-I]):", txt)
        appendix = m.group(1) if m else None
        if txt.strip() == "References":
            appendix = None
    if style not in ("TableCaption", "FigureCaption"):
        continue
    kind = "Table" if style == "TableCaption" else "Figure"
    prefix = appendix or str(chapter)
    counters[(kind, prefix)] = counters.get((kind, prefix), 0) + 1
    new = f"{kind} {prefix}.{counters[(kind, prefix)]}"
    first = p.find("w:r/w:t", NS)
    m_new = re.match(r"\{([TF])LABEL:([^}]+)\}: ", first.text)
    if m_new:
        labels[m_new.group(2)] = new
    else:
        m_old = re.match(r"((?:Table|Figure) \d+\.\d+): ", first.text)
        if not m_old:
            raise SystemExit(f"unrecognised caption: {txt!r}")
        old_to_new[m_old.group(1)] = new
    first.text = new + ": "

for key, num in ref_numbers.items():
    labels[f"R:{key}"] = f"[{num}]"

unresolved = set()
for t in b.body.iter(w("t")):
    if not t.text:
        continue
    par = t.getparent().getparent()
    st = par.find("w:pPr/w:pStyle", NS) if par.tag == w("p") else None
    if st is not None and (st.get(w("val"), "").startswith("TOC")
                           or st.get(w("val")) in ("TableCaption", "FigureCaption")):
        continue
    s = t.text
    # Old labels first, so that a placeholder resolving to a number that was
    # also an old label is not remapped a second time.
    s = re.sub(r"\b((?:Table|Figure) \d+\.\d+)\b", lambda m: old_to_new.get(m.group(1), m.group(1)), s)
    # Content writes "Table {T:key}"; the label already includes the word.
    s = re.sub(r"(?:(?:Table|Figure) )?\{([TF]):([^}]+)\}", lambda m: labels.get(m.group(2)) or unresolved.add(m.group(0)) or m.group(0), s)
    s = re.sub(r"\{R:([^}]+)\}", lambda m: labels.get("R:" + m.group(1)) or unresolved.add(m.group(0)) or m.group(0), s)
    t.text = s
if unresolved:
    raise SystemExit(f"unresolved placeholders: {sorted(unresolved)}")
leftover = [b.text(p) for p in b.body.iter(w("p")) if "LABEL:" in b.text(p) or "{T:" in b.text(p) or "{F:" in b.text(p)]
if leftover:
    raise SystemExit(f"leftover markers: {leftover[:3]}")

b.save()
ct = unpacked / "[Content_Types].xml"
names = [i.filename for i in zipfile.ZipFile(ROOT / "academic/Ninsho_BTech_Project_Report_REVISED_v4_2026-10-21.docx").infolist()]
extra = sorted(str(p.relative_to(unpacked)).replace("\\", "/") for p in unpacked.rglob("*") if p.is_file()
               and str(p.relative_to(unpacked)).replace("\\", "/") not in names)
with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
    for n in names + extra:
        z.write(unpacked / n, n)
print("captions renumbered:", len(old_to_new), "existing,", len(labels) - len(ref_numbers), "new")
print("changed existing labels:", {k: v for k, v in old_to_new.items() if k != v})
print("written", out_path)
