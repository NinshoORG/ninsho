"""Generate the paper's figures from recorded evidence only.

Reads the JSON files of the reported benchmark run; executes no benchmark,
test or probe. Diagrams are drawn from the architecture described in the
repository (AGENTS.md section 3, packages/server/src/session/manager.ts).

    python research/paper/figures/make_figures.py
"""
import json
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

HERE = Path(__file__).resolve().parent
RUN = HERE.parents[1] / "validation" / "benchmarks" / "results" / "2026-10-21T08-47-13-720Z-6f82026-standard"

plt.rcParams.update({
    "font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"],
    "font.size": 8, "axes.titlesize": 8, "axes.labelsize": 8,
    "xtick.labelsize": 7, "ytick.labelsize": 7, "legend.fontsize": 7,
    "pdf.fonttype": 42,
})
COLOURS = {"ninsho-opaque": "#1f77b4", "ninsho-paseto": "#2ca02c", "jwt-redis": "#d62728",
           "jwt-stateless": "#9467bd", "no-auth": "#7f7f7f"}
ARROW = "→"


def save(fig, name):
    fig.savefig(HERE / f"{name}.pdf", bbox_inches="tight")
    fig.savefig(HERE / f"{name}.png", dpi=200, bbox_inches="tight")
    plt.close(fig)


def box(ax, x, y, w, h, text, fc="#ffffff", ec="#333333", fs=7, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.01,rounding_size=0.015",
                                fc=fc, ec=ec, lw=0.8))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
            fontweight="bold" if bold else "normal")


def arrow(ax, x1, y1, x2, y2, dashed=False):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=7,
                                 lw=0.8, color="#333333", linestyle="--" if dashed else "-"))


# Fig. 1: architecture and trust boundaries
def architecture():
    fig, ax = plt.subplots(figsize=(3.5, 2.75))
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    ax.add_patch(FancyBboxPatch((0.01, 0.62), 0.30, 0.36, boxstyle="round,pad=0.005", fc="#eef4fb", ec="#1f77b4", lw=0.8))
    ax.text(0.16, 0.95, "Browser (untrusted)", ha="center", fontsize=7, fontweight="bold")
    box(ax, 0.03, 0.76, 0.26, 0.14, "@ninshorg/client\nDPoP proofs, token\nin memory only", fs=6)
    box(ax, 0.03, 0.645, 0.26, 0.09, "IndexedDB: non-\nextractable P-256 key", fs=6)
    ax.add_patch(FancyBboxPatch((0.37, 0.18), 0.62, 0.80, boxstyle="round,pad=0.005", fc="#f3f9f1", ec="#2ca02c", lw=0.8))
    ax.text(0.68, 0.95, "Application process (Node.js)", ha="center", fontsize=7, fontweight="bold")
    box(ax, 0.40, 0.78, 0.27, 0.13, "verify() middleware\n+ DPoP check", fs=6)
    box(ax, 0.70, 0.78, 0.27, 0.13, "Guards: role, scope,\nowner, tenant, fresh", fs=6)
    box(ax, 0.40, 0.58, 0.27, 0.15, "Token engine\nopaque | PASETO v4", fs=6)
    box(ax, 0.70, 0.58, 0.27, 0.15, "Session manager\nrotation, reuse,\nrevocation", fs=6)
    box(ax, 0.40, 0.40, 0.27, 0.13, "Rate limiter\n(IP + account)", fs=6)
    box(ax, 0.70, 0.40, 0.27, 0.13, "One-time tokens", fs=6)
    box(ax, 0.40, 0.22, 0.57, 0.12, "@ninshorg/webauthn (optional)", fs=6, fc="#fafafa")
    box(ax, 0.40, 0.01, 0.57, 0.12, "Store: RedisStore (shared) | MemoryStore (tests)", fs=6, fc="#fff4e5", ec="#ff7f0e")
    box(ax, 0.03, 0.26, 0.26, 0.20, "Application:\npasswords, passkey\nlookup, user model\n(not Ninsho)", fs=6, fc="#f7f7f7", ec="#999999")
    arrow(ax, 0.29, 0.835, 0.40, 0.845)
    ax.text(0.345, 0.87, "TB1", ha="center", fontsize=6, fontweight="bold")
    arrow(ax, 0.535, 0.78, 0.535, 0.73)
    arrow(ax, 0.67, 0.845, 0.70, 0.845)
    arrow(ax, 0.68, 0.22, 0.68, 0.13)
    ax.text(0.70, 0.158, "TB4", ha="left", va="center", fontsize=6, fontweight="bold", bbox=dict(fc="white", ec="none", pad=0.6))
    arrow(ax, 0.29, 0.43, 0.40, 0.60, dashed=True)
    ax.text(0.16, 0.48, "createSession()", ha="center", fontsize=6, style="italic")
    save(fig, "fig-architecture")


# Fig. 2: refresh rotation and reuse decision
def refresh_flow():
    fig, ax = plt.subplots(figsize=(3.5, 2.6))
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    box(ax, 0.30, 0.89, 0.40, 0.09, "Refresh token presented", fs=6.5, bold=True)
    box(ax, 0.24, 0.74, 0.52, 0.10, f"Peek record; DPoP binding\nmismatch {ARROW} refuse (nothing consumed)", fs=6)
    box(ax, 0.24, 0.59, 0.52, 0.10, "take() = atomic GETDEL\n(exactly one caller wins)", fs=6)
    box(ax, 0.01, 0.36, 0.36, 0.15, "Winner: write new token,\ngrace mapping, then\ntombstone; re-check revoked", fs=6, fc="#eef9ee")
    box(ax, 0.42, 0.38, 0.57, 0.11, "Lost race or replay: wait for\ntombstone (bounded backoff)", fs=6, fc="#fff4f4")
    box(ax, 0.01, 0.10, 0.36, 0.14, "Return new pair\n(authenticatedAt unchanged)", fs=6)
    box(ax, 0.42, 0.07, 0.18, 0.19, f"Grace\nmapping\npresent {ARROW}\nadopt", fs=5.8)
    box(ax, 0.615, 0.07, 0.18, 0.19, f"Grace over\n{ARROW} revoke\nfamily, emit\nreuse alarm", fs=5.8, fc="#fde3e3")
    box(ax, 0.81, 0.07, 0.18, 0.19, f"No\ntombstone\n{ARROW} invalid,\nno revoke", fs=5.8)
    arrow(ax, 0.5, 0.89, 0.5, 0.84)
    arrow(ax, 0.5, 0.74, 0.5, 0.69)
    arrow(ax, 0.38, 0.59, 0.19, 0.51)
    ax.text(0.27, 0.565, "record", fontsize=6, ha="right")
    arrow(ax, 0.62, 0.59, 0.705, 0.49)
    ax.text(0.68, 0.555, "null", fontsize=6, ha="left")
    arrow(ax, 0.19, 0.36, 0.19, 0.24)
    arrow(ax, 0.51, 0.38, 0.51, 0.26)
    arrow(ax, 0.705, 0.38, 0.705, 0.26)
    arrow(ax, 0.90, 0.38, 0.90, 0.26)
    save(fig, "fig-refresh-flow")


def load(name):
    return json.loads((RUN / name).read_text(encoding="utf-8"))


# Fig. 4: verification latency per trial
def verify_latency():
    rows = load("verify-cost.trials.json")["rows"]
    order = [("store.ioredis.exists", "EXISTS\n(ioredis)", "store"),
             ("store.ninsho.get", "GET\n(store)", "store"),
             ("verify.ninsho-opaque.redis", "Opaque", "cmp"),
             ("verify.ninsho-paseto.redis", "PASETO\n+deny", "cmp"),
             ("verify.jwt-redis.redis", "JWT\n+deny", "cmp"),
             ("verify.ninsho-paseto.no-revocation", "PASETO\nsig only*", "ref"),
             ("verify.jwt-stateless", "JWT\nsig only*", "ref")]
    colour = {"store": "#ff7f0e", "cmp": "#1f77b4", "ref": "#999999"}
    fig, ax = plt.subplots(figsize=(3.5, 2.1))
    for i, (key, _, kind) in enumerate(order):
        vals = [r["p50Ms"] for r in rows if r["id"] == key]
        ax.scatter([i] * len(vals), vals, s=12, color=colour[kind], zorder=3)
        ax.hlines(statistics.median(vals), i - 0.28, i + 0.28, color="black", lw=1.2, zorder=4)
    ax.set_xticks(range(len(order)))
    ax.set_xticklabels([o[1] for o in order], fontsize=6)
    ax.set_ylabel("p50 latency per trial (ms)")
    ax.set_ylim(0, 2.9)
    ax.grid(axis="y", lw=0.3, alpha=0.6)
    ax.text(0.02, 0.97, "orange: store round trip only\nblue: verification with revocation\ngrey*: no server-side revocation",
            transform=ax.transAxes, ha="left", va="top", fontsize=6)
    save(fig, "fig-verify-latency")


# Fig. 5: HTTP throughput per trial
def http_throughput():
    rows = load("http.trials.json")["rows"]
    configs = [("ninsho-opaque", "Opaque"), ("ninsho-paseto", "PASETO"), ("jwt-redis", "JWT+Redis"),
               ("jwt-stateless", "JWT stateless*"), ("no-auth", "No auth*")]
    fig, axes = plt.subplots(1, 2, figsize=(3.5, 2.0))
    for ax, c in zip(axes, (1, 16)):
        for i, (key, _) in enumerate(configs):
            vals = [r["throughputRps"] for r in rows if r["config"] == key and r["concurrency"] == c]
            ax.scatter([i] * len(vals), vals, s=10, color=COLOURS[key], zorder=3)
            ax.hlines(statistics.median(vals), i - 0.3, i + 0.3, color="black", lw=1.1, zorder=4)
        ax.set_xticks(range(len(configs)))
        ax.set_xticklabels([n for _, n in configs], rotation=45, ha="right", fontsize=6)
        ax.set_title(f"{c} concurrent client{'s' if c > 1 else ''}", fontsize=7)
        ax.set_ylim(0, 1450)
        ax.grid(axis="y", lw=0.3, alpha=0.6)
    axes[0].set_ylabel("Throughput (successful req/s)")
    fig.tight_layout()
    save(fig, "fig-http-throughput")


if __name__ == "__main__":
    architecture()
    refresh_flow()
    verify_latency()
    http_throughput()
    print("figures written to", HERE)
