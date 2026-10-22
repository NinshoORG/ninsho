"""Figures for the expanded Ninsho B.Tech report.

Diagrams are drawn from behaviour verified in the source tree (file references
in each function). Data figures read only recorded files under
research/validation/benchmarks/results/; nothing here runs a benchmark, test or
probe.

    python academic/report-figures-src/make_report_figures.py
Output: academic/report-figures/*.png (200 dpi, for Word)
"""
import gzip
import json
import statistics
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "academic" / "report-figures"
OUT.mkdir(parents=True, exist_ok=True)
RUN = ROOT / "research" / "validation" / "benchmarks" / "results" / "2026-10-21T08-47-13-720Z-6f82026-standard"

plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "DejaVu Serif"],
                     "font.size": 9, "axes.labelsize": 9, "xtick.labelsize": 8, "ytick.labelsize": 8})
ARROW = "→"


def save(fig, name):
    fig.savefig(OUT / f"{name}.png", dpi=200, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def box(ax, x, y, w, h, text, fc="#ffffff", ec="#333333", fs=8, bold=False, style="round"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=f"{style},pad=0.008", fc=fc, ec=ec, lw=0.9))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
            fontweight="bold" if bold else "normal")


def arrow(ax, x1, y1, x2, y2, label=None, dashed=False, fs=7, off=0.015, both=False):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="<|-|>" if both else "-|>",
                                 mutation_scale=8, lw=0.9, color="#333333",
                                 linestyle="--" if dashed else "-"))
    if label:
        ax.text((x1 + x2) / 2, (y1 + y2) / 2 + off, label, ha="center", va="bottom", fontsize=fs,
                bbox=dict(fc="white", ec="none", pad=0.4))


def canvas(w=6.3, h=4.0):
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    return fig, ax


# ── Sequence-diagram helper ────────────────────────────────────────────────
def sequence(name, participants, steps, height=5.6, width=6.3, title_fs=8):
    """participants: list of labels. steps: list of tuples
    ('m', a, b, label, dashed) message; ('n', a, b, text) note spanning a..b;
    ('g', text) group divider."""
    fig, ax = plt.subplots(figsize=(width, height))
    n = len(participants)
    xs = [0.08 + i * (0.84 / (n - 1)) for i in range(n)]
    rows = len(steps)
    top, bottom = 0.92, 0.03
    dy = (top - bottom) / (rows + 0.5)
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    for x, p in zip(xs, participants):
        box(ax, x - 0.075, 0.935, 0.15, 0.06, p, fc="#e8e7f3", fs=title_fs, bold=True)
        ax.plot([x, x], [bottom, 0.935], color="#999999", lw=0.7, ls=(0, (3, 3)), zorder=0)
    y = top - dy * 0.6
    for s in steps:
        kind = s[0]
        if kind == "m":
            _, a, b, label, dashed = s
            xa, xb = xs[a], xs[b]
            if a == b:
                ax.add_patch(FancyArrowPatch((xa, y + dy * 0.25), (xa + 0.001, y - dy * 0.25),
                                             connectionstyle="arc3,rad=-1.6", arrowstyle="-|>",
                                             mutation_scale=7, lw=0.8, color="#333333"))
                ax.text(xa + 0.035, y, label, ha="left", va="center", fontsize=7)
            else:
                ax.add_patch(FancyArrowPatch((xa, y), (xb, y), arrowstyle="-|>", mutation_scale=8, lw=0.9,
                                             color="#333333", linestyle="--" if dashed else "-"))
                ax.text((xa + xb) / 2, y + dy * 0.12, label, ha="center", va="bottom", fontsize=7,
                        bbox=dict(fc="white", ec="none", pad=0.3))
        elif kind == "n":
            _, a, b, text = s
            x1, x2 = min(xs[a], xs[b]) - 0.06, max(xs[a], xs[b]) + 0.06
            ax.add_patch(Rectangle((x1, y - dy * 0.38), x2 - x1, dy * 0.76, fc="#fff8dc", ec="#b8a000", lw=0.6))
            ax.text((x1 + x2) / 2, y, text, ha="center", va="center", fontsize=6.8)
        elif kind == "g":
            ax.plot([0.01, 0.99], [y, y], color="#555555", lw=0.6)
            ax.text(0.012, y + dy * 0.08, s[1], ha="left", va="bottom", fontsize=7, style="italic",
                    bbox=dict(fc="#f2f2f2", ec="none", pad=0.4))
        y -= dy
    save(fig, name)


# ── 1. System context (README, AGENTS.md section 1) ────────────────────────
def system_context():
    fig, ax = canvas(6.3, 3.9)
    box(ax, 0.36, 0.38, 0.30, 0.26, "Host application\n(Express, Fastify, Hono, Koa)\n\nembeds @ninshorg/server", fc="#f3f9f1", ec="#2ca02c", bold=False)
    box(ax, 0.02, 0.62, 0.22, 0.20, "End user\nbrowser + optional\n@ninshorg/client", fc="#eef4fb", ec="#1f77b4")
    box(ax, 0.02, 0.22, 0.22, 0.16, "Authenticator\n(passkey, optional)", fc="#eef4fb", ec="#1f77b4")
    box(ax, 0.76, 0.62, 0.22, 0.18, "Redis 6.2+\nsession and\nrevocation state", fc="#fff4e5", ec="#ff7f0e")
    box(ax, 0.76, 0.30, 0.22, 0.18, "Application database\nusers, password hashes,\npasskey records", fc="#f7f7f7", ec="#999999")
    box(ax, 0.36, 0.05, 0.30, 0.14, "Operator\nconfiguration, keys,\naudit-event sink", fc="#f7f7f7", ec="#999999")
    box(ax, 0.36, 0.80, 0.30, 0.13, "npm registry\n@ninshorg/* 0.1.1", fc="#f7f7f7", ec="#999999")
    arrow(ax, 0.24, 0.72, 0.36, 0.56, "HTTPS: credentials,\nAuthorization, DPoP", both=True)
    arrow(ax, 0.24, 0.30, 0.36, 0.44, "WebAuthn ceremony\n(via browser)", dashed=True, both=True)
    arrow(ax, 0.66, 0.56, 0.76, 0.70, "store contract", both=True)
    arrow(ax, 0.66, 0.46, 0.76, 0.40, "app-owned", both=True)
    arrow(ax, 0.51, 0.19, 0.51, 0.38, "config")
    arrow(ax, 0.51, 0.80, 0.51, 0.64, "install")
    save(fig, "ctx-system-context")


# ── 2. Packages and dependencies (package.json files) ──────────────────────
def packages():
    fig, ax = canvas(6.3, 3.3)
    box(ax, 0.38, 0.06, 0.24, 0.18, "@ninshorg/core\ntypes, errors, crypto,\ntime (no dependencies)", fc="#e8e7f3", bold=False)
    box(ax, 0.06, 0.48, 0.30, 0.30, "@ninshorg/server\nNinsho facade, engines,\nsession manager, guards,\nrate limiter, DPoP, stores\n+ subpaths: /fastify /hono /koa", fc="#f3f9f1", ec="#2ca02c")
    box(ax, 0.66, 0.48, 0.30, 0.30, "@ninshorg/webauthn\nceremonies, CBOR/COSE,\nattestation formats, MDS\n+ subpath: /testing", fc="#eef4fb", ec="#1f77b4")
    box(ax, 0.40, 0.82, 0.20, 0.14, "@ninshorg/client\nbrowser only,\nno dependencies", fc="#fff4e5", ec="#ff7f0e")
    box(ax, 0.06, 0.12, 0.18, 0.12, "ioredis ^6", fc="#f7f7f7", ec="#999999")
    arrow(ax, 0.26, 0.48, 0.42, 0.24, "depends on")
    arrow(ax, 0.74, 0.48, 0.58, 0.24, "depends on")
    arrow(ax, 0.15, 0.48, 0.15, 0.24, "RedisStore")
    arrow(ax, 0.40, 0.88, 0.25, 0.78, "HTTP + DPoP\n(no import)", dashed=True)
    save(fig, "pkg-architecture")


# ── 3. Multi-instance deployment ───────────────────────────────────────────
def deployment():
    fig, ax = canvas(6.3, 3.6)
    box(ax, 0.02, 0.70, 0.18, 0.20, "Browser tab 1", fc="#eef4fb", ec="#1f77b4")
    box(ax, 0.02, 0.36, 0.18, 0.20, "Browser tab 2", fc="#eef4fb", ec="#1f77b4")
    ax.annotate("", xy=(0.11, 0.56), xytext=(0.11, 0.70), arrowprops=dict(arrowstyle="<|-|>", lw=0.8, ls="--"))
    ax.text(0.125, 0.63, "BroadcastChannel\nnotices (opt-in)", fontsize=6.5, va="center")
    box(ax, 0.27, 0.50, 0.16, 0.26, "Reverse proxy /\nload balancer\n(sets Host,\nX-Forwarded-*)", fc="#f7f7f7", ec="#999999", fs=7)
    box(ax, 0.50, 0.66, 0.22, 0.22, "App instance A\nNinsho (same config)", fc="#f3f9f1", ec="#2ca02c")
    box(ax, 0.50, 0.30, 0.22, 0.22, "App instance B\nNinsho (same config)", fc="#f3f9f1", ec="#2ca02c")
    box(ax, 0.79, 0.44, 0.19, 0.26, "Shared Redis\nrt / at / sess / rev /\ndpop / rl / ott keys", fc="#fff4e5", ec="#ff7f0e", fs=7)
    arrow(ax, 0.20, 0.80, 0.27, 0.68)
    arrow(ax, 0.20, 0.46, 0.27, 0.58)
    arrow(ax, 0.43, 0.68, 0.50, 0.77)
    arrow(ax, 0.43, 0.58, 0.50, 0.41)
    arrow(ax, 0.72, 0.77, 0.79, 0.62, both=True)
    arrow(ax, 0.72, 0.41, 0.79, 0.52, both=True)
    ax.text(0.61, 0.12, "Logout on A writes the revocation to Redis; the next request\n"
            "to B finds no access record (opaque) or a deny-list entry (PASETO).", ha="center", fontsize=7)
    save(fig, "deploy-multi-instance")


# ── 4. Trust boundaries (security assessment threat model) ─────────────────
def trust_boundaries():
    fig, ax = canvas(6.3, 4.2)
    ax.add_patch(Rectangle((0.01, 0.52), 0.30, 0.46, fc="#fdecec", ec="#d62728", lw=0.9, ls="--"))
    ax.text(0.16, 0.95, "Untrusted: browser and network", ha="center", fontsize=7.5, fontweight="bold")
    box(ax, 0.03, 0.78, 0.26, 0.12, "Page script, client SDK\n(TB6: same-origin JS)", fs=7)
    box(ax, 0.03, 0.56, 0.26, 0.16, "HTTP request: Authorization,\nDPoP, Host, X-Forwarded-*,\nrefresh cookie, body", fs=7)
    ax.add_patch(Rectangle((0.37, 0.18), 0.40, 0.80, fc="#eef9ee", ec="#2ca02c", lw=0.9))
    ax.text(0.57, 0.95, "Trusted process: application + Ninsho", ha="center", fontsize=7.5, fontweight="bold")
    box(ax, 0.40, 0.78, 0.34, 0.12, "TB1 verify() + DPoP checks", fs=7)
    box(ax, 0.40, 0.62, 0.34, 0.12, "TB2 rate limiter (address, account)", fs=7)
    box(ax, 0.40, 0.46, 0.34, 0.12, "TB3 refresh / logout routes", fs=7)
    box(ax, 0.40, 0.30, 0.34, 0.12, "TB5 WebAuthn verification", fs=7)
    box(ax, 0.40, 0.20, 0.34, 0.07, "TB7 configuration by integrator", fs=7)
    ax.add_patch(Rectangle((0.83, 0.30), 0.16, 0.50, fc="#fff4e5", ec="#ff7f0e", lw=0.9))
    box(ax, 0.84, 0.45, 0.14, 0.22, "Redis\n(availability,\npersistence,\neviction)", fs=7, fc="#fff4e5", ec="#ff7f0e")
    arrow(ax, 0.29, 0.64, 0.40, 0.82)
    arrow(ax, 0.29, 0.62, 0.40, 0.68)
    arrow(ax, 0.29, 0.60, 0.40, 0.52)
    arrow(ax, 0.74, 0.56, 0.84, 0.56, "TB4", both=True)
    ax.text(0.02, 0.44, "Adversaries considered\n"
            "A1 remote, unauthenticated\nA2 signed-in user targeting others\n"
            "A3 holder of a stolen bearer or\n     refresh token, not the DPoP key\n"
            "A4 observer of proofs (logging proxy)\nA5 same-origin script (XSS)\n"
            "A6 operator or infrastructure failure", fontsize=6.8, va="top",
            bbox=dict(fc="#f7f7f7", ec="#999999", pad=3))
    save(fig, "threat-trust-boundaries")


# ── 5. Session creation and access-token verification (manager.ts, opaque.ts) ─
def seq_access():
    P = ["Client", "Application", "Ninsho", "Redis"]
    S = [("g", "Sign-in"),
         ("m", 0, 1, "POST /login (credentials)", False),
         ("m", 1, 1, "verify credentials (app-owned)", False),
         ("m", 1, 2, "createSession(principal)", False),
         ("m", 2, 3, "SET rt:<hash> (refresh record, family TTL)", False),
         ("m", 2, 3, "SET sess:<id>:meta; SADD user:<id>:sess", False),
         ("m", 2, 3, "SET at:<hash>, atid:<id>; SADD sess:<id>:at", False),
         ("m", 2, 3, "EXISTS sess:<id>:dead  (revoked meanwhile?)", False),
         ("m", 2, 1, "{accessToken, refreshToken, sessionId}", True),
         ("m", 1, 0, "access token (body); refresh token (HttpOnly cookie)", True),
         ("g", "Protected request"),
         ("m", 0, 1, "GET /orders  Authorization: Bearer <t>", False),
         ("m", 1, 2, "verify() middleware", False),
         ("m", 2, 3, "GET at:<SHA-256(t)>", False),
         ("m", 3, 2, "record | null | error", True),
         ("n", 1, 3, "null " + ARROW + " 401;  error " + ARROW + " 503 (fail closed);  record " + ARROW + " check expiry, binding"),
         ("m", 2, 1, "req.auth = {userId, roles, scopes, sessionId, ...}", True),
         ("m", 1, 0, "200 + response (guards may still return 403)", True)]
    sequence("seq-access-token", P, S, height=5.3)


# ── 6. Refresh rotation with a parallel tab and a later replay (manager.ts) ─
def seq_refresh():
    P = ["Tab A", "Tab B", "Ninsho", "Redis"]
    S = [("g", "Two tabs refresh the same token at once"),
         ("m", 0, 2, "refresh(R0)", False),
         ("m", 1, 2, "refresh(R0)", False),
         ("m", 2, 3, "GET rt:h0 (peek: DPoP binding check)", False),
         ("m", 2, 3, "GETDEL rt:h0  (A's call wins)", False),
         ("m", 2, 3, "GETDEL rt:h0  (B's call gets null)", False),
         ("n", 1, 3, "winner: SET rt:h1, SET rtg:h0 " + ARROW + " R1 (30 s), then SET rtc:h0 (tombstone)"),
         ("m", 2, 0, "{R1, new access token}", True),
         ("m", 2, 3, "B: GET rtc:h0 with backoff 2,4,...,64 ms", False),
         ("m", 2, 3, "B: GET rtg:h0 " + ARROW + " R1 (inside grace)", False),
         ("m", 2, 1, "{R1, new access token}  (tabs converge)", True),
         ("g", "Replay of R0 after the grace window"),
         ("m", 1, 2, "refresh(R0)  (attacker or stale copy)", False),
         ("m", 2, 3, "GETDEL rt:h0 " + ARROW + " null; GET rtc:h0 " + ARROW + " found; rtg:h0 expired", False),
         ("n", 2, 3, "revoke whole family; emit refresh.reuse_detected"),
         ("m", 2, 1, "401 REFRESH_REUSE_DETECTED", True)]
    sequence("seq-refresh-rotation", P, S, height=5.3)


# ── 7. Logout / revocation and a racing rotation (manager.ts #revokeFamily) ─
def seq_logout():
    P = ["Client", "Ninsho", "Redis", "Concurrent\nrotation"]
    S = [("m", 0, 1, "POST /logout (verified session)", False),
         ("m", 1, 2, "1. SET sess:<id>:dead  (marker first)", False),
         ("m", 1, 2, "2. GET sess:<id>:meta", False),
         ("m", 1, 2, "3. SMEMBERS sess:<id>:rt", False),
         ("m", 1, 2, "4. SET rtx:<h> for each hash", False),
         ("m", 1, 2, "5. DEL rt:<h>, rtc:<h>, rtg:<h>", False),
         ("m", 1, 2, "6. DEL sess:<id>:rt, sess:<id>:meta", False),
         ("m", 1, 2, "7. engine.revokeSession: DEL at/atid or SET rev:<jti>", False),
         ("m", 1, 2, "8. SREM user:<uid>:sess <id>", False),
         ("m", 1, 0, "204; client clears cookie and memory", True),
         ("g", "Interleaving guarded by the marker"),
         ("m", 3, 2, "issue new token, then EXISTS sess:<id>:dead", False),
         ("n", 1, 3, "marker present " + ARROW + " revoke the new token, undo writes, refuse"),
         ("n", 1, 3, "Either revocation enumerates the new token or the issuer sees the marker")]
    sequence("seq-logout-revocation", P, S, height=4.6)


# ── 8. DPoP-bound request (dpop-middleware.ts, dpop/proof.ts, dpop/replay.ts) ─
def seq_dpop():
    P = ["Browser client", "verify()", "Proof checks", "Redis"]
    S = [("m", 0, 0, "sign proof: htm, htu, iat, jti, ath (non-extractable key)", False),
         ("m", 0, 1, "Authorization: DPoP <t>;  DPoP: <proof>", False),
         ("m", 1, 1, "exactly one Authorization and one DPoP header (rawHeaders)", False),
         ("m", 1, 2, "verify proof", False),
         ("n", 1, 3, "typ dpop+jwt; alg in {ES256, EdDSA}; public jwk"),
         ("n", 1, 3, "signature first, then htm, htu, iat window, ath"),
         ("m", 2, 1, "jkt = RFC 7638 thumbprint", True),
         ("m", 1, 3, "SET dpop:<jkt>:<jti> NX EX (maxAge + 2" + "·" + "tolerance + 1)", False),
         ("m", 3, 1, "OK (first use) | nil (replay " + ARROW + " 401)", True),
         ("m", 1, 3, "token lookup / signature + deny-list", False),
         ("n", 1, 3, "token cnf.jkt must equal proof jkt, otherwise 401"),
         ("m", 1, 0, "request proceeds with req.auth", True)]
    sequence("seq-dpop-request", P, S, height=4.6)


# ── 9. WebAuthn: responsibilities (webauthn/src/server.ts, express example) ─
def webauthn_flow():
    fig, ax = canvas(6.3, 4.4)
    ax.add_patch(Rectangle((0.01, 0.02), 0.31, 0.90, fc="#f7f7f7", ec="#999999", lw=0.8))
    ax.add_patch(Rectangle((0.345, 0.02), 0.31, 0.90, fc="#eef4fb", ec="#1f77b4", lw=0.8))
    ax.add_patch(Rectangle((0.68, 0.02), 0.31, 0.90, fc="#f3f9f1", ec="#2ca02c", lw=0.8))
    for x, t in [(0.165, "Application (integrator)"), (0.5, "Browser / authenticator"), (0.835, "@ninshorg/webauthn")]:
        ax.text(x, 0.95, t, ha="center", fontsize=8, fontweight="bold")
    steps = [
        (0.835, 0.82, "startRegistration / startAuthentication:\nchallenge stored, single use"),
        (0.5, 0.67, "navigator.credentials\n.create() / .get()"),
        (0.835, 0.52, "finish*: type, challenge, origin,\nrpId hash, flags, signature,\ncounter, attestation policy"),
        (0.165, 0.37, "store credential: id, public key,\nsignCount, owner (userId)"),
        (0.165, 0.20, "look up credential by id; pass\nowner as StoredCredential.userId"),
        (0.835, 0.20, "principal returned"),
        (0.165, 0.06, "createSession(principal)"),
    ]
    for x, y, t in steps:
        box(ax, x - 0.14, y - 0.055, 0.28, 0.11, t, fs=6.6)
    arrow(ax, 0.835, 0.765, 0.5, 0.725)
    arrow(ax, 0.5, 0.615, 0.835, 0.575)
    arrow(ax, 0.835, 0.465, 0.165, 0.425)
    arrow(ax, 0.305, 0.20, 0.695, 0.20)
    arrow(ax, 0.835, 0.145, 0.305, 0.08)
    save(fig, "webauthn-responsibilities")


# ── 10. Data: latency distribution from raw samples ────────────────────────
def latency_cdf():
    fig, ax = plt.subplots(figsize=(6.3, 3.0))
    series = [("verify.ninsho-opaque.redis", "Opaque + Redis", "#1f77b4"),
              ("verify.ninsho-paseto.redis", "PASETO + deny-list", "#2ca02c"),
              ("verify.jwt-redis.redis", "JWT + deny-list", "#d62728"),
              ("store.ioredis.exists", "Redis EXISTS only", "#ff7f0e")]
    for key, label, colour in series:
        samples = []
        for t in (1, 2, 3):
            data = json.loads(gzip.decompress((RUN / "raw" / f"verify-cost.t{t}.{key}.json.gz").read_bytes()))
            samples.extend(data["samples"])
        samples.sort()
        n = len(samples)
        ax.plot(samples, [(i + 1) / n for i in range(n)], label=f"{label} (n={n})", color=colour, lw=1.1)
    ax.set_xscale("log")
    ax.set_xlabel("Single verification latency (ms, log scale)")
    ax.set_ylabel("Cumulative fraction")
    ax.axhline(0.5, color="#999999", lw=0.5, ls=":")
    ax.axhline(0.95, color="#999999", lw=0.5, ls=":")
    ax.axhline(0.99, color="#999999", lw=0.5, ls=":")
    ax.grid(lw=0.3, alpha=0.5)
    ax.legend(fontsize=7, loc="lower right")
    save(fig, "bench-latency-cdf")


# ── 11. Data: throughput vs position in run order (confound) ───────────────
def run_order():
    rows = json.loads((RUN / "http.trials.json").read_text(encoding="utf-8"))["rows"]
    orders = {1: ["jwt-stateless", "no-auth", "ninsho-opaque", "ninsho-paseto", "jwt-redis"],
              2: ["jwt-stateless", "ninsho-opaque", "no-auth", "ninsho-paseto", "jwt-redis"],
              3: ["no-auth", "ninsho-opaque", "jwt-stateless", "ninsho-paseto", "jwt-redis"]}
    colours = {"ninsho-opaque": "#1f77b4", "ninsho-paseto": "#2ca02c", "jwt-redis": "#d62728",
               "jwt-stateless": "#9467bd", "no-auth": "#7f7f7f"}
    fig, ax = plt.subplots(figsize=(6.3, 2.8))
    for cfg, col in colours.items():
        xs, ys = [], []
        for r in rows:
            if r["config"] == cfg and r["concurrency"] == 16:
                xs.append(orders[r["trial"]].index(cfg) + 1 + (r["trial"] - 2) * 0.08)
                ys.append(r["throughputRps"])
        ax.scatter(xs, ys, color=col, s=22, label=cfg, zorder=3)
    ax.set_xticks([1, 2, 3, 4, 5])
    ax.set_xlabel("Position of the configuration in its trial's run order (1 = first)")
    ax.set_ylabel("Throughput, 16 clients (req/s)")
    ax.grid(lw=0.3, alpha=0.5)
    ax.legend(fontsize=7, ncol=5, loc="upper center", bbox_to_anchor=(0.5, 1.16), frameon=False)
    save(fig, "bench-run-order")


if __name__ == "__main__":
    for f in (system_context, packages, deployment, trust_boundaries, seq_access, seq_refresh,
              seq_logout, seq_dpop, webauthn_flow, latency_cdf, run_order):
        f()
    print("written:", sorted(p.name for p in OUT.glob("*.png")))
