"""All figures are generated from results/tables/*.csv (never hand-edited). Non-interactive backend."""
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from .problem import SUITE_CLASSIC, SUITE_HYBRID, SUITE_PQ, SUITES  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLES = os.path.join(ROOT, "results", "tables")
FIGS = os.path.join(ROOT, "results", "figures")
COL = {"A": "#2b6cb0", "B": "#dd6b20", "B_contended": "#9b2c2c"}
LABEL = {"A": "Platform A (unconstrained)", "B": "Platform B (1 core, 256 MB cap)",
         "B_contended": "B + CPU contention (extra)"}
SUITE_LABEL = {SUITE_CLASSIC: "Classical\nP-256 + ECDSA", SUITE_PQ: "PQ only\nML-KEM-768 + ML-DSA-65",
               SUITE_HYBRID: "Hybrid\nP-256+ML-KEM-768 + ML-DSA-65"}
DPI = 150


def load(name):
    return pd.read_csv(os.path.join(TABLES, f"processor_{name}_metrics.csv"))


def tables():
    t = {n: load(n) for n in ("A", "B", "B_contended") if os.path.exists(os.path.join(TABLES, f"processor_{n}_metrics.csv"))}
    return t


def pick(df, pass_type, suite, op, payload=None):
    d = df[(df.pass_type == pass_type) & (df.suite == suite) & (df.operation == op)]
    if payload is None:
        return d
    return d[d.payload_bytes == payload]


def repeat_stat(df, suite, op, col="median_us", payload=None):
    return pick(df, "latency", suite, op, payload)[col].astype(float).values


def _save(fig, name):
    os.makedirs(FIGS, exist_ok=True)
    fig.savefig(os.path.join(FIGS, name), dpi=DPI, bbox_inches="tight")
    plt.close(fig)


# ---------------------------------------------------------------- 1/2: platform resource profile
def platform_profile(name, df):
    """PS-P1 replacement for a coupling-map drawing: effective constraints + measured memory vs the cap."""
    fig, (ax0, ax1) = plt.subplots(1, 2, figsize=(12, 4), gridspec_kw={"width_ratios": [1.15, 1.2], "wspace": 0.28})
    r = df.iloc[0]
    cap = r.rlimit_as_mb_effective
    cells = [["CPU affinity (cores)", str(r.cpu_affinity_effective)],
             ["RLIMIT_AS cap", "none" if pd.isna(cap) else f"{int(cap)} MB"],
             ["Docker limits", "unavailable (not faked)"],
             ["Busy neighbours (same core)", str(int(r.contention_workers))],
             ["Crypto backend", "kyber-py / dilithium-py"],
             ["Python", str(r.python_version)]]
    ax0.axis("off")
    tb = ax0.table(cellText=cells, colLabels=["Property", "Value"], loc="center", cellLoc="left", colWidths=[0.58, 0.42])
    tb.auto_set_font_size(False)
    tb.set_fontsize(8)
    tb.scale(1, 1.7)
    ax0.set_title(f"{LABEL[name.replace('platform_', '')]}\neffective constraints (read back)", fontsize=9)
    mem = df[df.pass_type == "memory"]
    items = [("interpreter\nbaseline", mem.rss_baseline_kb.median() / 1024)]
    for lbl, suite, op, pay in (("handshake\nclassical", SUITE_CLASSIC, "handshake_total", None),
                                ("handshake\nhybrid", SUITE_HYBRID, "handshake_total", None),
                                ("bulk 10 MB\nhybrid", SUITE_HYBRID, "bulk_roundtrip", 10_000_000)):
        d = mem[(mem.suite == suite) & (mem.operation == op)]
        if pay:
            d = d[d.payload_bytes == pay]
        items.append((lbl, d.peak_rss_kb.median() / 1024))
    ax1.bar([i[0] for i in items], [i[1] for i in items], color=COL[name.replace("platform_", "")])
    for x, (_, v) in enumerate(items):
        ax1.text(x, v + 1, f"{v:.0f}", ha="center", fontsize=8)
    if not pd.isna(cap):
        ax1.axhline(cap, color="k", ls="--", lw=1)
        ax1.text(len(items) - 0.5, cap + 3, f"RLIMIT_AS cap = {int(cap)} MB (virtual, not RSS)", ha="right", fontsize=8)
    ax1.set_ylabel("Peak resident memory (MB)")
    ax1.set_title("Measured process peak RSS (median of 3 fresh processes)", fontsize=9)
    ax1.set_ylim(0, max(100, (0 if pd.isna(cap) else cap) * 1.15))
    fig.suptitle("PS-P1: platform resource profile (replaces the qubit coupling graph, which does not apply to a PQC channel)",
                 fontsize=8, y=1.02)
    return fig


# ---------------------------------------------------------------- 3: logical flow vs measured cost
def logical_vs_measured(df_a):
    fig, (ax, bx) = plt.subplots(1, 2, figsize=(13, 5.2), gridspec_kw={"width_ratios": [1, 1.25]})
    sz = pd.read_csv(os.path.join(TABLES, "sizes.csv"))
    n = {m: int(sz[(sz.suite == SUITE_HYBRID) & (sz.message == m)].bytes.iloc[0])
         for m in ("ClientHello", "ServerHello", "ClientFinished")}
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 10)
    ax.axis("off")
    ax.set_title("Logical protocol (hybrid suite, exact bytes on the wire)", fontsize=10)
    for x, who in ((1.4, "Client"), (8.6, "Server")):
        ax.text(x, 9.5, who, ha="center", fontsize=11, weight="bold")
        ax.plot([x, x], [0.4, 9.1], color="gray", lw=1.5)
    steps = [(8.2, 1.4, 8.6, f"ClientHello  ({n['ClientHello']:,} B)\nP-256 pk + ML-KEM-768 pk + nonce"),
             (5.9, 8.6, 1.4, f"ServerHello  ({n['ServerHello']:,} B)\nKEM cts + ML-DSA-65 sig + Finished"),
             (3.9, 1.4, 8.6, f"ClientFinished  ({n['ClientFinished']} B)")]
    for y, x0, x1, txt in steps:
        ax.annotate("", xy=(x1, y), xytext=(x0, y), arrowprops=dict(arrowstyle="->", lw=1.8))
        ax.text(5, y + 0.25, txt, ha="center", fontsize=8)
    ax.annotate("", xy=(8.6, 1.9), xytext=(1.4, 1.9), arrowprops=dict(arrowstyle="<->", lw=1.8, color="#2f855a"))
    ax.text(5, 2.15, "application records: AES-256-GCM, 16 KiB chunks", ha="center", fontsize=8, color="#2f855a")
    ax.text(1.4, 7.2, "keygen\n(ECDH + ML-KEM)", ha="center", fontsize=7, color="#555")
    ax.text(8.6, 7.2, "encaps + sign", ha="center", fontsize=7, color="#555")
    ax.text(1.4, 5.0, "verify sig\n+ decaps", ha="center", fontsize=7, color="#555")
    # right: measured breakdown
    g = lambda s, o: float(np.median(repeat_stat(df_a, s, o))) / 1000.0   # noqa: E731  (ms)
    cl = [("KEM keygen", g(SUITE_HYBRID, "keygen")), ("ML-DSA verify", g("MLDSA65", "verify")),
          ("KEM decaps", g(SUITE_HYBRID, "decaps"))]
    sv = [("KEM encaps", g(SUITE_HYBRID, "encaps")), ("ML-DSA sign", g("MLDSA65", "sign"))]
    meas = {"Client": g(SUITE_HYBRID, "handshake_client_compute"), "Server": g(SUITE_HYBRID, "handshake_server_compute")}
    cols = {"KEM keygen": "#2b6cb0", "KEM decaps": "#63b3ed", "KEM encaps": "#90cdf4", "ML-DSA verify": "#d69e2e",
            "ML-DSA sign": "#975a16"}
    for y, (role, parts) in enumerate((("Client", cl), ("Server", sv))):
        left = 0
        for lbl, v in parts:
            bx.barh(y, v, left=left, color=cols[lbl], edgecolor="w", label=lbl)
            bx.text(left + v / 2, y, f"{v:.1f}", ha="center", va="center", fontsize=8,
                    color="w" if lbl in ("KEM keygen", "ML-DSA sign") else "k")
            left += v
        bx.plot([meas[role]] * 2, [y - 0.42, y + 0.42], "k--", lw=1.5)
        bx.text(meas[role] + 0.6, y - 0.55, f"measured {role.lower()} compute: {meas[role]:.1f} ms", fontsize=7, ha="left")
    bx.legend(fontsize=7, loc="upper right", ncol=2)
    bx.set_yticks([0, 1])
    bx.set_yticklabels(["Client", "Server"])
    bx.set_xlabel("Time (ms) on Platform A, median of 3 repeats")
    bx.set_ylim(-0.8, 1.8)
    bx.set_title("Measured cost per step (stacked = sum of isolated primitive medians;\n"
                 " dashed = measured whole-handshake compute)", fontsize=9)
    fig.suptitle("PS-P1 analogue of 'logical vs transpiled': protocol flow vs where the time actually goes. "
                 "ML-DSA sign is heavy-tailed, so sum of medians can exceed the measured median.", fontsize=8, y=0.02)
    return fig


# ---------------------------------------------------------------- 4: A vs B handshake latency
def ab_performance(t):
    fig, ax = plt.subplots(figsize=(9, 4.6))
    plats = [p for p in ("A", "B", "B_contended") if p in t]
    w = 0.26
    for k, p in enumerate(plats):
        meds, lo, hi, p95 = [], [], [], []
        for s in SUITES:
            m = repeat_stat(t[p], s, "handshake_total") / 1000
            meds.append(np.median(m))
            lo.append(np.median(m) - m.min())
            hi.append(m.max() - np.median(m))
            p95.append(np.median(repeat_stat(t[p], s, "handshake_total", "p95_us")) / 1000)
        x = np.arange(len(SUITES)) + (k - (len(plats) - 1) / 2) * w
        ax.bar(x, meds, w, yerr=[lo, hi], capsize=3, color=COL[p], label=LABEL[p], alpha=0.9 if p != "B_contended" else 0.55,
               hatch="//" if p == "B_contended" else None)
        ax.scatter(x, p95, marker="D", color="k", s=16, zorder=3, label="p95 of iterations" if k == 0 else None)
        for xi, v, h in zip(x, meds, hi):
            ax.text(xi, (v + h) * 1.1, f"{v:.1f}", ha="center", fontsize=7)
    ax.set_yscale("log")
    ax.set_xticks(range(len(SUITES)))
    ax.set_xticklabels([SUITE_LABEL[s] for s in SUITES], fontsize=8)
    ax.set_ylabel("Handshake latency (ms, log scale)")
    ax.set_title("Full handshake latency: bar = median of 3 repeats, whisker = min..max of repeat medians (run-to-run range)",
                 fontsize=9)
    ax.legend(fontsize=7, loc="upper left")
    ax.grid(axis="y", alpha=0.3, which="both")
    return fig


# ---------------------------------------------------------------- 5: trade-offs
def architecture_tradeoffs(t):
    """Three panels (latency | wire bytes | memory): classical vs PQ-only vs hybrid, Platform A and B."""
    fig, axes = plt.subplots(1, 3, figsize=(13, 4.6))
    sz = pd.read_csv(os.path.join(TABLES, "sizes.csv"))
    tot = {r.suite: r.bytes for r in sz[sz.message == "TOTAL"].itertuples()}
    plats = [p for p in ("A", "B") if p in t]
    w = 0.36
    panels = [("Handshake latency (ms, log)", lambda p, s: np.median(repeat_stat(t[p], s, "handshake_total")) / 1000, True),
              ("Bytes on the wire per handshake (log)", lambda p, s: tot[s], True),
              ("tracemalloc peak per handshake (KB)", lambda p, s: t[p][(t[p].pass_type == "memory") & (t[p].suite == s)
                                                                       & (t[p].operation == "handshake_total")]
                                                       .tracemalloc_peak_kb.median(), False)]
    for ax, (title, f, logy) in zip(axes, panels):
        for k, p in enumerate(plats):
            x = np.arange(len(SUITES)) + (k - (len(plats) - 1) / 2) * w
            v = [f(p, s) for s in SUITES]
            ax.bar(x, v, w, color=COL[p], label=LABEL[p])
            for xi, y in zip(x, v):
                ax.text(xi, y * (1.08 if logy else 1.02), f"{y:,.1f}" if y < 100 else f"{y:,.0f}", ha="center", fontsize=7)
        base = f(plats[0], SUITE_CLASSIC)
        ax.set_title(title + f"\nhybrid / classical = {f(plats[0], SUITE_HYBRID) / base:.1f}x (A)", fontsize=9)
        ax.set_xticks(range(len(SUITES)))
        ax.set_xticklabels([s.replace("+", "+\n") for s in SUITES], fontsize=8)
        if logy:
            ax.set_yscale("log")
        ax.grid(axis="y", alpha=0.3)
    h, lb = axes[0].get_legend_handles_labels()
    fig.legend(h, lb, loc="lower center", ncol=2, fontsize=8, bbox_to_anchor=(0.5, -0.07))
    fig.suptitle("Architecture trade-offs: classical vs PQ-only vs hybrid "
                 "(hybrid adds little over PQ-only; PQ itself is the cost)", fontsize=10, y=1.02)
    return fig


# ---------------------------------------------------------------- 6: bytes on the wire
def bytes_on_wire():
    fig, ax = plt.subplots(figsize=(8, 4.6))
    sz = pd.read_csv(os.path.join(TABLES, "sizes.csv"))
    msgs = ["ClientHello", "ServerHello", "ClientFinished"]
    bottom = np.zeros(len(SUITES))
    for m, c in zip(msgs, ("#2b6cb0", "#d69e2e", "#718096")):
        v = np.array([int(sz[(sz.suite == s) & (sz.message == m)].bytes.iloc[0]) for s in SUITES])
        ax.bar([SUITE_LABEL[s] for s in SUITES], v, bottom=bottom, label=m, color=c)
        for i, (b, x) in enumerate(zip(bottom, v)):
            if x > 300:
                ax.text(i, b + x / 2, f"{x:,}", ha="center", va="center", fontsize=8, color="w")
        bottom += v
    for i, b in enumerate(bottom):
        ax.text(i, b + 80, f"total {int(b):,} B", ha="center", fontsize=8)
    ax.set_ylabel("Bytes on the wire per handshake")
    ax.set_title("Handshake size: ML-KEM keys/ciphertexts and the 3,309-byte ML-DSA signature dominate", fontsize=9)
    ax.legend(fontsize=8)
    ax.tick_params(axis="x", labelsize=8)
    return fig


# ---------------------------------------------------------------- 7: throughput
def throughput_payloads(t):
    fig, ax = plt.subplots(figsize=(8.5, 4.5))
    pays = [1_000, 100_000, 10_000_000]
    plats = [p for p in ("A", "B", "B_contended") if p in t]
    w = 0.26
    for k, p in enumerate(plats):
        v = [np.median(repeat_stat(t[p], SUITE_HYBRID, "bulk_roundtrip", "throughput_mb_s", n)) for n in pays]
        runs = [repeat_stat(t[p], SUITE_HYBRID, "bulk_roundtrip", "throughput_mb_s", n) for n in pays]
        lo = [np.median(r) - min(r) for r in runs]
        hi = [max(r) - np.median(r) for r in runs]
        x = np.arange(3) + (k - (len(plats) - 1) / 2) * w
        ax.bar(x, v, w, yerr=[lo, hi], capsize=3, color=COL[p], label=LABEL[p], hatch="//" if p == "B_contended" else None,
               alpha=0.9 if p != "B_contended" else 0.55)
        for xi, y, h in zip(x, v, hi):
            ax.text(xi, (y + h) * 1.02, f"{y:.0f}", ha="center", fontsize=7)
    ax.set_xticks(range(3))
    ax.set_xticklabels(["1 KB", "100 KB", "10 MB"])
    ax.set_ylabel("Throughput (MB/s; payload bytes / (seal + open) time)")
    ax.set_xlabel("Payload size (AES-256-GCM, 16 KiB records, established hybrid session)")
    ax.set_title("Bulk transfer throughput (whisker = min..max of repeat medians)", fontsize=9)
    ax.legend(fontsize=7)
    ax.grid(axis="y", alpha=0.3)
    return fig


def make_all():
    t = tables()
    _save(platform_profile("platform_A", t["A"]), "processor_A_graph.png")
    _save(platform_profile("platform_B", t["B"]), "processor_B_graph.png")
    _save(logical_vs_measured(t["A"]), "logical_vs_transpiled.png")
    _save(ab_performance(t), "AB_performance.png")
    _save(architecture_tradeoffs(t), "architecture_tradeoffs.png")
    _save(bytes_on_wire(), "bytes_on_wire.png")
    _save(throughput_payloads(t), "throughput_payloads.png")
