"""Orchestrator: runs the identical workload on every platform (interleaved across repeats), then writes
results/tables/*.csv. Usage: python scripts/bench_all.py [--quick] [--repeats N] [--no-contended]"""
import argparse
import csv
import json
import os
import statistics
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import pandas as pd  # noqa: E402

from src.metrics import CSV_COLUMNS  # noqa: E402
from src.problem import SUITE_HYBRID, SUITES  # noqa: E402
from src.routing import run_isolated  # noqa: E402

TABLES = os.path.join(ROOT, "results", "tables")
RAW = os.path.join(ROOT, "data", "processed", "raw_rows.json")
SCRIPT = os.path.join(ROOT, "scripts", "run_benchmark.py")
PLAT = {"A": "processor_A.json", "B": "processor_B.json", "B_contended": "processor_B_contended.json"}
MEM_SCENARIOS = [f"handshake:{s}" for s in SUITES] + ["bulk:1000", "bulk:100000", "bulk:10000000"]


def loc():
    n = 0
    d = os.path.join(ROOT, "src")
    for f in sorted(os.listdir(d)):
        if f.endswith(".py"):
            for ln in open(os.path.join(d, f)):
                s = ln.strip()
                if s and not s.startswith("#"):
                    n += 1
    return n


def write_csv(path, rows, cols):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def run_all(platforms, repeats, quick):
    rows = []
    for rep in range(1, repeats + 1):
        order = platforms[(rep - 1) % len(platforms):] + platforms[:(rep - 1) % len(platforms)]   # rotate: drift hits all
        for p in order:
            path = os.path.join(ROOT, "processors", PLAT[p])
            t = time.time()
            extra = ["--quick"] if quick else []
            res = run_isolated(path, SCRIPT, ["--mode", "latency", "--repeat", rep, *extra])
            rows += res["rows"]
            for sc in MEM_SCENARIOS:
                rows += run_isolated(path, SCRIPT, ["--mode", "memory", "--scenario", sc, "--repeat", rep, *extra])["rows"]
            print(f"repeat {rep}/{repeats} {p}: {time.time() - t:.0f}s", flush=True)
            os.makedirs(os.path.dirname(RAW), exist_ok=True)
            json.dump(rows, open(RAW, "w"))
    return rows


def spread(vals):
    m = statistics.median(vals)
    return (max(vals) - min(vals)) / m if m else float("nan")


def compare(df, a, b):
    """Per (suite, operation, payload): median-over-repeats of per-repeat medians, ratio b/a, run-to-run spread."""
    lat = df[df.pass_type == "latency"].copy()
    lat["payload_bytes"] = lat["payload_bytes"].fillna("").astype(str).str.replace(r"\.0$", "", regex=True)
    g = lat.groupby(["platform", "suite", "operation", "payload_bytes"]).agg(
        median=("median_us", "median"), list=("median_us", list), best=("min_us", "min")).reset_index()
    out = []
    for (suite, op, pay), sub in g.groupby(["suite", "operation", "payload_bytes"]):
        pa, pb = sub[sub.platform == a], sub[sub.platform == b]
        if pa.empty or pb.empty:
            continue
        ma, mb = float(pa["median"].iloc[0]), float(pb["median"].iloc[0])
        sa, sb = spread(pa["list"].iloc[0]), spread(pb["list"].iloc[0])
        flag = "HIGH run-to-run spread (>20%)" if max(sa, sb) > 0.2 else "ok"
        out.append({"suite": suite, "operation": op, "payload_bytes": pay, "median_us_A": ma, "median_us_B": mb,
                    "ratio_B_over_A": mb / ma, "ci_note": f"spread_A={sa:.1%} spread_B={sb:.1%} {flag}",
                    "min_us_A": float(pa["best"].iloc[0]), "min_us_B": float(pb["best"].iloc[0]),
                    "ratio_min_B_over_A": float(pb["best"].iloc[0]) / float(pa["best"].iloc[0])})
    return pd.DataFrame(out)


def val(df, plat, pass_type, suite, op, col, payload=None):
    d = df[(df.platform == plat) & (df.pass_type == pass_type) & (df.suite == suite) & (df.operation == op)]
    if payload is not None:
        d = d[d.payload_bytes.astype(str).str.replace(r"\.0$", "", regex=True) == str(payload)]
    return float(d[col].astype(float).median())


def diff(a, b):
    return f"{b - a:+.2f} ({b / a:.2f}x)" if a else "n/a"


def final_table(df, has_c):
    h = SUITE_HYBRID
    L = loc()
    metrics = [
        ("Handshake latency, hybrid (ms, median)", lambda p: val(df, p, "latency", h, "handshake_total", "median_us") / 1000),
        ("Handshake bytes c2s+s2c, hybrid (bytes)", lambda p: val(df, p, "latency", h, "handshake_total", "bytes_c2s")
         + val(df, p, "latency", h, "handshake_total", "bytes_s2c")),
        ("Ciphertext size, hybrid KEM (bytes)", lambda p: val(df, p, "latency", h, "encaps", "ct_bytes")),
        ("Peak memory, hybrid handshake: tracemalloc (KB)", lambda p: val(df, p, "memory", h, "handshake_total",
                                                                           "tracemalloc_peak_kb")),
        ("Peak RSS, hybrid handshake process (MB)", lambda p: val(df, p, "memory", h, "handshake_total", "peak_rss_kb") / 1024),
        ("Peak RSS, 10 MB bulk process (MB)",
         lambda p: val(df, p, "memory", h, "bulk_roundtrip", "peak_rss_kb", 10000000) / 1024),
        ("Throughput, 10 MB payload (MB/s)",
         lambda p: val(df, p, "latency", h, "bulk_roundtrip", "throughput_mb_s", 10000000)),
        ("Code size, src/ (LOC, non-blank non-comment)", lambda p: float(L)),
    ]
    rows = []
    for name, f in metrics:
        a, b = f("platform_A"), f("platform_B")
        r = {"Metric": name, "Platform A": round(a, 3), "Platform B": round(b, 3), "Difference": diff(a, b)}
        if has_c:
            c = f("platform_B_contended")
            r["Platform B contended (extra)"] = round(c, 3)
            r["Difference (contended vs A)"] = diff(a, c)
        rows.append(r)
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--no-contended", action="store_true")
    ap.add_argument("--from-raw", action="store_true", help="skip running; rebuild tables from data/processed/raw_rows.json")
    a = ap.parse_args()
    plats = ["A", "B"] + ([] if a.no_contended else ["B_contended"])
    rows = json.load(open(RAW)) if a.from_raw else run_all(plats, a.repeats, a.quick)
    os.makedirs(TABLES, exist_ok=True)
    for name in sorted({r["platform"] for r in rows}):
        write_csv(os.path.join(TABLES, f"processor_{name.replace('platform_', '')}_metrics.csv"),
                  [r for r in rows if r["platform"] == name], CSV_COLUMNS)
    df = pd.DataFrame(rows)
    has_c = "platform_B_contended" in set(df.platform)
    ab = compare(df, "platform_A", "platform_B")
    ab.to_csv(os.path.join(TABLES, "AB_comparison.csv"), index=False, lineterminator="\n")
    if has_c:
        compare(df, "platform_A", "platform_B_contended").to_csv(os.path.join(TABLES, "AB_comparison_contended.csv"),
                                                                 index=False, lineterminator="\n")
    final_table(df, has_c).to_csv(os.path.join(TABLES, "final_comparison.csv"), index=False, lineterminator="\n")
    subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "make_sizes.py")], check=True)
    print("tables written to", TABLES)


if __name__ == "__main__":
    main()
