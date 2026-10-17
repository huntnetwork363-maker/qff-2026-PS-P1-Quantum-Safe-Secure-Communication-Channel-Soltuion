"""Independent spot-check: recompute report values from raw CSVs with stdlib csv/statistics (NOT the pandas code path used
by build_report.py) and verify (1) they equal the values the report used and (2) the report text contains them."""
import csv
import json
import os
import re
import statistics
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T = os.path.join(ROOT, "results", "tables")
H, P, K = "P256+MLKEM768", "MLKEM768", "P256"


def rows(path):
    return list(csv.DictReader(open(os.path.join(T, path))))


def f(x):
    return float(x) if x not in ("", None) else None


def per_repeat(rs, suite, op, col, ptype="latency", payload=None):
    out = [f(r[col]) for r in rs if r["pass_type"] == ptype and r["suite"] == suite and r["operation"] == op
           and (payload is None or f(r["payload_bytes"]) == payload)]
    return [x for x in out if x is not None]


def med(*a, **k):
    return statistics.median(per_repeat(*a, **k))


A = rows("processor_A_metrics.csv")
sz = rows("sizes.csv")
tot = {r["suite"]: int(r["bytes"]) for r in sz if r["message"] == "TOTAL"}
mem_h = [f(r["tracemalloc_peak_kb"]) for r in A if r["pass_type"] == "memory" and r["suite"] == H and r["operation"] == "handshake_total"]
rss_hs = [f(r["peak_rss_kb"]) for r in A if r["pass_type"] == "memory" and r["suite"] == H and r["operation"] == "handshake_total"]
rss_bulk = [f(r["peak_rss_kb"]) for r in A if r["pass_type"] == "memory" and r["operation"] == "bulk_roundtrip"
            and f(r["payload_bytes"]) == 10_000_000]
base = [f(r["rss_baseline_kb"]) for r in rows("processor_B_metrics.csv") if r["pass_type"] == "memory"]
expected = {
    "bytes_hybrid": tot[H], "bytes_classic": tot[K], "bytes_x": tot[H] / tot[K], "bytes_hyb_vs_pq": tot[H] - tot[P],
    "bytes_hyb_vs_pq_pct": 100 * (tot[H] - tot[P]) / tot[P],
    "hs_A_hybrid": med(A, H, "handshake_total", "median_us") / 1000, "hs_A_classic": med(A, K, "handshake_total", "median_us") / 1000,
    "hs_B_hybrid": med(rows("processor_B_metrics.csv"), H, "handshake_total", "median_us") / 1000,
    "tm_hybrid": statistics.median(mem_h), "rss_hs": statistics.median(rss_hs) / 1024, "rss_bulk": statistics.median(rss_bulk) / 1024,
    "rss_base": statistics.median(base) / 1024,
    "sign_ms": med(A, "MLDSA65", "sign", "median_us") / 1000, "verify_ms": med(A, "MLDSA65", "verify", "median_us") / 1000,
    "sv_hybrid_ms": med(A, H, "handshake_server_compute", "median_us") / 1000,
    "sv_pq_ms": med(A, P, "handshake_server_compute", "median_us") / 1000,
}
used = json.load(open(os.path.join(T, "report_values.json")))
report = open(os.path.join(ROOT, "report.md")).read()
bad = 0
for k, v in expected.items():
    ok_used = abs(used[k] - v) <= 1e-3 + 1e-6 * abs(v)   # final_comparison.csv is rounded to 3 decimals
    shown = [f"{v:,.0f}", f"{v:,.1f}", f"{v:,.2f}"]
    ok_text = any(s in report for s in shown)
    bad += not (ok_used and ok_text)
    print(("OK  " if ok_used and ok_text else "FAIL"), f"{k:22s} independent={v:,.4f} report_used={used[k]:,.4f} in_text={ok_text}")
# A-vs-B claim "N of M exceed noise", recomputed independently
ab = rows("AB_comparison.csv")
n = 0
for r in ab:
    m = re.search(r"spread_A=([\d.]+)% spread_B=([\d.]+)%", r["ci_note"])
    noise = max(float(m.group(1)), float(m.group(2))) / 100
    n += abs(float(r["ratio_B_over_A"]) - 1) > noise
claim = re.search(r"Only (\d+) of (\d+) A-vs-B comparisons", report) or re.search(r"None of the (\d+)", report)
ok_claim = bool(claim) and (int(claim.group(1)) == n if "Only" in claim.group(0) else n == 0) and (
    int(claim.group(2)) == len(ab) if "Only" in claim.group(0) else int(claim.group(1)) == len(ab))
bad += not ok_claim
print(("OK  " if ok_claim else "FAIL"), f"A-vs-B noise claim: independent {n} of {len(ab)}")
# final_comparison rows present verbatim in the report table
for r in rows("final_comparison.csv"):
    present = r["Metric"] in report and r["Difference"] in report
    bad += not present
    print(("OK  " if present else "FAIL"), "final table row:", r["Metric"][:55])
print(f"\n{bad} mismatches")
sys.exit(1 if bad else 0)
