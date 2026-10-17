"""Self-check. `python scripts/check_repo.py` = repo + results checks; `--results-only` = Phase 4 sanity checks only."""
import csv
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import pandas as pd  # noqa: E402

from src.channel import wire_suite  # noqa: E402
from src.metrics import CSV_COLUMNS  # noqa: E402
from src.problem import EXPECTED_SIZES as S  # noqa: E402
from src.problem import SUITE_CLASSIC, SUITE_HYBRID, SUITE_PQ  # noqa: E402

T = os.path.join(ROOT, "results", "tables")
REQUIRED = ["README.md", "report.md", "main.ipynb", "requirements.txt", "processors/processor_A.json",
            "processors/processor_B.json", "src/problem.py", "src/processors.py", "src/routing.py", "src/metrics.py",
            "src/visualization.py", "results/tables/processor_A_metrics.csv", "results/tables/processor_B_metrics.csv",
            "results/tables/AB_comparison.csv", "results/tables/final_comparison.csv", "results/tables/sizes.csv",
            "results/figures/processor_A_graph.png", "results/figures/processor_B_graph.png",
            "results/figures/logical_vs_transpiled.png", "results/figures/AB_performance.png",
            "results/figures/architecture_tradeoffs.png", "results/figures/bytes_on_wire.png",
            "results/figures/throughput_payloads.png", "docs/DECISIONS.md", "docs/BUGLOG.md", "docs/THREAT_MODEL.md",
            "docs/AI_DISCLOSURE.md"]
AB_COLS = ["suite", "operation", "payload_bytes", "median_us_A", "median_us_B", "ratio_B_over_A", "ci_note"]
FINAL_COLS = ["Metric", "Platform A", "Platform B", "Difference"]


def _norm(s):
    return s.fillna("").astype(str).str.replace(r"\.0$", "", regex=True)


def check_repo():
    res = []
    for f in REQUIRED:
        res.append((f"exists {f}", os.path.exists(os.path.join(ROOT, f)), ""))
    reqs = [ln.strip() for ln in open(os.path.join(ROOT, "requirements.txt")) if ln.strip() and not ln.startswith("#")]
    res.append(("requirements pinned (==)", all("==" in r and ">=" not in r for r in reqs), str(reqs)))
    rd = open(os.path.join(ROOT, "README.md")).read()
    for needle in ("P1", "Platform A", "Platform B"):
        res.append((f"README mentions {needle}", needle in rd, ""))
    res.append(("README has AI disclosure heading", bool(re.search(r"^#+ .*AI", rd, re.M)), ""))
    res.append(("README has assumptions heading", bool(re.search(r"^#+ .*[Aa]ssumption", rd, re.M)), ""))
    return res


def check_results():
    res = []
    ok = lambda name, cond, msg="": res.append((name, bool(cond), msg))   # noqa: E731
    dfs = {}
    for name in ("A", "B"):
        p = os.path.join(T, f"processor_{name}_metrics.csv")
        ok(f"{name} csv exists", os.path.exists(p))
        with open(p) as f:
            header = next(csv.reader(f))
        ok(f"{name} csv header == schema", header == CSV_COLUMNS, str(set(header) ^ set(CSV_COLUMNS)))
        dfs[name] = pd.read_csv(p)
    for fn, cols in (("AB_comparison.csv", AB_COLS), ("final_comparison.csv", FINAL_COLS)):
        h = list(pd.read_csv(os.path.join(T, fn)).columns)
        ok(f"{fn} header", h[:len(cols)] == cols, str(h))
    A, B = dfs["A"], dfs["B"]
    ok("problem_id always P1", (A.problem_id == "P1").all() and (B.problem_id == "P1").all())
    for n, d in dfs.items():
        lat = d[d.pass_type == "latency"]
        ok(f"{n}: latencies finite and > 0", lat.median_us.notna().all() and (lat.median_us > 0).all())
        ok(f"{n}: min<=median<=p95<=max", ((lat.min_us <= lat.median_us) & (lat.median_us <= lat.p95_us)
                                          & (lat.p95_us <= lat.max_us)).all())
        kg = lat[(lat.suite == SUITE_PQ) & (lat.operation == "keygen")].median_us
        ok(f"{n}: ML-KEM-768 keygen in plausible range (0.3 ms..500 ms)", kg.between(300, 500_000).all(), str(list(kg)))
    # 1. hybrid does both component computations -> not meaningfully faster than either (10% noise tolerance)
    for n, d in dfs.items():
        lat = d[d.pass_type == "latency"].groupby(["suite", "operation"]).median_us.median()
        for op in ("keygen", "encaps", "decaps"):
            h, c, q = lat[(SUITE_HYBRID, op)], lat[(SUITE_CLASSIC, op)], lat[(SUITE_PQ, op)]
            ok(f"{n}: hybrid {op} >= 0.9*max(classical, PQ)", h >= 0.9 * max(c, q), f"h={h:.0f} c={c:.0f} q={q:.0f}")
    # 2. byte additivity (exact)
    sz = pd.read_csv(os.path.join(T, "sizes.csv"))
    tot = {r.suite: r.bytes for r in sz[sz.message == "TOTAL"].itertuples()}
    extra = 2 * S["ecdh_pk"] + 2 * (len(wire_suite(SUITE_HYBRID)) - len(wire_suite(SUITE_PQ)))
    ok("hybrid handshake bytes == PQ + 2*65 + suite-id delta", tot[SUITE_HYBRID] == tot[SUITE_PQ] + extra,
       f"{tot[SUITE_HYBRID]} vs {tot[SUITE_PQ]}+{extra}")
    for n, d in dfs.items():
        e = d[(d.operation == "encaps") & (d.pass_type == "latency")].drop_duplicates("suite").set_index("suite")
        ok(f"{n}: hybrid pk/ct = classical + PQ", e.loc[SUITE_HYBRID, "pk_bytes"] == e.loc[SUITE_CLASSIC, "pk_bytes"]
           + e.loc[SUITE_PQ, "pk_bytes"] and e.loc[SUITE_HYBRID, "ct_bytes"] == e.loc[SUITE_CLASSIC, "ct_bytes"]
           + e.loc[SUITE_PQ, "ct_bytes"])
        ok(f"{n}: ML-KEM-768 pk/ct = 1184/1088", e.loc[SUITE_PQ, "pk_bytes"] == S["mlkem768_pk"]
           and e.loc[SUITE_PQ, "ct_bytes"] == S["mlkem768_ct"])
    # 3. A and B identical except constraints
    for col in ("backend", "backend_version", "python_version", "iterations", "warmup", "seed"):
        ok(f"A and B identical in '{col}'", set(A[col].astype(str)) == set(B[col].astype(str)))
    ka = A[A.pass_type == "latency"][["suite", "operation", "payload_bytes"]].fillna("").astype(str)
    kb = B[B.pass_type == "latency"][["suite", "operation", "payload_bytes"]].fillna("").astype(str)
    ok("A and B ran the same workload set", set(map(tuple, ka.values)) == set(map(tuple, kb.values)))
    # 4. constraints recorded and different
    ok("A: no RLIMIT recorded", A.rlimit_as_mb_effective.isna().all())
    ok("B: RLIMIT_AS recorded (256) on every row", (B.rlimit_as_mb_effective == 256).all())
    ok("B: affinity recorded on every row", B.cpu_affinity_effective.notna().all())
    # 5. spread report (warnings only)
    ab = pd.read_csv(os.path.join(T, "AB_comparison.csv"))
    hi = ab[ab.ci_note.str.contains("HIGH")]
    ok("run-to-run spread reported for all rows", ab.ci_note.str.contains("spread_A=").all())
    if len(hi):
        hi.to_csv(os.path.join(T, "spread_flags.csv"), index=False, lineterminator="\n")
        res.append((f"WARNING: {len(hi)} rows with >20% run-to-run spread (see spread_flags.csv)", True, ""))
    return res


def main():
    results = check_results() if "--results-only" in sys.argv else check_repo() + check_results()
    bad = [r for r in results if not r[1]]
    for name, passed, msg in results:
        tag = "WARN " if name.startswith("WARNING") else ("PASS " if passed else "FAIL ")
        print(tag + name + (f"  [{msg}]" if msg and not passed else ""))
    print(f"\n{len(results) - len(bad)}/{len(results)} checks passed")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
