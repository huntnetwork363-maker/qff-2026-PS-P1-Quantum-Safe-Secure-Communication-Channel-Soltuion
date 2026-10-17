"""Quick-mode end-to-end test of the benchmark child on platform A and B (tiny iteration counts)."""
import os

import pytest

from src.metrics import CSV_COLUMNS, validate_row
from src.routing import ROOT, run_isolated

SCRIPT = os.path.join(ROOT, "scripts", "run_benchmark.py")


def P(n):
    return os.path.join(ROOT, "processors", n)


@pytest.fixture(scope="module")
def quick_rows():
    return {p: run_isolated(P(f"processor_{p}.json"), SCRIPT, ["--mode", "latency", "--quick"])["rows"] for p in "AB"}


def test_rows_valid_and_complete(quick_rows):
    for rows in quick_rows.values():
        for r in rows:
            validate_row(r)
            assert set(r) <= set(CSV_COLUMNS)
        ops = {(r["suite"], r["operation"]) for r in rows}
        assert ("P256+MLKEM768", "handshake_total") in ops and ("MLDSA65", "sign") in ops


def test_same_workload_on_A_and_B(quick_rows):
    key = lambda rows: {(r["suite"], r["operation"], r["payload_bytes"]) for r in rows}   # noqa: E731
    assert key(quick_rows["A"]) == key(quick_rows["B"])


def test_constraint_columns_differ(quick_rows):
    assert quick_rows["A"][0]["rlimit_as_mb_effective"] == "" and quick_rows["B"][0]["rlimit_as_mb_effective"] == 256


def test_sizes_are_platform_independent(quick_rows):
    pick = lambda rows: {r["suite"]: (r["bytes_c2s"], r["bytes_s2c"]) for r in rows if r["operation"] == "handshake_total"}   # noqa: E731
    assert pick(quick_rows["A"]) == pick(quick_rows["B"])
    assert pick(quick_rows["A"])["P256+MLKEM768"] == (1309 + 32, 4554)


def test_memory_scenario_separate_pass():
    r = run_isolated(P("processor_B.json"), SCRIPT, ["--mode", "memory", "--scenario", "bulk:100000"])["rows"][0]
    assert r["pass_type"] == "memory" and r["tracemalloc_peak_kb"] > 100 and r["peak_rss_kb"] > r["rss_baseline_kb"]
    assert "median_us" not in r              # memory rows carry no latency numbers (empty cell in the CSV)
