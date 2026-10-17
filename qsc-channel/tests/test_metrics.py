import gc
import math

import pytest

from src.metrics import CSV_COLUMNS, measure_memory, percentile, summarize, time_it, time_it_interleaved, validate_row


def test_summarize_hand_computed():
    s = summarize([1000, 2000, 3000, 4000, 5000])   # ns -> 1..5 us
    assert s["median_us"] == 3.0 and s["mean_us"] == 3.0 and s["min_us"] == 1.0 and s["max_us"] == 5.0
    assert s["iqr_us"] == 2.0                        # q3=4, q1=2
    assert s["p95_us"] == pytest.approx(4.8)
    assert s["stdev_us"] == pytest.approx(math.sqrt(2.5))


def test_percentile_edges():
    assert percentile([7.0], 95) == 7.0
    with pytest.raises(ValueError):
        percentile([], 50)


def test_warmup_excluded_and_count():
    calls = []
    out = time_it(lambda i: calls.append(i), iterations=5, warmup=3)
    assert len(out) == 5 and calls == list(range(8))


def test_gc_restored_even_on_exception():
    assert gc.isenabled()
    with pytest.raises(RuntimeError):
        time_it(lambda i: (_ for _ in ()).throw(RuntimeError("x")), 3, 0)
    assert gc.isenabled()


def test_measure_memory_detects_allocation():
    big = measure_memory(lambda i: bytearray(5 * 1024 * 1024))
    small = measure_memory(lambda i: bytearray(1024))
    assert big > 4000 and small < 100


def test_validate_row():
    ok = {"problem_id": "P1", "pass_type": "latency", "median_us": 12.0}
    validate_row(ok)
    for bad in ({**ok, "median_us": -1}, {**ok, "median_us": float("nan")}, {**ok, "problem_id": "P2"},
                {**ok, "nope": 1}, {**ok, "pass_type": "x"}, {**ok, "median_us": 0}):
        with pytest.raises(ValueError):
            validate_row(bad)
    assert len(CSV_COLUMNS) == len(set(CSV_COLUMNS))


def test_peak_rss_not_inherited_from_bloated_parent():
    """Regression (Phase 4 finding): ru_maxrss of an exec'd child includes the PARENT's high-water mark on Linux."""
    import subprocess
    import sys

    from src.routing import ROOT

    hog = bytearray(200 * 1024 * 1024)
    for i in range(0, len(hog), 4096):
        hog[i] = 1                                   # touch every page so the parent's RSS really is >= 200 MB
    out = subprocess.run([sys.executable, "-c", "from src.metrics import peak_rss_kb; print(peak_rss_kb())"],
                         capture_output=True, text=True, cwd=ROOT, check=True).stdout
    assert float(out) < 80_000, f"child baseline {out.strip()} KB looks inherited from the parent"


def test_interleaved_pairs_rotates_and_drops_warmup():
    order = []
    fns = {n: (lambda i, n=n: order.append((i, n))) for n in "abc"}
    out = time_it_interleaved(fns, iterations=6, warmup=2)
    assert all(len(v) == 6 for v in out.values())                 # equal, paired sample counts; warm-up excluded
    assert len(order) == 8 * 3                                    # every fn ran in every iteration incl. warm-up
    firsts = [next(n for (i, n) in order if i == k) for k in range(8)]
    assert len(set(firsts)) == 3                                  # starting position rotates (no fixed-slot bias)


def test_interleaved_restores_gc_on_error():
    import pytest as _p
    assert gc.isenabled()
    with _p.raises(RuntimeError):
        time_it_interleaved({"x": lambda i: (_ for _ in ()).throw(RuntimeError("boom"))}, 2, 0)
    assert gc.isenabled()
