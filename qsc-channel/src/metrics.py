"""PS-P1: timing/memory harness, statistics and CSV schema. Stdlib only."""
import gc
import math
import resource
import statistics
import sys
import time
import tracemalloc

CSV_COLUMNS = [
    "problem_id", "platform", "repeat", "pass_type", "suite", "operation", "payload_bytes", "iterations", "warmup",
    "median_us", "mean_us", "p95_us", "min_us", "max_us", "iqr_us", "stdev_us",
    "tracemalloc_peak_kb", "peak_rss_kb", "rss_baseline_kb",
    "bytes_c2s", "bytes_s2c", "pk_bytes", "ct_bytes", "sig_bytes",
    "throughput_mb_s", "backend", "backend_version", "python_version", "seed",
    "cpu_affinity_effective", "rlimit_as_mb_effective", "docker_cpus", "docker_memory_mb", "contention_workers",
]
PASS_TYPES = ("latency", "memory", "size")


def time_it(fn, iterations, warmup):
    """Call fn(i) for i in range(warmup+iterations); return the timed (post-warm-up) samples in ns.
    GC is disabled during the loop and restored in `finally`, even if fn raises."""
    was_enabled = gc.isenabled()
    out = []
    gc.disable()
    try:
        for i in range(warmup + iterations):
            t0 = time.perf_counter_ns()
            fn(i)
            dt = time.perf_counter_ns() - t0
            if i >= warmup:
                out.append(dt)
    finally:
        if was_enabled:
            gc.enable()
    return out


def time_it_interleaved(fns, iterations, warmup):
    """Time several competing implementations PAIRED: in every iteration each fn(i) runs once, in an order that rotates
    each iteration. All candidates then experience the same host conditions (noisy-neighbour bursts, frequency drift),
    which contiguous per-candidate timing windows cannot guarantee. Returns {name: [ns, ...]} (warm-up dropped)."""
    names = list(fns)
    out = {n: [] for n in names}
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        for i in range(warmup + iterations):
            k = i % len(names)
            for n in names[k:] + names[:k]:
                t0 = time.perf_counter_ns()
                fns[n](i)
                dt = time.perf_counter_ns() - t0
                if i >= warmup:
                    out[n].append(dt)
    finally:
        if was_enabled:
            gc.enable()
    return out


def percentile(sorted_vals, q):
    """Linear-interpolation percentile, q in [0,100]."""
    if not sorted_vals:
        raise ValueError("empty sample")
    k = (len(sorted_vals) - 1) * q / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def summarize(samples_ns):
    """Stats in microseconds (ns/1000 exactly once)."""
    us = sorted(s / 1000.0 for s in samples_ns)
    return {"n": len(us), "min_us": us[0], "median_us": percentile(us, 50), "mean_us": statistics.fmean(us),
            "p95_us": percentile(us, 95), "max_us": us[-1],
            "iqr_us": percentile(us, 75) - percentile(us, 25),
            "stdev_us": statistics.stdev(us) if len(us) > 1 else 0.0}


def peak_rss_kb():
    """This process's OWN peak RSS in KB.

    Linux: read VmHWM from /proc/self/status. Do NOT use ru_maxrss there: after fork+exec it still contains the
    PARENT's high-water mark (measured: a fresh child reported 233 MB when started from a 200 MB parent).
    Elsewhere fall back to ru_maxrss (KB on Linux, BYTES on macOS)."""
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return float(line.split()[1])
    except OSError:
        pass
    v = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return v / 1024.0 if sys.platform == "darwin" else float(v)


def measure_memory(fn, calls=1):
    """SEPARATE memory pass (tracemalloc slows code, never mix with timing). Returns peak traced KB."""
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        for i in range(calls):
            fn(i)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak / 1024.0


def validate_row(row):
    """Raise ValueError on schema violations / implausible values."""
    unknown = set(row) - set(CSV_COLUMNS)
    if unknown:
        raise ValueError(f"unknown columns: {sorted(unknown)}")
    if row.get("problem_id") != "P1":
        raise ValueError("problem_id must be 'P1'")
    if row.get("pass_type") not in PASS_TYPES:
        raise ValueError(f"bad pass_type {row.get('pass_type')!r}")
    for k, v in row.items():
        if v in ("", None):
            continue
        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            raise ValueError(f"{k} is NaN/inf")
        if k.endswith(("_us", "_kb", "_bytes")) or k in ("throughput_mb_s",):
            if not isinstance(v, (int, float)) or v < 0:
                raise ValueError(f"{k} must be a non-negative number, got {v!r}")
    if row["pass_type"] == "latency" and not (row.get("median_us") or 0) > 0:
        raise ValueError("latency row needs median_us > 0")
    return row
