"""Child used by test_platforms: applies constraints first, then runs a tiny job."""
import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.processors import apply_constraints, load_processor
from src.routing import emit_result

ap = argparse.ArgumentParser()
ap.add_argument("--proc")
ap.add_argument("--job", default="sha")
a = ap.parse_args()
eff = apply_constraints(load_processor(a.proc))
print("stray print that must not corrupt the result")
if a.job == "sha":
    h = b"x"
    for _ in range(1000):
        h = hashlib.sha256(h).digest()
    eff["job"] = "ok"
elif a.job == "alloc":
    buf = bytearray(1024 * 1024 * 1024)
    eff["job"] = f"allocated {len(buf)}"
eff["cpu_count_visible"] = len(os.sched_getaffinity(0))
emit_result(eff)
