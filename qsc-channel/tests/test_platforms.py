import json
import os

import pytest

from src.processors import CONSTRAINT_KEYS, load_processor
from src.routing import ROOT, run_isolated


def P(n):
    return os.path.join(ROOT, "processors", n)


CHILD = os.path.join(ROOT, "tests", "smoke_child.py")


def test_A_and_B_differ_only_in_constraints():
    a, b = load_processor(P("processor_A.json")), load_processor(P("processor_B.json"))
    for k in set(a) | set(b):
        if k not in CONSTRAINT_KEYS:
            assert a[k] == b[k], f"{k} differs between A and B"
    assert a["cpu_affinity"] is None and a["rlimit_as_mb"] is None
    assert b["cpu_affinity"] == [0] and b["rlimit_as_mb"] == 256


def test_invalid_config_rejected(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(json.dumps({"name": "x", "iterations": "100", "warmup": 1, "seed": 1, "repeats": 1}))
    with pytest.raises(ValueError):
        load_processor(str(f))


def test_effective_constraints_readback_and_clean_json():
    ra = run_isolated(P("processor_A.json"), CHILD, ["--job", "sha"])
    rb = run_isolated(P("processor_B.json"), CHILD, ["--job", "sha"])
    assert ra["job"] == rb["job"] == "ok"            # stray print did not corrupt output
    assert ra["rlimit_as_mb_effective"] == ""         # A: no cap
    assert rb["rlimit_as_mb_effective"] == 256        # B: cap really in force
    assert rb["cpu_affinity_effective"] == "0"


def test_memory_cap_is_real():
    run_isolated(P("processor_A.json"), CHILD, ["--job", "alloc"])      # A allows 1 GB
    with pytest.raises(RuntimeError):
        run_isolated(P("processor_B.json"), CHILD, ["--job", "alloc"])  # B must fail


def test_contention_config_records_workers():
    r = run_isolated(P("processor_B_contended.json"), CHILD, ["--job", "sha"])
    assert r["contention_workers"] == 1
