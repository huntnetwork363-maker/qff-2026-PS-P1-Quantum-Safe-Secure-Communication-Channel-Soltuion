"""PS-P1: platform (processor) definitions and constraint application.

IMPORTANT: stdlib only. This module must be importable and applied BEFORE the
crypto libraries are imported, so RLIMIT_AS covers them.
"""
import json
import os
import resource
import shutil

REQUIRED_KEYS = {"name": str, "iterations": int, "warmup": int, "seed": int, "repeats": int}
CONSTRAINT_KEYS = ("name", "description", "cpu_affinity", "rlimit_as_mb", "docker", "contention")


def load_processor(path):
    with open(path) as f:
        proc = json.load(f)
    for k, t in REQUIRED_KEYS.items():
        if k not in proc or not isinstance(proc[k], t):
            raise ValueError(f"{path}: key '{k}' missing or not {t.__name__}")
    aff = proc.get("cpu_affinity")
    if aff is not None and not (isinstance(aff, list) and all(isinstance(c, int) and c >= 0 for c in aff) and aff):
        raise ValueError(f"{path}: cpu_affinity must be null or a non-empty list of core ids")
    lim = proc.get("rlimit_as_mb")
    if lim is not None and not (isinstance(lim, int) and lim > 0):
        raise ValueError(f"{path}: rlimit_as_mb must be null or a positive int")
    return proc


def apply_constraints(proc):
    """Apply constraints to the CURRENT process; return values read back (what is really in force)."""
    eff = {"cpu_affinity_effective": "", "rlimit_as_mb_effective": "", "docker_cpus": "",
           "docker_memory_mb": "", "docker_available": shutil.which("docker") is not None,
           "contention_workers": (proc.get("contention") or {}).get("busy_workers", 0)}
    aff = proc.get("cpu_affinity")
    if hasattr(os, "sched_setaffinity"):
        if aff is not None:
            os.sched_setaffinity(0, set(aff))
        eff["cpu_affinity_effective"] = ",".join(str(c) for c in sorted(os.sched_getaffinity(0)))
    else:
        eff["cpu_affinity_effective"] = "unsupported"
    lim = proc.get("rlimit_as_mb")
    if lim is not None:
        b = lim * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (b, b))
    soft = resource.getrlimit(resource.RLIMIT_AS)[0]
    eff["rlimit_as_mb_effective"] = "" if soft == resource.RLIM_INFINITY else soft // (1024 * 1024)
    dk = proc.get("docker")
    # Docker limits are only recorded if this process really runs under them; we never fake them.
    if dk and os.path.exists("/sys/fs/cgroup/cpu.max"):
        try:
            q, p = open("/sys/fs/cgroup/cpu.max").read().split()
            if q != "max":
                eff["docker_cpus"] = round(int(q) / int(p), 3)
        except (OSError, ValueError):
            pass
    return eff
