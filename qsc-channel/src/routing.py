"""PS-P1 meaning: isolated subprocess runner (placement/pinning analogue). No qubit routing here."""
import json
import os
import subprocess
import sys
import time

from .processors import load_processor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SENTINEL = "@@RESULT@@"


def emit_result(obj):
    """Called by child scripts: one sentinel line so stray prints cannot corrupt the JSON."""
    print(SENTINEL + json.dumps(obj), flush=True)


def _start_hogs(proc):
    c = proc.get("contention")
    if not c:
        return []
    cores = proc.get("cpu_affinity") or [0]
    code = f"import os; os.sched_setaffinity(0, {set(cores)!r})\nwhile True: pass"
    hogs = [subprocess.Popen([sys.executable, "-c", code]) for _ in range(int(c.get("busy_workers", 1)))]
    time.sleep(0.5)
    return hogs


def run_isolated(proc_path, script, args=(), timeout=1800):
    """Run `script` in a FRESH subprocess; the child applies constraints itself before importing crypto."""
    proc = load_processor(proc_path)
    hogs = _start_hogs(proc)
    try:
        r = subprocess.run([sys.executable, script, "--proc", proc_path, *map(str, args)],
                           capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    finally:
        for h in hogs:
            h.kill()
            h.wait()
    if r.returncode != 0:
        raise RuntimeError(f"child failed (exit {r.returncode}) on {proc['name']}:\n{r.stderr[-2000:]}")
    lines = [ln for ln in r.stdout.splitlines() if ln.startswith(SENTINEL)]
    if not lines:
        raise RuntimeError(f"no result line from child. stdout tail: {r.stdout[-500:]}")
    return json.loads(lines[-1][len(SENTINEL):])
