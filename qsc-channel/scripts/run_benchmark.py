"""Child entrypoint (called through src/routing.run_isolated). Applies platform constraints FIRST, then imports crypto.

--mode latency            : all timing passes (NO tracemalloc), plus size rows
--mode memory --scenario  : one fresh process per scenario: handshake:<suite> | bulk:<payload_bytes>
"""
import argparse
import os
import platform as pyplatform
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.metrics import measure_memory, peak_rss_kb, summarize, time_it, time_it_interleaved, validate_row  # noqa: E402  (stdlib only)
from src.processors import apply_constraints, load_processor  # noqa: E402
from src.routing import emit_result  # noqa: E402

RSS_BASELINE_KB = peak_rss_kb()          # interpreter + stdlib only, before any crypto import

ap = argparse.ArgumentParser()
ap.add_argument("--proc", required=True)
ap.add_argument("--mode", choices=["latency", "memory"], required=True)
ap.add_argument("--scenario", default="")
ap.add_argument("--repeat", type=int, default=1)
ap.add_argument("--quick", action="store_true", help="tiny iteration counts (tests only)")
args = ap.parse_args()

PROC = load_processor(args.proc)
EFF = apply_constraints(PROC)            # BEFORE importing the crypto libraries so RLIMIT_AS covers them

from src.channel import Client, Server, make_identities, run_handshake  # noqa: E402
from src.kem import BACKEND_NAME, BACKEND_VERSION, KEMS  # noqa: E402
from src.problem import SUITE_HYBRID, SUITE_SIG, SUITES  # noqa: E402
from src.sig import SIG_BACKEND_VERSION, SIGS  # noqa: E402

N, W = (5, 1) if args.quick else (PROC["iterations"], PROC["warmup"])
BULK = {1_000: (N, W), 100_000: (N, W), 10_000_000: (2, 1) if args.quick else (10, 2)}   # same on every platform
SEED = PROC["seed"]


def base(pass_type, suite, op, payload=""):
    return {"problem_id": "P1", "platform": PROC["name"], "repeat": args.repeat, "pass_type": pass_type, "suite": suite,
            "operation": op, "payload_bytes": payload, "backend": BACKEND_NAME,
            "backend_version": f"{BACKEND_VERSION}; {SIG_BACKEND_VERSION}".replace("cryptography", "cryptography", 1),
            "python_version": pyplatform.python_version(), "seed": SEED,
            "cpu_affinity_effective": EFF["cpu_affinity_effective"], "rlimit_as_mb_effective": EFF["rlimit_as_mb_effective"],
            "docker_cpus": EFF["docker_cpus"], "docker_memory_mb": EFF["docker_memory_mb"],
            "contention_workers": EFF["contention_workers"]}


def lat_row(suite, op, samples, iters, warm, payload="", **extra):
    s = summarize(samples)
    row = base("latency", suite, op, payload)
    row.update({"iterations": iters, "warmup": warm, "median_us": s["median_us"], "mean_us": s["mean_us"],
                "p95_us": s["p95_us"], "min_us": s["min_us"], "max_us": s["max_us"], "iqr_us": s["iqr_us"],
                "stdev_us": s["stdev_us"]})
    row.update(extra)
    return validate_row(row)


def latency_rows():
    rows = []
    rng = random.Random(SEED)
    ids = make_identities()
    # --- KEM primitive ops: suites are timed INTERLEAVED (paired) so host drift cannot bias suite-vs-suite comparisons.
    #     decaps uses a FRESH (sk, ct) pair every iteration; encaps reuses one pk (fresh ephemeral randomness each call).
    fns = {"keygen": {}, "encaps": {}, "decaps": {}}
    for suite in SUITES:
        kem = KEMS[suite]
        pk, _ = kem.keygen()
        pairs = []
        for _ in range(N + W):
            p, s = kem.keygen()
            pairs.append((s, kem.encaps(p)[0]))
        fns["keygen"][suite] = lambda i, kem=kem: kem.keygen()
        fns["encaps"][suite] = lambda i, kem=kem, pk=pk: kem.encaps(pk)
        fns["decaps"][suite] = lambda i, kem=kem, pairs=pairs: kem.decaps(*pairs[i])
    for op, group in fns.items():
        samples = time_it_interleaved(group, N, W)
        for suite in SUITES:
            sizes = {"pk_bytes": KEMS[suite].PK_LEN, "ct_bytes": KEMS[suite].CT_LEN}
            rows.append(lat_row(suite, op, samples[suite], N, W, **sizes))
    # --- signature ops (interleaved ML-DSA-65 vs ECDSA-P256)
    msg = rng.randbytes(32)
    keys = {name: cls.keygen() for name, cls in SIGS.items()}
    sigs = {name: SIGS[name].sign(keys[name][1], msg) for name in SIGS}
    sfns = {"sign": {n: (lambda i, n=n: SIGS[n].sign(keys[n][1], msg)) for n in SIGS},
            "verify": {n: (lambda i, n=n: SIGS[n].verify(keys[n][0], msg, sigs[n])) for n in SIGS}}
    for op, group in sfns.items():
        samples = time_it_interleaved(group, N, W)
        for name in SIGS:
            rows.append(lat_row(name, op, samples[name], N, W, sig_bytes=SIGS[name].SIG_LEN))
    # --- full handshake (client + server in one process, in-memory pipe), suites interleaved;
    #     client/server compute split recorded per iteration
    splits = {s: [] for s in SUITES}
    last = {}

    def make_one(suite):
        def one(i):
            r = run_handshake(Client(suite, ids[SUITE_SIG[suite]][0]), Server(ids))
            splits[suite].append((r.client_ns, r.server_ns))
            last[suite] = r
        return one

    totals = time_it_interleaved({s: make_one(s) for s in SUITES}, N, W)
    for suite in SUITES:
        sp = splits[suite][W:]
        kem, sig = KEMS[suite], SIGS[SUITE_SIG[suite]]
        ex = {"bytes_c2s": last[suite].counter.c2s, "bytes_s2c": last[suite].counter.s2c, "pk_bytes": kem.PK_LEN,
              "ct_bytes": kem.CT_LEN, "sig_bytes": sig.SIG_LEN}
        rows.append(lat_row(suite, "handshake_total", totals[suite], N, W, **ex))
        rows.append(lat_row(suite, "handshake_client_compute", [c for c, _ in sp], N, W, **ex))
        rows.append(lat_row(suite, "handshake_server_compute", [s for _, s in sp], N, W, **ex))
        size = base("size", suite, "handshake_bytes")
        size.update(ex)
        rows.append(validate_row(size))
    # --- bulk transfer through an established hybrid session (seal + open, 16 KiB records)
    r = run_handshake(Client(SUITE_HYBRID, ids[SUITE_SIG[SUITE_HYBRID]][0]), Server(ids))
    for n, (it, wu) in BULK.items():
        data = random.Random(SEED).randbytes(n)

        def rt(i, data=data):
            r.server.recv(r.client.send(data))

        row = lat_row(SUITE_HYBRID, "bulk_roundtrip", time_it(rt, it, wu), it, wu, payload=n)
        row["throughput_mb_s"] = n / row["median_us"]        # bytes per microsecond == MB/s (1 MB = 1e6 B)
        rows.append(row)
    return rows


def memory_rows():
    kind, _, arg = args.scenario.partition(":")
    ids = make_identities() if kind == "handshake" else None
    if kind == "handshake":
        suite = arg

        def fn(i):
            run_handshake(Client(suite, ids[SUITE_SIG[suite]][0]), Server(ids))

        peak = measure_memory(fn, calls=3)
        row = base("memory", suite, "handshake_total")
    elif kind == "bulk":
        n = int(arg)
        ids = make_identities()
        r = run_handshake(Client(SUITE_HYBRID, ids[SUITE_SIG[SUITE_HYBRID]][0]), Server(ids))
        data = random.Random(SEED).randbytes(n)
        peak = measure_memory(lambda i: r.server.recv(r.client.send(data)), calls=1)
        row = base("memory", SUITE_HYBRID, "bulk_roundtrip", n)
    else:
        raise SystemExit(f"unknown scenario {args.scenario!r}")
    row.update({"tracemalloc_peak_kb": peak, "peak_rss_kb": peak_rss_kb(), "rss_baseline_kb": RSS_BASELINE_KB})
    return [validate_row(row)]


rows = latency_rows() if args.mode == "latency" else memory_rows()
emit_result({"rows": rows, "effective": EFF})
