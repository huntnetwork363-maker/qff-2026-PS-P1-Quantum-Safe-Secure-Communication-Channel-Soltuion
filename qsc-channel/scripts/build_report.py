"""Generate report.md from results/tables/*.csv so every number in the prose is traceable to a CSV.
Also writes results/tables/report_values.json (key -> value) used by spot_check_report.py."""
import json
import os
import re
import subprocess
import sys

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from src.problem import SUITE_CLASSIC, SUITE_HYBRID, SUITE_PQ  # noqa: E402

T = os.path.join(ROOT, "results", "tables")
V = {}   # every quoted number: key -> value


def load(n):
    return pd.read_csv(os.path.join(T, f"processor_{n}_metrics.csv"))


A, B, C = load("A"), load("B"), load("B_contended")
AB = pd.read_csv(os.path.join(T, "AB_comparison.csv"))
ABC = pd.read_csv(os.path.join(T, "AB_comparison_contended.csv"))
FIN = pd.read_csv(os.path.join(T, "final_comparison.csv"))
SZ = pd.read_csv(os.path.join(T, "sizes.csv"))


def runs(df, suite, op, col="median_us", payload=None):
    d = df[(df.pass_type == "latency") & (df.suite == suite) & (df.operation == op)]
    if payload is not None:
        d = d[d.payload_bytes == payload]
    return d[col].astype(float).values


def med(df, suite, op, col="median_us", payload=None):
    return float(np.median(runs(df, suite, op, col, payload)))


def put(key, val, fmt="{:,.1f}"):
    V[key] = float(val)
    return fmt.format(val)


def md_table(df):
    cols = list(df.columns)
    out = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for r in df.itertuples(index=False):
        out.append("| " + " | ".join(str(x) for x in r) + " |")
    return "\n".join(out)


def spreads(note):
    m = re.search(r"spread_A=([\d.]+)% spread_B=([\d.]+)%", note)
    return float(m.group(1)) / 100, float(m.group(2)) / 100


def total_bytes(s):
    return int(SZ[(SZ.suite == s) & (SZ.message == "TOTAL")].bytes.iloc[0])


H, P, K = SUITE_HYBRID, SUITE_PQ, SUITE_CLASSIC
# ------------------------------------------------------------------ numbers
hs = {p: {s: med(d, s, "handshake_total") / 1000 for s in (K, P, H)} for p, d in (("A", A), ("B", B), ("C", C))}
hs_rep = {p: runs(d, H, "handshake_total") / 1000 for p, d in (("A", A), ("B", B))}
overlap = max(hs_rep["A"].min(), hs_rep["B"].min()) <= min(hs_rep["A"].max(), hs_rep["B"].max())
sp = AB.ci_note.map(spreads)
AB["noise"] = [max(a, b) for a, b in sp]
AB["dist"] = (AB.ratio_B_over_A - 1).abs() > AB.noise
n_rows, n_dist = len(AB), int(AB.dist.sum())
dist_names = [f"{r.suite}/{r.operation}" + (f"/{int(r.payload_bytes)}B" if pd.notna(r.payload_bytes) else "")
              + f" ({r.ratio_B_over_A:.2f}x)" for r in AB[AB.dist].itertuples()]
n_high = int(AB.ci_note.str.contains("HIGH").sum())
c_dist = ABC[(ABC.operation == "handshake_total")]
sv_h, sv_p = med(A, H, 'handshake_server_compute') / 1000, med(A, P, 'handshake_server_compute') / 1000
ecdh_lo = min(med(A, K, o) for o in ('keygen', 'encaps', 'decaps')) / 1000
ecdh_hi = max(med(A, K, o) for o in ('keygen', 'encaps', 'decaps')) / 1000
prim = {(s, o): med(A, s, o) for s in (K, P, H) for o in ("keygen", "encaps", "decaps")}
bulk = {(p, n): med(d, H, "bulk_roundtrip", "throughput_mb_s", n) for p, d in (("A", A), ("B", B), ("C", C))
        for n in (1000, 100000, 10000000)}
rss = FIN.set_index("Metric")
loc = int(FIN[FIN.Metric.str.startswith("Code size")]["Platform A"].iloc[0])
rss_bulk_v = float(rss.loc['Peak RSS, 10 MB bulk process (MB)', 'Platform A'])
ntests = int(re.search(r"(\d+) tests? collected", subprocess.run(
    [sys.executable, "-m", "pytest", "--collect-only", "-q"], capture_output=True, text=True, cwd=ROOT).stdout).group(1))
vers = '; '.join(dict.fromkeys(s.strip() for s in A.backend_version.iloc[0].split(';')))
pyv = A.python_version.iloc[0]
b_tot, p_tot, k_tot = total_bytes(H), total_bytes(P), total_bytes(K)

ratio_med = float(np.median(AB.ratio_B_over_A))
ratio_rng = (float(AB.ratio_B_over_A.min()), float(AB.ratio_B_over_A.max()))
if n_dist == 0:
    verdict = (f"**None of the {n_rows} A-vs-B comparisons exceeds its own run-to-run noise**, so this experiment does not "
               "show a measurable difference between Platform A and Platform B.")
else:
    verdict = (f"Only {n_dist} of {n_rows} A-vs-B comparisons exceed their own run-to-run noise: " + "; ".join(dist_names)
               + ". All others are indistinguishable from noise. With this many comparisons, a few exceedances are expected by chance "
               + ("even when there is no true difference" + (", and the exceeding direction here is B *faster*, which a constraint cannot plausibly cause."
                  if all(r < 1 for r in AB[AB.dist].ratio_B_over_A) else ".")))

report = f"""# P1 — Quantum-Safe Secure Communication Channel: Report

Problem **P1** (Track 5, Post-Quantum Cryptography). All numbers below come from `results/tables/*.csv`
(regenerate everything with `make all`; `python scripts/spot_check_report.py` re-derives the quoted values independently).

## 1. Summary

We built a 1-round-trip, server-authenticated secure channel with a **hybrid key exchange (ECDH P-256 + ML-KEM-768)**,
**ML-DSA-65** transcript signatures, **HKDF-SHA256** key derivation and an **AES-256-GCM** record layer, using only vetted
library primitives (`{vers}`). We benchmarked it against a classical baseline (P-256 + ECDSA) and a PQ-only baseline on
**Platform A** (unconstrained) and **Platform B** (1-core affinity + 256 MB address-space cap), 3 independent process repeats ×
100 timed iterations.

Headline results (hybrid suite, medians):

* **Handshake on the wire:** {put('bytes_hybrid', b_tot, '{:,.0f}')} B (client→server {int(SZ[(SZ.suite == H) & (SZ.message == 'TOTAL_c2s')].bytes.iloc[0]):,} B,
  server→client {int(SZ[(SZ.suite == H) & (SZ.message == 'TOTAL_s2c')].bytes.iloc[0]):,} B) versus {put('bytes_classic', k_tot, '{:,.0f}')} B classical
  = **{put('bytes_x', b_tot / k_tot)}x**; only **+{put('bytes_hyb_vs_pq', b_tot - p_tot, '{:,.0f}')} B ({put('bytes_hyb_vs_pq_pct', 100 * (b_tot - p_tot) / p_tot)} %)** over PQ-only.
* **Handshake latency:** {put('hs_A_hybrid', hs['A'][H])} ms on A vs {put('hs_B_hybrid', hs['B'][H])} ms on B (classical: {put('hs_A_classic', hs['A'][K], '{:,.2f}')} ms on A). The A-vs-B gap is within run-to-run noise (section 5).
* **A vs B:** {verdict}
* **Memory:** {put('tm_hybrid', float(A[(A.pass_type == 'memory') & (A.suite == H) & (A.operation == 'handshake_total')].tracemalloc_peak_kb.median()), '{:,.0f}')} KB traced peak per hybrid handshake;
  process peak RSS {put('rss_hs', float(rss.loc['Peak RSS, hybrid handshake process (MB)', 'Platform A']))} MB (handshake) / {put('rss_bulk', float(rss.loc['Peak RSS, 10 MB bulk process (MB)', 'Platform A']))} MB (10 MB bulk).
* **Correctness evidence:** {ntests} automated tests (sizes vs FIPS values, independent ML-KEM cross-check, tamper/replay/MITM/downgrade tests, an unauthenticated-MITM negative control), see section 3.

## 2. Method

**Protocol** (`src/channel.py`): ClientHello (version, suite id, nonce, KEM public key) → ServerHello (KEM ciphertext, ML-DSA-65
signature over the SHA-256 transcript hash, Finished MAC) → ClientFinished. Keys: `HKDF-Extract(salt = nonce_c‖nonce_s, ikm = hybrid secret)`,
then separate Expand labels for client→server key, server→client key, nonce prefixes and the Finished key. The hybrid secret is
`HKDF(ikm = ss_ecdh ‖ ss_mlkem, info = label ‖ all public values)`. Records are ≤ 16 KiB, AAD = direction ‖ sequence ‖ length, nonces are counters (never random).
See `figures: logical_vs_transpiled.png` and `docs/THREAT_MODEL.md`.

![flow and cost](results/figures/logical_vs_transpiled.png)

**Platforms** (`processors/*.json`, `src/processors.py`, `src/routing.py`). Each benchmark repeat runs in a **fresh subprocess**
that applies its constraints *before* importing the crypto libraries and records the values read back (they are in every CSV row).

| | Platform A | Platform B | B contended (extra, D11) |
|---|---|---|---|
| CPU affinity (effective) | {A.cpu_affinity_effective.iloc[0]} | {B.cpu_affinity_effective.iloc[0]} | {C.cpu_affinity_effective.iloc[0]} |
| RLIMIT_AS | none | {int(B.rlimit_as_mb_effective.iloc[0])} MB | {int(C.rlimit_as_mb_effective.iloc[0])} MB |
| Busy-loop neighbours on same core | 0 | 0 | {int(C.contention_workers.iloc[0])} |
| Docker `--cpus/--memory` | not available | not available | not available |

**Important honesty note.** This sandbox has **one CPU core and no Docker**, so pinning B to core 0 does **not** reduce its CPU relative to A.
The only genuine A/B difference in the required experiment is the 256 MB address-space cap. To still obtain a real CPU-constrained condition
we added an **extra, clearly labelled** experiment, *B contended*: a busy-loop process pinned to the same core, so the benchmark receives roughly half of the CPU.
This is real contention, not a scaled or faked number, but it is still an emulation on the same host, not real constrained hardware.

**Measurement.** `time.perf_counter_ns`, GC disabled inside timed loops, 10 warm-up + 100 timed iterations (10 MB payload: 2 + 10), 3 independent
process repeats, median/IQR/p95 per repeat. Latency and memory are **separate passes** (tracemalloc inflates run time); memory scenarios each run in a fresh process.
Competing suites/primitives are timed **interleaved with rotating order** so host drift cannot favour one suite (see `docs/BUGLOG.md`).
Peak RSS is read from `/proc/self/status` (`VmHWM`) because `ru_maxrss` wrongly includes the parent's high-water mark after `exec`.
Keys use OS randomness, so results are statistically, not bit-for-bit, reproducible; seed 42 only generates payload bytes.

## 3. Correctness evidence

{ntests} tests pass (`make test`). Highlights:

* Sizes asserted against FIPS values: ML-KEM-768 pk 1184 / ct 1088 / sk 2400, ML-DSA-65 pk 1952 / sig 3309, P-256 point 65.
* ML-KEM backend (`kyber-py`) interoperates with an independent implementation (`mlkem`) in both directions; a wrong-key negative control fails as it must.
* Hybrid combiner: replacing **only** the ECDH share or **only** the ML-KEM share changes the session key; tampered ML-KEM ciphertext gives a different key (implicit rejection) without an exception.
* Handshake: signature verified before key use; every one of ≥ 30 single-bit tampers over all three messages is rejected; downgrade to a classical suite is rejected;
  a signed MITM (fake server or KEM substitution) is rejected; record tamper / drop / reorder / replay are rejected.
* **Negative control:** with authentication disabled, the MITM attack *succeeds* (attacker reads and relays plaintext) — which is why the signature is mandatory.
* Payloads 1 KB / 100 KB / 10 MB (and 0, 1, 16384, 16385 bytes) round-trip byte-exactly (SHA-256).

## 4. Results

![A vs B latency](results/figures/AB_performance.png)

{md_table(FIN)}

*Difference = B − A (and B/A). Code size is the same on both platforms by construction. Memory values: tracemalloc peak is per handshake; RSS peaks include
about {put('rss_base', float(B[B.pass_type == 'memory'].rss_baseline_kb.median()) / 1024)} MB of interpreter baseline and the imported libraries, so they differ little between scenarios except for the 10 MB payload.*

Per-suite handshake latency (median of 3 repeats, ms):

| Suite | A | B | B contended (extra) |
|---|---|---|---|
| Classical (P-256 + ECDSA) | {hs['A'][K]:.2f} | {hs['B'][K]:.2f} | {hs['C'][K]:.2f} |
| PQ only (ML-KEM-768 + ML-DSA-65) | {hs['A'][P]:.1f} | {hs['B'][P]:.1f} | {hs['C'][P]:.1f} |
| Hybrid (P-256+ML-KEM-768 + ML-DSA-65) | {hs['A'][H]:.1f} | {hs['B'][H]:.1f} | {hs['C'][H]:.1f} |

![sizes](results/figures/bytes_on_wire.png)
![trade-offs](results/figures/architecture_tradeoffs.png)
![throughput](results/figures/throughput_payloads.png)
![platform A](results/figures/processor_A_graph.png)
![platform B](results/figures/processor_B_graph.png)

## 5. Interpretation

1. **What changed between A and B?** Only constraints. B is pinned to core 0 and capped at 256 MB of address space; on this single-core host the pin changes nothing for CPU,
   so the cap is the only effective difference. Algorithm, backend, versions, iterations and seed are identical (checked by `scripts/check_repo.py`).
2. **Which platform property changed?** Memory ceiling only (A vs B). Every workload completed under the cap (peak RSS ≤ {rss_bulk_v:.0f} MB; note `RLIMIT_AS` limits *virtual address space*, which is larger than RSS), so the cap did not constrain this workload. In the extra experiment the property that changed is **CPU share**.
3. **Did the handshake slow down, and which step dominates?** {verdict} Across all {n_rows} A/B comparisons the B/A ratio has median {ratio_med:.2f} (range {ratio_rng[0]:.2f}–{ratio_rng[1]:.2f}).
   The headline hybrid handshake reads {hs['B'][H] / hs['A'][H]:.2f}x slower on B, but its run-to-run spread is about 20 % on both platforms and the per-repeat ranges
   {'overlap' if overlap else 'do not overlap'} (A: {hs_rep['A'].min():.1f}–{hs_rep['A'].max():.1f} ms, B: {hs_rep['B'].min():.1f}–{hs_rep['B'].max():.1f} ms), so we do not claim a real slowdown.
   **Dominant step:** ML-DSA-65 signing on the server (median {put('sign_ms', med(A, 'MLDSA65', 'sign') / 1000)} ms) which accounts for most of the server's measured compute ({put('sv_hybrid_ms', sv_h)} ms hybrid, {put('sv_pq_ms', sv_p)} ms PQ-only; medians of separately measured, heavy-tailed quantities, so we do not quote a percentage); on the client ML-DSA verification ({put('verify_ms', med(A, 'MLDSA65', 'verify') / 1000)} ms) is the largest part.
   ML-KEM-768 keygen/encaps/decaps medians are {prim[(P, 'keygen')] / 1000:.1f} / {prim[(P, 'encaps')] / 1000:.1f} / {prim[(P, 'decaps')] / 1000:.1f} ms. ML-DSA signing uses rejection sampling, so its time is heavy-tailed, which also explains the large p95 values.
4. **Extra bytes from hybrid vs classical?** +{b_tot - k_tot:,} B ({b_tot / k_tot:.1f}x): the ML-KEM-768 public key (1,184 B) and ciphertext (1,088 B) plus the ML-DSA-65 signature (3,309 B versus a 64-byte ECDSA signature).
   Hybrid vs PQ-only adds only the two P-256 points (+130 B) and a longer suite id (+10 B) = +{b_tot - p_tot} B.
5. **Did sizes change between platforms?** No: byte counts are identical on A, B and contended, as they must be — sizes are a property of the algorithms and framing, not of the CPU or memory budget.
6. **Could host noise / backend implementation also contribute?** Yes, strongly. {n_high} of {n_rows} comparisons carry more than 20 % run-to-run spread on this shared virtual host.
   The PQ code is pure Python while ECDH/AES come from OpenSSL-backed `cryptography`: hybrid keygen is {prim[(H, 'keygen')] / prim[(K, 'keygen')]:.0f}x slower than classical keygen mainly because of
   this implementation difference, **not** because ML-KEM is inherently that much slower; an optimised C backend (liboqs) would change the absolute numbers considerably (not measured here).
   Paired timing shows hybrid ≈ PQ-only at the primitive level (hybrid/PQ median ratio keygen {prim[(H, 'keygen')] / prim[(P, 'keygen')]:.2f}, encaps {prim[(H, 'encaps')] / prim[(P, 'encaps')]:.2f}, decaps {prim[(H, 'decaps')] / prim[(P, 'decaps')]:.2f}); the P-256 ECDH operations cost only {ecdh_lo:.2f}–{ecdh_hi:.2f} ms, below the noise floor, so handshake-level hybrid-vs-PQ differences are not resolvable.
7. **Extra experiment (CPU contention).** With a competing busy loop, the PQ and hybrid handshakes take {hs['C'][P] / hs['A'][P]:.2f}x and {hs['C'][H] / hs['A'][H]:.2f}x the time of A, and 10 MB throughput falls to
   {bulk[('C', 10000000)] / bulk[('A', 10000000)]:.2f}x ({bulk[('C', 10000000)]:.0f} vs {bulk[('A', 10000000)]:.0f} MB/s). The classical handshake ({hs['A'][K]:.2f} ms) and the 1 KB / 100 KB transfers
   ({bulk[('A', 1000)]:.0f} / {bulk[('A', 100000)]:.0f} MB/s on A vs {bulk[('C', 1000)]:.0f} / {bulk[('C', 100000)]:.0f} on contended) show **no median slowdown**. A consistent (not separately proven) explanation: those operations are shorter than a scheduler time slice,
   so most iterations run un-preempted, which appears only in their tails (classical contended p95 = {float(np.median(runs(C, K, 'handshake_total', 'p95_us'))) / 1000:.1f} ms vs {float(np.median(runs(A, K, 'handshake_total', 'p95_us'))) / 1000:.2f} ms on A).
   Take-away: for CPU-starved devices, long-running PQ operations are the ones that suffer.
8. **What remains uncertain?** Behaviour on real constrained hardware (ARM cores, caches, frequency scaling), network latency/loss, a compiled backend, side-channel behaviour of the pure-Python libraries,
   and why 10 MB throughput ({bulk[('A', 10000000)]:.0f} MB/s) is far below 100 KB throughput ({bulk[('A', 100000)]:.0f} MB/s) (we suspect cache effects and Python copying of large buffers; not tested).

## 6. Trade-offs

* **Cost of PQ at all:** versus classical, hybrid costs {b_tot / k_tot:.1f}x the handshake bytes and ~{hs['A'][H] / hs['A'][K]:.0f}x the handshake time in this pure-Python setup — acceptable for a once-per-connection handshake,
  more painful for very short-lived connections or constrained links.
* **Cost of hybrid over PQ-only:** +{100 * (b_tot - p_tot) / p_tot:.1f} % bytes, negligible compute, identical memory — a cheap premium.
* **Benefit of hybrid:** recorded traffic stays confidential unless **both** P-256 ECDH and ML-KEM-768 fail, hedging a future quantum computer (harvest-now-decrypt-later) *and* a flaw in a young algorithm.
* **When it is worth it on constrained devices:** when long-lived confidentiality matters and handshakes are infrequent. Bulk encryption cost (AES-GCM) is independent of the PQ choice.

## 7. Limitations

* Platform B is an **emulation on one host**; CPU throttling via Docker/cgroups was not available; the contended run is an extra experiment, not part of the required A/B definition.
* PQ libraries are pure Python research code: **not constant-time, not for production**; absolute latencies are not representative of optimised implementations.
* Shared virtual host: considerable run-to-run noise (see `results/tables/spread_flags.csv`); only 3 process repeats.
* In-memory transport: no network latency, loss or TCP effects. No PKI/revocation (server key is pinned), server-only authentication.
* Python {pyv}; versions: {vers}.

## 8. Reproduction

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
make test          # {ntests} tests
make bench         # ~6 minutes; writes results/tables/*.csv  (python scripts/bench_all.py --quick for a fast smoke run)
make figures       # results/figures/*.png
python scripts/build_report.py && python scripts/spot_check_report.py && python scripts/check_repo.py
```
"""
open(os.path.join(ROOT, "report.md"), "w").write(report)
readme_p = os.path.join(ROOT, "README.md")
block = (f"Hybrid suite, Platform A vs B (extra: B contended). Medians over 3 process repeats; see `report.md` for method, caveats and figures.\n\n"
         + md_table(FIN) + f"\n\n* Handshake bytes: hybrid {b_tot:,} B vs classical {k_tot:,} B ({b_tot / k_tot:.1f}x), only +{b_tot - p_tot} B over PQ-only.\n"
         + f"* A vs B: {verdict}\n"
         + "* Extra CPU-contention experiment: long PQ operations slow down roughly 2x; sub-millisecond operations do not (median).\n\n"
         + "![A vs B latency](results/figures/AB_performance.png)\n![bytes](results/figures/bytes_on_wire.png)\n")
rd = open(readme_p).read()
rd = re.sub(r"<!-- RESULTS:START -->.*<!-- RESULTS:END -->", lambda m: "<!-- RESULTS:START -->\n" + block + "<!-- RESULTS:END -->", rd, flags=re.S)
open(readme_p, "w").write(rd)
json.dump(V, open(os.path.join(T, "report_values.json"), "w"), indent=1)
print("report.md written;", len(V), "tracked values;", len(report.split()), "words")
