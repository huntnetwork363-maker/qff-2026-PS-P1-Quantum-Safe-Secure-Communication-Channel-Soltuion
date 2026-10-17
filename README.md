# P1 — Quantum-Safe Secure Communication Channel

**Qiskit Fall Fest 2026 · Phase 1 · Track 5 (Post-Quantum Cryptography) · Problem P1**

Team: **TODO: team name and members (fill in before submission)** · Final commit: **TODO: tag `v1-submission` and paste hash**

## Summary

A reproducible Python implementation and benchmark of a **quantum-safe secure channel**: a 1-round-trip, server-authenticated handshake using a
**hybrid key exchange (ECDH P-256 + ML-KEM-768)**, **ML-DSA-65** transcript signatures, **HKDF-SHA256** key derivation and an
**AES-256-GCM** record layer. It is measured against classical (P-256 + ECDSA) and PQ-only baselines on **Platform A** (unconstrained) and
**Platform B** (constrained emulation). We write **no cryptographic primitives**: only vetted libraries are composed.
Full analysis: [`report.md`](report.md). Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Approach

```
Client                                                   Server (ML-DSA-65 key pinned by client)
 ClientHello  (version, suite, nonce_c, ECDH pk + ML-KEM pk)  ───────────▶
                                   ◀───────────  ServerHello (nonce_s, ECDH pk + ML-KEM ct,
                                                   ML-DSA sig over SHA-256 transcript, Finished)
 verify signature → decaps → derive keys → verify Finished
 ClientFinished  ───────────▶
 ═══════ application records: AES-256-GCM, separate keys per direction, counter nonces ═══════
```
Hybrid secret: `HKDF(ikm = ss_ecdh ‖ ss_mlkem, info = label ‖ all public values)`. See `src/kem.py`, `src/channel.py`, the figure `results/figures/logical_vs_transpiled.png`.

## Environment and how to run

Tested on Python **3.12.3** (Linux). Dependencies are pinned in `requirements.txt`.

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
make test                                   # 84 tests (unit, negative, attack, interop)
python scripts/bench_all.py --quick --repeats 1 --no-contended   # ~1 min smoke benchmark (writes results/tables!)
make bench                                  # full benchmark, ~6 min, writes results/tables/*.csv
make figures                                # results/figures/*.png
python scripts/build_report.py && python scripts/spot_check_report.py && python scripts/check_repo.py
jupyter nbconvert --to notebook --execute --inplace main.ipynb   # end-to-end notebook (does not overwrite results)
```
`make bench` overwrites `results/tables/`; the committed tables are the ones the report describes.

## Data / instance description

There is no external dataset. Payloads of **1 KB, 100 KB and 10 MB** are generated with `random.Random(42).randbytes(n)` (seed 42, identical on both platforms).
Cryptographic keys use OS randomness, so results are reproducible *statistically*, not bit-for-bit.

## Processor (platform) assumptions: Platform A vs Platform B

For Track 5 "processors" are **computing platforms**, not quantum devices (no qubits, coupling maps or SWAP counts apply).

| | Platform A | Platform B | B contended (extra experiment) |
|---|---|---|---|
| Definition | standard, no limits | 1 core pinned + 256 MB `RLIMIT_AS` | B + one busy-loop neighbour on the same core |
| Config | `processors/processor_A.json` | `processors/processor_B.json` | `processors/processor_B_contended.json` |

Constraints are applied inside a fresh subprocess **before** the crypto libraries are imported, and the values read back are stored in every CSV row.
**Platform B is an emulation on the same host.** The sandbox used here had **one core and no Docker**, so pinning to core 0 does not reduce B's CPU versus A;
the memory cap does not bind. The A-vs-B results are therefore (honestly) indistinguishable from noise. The extra *contended* experiment provides a real CPU-share
constraint (still emulated, not real constrained hardware). Details and caveats: `report.md` §2, §7.

## Results

<!-- RESULTS:START -->
Hybrid suite, Platform A vs B (extra: B contended). Medians over 3 process repeats; see `report.md` for method, caveats and figures.

| Metric | Platform A | Platform B | Difference | Platform B contended (extra) | Difference (contended vs A) |
|---|---|---|---|---|---|
| Handshake latency, hybrid (ms, median) | 57.623 | 66.978 | +9.36 (1.16x) | 127.235 | +69.61 (2.21x) |
| Handshake bytes c2s+s2c, hybrid (bytes) | 5895.0 | 5895.0 | +0.00 (1.00x) | 5895.0 | +0.00 (1.00x) |
| Ciphertext size, hybrid KEM (bytes) | 1153.0 | 1153.0 | +0.00 (1.00x) | 1153.0 | +0.00 (1.00x) |
| Peak memory, hybrid handshake: tracemalloc (KB) | 1194.779 | 1194.59 | -0.19 (1.00x) | 1194.645 | -0.13 (1.00x) |
| Peak RSS, hybrid handshake process (MB) | 36.598 | 36.578 | -0.02 (1.00x) | 36.5 | -0.10 (1.00x) |
| Peak RSS, 10 MB bulk process (MB) | 71.516 | 71.305 | -0.21 (1.00x) | 71.414 | -0.10 (1.00x) |
| Throughput, 10 MB payload (MB/s) | 523.19 | 499.005 | -24.19 (0.95x) | 213.722 | -309.47 (0.41x) |
| Code size, src/ (LOC, non-blank non-comment) | 730.0 | 730.0 | +0.00 (1.00x) | 730.0 | +0.00 (1.00x) |

* Handshake bytes: hybrid 5,895 B vs classical 364 B (16.2x), only +140 B over PQ-only.
* A vs B: Only 1 of 25 A-vs-B comparisons exceed their own run-to-run noise: MLDSA65/sign (0.88x). All others are indistinguishable from noise. With this many comparisons, a few exceedances are expected by chance even when there is no true difference, and the exceeding direction here is B *faster*, which a constraint cannot plausibly cause.
* Extra CPU-contention experiment: long PQ operations slow down roughly 2x; sub-millisecond operations do not (median).

![A vs B latency](results/figures/AB_performance.png)
![bytes](results/figures/bytes_on_wire.png)
<!-- RESULTS:END -->

## Conflict-resolution notes (Master Guide vs Giant Kit)

The Master Guide governs. Required: hybrid KEM (ECDH P-256 + ML-KEM-768) and latency / ciphertext size / memory on Platform A vs B. Included as extras from the
Giant Kit: ML-DSA-65 authentication, HKDF + AES-256-GCM record layer, 1 KB / 100 KB / 10 MB payloads, flow diagram, bytes exchanged, code size.
Not required for P1 and not built: a third platform ("Processor D"), liboqs backend, Docker-based throttling.

## Known limitations

* Platform B is an emulation on one host; CPU throttling via Docker/cgroups was unavailable. Shared virtual host → noticeable run-to-run noise (3 process repeats).
* `kyber-py` and `dilithium-py` are **pure-Python research implementations: not constant-time, not production-grade.** Absolute latencies are not representative of optimised C backends.
* In-memory transport (no network latency/loss); no PKI/revocation (pinned server key); server-only authentication.

## AI-assistance disclosure

This repository (code, tests, benchmark harness, figures, report and documentation) was produced with substantial assistance from **Claude (Anthropic)** working
in a sandbox under the team's direction. See [`docs/AI_DISCLOSURE.md`](docs/AI_DISCLOSURE.md) for what the AI did, how it was verified, and what the team still needs to confirm.
