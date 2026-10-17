# BUGLOG
Template: `### [PhaseN] file — time` · checks run · bugs found · fix · evidence

### [Phase0] skeleton — setup
- Checks: imports ok ✔ · pytest collects (0 tests) ✔ · pins use == ✔
- Bugs found: none. Note: docker not available in sandbox (-> D11)
- Evidence: `python -c "...; print('imports ok')"`

### [Phase1] processors/routing/metrics — harness
- Checks: pytest 11 passed ✔ · compileall ✔ · ruff ✔ (after fixes) · trap list ✔ · negative tests ✔ (1 GB alloc fails under B; bad config rejected; NaN/neg rows rejected; GC restored after exception)
- Bugs found: (1) lint: multiple statements per line / unsorted imports — fixed. (2) FINDING, not a code bug: sandbox has 1 core, no docker, no cgroup cpu.max → B's affinity [0] equals A's; the only real A/B difference is RLIMIT_AS=256 MB (which did not bind for ML-KEM in an earlier probe: 128 MB still ran all three libs). Mitigation: EXTRA labelled `platform_B_contended` (D11).
- Evidence: effective constraints read back: A rlimit '' / B 256, affinity '0' both, contended workers=1.

### [Phase2] problem/kem/sig/aead — crypto core
- Checks: pytest 42 passed ✔ · compileall ✔ · ruff ✔ · trap list ✔ · negative tests ✔
- Negative evidence: tampered ML-KEM ct -> different secret & no exception; swapping only the ECDH share or only the ML-KEM share changes ss; off-curve/truncated/compressed ECDH point -> KEMError; flipped bit in msg/sig, wrong pk, junk sig -> verify False (never raises); AEAD tamper/AAD/key/nonce/replay/reorder all fail; failed open does not advance counter; counter-exhaustion guard.
- Bugs found: (1) my first interop test guessed the mlkem `from_bytes` signature (test-code bug, fixed). (2) lint E501 in kem.py docstring (fixed).
- KAT note: neither ML-KEM library ships NIST vectors offline, so KAT is replaced by an INDEPENDENT-implementation interop test (kyber-py <-> mlkem 0.2.0, both directions, 10 keys each); negative control (wrong key) correctly yields different secrets. ML-DSA has no second implementation here: only size + sign/verify/negative tests.
- Evidence: `pytest -q` -> 42 passed

### [Phase3] channel / attacks / threat model
- Checks: pytest 76 passed ✔ · compileall ✔ · ruff ✔ · trap grep (no assert/random/print in src except routing sentinel) ✔ · negative tests ✔
- BUG FOUND by the tamper test: flipping a byte in the ML-KEM public key of ClientHello made kyber-py raise a raw `ValueError` (FIPS 203 modulus check) which escaped `Server.accept` as an unhandled non-HandshakeError exception (error-detail leak / crash path).
  Fix: `kem.py` now wraps kyber-py encaps/decaps `ValueError` into `KEMError`; channel maps that to `HandshakeError`. Regression test: `test_invalid_mlkem_public_key_gives_kemerror_not_valueerror`.
- Also fixed: lint (multiple statements per line, ambiguous var name, long lines, CSV CRLF line endings in sizes.csv).
- Verified: client verifies signature before decaps/key use; suite_id/version/nonces/KEM values are in the signed transcript; Finished compared with hmac.compare_digest; c2s != s2c keys (explicit test); per-connection state (cross-connection records rejected); chunk boundaries 0/1/16384/16385/100k and 1 KB/100 KB/10 MB byte-exact via SHA-256.
- Attack table (all asserted): passive eavesdropper learns nothing ✔; MITM fake server (signed) rejected ✔; MITM KEM substitution rejected by signature ✔; **unsigned MITM negative control SUCCEEDS** (attacker reads and relays plaintext) ✔; downgrade rejected ✔; ≥30 single-bit tampers across all 3 handshake messages all fail ✔ (hybrid + classical); record tamper/drop/reorder/replay all rejected ✔.
- Evidence: `pytest -q` -> 76 passed; sizes.csv hybrid total 5895 B vs classical 364 B.

### [Phase4] benchmark harness (before full run)
- Checks: pytest 82 passed ✔ · ruff ✔ · quick end-to-end bench_all + check_repo --results-only ✔ (35/36 on 5-iteration noise data; the 1 failure was hybrid-encaps-vs-PQ noise at n=5, check is able to fail ✔)
- **BUG (significant, measurement validity):** `ru_maxrss` in an exec'd child includes the PARENT's peak-RSS high-water mark on Linux. Reproduced: child started from a 200 MB parent reported 233 MB baseline. Effect on the quick run: "peak RSS = 64.242 MB" was IDENTICAL on A, B and B_contended (it was bench_all's own pandas-loaded memory leaking in) -> every peak_rss/baseline value would have been wrong. Found because test_memory_scenario_separate_pass failed only when pytest's process was large.
  Fix: `metrics.peak_rss_kb()` reads `VmHWM` from /proc/self/status (macOS/other fallback to ru_maxrss). Regression test: `test_peak_rss_not_inherited_from_bloated_parent`.
- **Process mistake caught:** a full benchmark was started while pytest was still running on the 1-core sandbox, which would have contaminated timings; killed it, verified no stray processes (0 bench/hog processes), restarted on a quiet machine. Rule going forward: nothing else runs during a benchmark.
- Test bug fixed: memory rows have no `median_us` key (empty CSV cell), test asserted the wrong thing.

### [Phase4] full benchmark (final run)
- Checks: `check_repo --results-only` 36/36 ✔ · pytest 84 ✔ · ruff ✔
- First full run (suites timed in separate contiguous windows) FAILED the sanity check "hybrid >= 0.9*max(classical, PQ)" (hybrid encaps looked ~16% FASTER than PQ-only; even best-case `min` showed 0.8x; direction mixed across ops). Cause: measurement design, not crypto: a noisy shared 1-core VM drifts over seconds, so each suite's window had different conditions.
  Fix (methodology, not a threshold change): `time_it_interleaved` times competing suites/primitives PAIRED per iteration with rotating order; unit tests added. Re-ran everything; the check passes with the ORIGINAL 0.9 tolerance. First-run data was discarded.
- Operational: background runs die between tool calls unless launched with `setsid`; a benchmark must not share the single core with tests (earlier contaminated start was killed and restarted).
- FINDING (honest result kept): A vs B indistinguishable from noise (1-core, no docker; only RLIMIT_AS differs and does not bind). Extra labelled experiment `platform_B_contended` gives real CPU-share contention (~2.1-2.2x for long PQ ops, ~0.4x throughput on 10 MB).

### [Phase5] figures + report
- Visual recheck found and fixed: overlapping bar labels and a clipped table (logical_vs_transpiled, processor_*_graph), legend hiding a value (trade-offs), a bubble chart where PQ-only and hybrid overlapped (replaced by 3-panel bars), labels colliding with whiskers (AB_performance, throughput).
- Report text recheck found and fixed: duplicated `cryptography` in the version string; a "92% of server compute" claim built from medians of different, heavy-tailed distributions (now "most", with the measured values); an RSS-vs-RLIMIT_AS (virtual) comparison that was apples-to-oranges; a spurious "1 of 25 exceeds noise" result (B *faster*) now stated as chance-level; ECDH cost range written from memory (now computed).
- `scripts/spot_check_report.py` re-derives 16 values + the A-vs-B claim + final-table rows with a different code path: 0 mismatches (tolerance 1e-3 because final_comparison.csv is rounded to 3 decimals; it initially flagged 2 values differing in the 4th decimal for that reason).

### [Phase6] release
- Notebook executes top-to-bottom (0 error outputs, 13 s) and leaves results/ byte-identical. Grep for absolute paths/secrets clean; only the deliberate README placeholders (team name, final commit hash) remain.
