# Decisions
| # | Decision | Reason |
|---|---|---|
| D1 | PS = P1 only | Rule: exactly one PS |
| D2 | ML-KEM-768 + ECDH P-256 | Master Guide |
| D3 | ML-DSA-65 signature over transcript (ECDSA-P256 for the classical baseline suite) | MITM resistance; true classical baseline |
| D4 | Platform A = unconstrained; Platform B = 1-core affinity + RLIMIT_AS (+ Docker if available) | Guide: B = constrained |
| D5 | B is an emulation on the same host; memory caps barely bind | Honesty |
| D6 | Backends: cryptography, kyber-py 1.2.0, dilithium-py 1.5.1 (pure Python, not constant-time, not production) | Verified vs FIPS sizes |
| D7 | Same backend/versions/seed/iterations on A and B | Controlled comparison |
| D8 | Keys use OS randomness: statistical, not bit-exact, reproducibility; seed 42 for payloads only | |
| D9 | Required filenames kept (processors/, routing.py ...) with PS-P1 meaning | Automated check |
| D10 | Master Guide rubric | |
| D11 | Sandbox has 1 CPU core and no Docker, so affinity [0] does not reduce CPU vs A. Added an EXTRA, clearly labelled experiment `platform_B_contended` (a busy-loop neighbour pinned to the same core = real CPU-share contention, not faked scaling). Required A/B comparison stays unchanged | Plan: no faked throttling; need a real CPU lever |
| D12 | CSV gets one extra column `pass_type` (latency/memory/size) | Latency and memory must be separate passes |
