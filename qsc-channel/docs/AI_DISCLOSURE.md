# AI assistance disclosure

**Tool:** Claude (Anthropic), used interactively in a chat/sandbox session directed by the team.

## What the AI did
* Wrote the project plan (phase files), all source code (`src/`), tests (`tests/`), benchmark scripts (`scripts/`), figures code, `report.md` generator,
  README and documentation.
* Ran the tests and the full benchmark inside the sandbox and analysed the results.

## How it was checked (by the AI, automatically)
* 84 automated tests, including negative tests, an attack suite, and a cross-check of the ML-KEM backend against a second implementation.
* A per-phase "recheck" loop (`docs/BUGLOG.md`) that found and fixed real bugs: an uncaught ML-KEM `ValueError` on malformed keys, an invalid peak-RSS
  measurement (inherited parent high-water mark), and a suite-vs-suite timing bias (fixed with paired interleaved timing).
* A script that re-derives every quoted report number independently from the CSVs (`scripts/spot_check_report.py`).

## What humans must still do (not yet done by the AI)
* [ ] Read and understand the code and the report; run `make test` and the notebook on your own machine.
* [ ] Re-run `make bench` on your own hardware if you want numbers that represent your environment (the committed results come from a shared 1-core virtual sandbox).
* [ ] Fill in the team name/members and final commit hash in `README.md`.
* [ ] Confirm that this disclosure matches the rules of the hackathon and edit it if your actual workflow differed.

The AI cannot attest that humans reviewed the work; this checklist is left unchecked deliberately.
