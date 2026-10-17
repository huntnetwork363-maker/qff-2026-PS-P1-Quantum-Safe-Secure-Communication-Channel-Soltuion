"""Write results/tables/sizes.csv: exact bytes on the wire per suite and message (from the real handshake)."""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.channel import Client, Server, make_identities, run_handshake  # noqa: E402
from src.problem import SUITE_SIG, SUITES  # noqa: E402

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results", "tables", "sizes.csv")


def main():
    ids = make_identities()
    rows = []
    for s in SUITES:
        r = run_handshake(Client(s, ids[SUITE_SIG[s]][0]), Server(ids))
        for label, d, n in r.counter.messages:
            rows.append({"suite": s, "signature": SUITE_SIG[s], "message": label, "direction": d, "bytes": n})
        rows.append({"suite": s, "signature": SUITE_SIG[s], "message": "TOTAL_c2s", "direction": "c2s", "bytes": r.counter.c2s})
        rows.append({"suite": s, "signature": SUITE_SIG[s], "message": "TOTAL_s2c", "direction": "s2c", "bytes": r.counter.s2c})
        total = r.counter.c2s + r.counter.s2c
        rows.append({"suite": s, "signature": SUITE_SIG[s], "message": "TOTAL", "direction": "both", "bytes": total})
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", newline="") as f:
        w = csv.DictWriter(f, lineterminator="\n", fieldnames=["suite", "signature", "message", "direction", "bytes"])
        w.writeheader()
        w.writerows(rows)
    print("wrote", OUT, len(rows), "rows")


if __name__ == "__main__":
    main()
