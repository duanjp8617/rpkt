#!/usr/bin/env python3
"""Summarize complete uninstrumented raw/checked-accessor NAT matrices."""
import json
import statistics
import sys
from pathlib import Path

MODES = ["rpkt", "rpkt-checked", "pnet", "smoltcp"]


def summarize(path):
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
    options = json.loads(Path(str(path) + ".environment.json").read_text())["options"]
    assert not options["perf"], "instrumented trials must not enter throughput medians"
    cases = [tuple([p, int(s), int(f)]) for p, s, f in
             (case.split(":") for case in options["cases"])]
    assert len(rows) == len(cases) * len(MODES) * options["repeats"]
    result = []
    for pattern, size, flows in cases:
        groups = {}
        for mode in MODES:
            selected = [r for r in rows if (r["pattern"], r["bytes"], r["flows"], r["mode"])
                        == (pattern, size, flows, mode)]
            assert len(selected) == options["repeats"]
            assert {r["repeat"] for r in selected} == set(range(options["repeats"]))
            rates = []
            for row in selected:
                assert "perf_report" not in row
                assert row["dut"]["mode"] == ("rpkt" if mode == "rpkt-checked" else mode)
                expected = options["baseline_binary"] if mode == "rpkt-checked" else options["dut_binary"]
                assert row["dut_binary"] == expected
                assert 4.9 <= row["gen"]["seconds"] <= 6
                for role in ["dut", "sink"]:
                    assert row[role]["bad_checksum"] == row[role]["bad_output"] == 0
                assert row["sink"]["output_samples"] > 0
                rates.append(row["sink"]["rx"] / row["gen"]["seconds"] / 1e6)
            groups[mode] = (statistics.median(rates), min(rates), max(rates))
        result.append((pattern, size, flows, groups))
    return result, rows


def main():
    for path in sys.argv[1:]:
        result, rows = summarize(path)
        print(f"\n{path}: {len(rows)} trials; returned Mpps median [min–max]\n")
        print("| Pattern | Bytes | Flows | Raw rpkt | Checked rpkt | libpnet | smoltcp | Raw/checked | Raw/pnet | Raw/smol |")
        print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for pattern, size, flows, groups in result:
            cells = [f"{m:.3f} [{lo:.3f}–{hi:.3f}]" for m, lo, hi in groups.values()]
            raw = groups["rpkt"][0]
            ratios = [f"{raw / groups[k][0]:.3f}x" for k in MODES[1:]]
            print("| " + " | ".join(map(str, [pattern, size, flows, *cells, *ratios])) + " |")
        for role in ["gen", "dut", "sink"]:
            totals = {k: sum(r[role][k] for r in rows) for k in [
                "tx", "rx", "rejected", "bad_checksum", "bad_output", "output_samples",
                "unsent", "rx_missed", "rx_no_mbuf", "tx_errors"]}
            print(role, json.dumps(totals, sort_keys=True))


if __name__ == "__main__":
    main()
