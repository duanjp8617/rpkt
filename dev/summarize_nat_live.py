#!/usr/bin/env python3
"""Summarize every live NAT case; never select the fastest one-second bin."""
import json
import statistics
import sys


def rate(row, role):
    if role == "gen":
        return row[role]["tx"] / row[role]["seconds"] / 1e6
    if role == "sink":
        # Common offered-trial denominator avoids summing RSS-worker bins
        # whose first-arrival origins differ. Includes all returned packets
        # after draining, and does not count sender/sink startup as traffic.
        return row[role]["rx"] / row["gen"]["seconds"] / 1e6
    interior = row[role]["rx_bins_1s"][1:-1]
    assert len(interior) >= 3, row
    return statistics.mean(interior) / 1e6


def main():
    with open(sys.argv[1]) as source:
        rows = [json.loads(line) for line in source]
    assert len(rows) == 90, len(rows)
    groups = sorted({(r["pattern"], r["bytes"], r["flows"]) for r in rows})
    print("| Pattern | Bytes | Flows | Returned rpkt Mpps | Returned pnet Mpps | Returned smoltcp Mpps | rpkt/pnet | rpkt/smoltcp | DUT rpkt steady Mpps |\n"
          "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for pattern, size, flows in groups:
        rates = {}
        for mode in ["rpkt", "pnet", "smoltcp"]:
            cases = [r for r in rows if (r["pattern"], r["bytes"], r["flows"], r["mode"]) == (pattern, size, flows, mode)]
            assert len(cases) == 3
            assert {r["repeat"] for r in cases} == {0, 1, 2}
            rates[mode] = {role: statistics.median(rate(r, role) for r in cases) for role in ["gen", "dut", "sink"]}
        rpkt = rates["rpkt"]["sink"]
        print(f"| {pattern} | {size} | {flows} | {rpkt:.3f} | {rates['pnet']['sink']:.3f} | {rates['smoltcp']['sink']:.3f} | "
              f"{rpkt / rates['pnet']['sink']:.3f}x | {rpkt / rates['smoltcp']['sink']:.3f}x | {rates['rpkt']['dut']:.3f} |")
    print("\nTotals across all 90 runs:")
    for role in ["gen", "dut", "sink"]:
        counters = {key: sum(r[role][key] for r in rows) for key in [
            "tx", "rx", "rejected", "bad_checksum", "checksum_fallback", "output_samples",
            "bad_output", "unsent", "partial_tx", "rx_missed", "rx_no_mbuf", "tx_errors"]}
        print(role, json.dumps(counters, sort_keys=True))
    for role in ["dut", "sink"]:
        assert all(r[role]["bad_checksum"] == r[role]["bad_output"] == 0 for r in rows)


if __name__ == "__main__":
    main()
