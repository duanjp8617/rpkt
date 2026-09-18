#!/usr/bin/env python3
"""Summarize every live NAT case; never select the fastest one-second bin."""
import json
import statistics
import sys


def rate(row, role):
    if role == "gen":
        return row[role]["tx"] / row[role]["seconds"] / 1e6
    interior = row[role]["rx_bins_1s"][1:-1]
    assert len(interior) >= 3, row
    return statistics.mean(interior) / 1e6


def main():
    with open(sys.argv[1]) as source:
        rows = [json.loads(line) for line in source]
    assert len(rows) == 90, len(rows)
    groups = sorted({(r["pattern"], r["bytes"], r["flows"]) for r in rows})
    print("| Pattern | Bytes | Flows | DUT rpkt Mpps | DUT pnet Mpps | DUT smoltcp Mpps | rpkt/pnet | rpkt/smoltcp | Returned rpkt Mpps |\n"
          "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for pattern, size, flows in groups:
        rates = {}
        for mode in ["rpkt", "pnet", "smoltcp"]:
            cases = [r for r in rows if (r["pattern"], r["bytes"], r["flows"], r["mode"]) == (pattern, size, flows, mode)]
            assert len(cases) == 3
            rates[mode] = {role: statistics.median(rate(r, role) for r in cases) for role in ["gen", "dut", "sink"]}
        rpkt = rates["rpkt"]["dut"]
        print(f"| {pattern} | {size} | {flows} | {rpkt:.3f} | {rates['pnet']['dut']:.3f} | {rates['smoltcp']['dut']:.3f} | "
              f"{rpkt / rates['pnet']['dut']:.3f}x | {rpkt / rates['smoltcp']['dut']:.3f}x | {rates['rpkt']['sink']:.3f} |")
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
