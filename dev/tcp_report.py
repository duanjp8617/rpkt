#!/usr/bin/env python3
"""Summarize uninstrumented TCP JSONL: medians and ranges, never best runs."""
import argparse
import collections
import json
import statistics


def rate(row):
    endpoint = row["client"] if row["mode"] == "echo" else row["server"]
    ns = endpoint["measured_ns"]
    assert endpoint["measured"] and ns > 0 and endpoint["errors"] == 0
    if row["mode"] == "echo":
        return endpoint["responses"] * 1000 / ns  # million responses/s
    return endpoint["bytes"] * 8 / ns  # application Gbit/s


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()
    groups = collections.defaultdict(lambda: collections.defaultdict(list))
    for name in args.files:
        with open(name + ".environment.json") as f:
            assert not json.load(f)["options"].get("profile", False), "Do not pool profiles with throughput"
        with open(name) as f:
            for line in f:
                row = json.loads(line)
                key = (row["dut"], row["mode"], row["request"], row["connections"], row["timestamps"])
                groups[key][row["backend"]].append(rate(row))
    print("| DUT | Mode/write/connections/TS | Unit | smoltcp median [range] | rpkt median [range] | rpkt / smoltcp | n |")
    print("| --- | --- | --- | ---: | ---: | ---: | ---: |")
    for (dut, mode, size, connections, ts), backends in sorted(groups.items()):
        a, b = backends["smoltcp"], backends["rpkt"]
        assert len(a) == len(b) and a and min(a + b) > 0, "Incomplete or stalled matrix"
        def cell(values):
            return f"{statistics.median(values):.3f} [{min(values):.3f}–{max(values):.3f}]"
        ratio = statistics.median(b) / statistics.median(a)
        unit = "M responses/s" if mode == "echo" else "Gbit/s"
        print(f"| {dut} | {mode}/{size}/{connections}/{int(ts)} | {unit} | {cell(a)} | {cell(b)} | {ratio:.3f}x | {len(a)} |")


if __name__ == "__main__":
    main()
