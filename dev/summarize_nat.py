#!/usr/bin/env python3
"""Collect NAT Criterion intervals and print all median-of-run comparisons.

Usage: summarize_nat.py OUTPUT.json HOST=artifact_dir [HOST=artifact_dir ...]
Keeps per-run confidence intervals; ratios of medians are NOT confidence bounds.
"""
import json
import pathlib
import statistics
import sys


def main():
    output = {"contract": "ns/packet; ratio = competitor time / rpkt time; median of four run point estimates", "hosts": {}}
    for argument in sys.argv[2:]:
        host, directory = argument.split("=", 1)
        root = pathlib.Path(directory)
        samples = []
        for path in sorted(root.glob("criterion/nat_*/**/nat-final-*/estimates.json")):
            baseline = path.parent.name
            _, policy, run = baseline.rsplit("-", 2)
            if policy not in ["siphash", "ahash"]:
                continue
            bench = json.loads((path.parent / "benchmark.json").read_text())
            group = bench["group_id"]
            _, protocol, size, flows = group.split("/")
            count = int(flows.removeprefix("flows"))
            estimate = json.loads(path.read_text())["mean"]
            samples.append(dict(policy=policy, run=int(run), protocol=protocol,
                                bytes=int(size), flows=count, library=bench["function_id"],
                                ns=estimate["point_estimate"] / count,
                                lower_ns=estimate["confidence_interval"]["lower_bound"] / count,
                                upper_ns=estimate["confidence_interval"]["upper_bound"] / count))
        assert len(samples) == 2 * 4 * 3 * 3 * 2 * 4, (host, len(samples))
        summaries = []
        for policy in ["siphash", "ahash"]:
            print(f"\n### {host}, {policy}\n\n| Workload | Bytes | Flows | rpkt ns | pnet/rpkt | smoltcp/rpkt | cursor/rpkt |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
            groups = sorted({(r["protocol"], r["bytes"], r["flows"]) for r in samples})
            for proto, size, count in groups:
                medians = {}
                for library in ["rpkt", "pnet", "smoltcp", "rpkt_cursor"]:
                    values = [r["ns"] for r in samples if (r["policy"], r["protocol"], r["bytes"], r["flows"], r["library"]) == (policy, proto, size, count, library)]
                    assert len(values) == 4
                    medians[library] = statistics.median(values)
                ratios = {library: value / medians["rpkt"] for library, value in medians.items()}
                summaries.append(dict(policy=policy, protocol=proto, bytes=size, flows=count, median_ns=medians, ratios=ratios))
                print(f"| {proto} | {size} | {count} | {medians['rpkt']:.2f} | {ratios['pnet']:.3f}x | {ratios['smoltcp']:.3f}x | {ratios['rpkt_cursor']:.3f}x |")
        output["hosts"][host] = dict(environment=(root / "environment.txt").read_text(), samples=samples, summaries=summaries)
    pathlib.Path(sys.argv[1]).write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
