#!/usr/bin/env python3
"""Summarize uninstrumented TCP JSONL: medians and ranges, never best runs."""
import argparse
import collections
import json
import statistics


def validate_offloads(row):
    if not row.get("offloads", False):
        return
    server, client = row["server"], row["client"]
    assert server["offloads"] and client["offloads"]
    assert server.get("rx_data_room", 2048) == client.get("rx_data_room", 2048) == row.get("rx_data_room", 2048)
    assert server["chains"] > 0 and server["lro"] > 0 and server["max_rx_len"] > 1514, "No real LRO chains"
    assert client["tso"] > 0, "No real TSO submissions"
    direct = row["backend"] == "rpkt" and not row.get("linearize_rpkt", False)
    assert (server["linearized_bytes"] == 0) == direct, "Wrong RX copy path"
    if row["mode"] == "echo":
        assert server["tso"] > 0 and client["lro"] > 0 and client["chains"] > 0


def rate(row):
    validate_offloads(row)
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
    fingerprints = {}
    for name in args.files:
        with open(name + ".environment.json") as f:
            environment = json.load(f)
            assert not environment["options"].get("profile", False), "Do not pool profiles with throughput"
        build = environment["options"].get("binary_dir", "bench-results-tcp")
        fingerprint = tuple(sorted((host, line) for host, value in environment["hosts"].items()
                                   for line in value.splitlines() if "/tcp-stack-" in line))
        assert fingerprint, "Missing frozen binary hashes"
        assert build not in fingerprints or fingerprints[build] == fingerprint, "Same artifact directory contains different binaries"
        fingerprints[build] = fingerprint
        with open(name) as f:
            for line in f:
                row = json.loads(line)
                key = (build, row.get("rx_data_room", 2048), row["dut"], row["mode"], row["request"], row["connections"], row["timestamps"], row.get("offloads", False), row.get("linearize_rpkt", False))
                groups[key][row["backend"]].append(rate(row))
    print("| Build | RX room | DUT | Mode/write/connections/TS | Offload/copy-control | Unit | smoltcp median [range] | rpkt median [range] | rpkt / smoltcp | n |")
    print("| --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: |")
    for (build, rx_room, dut, mode, size, connections, ts, offloads, linearize), backends in sorted(groups.items()):
        a, b = backends["smoltcp"], backends["rpkt"]
        assert len(a) == len(b) and a and min(a + b) > 0, "Incomplete or stalled matrix"
        def cell(values):
            return f"{statistics.median(values):.3f} [{min(values):.3f}–{max(values):.3f}]"
        ratio = statistics.median(b) / statistics.median(a)
        unit = "M responses/s" if mode == "echo" else "Gbit/s"
        print(f"| {build} | {rx_room} | {dut} | {mode}/{size}/{connections}/{int(ts)} | {int(offloads)}/{int(linearize)} | {unit} | {cell(a)} | {cell(b)} | {ratio:.3f}x | {len(a)} |")


if __name__ == "__main__":
    main()
