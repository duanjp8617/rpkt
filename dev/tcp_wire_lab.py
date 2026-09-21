#!/usr/bin/env python3
"""Pinned, alternating wire-only measurements. Run after all live TCP tests."""
import argparse
import json
import itertools
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, choices=["tg", "duanjp"])
    parser.add_argument("--output", required=True)
    parser.add_argument("--inline-control", action="store_true", help="Six permutations of native, force-inlined native, rpkt")
    args = parser.parse_args()
    base, core = ("/root/rpkt-ws", 4) if args.host == "tg" else ("/home/duanjp/rpkt-ws", 60)
    with tempfile.TemporaryDirectory(prefix="rpkt-wire-ssh-") as sockets:
        options = ["-oConnectTimeout=10", "-oControlMaster=auto", "-oControlPersist=30",
                   f"-oControlPath={sockets}/%C"]

        def ssh(command):
            return subprocess.check_output(["ssh", *options, args.host, command], text=True, timeout=60)

        if ssh("pgrep -f '[t]cp-stack-(smoltcp|rpkt)' || true").strip():
            raise RuntimeError("Live TCP processes are running; do not overlap measurements")
        variants = ["smoltcp", "smoltcp-inline", "rpkt"] if args.inline_control else ["smoltcp", "rpkt"]
        prefix = "tcp-wire-control" if args.inline_control else "tcp-wire"
        binaries = " ".join(f"bench-results-tcp/{prefix}-{variant}" for variant in variants)
        environment = ssh(f"cd {base} && date -u && sha256sum {binaries} "
                          "tcp-eval/src/bin/tcp_wire.rs tcp-eval/Cargo.toml vendor/smoltcp-rpkt/Cargo.toml "
                          "vendor/smoltcp-rpkt/src/wire/tcp.rs vendor/smoltcp-rpkt/src/wire/tcp/rpkt_backend.rs")
        with open(args.output + ".environment.json", "x") as f:
            json.dump(dict(host=args.host, core=core, inline_control=args.inline_control, environment=environment), f, indent=2)
        for backend in variants:
            ssh(f"taskset -c {core} {base}/bench-results-tcp/{prefix}-{backend}")  # warmup
        with open(args.output, "x") as f:
            orders = list(itertools.permutations(variants)) if args.inline_control else [
                variants if repeat % 2 == 0 else list(reversed(variants)) for repeat in range(5)]
            for repeat, order in enumerate(orders):
                for backend in order:
                    rows = ssh(f"taskset -c {core} {base}/bench-results-tcp/{prefix}-{backend}").splitlines()
                    assert len(rows) == 8
                    for line in rows:
                        row = json.loads(line)
                        assert row["backend"] == ("rpkt" if backend == "rpkt" else "smoltcp") and row["ns"] > 0
                        row.update(host=args.host, core=core, repeat=repeat, configuration=backend)
                        f.write(json.dumps(row) + "\n")
                    print(args.host, repeat, backend, flush=True)


if __name__ == "__main__":
    main()
