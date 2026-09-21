#!/usr/bin/env python3
"""Sequential real TCP endpoints on the dedicated tg/duanjp link. No pause,
MTU, driver or host-network-service changes. Restore temporary DUT hugepages.
Requires frozen tcp-stack-{smoltcp,rpkt} binaries under bench-results-tcp/.
"""
import argparse
import json
import os
import shlex
import subprocess
import tempfile
import time
from tcp_report import validate_offloads


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True)
    p.add_argument("--dut", choices=["duanjp", "tg"], default="duanjp")
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--quick", action="store_true")
    p.add_argument("--profile", action="store_true", help="Separate, instrumented active-window cycle samples")
    p.add_argument("--offloads", action="store_true", help="Identical TSO/LRO/scatter on both endpoints")
    p.add_argument("--plain", action="store_true", help="Disable TCP timestamps identically")
    p.add_argument("--linearize-rpkt", action="store_true", help="Ablation: rpkt parser with the native extra copy")
    p.add_argument("--perf", default="perf", help="perf executable on the DUT")
    p.add_argument("--rx-data-room", type=int, choices=[2048, 8192], default=2048)
    p.add_argument("--binary-dir", default="bench-results-tcp")
    args = p.parse_args()
    assert 1 <= args.repeats <= 5
    assert args.offloads or args.rx_data_room == 2048
    if not args.binary_dir.replace("-", "").replace("_", "").isalnum():
        raise ValueError("binary-dir must be a single safe directory name")
    password = os.environ.pop("RPKT_DUT_SUDO_PASSWORD", None)
    bases = dict(duanjp="/home/duanjp/rpkt-ws", tg="/root/rpkt-ws")
    huge = "/sys/devices/system/node/node2/hugepages/hugepages-2048kB/nr_hugepages"
    sockets = tempfile.TemporaryDirectory(prefix="rpkt-tcp-ssh-")
    ssh_options = ["-oConnectTimeout=10", "-oServerAliveInterval=5",
                   "-oServerAliveCountMax=2", "-oControlMaster=auto",
                   "-oControlPersist=30", f"-oControlPath={sockets.name}/%C"]

    def ssh(host, command, root=False, data="", background=False):
        if root and host == "duanjp":
            command = ("sudo -S -p '' " if password else "sudo -n ") + command
            if password:
                data = password + "\n" + data
        process = subprocess.Popen(["ssh", *ssh_options, host, command],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        process.stdin.write(data)
        process.stdin.close()
        process.stdin = None
        if background:
            return process
        out, err = process.communicate(timeout=45)
        if process.returncode:
            raise RuntimeError(f"{host}: {err} {out}")
        return out

    old = ssh("duanjp", f"cat {huge}").strip()
    if old != "0":
        raise RuntimeError("node 2 has an existing hugepage reservation")
    if args.profile:
        ssh(args.dut, "command -v " + shlex.quote(args.perf))
    metadata = {"dut": args.dut, "options": vars(args), "hosts": {}}
    for host in bases:
        iface = "ens31f1np1" if host == "duanjp" else "enp23s0f0np0"
        metadata["hosts"][host] = ssh(host, f"cd {bases[host]} && date -u && uname -a && "
            f"{bases[host].rsplit('/', 1)[0]}/.cargo/bin/rustc -Vv && "
            'PKG_CONFIG_PATH="$(cat rpkt-dpdk/.dpdk_install)" pkg-config --modversion libdpdk && '
            "sha256sum Cargo.lock Cargo.toml tcp-eval/Cargo.toml tcp-eval/src/lib.rs rpkt-dpdk/examples/tcp_stack.rs "
            "rpkt-dpdk/src/tcp_device.rs vendor/smoltcp-rpkt/src/wire/tcp/rpkt_backend.rs "
            "rpkt-dpdk/src/pbuf.rs vendor/smoltcp-rpkt/src/phy/mod.rs "
            "vendor/smoltcp-rpkt/src/iface/interface/mod.rs vendor/smoltcp-rpkt/src/iface/interface/ipv4.rs "
            "vendor/smoltcp-rpkt/src/wire/tcp.rs vendor/smoltcp-rpkt/src/socket/tcp.rs "
            "rpkt/src/tcp/generated.rs vendor/smoltcp-rpkt/src/iface/interface/scatter.rs "
            f"{args.binary_dir}/tcp-stack-smoltcp {args.binary_dir}/tcp-stack-rpkt && ethtool -a {iface} && "
            f"cat /sys/class/net/{iface}/speed /sys/class/net/{iface}/mtu")
    with open(args.output + ".environment.json", "x") as f:
        json.dump(metadata, f, indent=2)
    processes = []
    try:
        ssh("duanjp", f"tee {huge}", root=True, data=("256\n" if args.offloads else "128\n"))
        cases = [("echo", 64, 1, True), ("echo", 64, 16, True),
                 ("echo", 512, 16, True), ("bulk", 64, 16, True),
                 ("bulk", 1400, 16, True), ("echo", 64, 16, False)]
        if args.quick:
            cases = [("echo", 64, 1, True), ("bulk", 1400, 4, True)]
        if args.profile:
            cases = [("echo", 64, 16, True), ("bulk", 1400, 16, True)]
        if args.offloads:
            cases = [("bulk", request, connections, True) for request in [4096, 16384, 65536] for connections in [1, 16]]
            cases += [("echo", 16384, 16, True), ("echo", 65536, 16, True)]
            if args.quick or args.profile:
                cases = [("bulk", 65536, 16, True), ("echo", 16384, 16, True)]
        if args.plain:
            cases = [(mode, request, connections, False) for mode, request, connections, _ in cases]
        with open(args.output, "x", buffering=1) as output:
            for repeat in range(args.repeats):
                for mode, request, connections, timestamps in cases:
                    for backend in (["smoltcp", "rpkt"] if repeat % 2 == 0 else ["rpkt", "smoltcp"]):
                        stamp = f"{os.getpid()}-{repeat}-{mode}-{request}-{connections}-{timestamps}-{backend}"
                        processes = []
                        logs = {}
                        for role, host, variant in [("server", args.dut, backend),
                            ("client", "tg" if args.dut == "duanjp" else "duanjp", "smoltcp")]:
                            core = 60 if host == "duanjp" else 4
                            memory = 512 if args.offloads else 256
                            eal = (f"--huge-unlink=always --socket-mem 0,0,{memory},0 -a 0000:b8:00.1"
                                   if host == "duanjp" else f"--no-huge -m {memory} -a 0000:17:00.0")
                            binary = f"{bases[host]}/{args.binary_dir}/tcp-stack-{variant}"
                            log = f"/tmp/tcp-{stamp}-{role}.log"
                            logs[role] = (host, log)
                            linearize = args.linearize_rpkt and variant == "rpkt"
                            command = (f"RPKT_TCP_RX_DATA_ROOM={args.rx_data_room} RPKT_TCP_FORCE_LINEARIZE={int(linearize)} RPKT_TCP_OFFLOADS={int(args.offloads)} timeout 30 {binary} {role} {core} 0 5 {connections} {request} {mode} "
                                       f"{'timestamps' if timestamps else 'plain'} -- -l {core} --no-shconf "
                                       f"--file-prefix tcp-{role} {eal} > {log} 2>&1")
                            process = ssh(host, "sh -c " + shlex.quote(command), root=True, background=True)
                            processes.append(process)
                            if role == "server" or args.profile:
                                deadline = time.monotonic() + 10
                                while True:
                                    content = ssh(host, f"test ! -f {log} || cat {log}")
                                    if "READY " in content:
                                        break
                                    if process.poll() is not None or time.monotonic() > deadline:
                                        raise RuntimeError(content)
                                    time.sleep(.2)
                        if args.profile:
                            # Both connections are live; avoid initialization, warmup and drain.
                            time.sleep(2.2)
                            host, log = logs["server"]
                            core = 60 if host == "duanjp" else 4
                            processes.append(ssh(host, f"{shlex.quote(args.perf)} record -q -F 997 -e cycles:u -C {core} "
                                f"-o {log}.perf -- sleep 3", root=True, background=True))
                        for process in processes:
                            out, err = process.communicate(timeout=40)
                            if process.returncode:
                                raise RuntimeError(f"TCP process failed: {out} {err}; logs={logs}")
                        result = dict(repeat=repeat, dut=args.dut, mode=mode, backend=backend, offloads=args.offloads, linearize_rpkt=args.linearize_rpkt, rx_data_room=args.rx_data_room,
                                      request=request, connections=connections, timestamps=timestamps, logs=logs)
                        for role, (host, log) in logs.items():
                            content = ssh(host, f"cat {log}")
                            records = [json.loads(s) for s in content.splitlines() if s.startswith("{")]
                            assert len(records) == 1, content
                            result[role] = records[0]
                            assert records[0]["measured"] and records[0]["errors"] == 0, result
                            assert records[0]["backend"] == (backend if role == "server" else "smoltcp"), "Binary/backend mismatch"
                            assert records[0].get("rx_data_room", 2048) == args.rx_data_room, "Wrong RX buffer configuration"
                        validate_offloads(result)
                        output.write(json.dumps(result) + "\n")
                        if args.profile:
                            host, log = logs["server"]
                            report = ssh(host, f"{shlex.quote(args.perf)} report --stdio --no-children --sort symbol -i {log}.perf", root=True)
                            with open(f"{args.output}.{stamp}.perf.txt", "x") as f:
                                f.write(report)
                        print(stamp, "responses", result["client"]["responses"], "server_bytes", result["server"]["bytes"], flush=True)
    finally:
        try:
            for process in processes:
                if process.poll() is None:
                    process.communicate(timeout=40)
        finally:
            ssh("duanjp", f"tee {huge}", root=True, data=old + "\n")
            assert ssh("duanjp", f"cat {huge}").strip() == old
            print("Original hugepage reservation restored; pause settings were not changed", flush=True)


if __name__ == "__main__":
    main()
