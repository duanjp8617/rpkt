#!/usr/bin/env python3
"""Bounded, sequential three-process NAT tests on the documented two-host lab.

Requires already-built identical nat_loop binaries; never changes drivers,
addresses or MTUs. RPKT_DUT_SUDO_PASSWORD is optional (otherwise sudo -n).
Temporary node-2 hugepages are restored even when a run fails. Run only on
idle, dedicated test links. Results are JSONL; raw process logs stay on hosts.
"""
import argparse
import json
import os
import shlex
import subprocess
import tempfile
import time


def environment():
    """Read-only provenance; never includes credentials or process arguments."""
    result = {}
    for host, base, interfaces in [
        ("tg", "/root/rpkt-ws", ["enp23s0f0np0", "enp37s0f1np1"]),
        ("duanjp", "/home/duanjp/rpkt-ws", ["ens31f0np0", "ens31f1np1"]),
    ]:
        command = (f"cd {base} && date -u && uname -a && "
                   'PKG_CONFIG_PATH="$(cat rpkt-dpdk/.dpdk_install)" pkg-config --modversion libdpdk '
                   "&& sha256sum Cargo.lock Cargo.toml rpkt-dpdk/examples/nat_loop.rs "
                   "benches/nat_support/mod.rs target/performance/examples/nat_loop")
        for interface in interfaces:
            command += f" && ethtool -a {interface} && cat /sys/class/net/{interface}/speed /sys/class/net/{interface}/mtu"
        result[host] = subprocess.check_output(["ssh", "-oConnectTimeout=10", host, command],
                                              text=True, timeout=30)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--pilot", action="store_true")
    args = parser.parse_args()
    assert 1 <= args.repeats <= 5
    password = os.environ.pop("RPKT_DUT_SUDO_PASSWORD", None)
    huge = "/sys/devices/system/node/node2/hugepages/hugepages-2048kB/nr_hugepages"
    sockets = tempfile.TemporaryDirectory(prefix="rpkt-nat-ssh-")
    ssh_options = ["-oConnectTimeout=10", "-oServerAliveInterval=5",
                   "-oServerAliveCountMax=2", "-oControlMaster=auto",
                   "-oControlPersist=30", f"-oControlPath={sockets.name}/%C"]

    def ssh(host, command, root=False, data="", background=False):
        if root:
            command = ("sudo -S -p '' " if password else "sudo -n ") + command
            if password:
                data = password + "\n" + data
        proc = subprocess.Popen(["ssh", *ssh_options, host, command], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        proc.stdin.write(data)
        proc.stdin.close()
        proc.stdin = None
        if background:
            return proc
        stdout, stderr = proc.communicate(timeout=45)
        if proc.returncode:
            raise RuntimeError(f"{host}: {stderr.strip()}")
        return stdout

    old = ssh("duanjp", f"cat {huge}").strip()
    # Do not reduce somebody else's reservation or appropriate a used pool.
    if old != "0":
        raise RuntimeError("node 2 already reserves hugepages; use an idle lab")
    with open(args.output + ".environment.json", "x") as metadata:
        json.dump(dict(hosts=environment(), initial_node2_hugepages=old), metadata, indent=2)
    processes = []
    try:
        ssh("duanjp", f"tee {huge}", root=True, data="128\n")
        assert ssh("duanjp", f"cat {huge}").strip() == "128"
        cases = [(p, s, f) for p in ["udp", "tcp"]
                 for s, f in [(64, 64), (64, 4096), (512, 4096), (1500, 4096)]]
        cases += [("mixed", 64, 4096), ("tcpopts", 128, 4096)]
        if args.pilot:
            cases = [("udp", 64, 64), ("tcp", 64, 64)]
        with open(args.output, "x", buffering=1) as output:
            for repeat in range(args.repeats):
                modes = ["rpkt", "pnet", "smoltcp"]
                modes = modes[repeat % 3:] + modes[:repeat % 3]
                for pattern, size, flows in cases:
                    for mode in modes:
                        stamp = f"{os.getpid()}-{repeat}-{pattern}-{size}-{flows}-{mode}"
                        logs = {}
                        processes = []
                        for role, host, core, rx, tx, seconds, eal in [
                            (mode, "duanjp", 60, 1, 0, 30,
                             "--huge-unlink=always --socket-mem 0,0,256,0 -a 0000:b8:00.0,rx_vec_en=0 -a 0000:b8:00.1,rx_vec_en=0"),
                            ("sink", "tg", 4, 0, 0, 30,
                             "--no-huge -m 256 -a 0000:25:00.1"),
                            ("gen", "tg", 2, 0, 0, 5,
                             "--no-huge -m 256 -a 0000:17:00.0"),
                        ]:
                            base = "/home/duanjp/rpkt-ws" if host == "duanjp" else "/root/rpkt-ws"
                            log = f"/tmp/nat-{stamp}-{role}.log"
                            logs[role] = (host, log)
                            cores = str(core) if host == "duanjp" else f"{core}-{core + 1}"
                            command = (f"env RPKT_TRAFFIC_WORKERS=2 timeout 40 {base}/target/performance/examples/nat_loop "
                                       f"{role} {core} {rx} {tx} {seconds} {size} {flows} {pattern} "
                                       f"-- -l {cores} --no-shconf --file-prefix nat-{role} {eal}")
                            # Wrap redirection inside the sudo shell, not around password input.
                            command = "sh -c " + shlex.quote(command + f" > {log} 2>&1")
                            proc = ssh(host, command, root=host == "duanjp", background=True)
                            processes.append(proc)
                            if role != "gen":
                                deadline = time.monotonic() + 8
                                while True:
                                    content = ssh(host, f"test ! -f {log} || cat {log}")
                                    if "READY " in content:
                                        break
                                    if proc.poll() is not None or time.monotonic() > deadline:
                                        raise RuntimeError(f"{role} failed to start: {content}")
                                    time.sleep(0.2)
                        for proc in processes:
                            stdout, stderr = proc.communicate(timeout=45)
                            if proc.returncode:
                                raise RuntimeError(f"test process failed: {stdout} {stderr}")
                        record = dict(repeat=repeat, pattern=pattern, bytes=size, flows=flows, mode=mode)
                        for role, (host, log) in logs.items():
                            content = ssh(host, f"cat {log}")
                            workers = [json.loads(line) for line in content.splitlines() if line.startswith("{")]
                            assert len(workers) == (1 if role == mode else 2), content
                            name = "dut" if role == mode else role
                            combined = dict(workers[0])
                            for counter in ["tx", "rx", "rejected", "bad_checksum", "checksum_fallback",
                                            "output_samples", "bad_output", "unsent", "partial_tx",
                                            "rx_missed", "rx_no_mbuf", "tx_errors"]:
                                combined[counter] = sum(w[counter] for w in workers)
                            for duration in ["seconds", "active_seconds"]:
                                combined[duration] = max(w[duration] for w in workers)
                            combined["rx_bins_1s"] = [sum(w["rx_bins_1s"][i] if i < len(w["rx_bins_1s"]) else 0 for w in workers)
                                                      for i in range(max(len(w["rx_bins_1s"]) for w in workers))]
                            record[name] = combined
                            record[name + "_workers"] = workers
                        record["logs"] = logs
                        output.write(json.dumps(record) + "\n")
                        print(f"{stamp}: dut={record['dut']['rx']} sink={record['sink']['rx']} "
                              f"sink_drops={record['sink']['rx_missed']}", flush=True)
                        for role in ["dut", "sink"]:
                            assert record[role]["bad_checksum"] == 0, record
                            assert record[role]["bad_output"] == 0, record
                        assert record["sink"]["output_samples"] > 0, record
                        assert all(w["rx"] > 0 for w in record["sink_workers"]), "RSS failed to distribute traffic"
                        assert 4.9 <= record["dut"]["active_seconds"] <= 6, record
    finally:
        # Remote commands have timeout bounds; let them finish before releasing memory.
        for proc in processes:
            if proc.poll() is None:
                proc.communicate(timeout=45)
        ssh("duanjp", f"tee {huge}", root=True, data=old + "\n")
        assert ssh("duanjp", f"cat {huge}").strip() == old
        for host in ["tg", "duanjp"]:
            subprocess.run(["ssh", *ssh_options, "-O", "exit", host],
                           capture_output=True, timeout=15, check=False)
        sockets.cleanup()


if __name__ == "__main__":
    main()
