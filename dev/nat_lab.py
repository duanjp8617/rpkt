#!/usr/bin/env python3
"""Bounded, sequential three-process NAT tests on the documented two-host lab.

Requires already-built identical nat_loop binaries; never changes drivers,
addresses or MTUs. RPKT_DUT_SUDO_PASSWORD is optional (otherwise sudo -n).
Temporary node-2 hugepages are restored even when a run fails. Run only on
idle, dedicated test links. Results are JSONL; raw process logs stay on hosts.
With --disable-pause, the four test ports' original pause settings are also
restored and verified. This option requires the link owner's approval.
"""
import argparse
import json
import os
import shlex
import subprocess
import tempfile
import time

PORTS = [("duanjp", "ens31f0np0"), ("duanjp", "ens31f1np1"),
         ("tg", "enp23s0f0np0"), ("tg", "enp37s0f1np1")]


def pause_state(output):
    fields = dict(line.lower().split(":", 1) for line in output.splitlines() if ":" in line)
    state = {key: fields[name].strip() for key, name in
             [("autoneg", "autonegotiate"), ("rx", "rx"), ("tx", "tx")]}
    assert all(value in ["on", "off"] for value in state.values()), state
    return state


def pause_command(interface, state):
    return f"ethtool -A {interface} " + " ".join(f"{key} {state[key]}" for key in ["autoneg", "rx", "tx"])


def environment(dut_binary):
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
        if host == "duanjp":
            command += f" && sha256sum {shlex.quote(dut_binary)}"
        for interface in interfaces:
            command += f" && ethtool -a {interface} && cat /sys/class/net/{interface}/speed /sys/class/net/{interface}/mtu"
        result[host] = subprocess.check_output(["ssh", "-oConnectTimeout=10", host, command],
                                              text=True, timeout=30)
    return result


def restore_pause(ssh, originals):
    """Try every saved port even if one restore/readback fails."""
    errors = []
    for host, interface, original in reversed(originals):
        try:
            ssh(host, pause_command(interface, original), root=host == "duanjp")
            if pause_state(ssh(host, f"ethtool -a {interface}")) != original:
                raise RuntimeError("pause readback differs from original")
        except Exception as error:
            errors.append(f"RESTORE FAILED {host}/{interface}: {error}")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--pilot", action="store_true")
    parser.add_argument("--modes", nargs="+", choices=["rpkt", "cursor", "pnet", "smoltcp", "io"],
                        default=["rpkt", "pnet", "smoltcp"])
    parser.add_argument("--dut-binary", default="/home/duanjp/rpkt-ws/target/performance/examples/nat_loop")
    parser.add_argument("--perf", action="store_true", help="Record DUT counters and active-window cycle samples")
    parser.add_argument("--vector-rx", action="store_true", help="Use mlx5 vector RX for every DUT (burst remains 64)")
    parser.add_argument("--sink-workers", type=int, choices=[2, 4], default=2)
    parser.add_argument("--gen-workers", type=int, choices=[2, 4], default=2)
    parser.add_argument("--disable-pause", action="store_true",
                        help="Temporarily disable pause on all four dedicated ports, then verify restoration")
    parser.add_argument("--dut-queues", type=int, choices=[1, 2, 4], default=1,
                        help="Hardware queues serviced by the one DUT thread")
    args = parser.parse_args()
    assert 1 <= args.repeats <= 5
    assert len(args.modes) == len(set(args.modes)), "duplicate DUT modes"
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
        json.dump(dict(hosts=environment(args.dut_binary), initial_node2_hugepages=old,
                       options=vars(args)), metadata, indent=2)
    processes = []
    pause_restore = []
    try:
        if args.disable_pause:
            # Record each original state before modifying it; even a partially
            # successful ethtool operation must be rolled back on failure.
            for host, interface in PORTS:
                original = pause_state(ssh(host, f"ethtool -a {interface}"))
                pause_restore.append((host, interface, original))
                disabled = dict(autoneg="off", rx="off", tx="off")
                ssh(host, pause_command(interface, disabled), root=host == "duanjp")
                assert pause_state(ssh(host, f"ethtool -a {interface}")) == disabled
            print("Pause disabled and verified on all four test ports", flush=True)
        ssh("duanjp", f"tee {huge}", root=True, data="128\n")
        assert ssh("duanjp", f"cat {huge}").strip() == "128"
        cases = [(p, s, f) for p in ["udp", "tcp"]
                 for s, f in [(64, 64), (64, 4096), (512, 4096), (1500, 4096)]]
        cases += [("mixed", 64, 4096), ("tcpopts", 128, 4096)]
        if args.pilot:
            cases = [("udp", 64, 64), ("tcp", 64, 64)]
        with open(args.output, "x", buffering=1) as output:
            for repeat in range(args.repeats):
                modes = args.modes
                modes = modes[repeat % len(modes):] + modes[:repeat % len(modes)]
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
                            ("gen", "tg", 0 if args.gen_workers == 4 else 2, 0, 0, 5,
                             "--no-huge -m 256 -a 0000:17:00.0"),
                        ]:
                            if host == "duanjp" and args.vector_rx:
                                eal = eal.replace(",rx_vec_en=0", "")
                            base = "/home/duanjp/rpkt-ws" if host == "duanjp" else "/root/rpkt-ws"
                            log = f"/tmp/nat-{stamp}-{role}.log"
                            logs[role] = (host, log)
                            workers_count = args.sink_workers if role == "sink" else (1 if host == "duanjp" else args.gen_workers)
                            cores = str(core) if workers_count == 1 else f"{core}-{core + workers_count - 1}"
                            binary = args.dut_binary if host == "duanjp" else f"{base}/target/performance/examples/nat_loop"
                            command = (f"env RPKT_TRAFFIC_WORKERS={workers_count} timeout 40 {shlex.quote(binary)} "
                                       f"{role} {core} {rx} {tx} {seconds} {size} {flows} {pattern} "
                                       f"-- -l {cores} --no-shconf --file-prefix nat-{role} {eal}")
                            if mode == "io":
                                command = "env RPKT_NAT_IO_ONLY=1 " + command
                            if host == "duanjp":
                                command = f"env RPKT_DUT_QUEUES={args.dut_queues} " + command
                            if host == "duanjp" and args.perf:
                                command = (f"perf stat -x, -e cycles,instructions,branches,branch-misses "
                                           f"-o /tmp/nat-{stamp}.stat -- perf record -q -F 999 --clockid mono "
                                           f"-o /tmp/nat-{stamp}.data -- " + command)
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
                            if role == mode:
                                queue_rx = [json.loads(line[len("QUEUE_RX "):]) for line in content.splitlines()
                                            if line.startswith("QUEUE_RX ")]
                                record["dut_queue_rx"] = queue_rx[0] if queue_rx else None
                            if role == mode and args.perf:
                                window = [line.split()[1:] for line in content.splitlines()
                                          if line.startswith("PROFILE_WINDOW ")]
                                record["profile_window"] = window[0] if window else None
                            workers = [json.loads(line) for line in content.splitlines() if line.startswith("{")]
                            assert len(workers) == (1 if role == mode else (args.sink_workers if role == "sink" else args.gen_workers)), content
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
                            record[name + "_reject_samples"] = [
                                line for line in content.splitlines() if line.startswith("REJECT ")]
                        record["logs"] = logs
                        record["dut_binary"] = args.dut_binary
                        record["vector_rx"] = args.vector_rx
                        record["pause_disabled"] = args.disable_pause
                        record["dut_queues"] = args.dut_queues
                        if args.perf:
                            record["perf_stat"] = ssh("duanjp", f"cat /tmp/nat-{stamp}.stat", root=True)
                            window = record["profile_window"]
                            time_filter = "" if window is None else f" --time {float(window[0]) + 0.25:.9f},{float(window[1]) - 0.25:.9f}"
                            record["perf_report"] = ssh("duanjp", f"perf report --stdio --no-children --percent-limit 0.5{time_filter} -i /tmp/nat-{stamp}.data", root=True)
                        output.write(json.dumps(record) + "\n")
                        print(f"{stamp}: dut={record['dut']['rx']} sink={record['sink']['rx']} "
                              f"sink_drops={record['sink']['rx_missed']}", flush=True)
                        for role in ["dut", "sink"]:
                            assert record[role]["bad_checksum"] == 0, record
                            assert record[role]["bad_output"] == 0, record
                        assert record["sink"]["output_samples"] > 0, record
                        assert all(w["rx"] > 0 for w in record["sink_workers"]), "RSS failed to distribute traffic"
                        if record["dut_queue_rx"] is not None:
                            assert len(record["dut_queue_rx"]) == args.dut_queues
                            assert all(n > 0 for n in record["dut_queue_rx"]), "DUT RSS failed to distribute traffic"
                        assert 4.9 <= record["dut"]["active_seconds"] <= 6, record
    finally:
        # Remote commands have timeout bounds; let them finish before releasing memory.
        cleanup_errors = []
        for proc in processes:
            if proc.poll() is None:
                try:
                    proc.communicate(timeout=45)
                except Exception as error:
                    cleanup_errors.append(str(error))
        cleanup_errors.extend(restore_pause(ssh, pause_restore))
        try:
            ssh("duanjp", f"tee {huge}", root=True, data=old + "\n")
            assert ssh("duanjp", f"cat {huge}").strip() == old
        except Exception as error:
            cleanup_errors.append(f"HUGEPAGE RESTORE FAILED: {error}")
        for host in ["tg", "duanjp"]:
            subprocess.run(["ssh", *ssh_options, "-O", "exit", host],
                           capture_output=True, timeout=15, check=False)
        sockets.cleanup()
        if cleanup_errors:
            raise RuntimeError("; ".join(cleanup_errors))
        if pause_restore:
            print("Original pause settings restored and verified on all four ports", flush=True)


if __name__ == "__main__":
    main()
