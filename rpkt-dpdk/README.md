# DPDK setup and examples

Build support is limited to 64-bit Linux with DPDK 21.11, 22.11, 23.11 or 24.11.
CI compiles against Ubuntu 22.04's packaged DPDK; the remote development hosts
also build against 24.11.7. Runtime compatibility depends on the selected PMD,
NIC firmware and kernel drivers.

## Build

From the repository root:

```sh
sudo sh dev/install_deps_ubuntu.sh
sudo apt-get install libdpdk-dev
pkg-config --modversion --cflags --libs libdpdk
cargo test -p rpkt-dpdk --tests --no-run
cargo check -p rpkt-dpdk --examples --all-features
```

The dependency script includes the C toolchain, Meson/Ninja/pyelftools for source
builds, Clang/libclang for bindgen, NUMA/RDMA/ELF support, and the optional static
link dependencies formerly listed only in the root README. Which optional
libraries are needed depends on how DPDK was built. It does not install DPDK or
change NIC/hugepage settings. For source installs, set `PKG_CONFIG_PATH` to the
directory containing `libdpdk.pc`; the build script remembers an explicit value
in ignored `.dpdk_install`. An exported value takes precedence. Delete that
single file to forget a previous installation.

Use `LIBCLANG_PATH` for the directory containing libclang.so. If bindgen reports
missing `stddef.h`, install matching Clang resource headers and set, for example,
`BINDGEN_EXTRA_CLANG_ARGS="-resource-dir $(clang -print-resource-dir)"`.
CI pins Clang/libclang 14 together on Ubuntu 22.04. A Python libclang wheel may
supply the library without builtin headers; supply the matching resource
directory separately. Set `PKG_CONFIG` to override the executable; compiler and
linker flags are parsed with shell quoting, including paths with spaces.

See [DPDK build requirements](https://doc.dpdk.org/guides-24.11/linux_gsg/sys_reqs.html).
For hosts with restricted downloads, use an accessible mirror or transfer the
source archive from your local machine.

## Tests and privileges

Core tests need neither DPDK nor root. DPDK compilation needs headers/libraries,
but does not need a device. Native runtime tests initialize EAL, allocate
hugepage-backed pools and bind CPU cores. Provision hugepages on the tested NUMA
nodes and verify the CPU IDs used in the fixtures are available.

```sh
DPDK_TEST_RUNNER='sudo -E' bash rpkt-dpdk/tests/run_tests.sh
```

The script runs initialization tests in separate processes and starts/stops the
primary process required by secondary-process tests. Set `RUST_TEST_THREADS=1`
when running a selected test binary manually. Do not put a sudo runner in global
Cargo configuration. Use distinct EAL file prefixes for simultaneous unrelated
applications. Root (or equivalent device/hugepage permissions and capabilities)
is needed only at runtime. Run tests on an otherwise idle test host.

For non-native buffer interpretation see `../fuzz/README.md`; Miri uses Rust
allocations and does not call native DPDK during the selected tests.

## Device configuration

Keep mlx5 devices bound to their kernel driver; the bifurcated PMD uses RDMA
libraries and the network interface. Verify link state, NUMA node and MTU on
both ends. See the [mlx5 guide](https://doc.dpdk.org/guides-24.11/nics/mlx5.html).
Other PMDs may require VFIO/IOMMU setup; consult their release-specific guide.
Record firmware, driver and DPDK versions when diagnosing Intel E810 or other
hardware. Avoid applying old firmware/driver recipes without checking the
installed versions.

## Examples

All Rust files directly under `examples/` compile in CI. Their constants select
ports, socket, worker cores and MAC/IP addresses; adjust these to the dedicated
test links before execution. Thread placement must match the chosen NIC/pool
NUMA node. Stop examples with Ctrl-C and allow their cleanup to finish.

- `dump_device_info`: report device limits and capabilities.
- `mempool_primary`, `mbuf_test`: primary-process and pool/cache demonstrations.
- `loopback_tx`, `loopback_rx`: generate and return traffic on the same link.
- `relay_tx`, `relay_rx`: request/reply traffic.
- `rss_rx`: count flows distributed across RX queues.
- `traffic_fwd`: smoltcp forwarding edits.
- `two_port`: bounded, single-worker two-link generator/forwarder with JSON
  throughput, loss, partial-TX and sampled RTT counters; see below.
- `checksum_offload_tx`, `checksum_offload_rx`: compare software and NIC checksum
  results. TX mode 0/1 is UDP software/offload, 2/3 is TCP software/offload;
  4/5 deliberately append bytes beyond the UDP length. Such layouts may have
  device-specific checksum behavior and are not valid offload baselines.
- `jumboframe_tx`, `jumboframe_rx`: 8000-byte Ethernet frames in chained mbufs.
  TX modes 0/1 select UDP software/offload; 2/3 select TCP software/offload.
- `lro_rx`, `tso_tx`: device-specific receive coalescing/segmentation.

### Jumbo frames

Multisegment buffers are always available; no `multiseg` Cargo feature is needed.
Set the MTU to 9000 on both dedicated mlx5 interfaces, and any switch ports in
between (substitute the actual interface):

```sh
sudo ip link set dev TEST_INTERFACE mtu 9000
cargo build -p rpkt-dpdk --example jumboframe_rx --example jumboframe_tx
# Start RX on the peer, then TX on the generator:
sudo -E target/debug/examples/jumboframe_rx
sudo -E target/debug/examples/jumboframe_tx 0
```

The examples configure DPDK MTU 9000, RX scatter and TX multisegment capabilities,
and use 2048-byte data rooms. Check the printed segment lengths sum to 8000,
software checksums validate, and device errors/drop counters stay stable.
Start with software checksums before comparing mode 1 or 3. Restore the original
interface MTU after the experiment. The frame length excludes the Ethernet FCS.

Offload metadata is valid only when the packet layout, configured capabilities,
L2/L3 lengths and pseudo-header seed agree. Never use a pending offload checksum
as the starting point for an incremental software update.

### Bounded two-port loopback

Build with `cargo build --locked -p rpkt-dpdk --example two_port --profile performance`.
The command accepts:

```text
two_port <gen|fwd> CORE RX_PORT TX_PORT SECONDS FRAME_BYTES BURST <software|offload> -- EAL_ARGS
```

Use two dedicated, directly connected links. Start the forwarder first and wait
for `READY: both links up` before starting the generator. Pick CPUs on the same
NUMA node as both local NICs. `Lcore::socket_id` means NUMA node, not physical CPU
package (DPDK builds with NUMA disabled report zero for all CPUs). The harness
checks placement and link state, creates node-local pools
and queues, and cleans up after its bounded run. A 10-second link timeout is
outside the requested traffic duration. Both ports must be distinct.

For the verified lab wiring (port IDs assume only these two allowlisted devices):

```sh
# duanjp, RX from tg's first link and TX over the second:
sudo target/performance/examples/two_port fwd 60 1 0 15 64 32 software -- \
  -l 60 -n 4 -a 0000:b8:00.0,rx_vec_en=0 -a 0000:b8:00.1,rx_vec_en=0 \
  --file-prefix rpkt_two_port
# tg, after the forwarder's READY message:
sudo target/performance/examples/two_port gen 2 1 0 3 64 32 software -- \
  -l 2 -n 4 -a 0000:17:00.0,rx_vec_en=0 -a 0000:25:00.1,rx_vec_en=0 \
  --file-prefix rpkt_two_port
```

Burst sizes are 1/4/8/16/32/64. For mlx5, `rx_vec_en=0` is required on **both**
ports for burst 1: vector RX otherwise returns no packets. Use the same RX mode
for all sizes in a comparison. Other PMDs can have their own minimum/multiple
burst requirements. Frame sizes 64..9014 include Ethernet but not FCS; configure
peer MTUs for jumbo cases and restore them afterward. The measured lab cases
use 64 and 1500, so no MTU changes are needed.

The generator initializes every transmitted byte, copies a prepared header,
patches identification/sequence/timestamp, and either computes software
checksums or requests supported IPv4/UDP TX offloads. Unsupported offloads
fall back to software and are reported in JSON. Offload mode omits the software
payload checksum; IP checksum is zero and UDP carries the pseudo-header seed.
The forwarder verifies the incoming IPv4 checksum before decrementing TTL and
updating it incrementally. The generator verifies both returned checksums in
software. This is a controlled UDP workload, not a general router.

Each worker owns its counters. RX, processing, allocation/free and TX retain
bursts; available partial bursts are processed immediately. TX transfers only
the accepted prefix, and the application frees unsent packets without retrying
forever. The generator drains RX for 200 ms after sending stops. `unreturned`
is accepted TX minus returned marked packets, not a precise per-device drop
attribution; unrelated frames are counted as invalid. No deduplication is done.
Rates use the requested duration; forwarder rates include its idle waiting time
and are **not** a standalone forwarding-capacity measurement. RTT is measured
on the generator's clock for every 1024th sequence, capped at 65536 samples;
zero percentiles mean no samples. It includes queueing, both links and polling.
Record both endpoint JSON objects, not just the peak rate. See the checked-in
[lab report](../benches/results/2026-09-18-two-port.md) for results and limits.

## Three-process NAT forwarding experiment

`nat_loop` uses separate generator, single-thread forwarding worker and sink
processes. The forwarding adapters and independent reference are shared with
the [CPU NAT workload](../benches/README.md#established-flow-nat). Build the
same feature/profile combination on both hosts:

```sh
cargo build --locked --profile performance -p rpkt-dpdk --features nat-fast-table --example nat_loop
# CLI (EAL allowlist determines local port numbers):
nat_loop <gen|sink|rpkt|cursor|pnet|smoltcp> CORE RX TX SECONDS SIZE FLOWS <udp|tcp|mixed|tcpopts> -- EAL_ARGS
```

`RPKT_TRAFFIC_WORKERS=2` gives the generator/sink two dedicated queues and
consecutive CPU cores starting at `CORE` (maximum four). Sender workers partition
flow IDs; sink workers use IPv4 TCP/UDP RSS with a deterministic nonperiodic key
(the repeating symmetric default can collapse correlated synthetic tuples onto
one queue). A barrier aligns their start and
completion. Each worker emits its own JSON, with device-wide counters emitted
only by worker 0. The runner retains those records and aggregates counters;
summed receiver bins have independently aligned first-packet origins and are
approximate. **The NAT DUT always uses one worker**, regardless of this setting.

Use only dedicated idle test links. Frame sizes exclude FCS; MTU stays 1500.
Each role uses burst 64, queue descriptors 2048, a NUMA-local 16383-object pool
with cache 256 and data room 2176. DUT RX and TX must differ. No TX checksum
offload is requested. The DUT checks NIC checksum status and falls back to
software verification if status is unknown. All libraries share that ingress
gate and identical I/O. Segmented packets are rejected by this experiment.

The sink checks length, MACs and NIC bad-checksum flags on every packet. Every
1021st received packet is compared byte-for-byte with the independent expected
packet and full checksum recomputation; the prime stride avoids repeatedly
sampling only the same few flows. This is sampled validation, not exhaustive
inspection of every payload. Generator inputs and expected outputs are built
outside timing. Generator TX failures/partial bursts are counted and freed;
there is no unbounded retry. Counters include receiver misses, allocation
failures and checksum fallback. Rates must distinguish offered, DUT and returned
traffic. Receiver loss or insufficient offered load invalidates a capacity claim.

`SECONDS` is a 1–60-second wall-time bound. DUT/sink also finish one second
after their last accepted traffic. `active_seconds` spans first to last accepted
burst; one-second RX bins start at the first accepted burst. For steady rates,
use **all complete interior bins**, dropping the first and final partial bin,
not the highest bin. This is not RFC 2544 zero-loss throughput testing.

`python3 dev/nat_lab.py --output NEW_FILE.jsonl` runs the documented tg/duanjp
wiring with three rotated-order repetitions. It refuses an existing output
file or a nonzero duanjp node-2 hugepage reservation, temporarily reserves
128 two-MiB pages, and restores the original count in cleanup. DUT EAL uses
`--huge-unlink=always` so no backing files retain those pages after exit.
The generator/sink use `--no-huge`; no addresses, routes, drivers or MTUs are
changed. Configure passwordless sudo or supply `RPKT_DUT_SUDO_PASSWORD` through
your local secret mechanism (never put it in source, logs or command arguments).
The runner is intentionally specific to the documented lab, not autodetection
or a generally safe command for arbitrary production interfaces.

Wiring: tg `17:00.0` → duanjp `b8:00.1` (RX port 1), then duanjp `b8:00.0`
(TX port 0) → tg `25:00.1`. duanjp uses
core 60 on NUMA node 2. In the two-worker traffic configuration, tg uses cores
2/3 for generation and 4/5 for reception. The runner keeps scalar RX on the DUT and allows the
default mlx5 vector RX path on the sink; this setting is identical across DUT
implementations. See the [NAT report](../benches/results/2026-09-18-nat.md).
