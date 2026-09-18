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
