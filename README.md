# rpkt

Rust packet parsing and construction over slices or DPDK packet buffers.
The workspace uses Rust 2021 and requires Rust 1.98 or newer.

| Crate | Purpose |
| --- | --- |
| `rpkt` | Protocol APIs, cursors, checksums; supports `no_std` |
| `pktfmt` | Compiler for protocol definitions and generated Rust APIs |
| `rpkt-dpdk` | DPDK memory pools, segmented buffers and RX/TX queues |
| `benches` | Criterion comparisons with pnet and smoltcp |

The root `examples/` crate contains historical experiments; maintained examples
live in `rpkt-dpdk/examples/` and are compiled in CI.

## Core quick start

Core development requires Rust only, with no DPDK installation or privileges:

```sh
cargo test -p rpkt -p pktfmt
bash gen_cmds.sh --check
cargo build -p pktfmt --bin pktfmt
bash pktfmt/errors/check_errors.sh "$PWD/target/debug/pktfmt"
```

Build and parse a UDP datagram (checksum zero means omitted for IPv4):

```rust
use rpkt::{Buf, Cursor, CursorMut};
use rpkt::udp::{Udp, UDP_HEADER_TEMPLATE};

let mut bytes = [0u8; 12];
bytes[8..].copy_from_slice(b"rpkt");
let mut cursor = CursorMut::new(&mut bytes);
cursor.advance(8); // reserve header space in front of the payload
let mut udp = Udp::prepend_header(cursor, &UDP_HEADER_TEMPLATE);
udp.set_src_port(1234);
udp.set_dst_port(4321);
udp.set_checksum(0);

let udp = Udp::parse(Cursor::new(&bytes)).expect("valid datagram");
assert_eq!(udp.packet_len(), 12);
assert_eq!(udp.dst_port(), 4321);
assert_eq!(udp.payload().chunk(), b"rpkt");
```

Checked parsers validate accessible header and declared packet lengths. Callers
still enforce protocol version, encapsulation, fragmentation and checksum policy.
Headers must fit in the current contiguous chunk of a segmented buffer.

Disable default features for `no_std`; CI checks `thumbv7em-none-eabi`, which has
no standard library. See `pktfmt/protocols/README.md` for generation and protocol
support, and `fuzz/README.md` for property tests, fuzzing and Miri.

## DPDK development

`rpkt-dpdk` supports 64-bit Linux and DPDK LTS families 21.11, 22.11, 23.11 and
24.11. Core CI and DPDK build CI are separate; hardware tests run only on
explicitly provisioned machines. Install Ubuntu build dependencies with
`sudo sh dev/install_deps_ubuntu.sh`, then install `libdpdk-dev` or build a
supported DPDK release and set `PKG_CONFIG_PATH` to its pkgconfig directory.

```sh
pkg-config --modversion libdpdk
cargo test -p rpkt-dpdk --tests --no-run
cargo check -p rpkt-dpdk --examples --all-features
# On a configured test host; privilege applies only to test executables:
DPDK_TEST_RUNNER='sudo -E' bash rpkt-dpdk/tests/run_tests.sh
```

Do not install a global Cargo `sudo` runner. Device tests need access to the
selected NIC, hugepages and suitable CPU cores; tests that initialize EAL run in
separate processes and with one test thread. See `rpkt-dpdk/README.md` for device
setup, Clang troubleshooting, jumbo frames and per-example configuration.

Ordinary release builds use Cargo defaults. Use `--profile performance` to opt
into fat LTO and one codegen unit, and measure the effect on your workload.
