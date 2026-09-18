# Repeatable packet benchmarks

Use the committed workspace Cargo.lock and Rust 1.98 toolchain. Do not update
dependencies between comparisons. Capture dependency changes in a separate
baseline. `dev/bench.sh` requires Bash, jq, taskset and an idle CPU:

```sh
RPKT_BENCH_CPU=2 bash dev/bench.sh before checksum_bytes
# After a change, on the same machine and CPU:
RPKT_BENCH_CPU=2 bash dev/bench.sh after checksum_bytes --baseline before
RPKT_BENCH_FULL=1 RPKT_BENCH_CPU=2 bash dev/bench.sh full
```

The script saves a named baseline by default; passing `--baseline` selects
comparison mode instead.
The script saves the complete Criterion directory, log, lockfile, toolchain,
git revision/dirty status, CPU/kernel details, flags, affinity and dependency tree
in a unique `bench-results-*` directory. Keep these artifacts with any published
results. CI compiles benchmarks but does not enforce timing thresholds.

`matrix` replaces the old assertion-heavy fixtures as the comparison baseline.
The old named suites remain historical microbenchmarks, and their application
cases include copying/assertions; do not compare their numbers to matrix results.

| Workload | Timed work |
| --- | --- |
| `checksum_bytes` | Folded Internet checksum; lengths count only checksum input bytes, with offsets 0/1/7/31 and an odd segment boundary |
| `parse` | Equivalent layout validation plus source/destination IPv4 addresses and UDP ports; no checksum scan or payload copy |
| `work/validation` | Layout/length/protocol checks only |
| `work/payload_copy` | Copy bytes after the 42-byte Ethernet/IPv4/UDP header |
| `work/header_build` | Construct headers into preallocated storage; no payload fill or checksum scan |
| `work/complete_build` | Header construction, payload fill and valid IP/UDP software checksums |
| `field_initialization` | Full-field IPv4 initializer prototype versus generated independent setters, including width checks and output stores |

Frame sizes 64/128/512/1500/9000 include the Ethernet header but exclude FCS,
preamble and interpacket gap. Checksum sizes additionally cover 0/1 and both
sides of 16/32/64-byte boundaries. The default parsing matrix uses 64 and 1500;
`RPKT_BENCH_FULL=1` enables all frame sizes. All parsing starts are offset by one
byte. Mixed inputs cycle through ordinary UDP, VLAN (+4 bytes), IPv4 options
(+4 bytes), a 33-byte truncation, and TCP (rejected by this UDP workload).
Field values vary across frames. Generic and cursor rpkt APIs, pnet and smoltcp
consume exactly the same four fields and validation contract; equality checks
run before timing. Library parser checks remain in the timed path.

Batches 1/4/8/16/32/64 are processed without waiting for more input. Warm sets
contain 64 frames; large sets contain at least 16 MiB of packet bytes, plus Vec
metadata/allocator overhead. A 16 MiB set may fit in a large last-level cache;
it is a larger working set, not a guarantee of cold memory. Dataset allocation,
correctness assertions and output allocation are outside timing. Function
dispatch, input traversal and black-box output consumption are included.

Criterion reports ns/iteration and throughput. For a parsing batch of N packets,
ns/packet = ns/iteration / N and packets/second = N * 1e9 / ns/iteration. Checksum
bytes/second uses the input length. Measure actual cycles and branch/cache misses
with `perf stat -e cycles,instructions,branches,branch-misses,cache-misses` around
the selected executable; process totals include the harness, so use a long
single workload and report that limitation. Do not infer CPU cycles from nominal
clock speed. Record governor/turbo settings, competing processes, NUMA placement,
SMT sibling activity and CPU temperature separately with the result.

Benchmark profile uses fat LTO and one codegen unit. `RUSTFLAGS=-Ctarget-cpu=native`
is a separate experiment and must be recorded; portable builds are the baseline.
Inspect optimized assembly with `cargo rustc -p rpkt --release -- --emit=asm` and
use profiles before retaining an optimization. Preserve at least three runs per
candidate, including short/mixed inputs, and report confidence intervals and
code-size costs. No regression threshold is established yet.

`RPKT_BENCH_CPU=2 bash dev/bench_profiles.sh` compares no LTO/16 codegen units,
no LTO/1 unit, and fat LTO/1 unit separately, with three runs each. It retains
per-run artifacts through `dev/bench.sh`, including the profile overrides.
The initializer is benchmark-only: its proposed grouped-store output is checked
against the actual generated setters over all 65536 varying inputs, including
guard bytes. It does not add a generator API or change standalone setter
behavior. See [the experiment report](results/2026-09-18-codegen-profiles.md).

Live DPDK runs additionally need port/link map, NIC/firmware/driver and DPDK
versions, worker and pool NUMA placement, offered and received rates, RX errors,
drops, partial TX bursts, and round-trip p50/p95/p99 latency. Microbenchmarks do
not establish live forwarding throughput or tail latency.

## Common protocols and TCP options

`protocols` compares checked packet views for Ethernet, IPv4, UDP, TCP,
Ethernet/IPv4/UDP and Ethernet/IPv4/TCP. It also extracts TCP timestamps,
SYN options (MSS, window scale, SACK-permitted, timestamps), and three SACK
blocks plus timestamps. This measures parsing and field extraction, not TCP
connection processing, packet construction or live forwarding.

```sh
# Fast optimized correctness check, also run in CI:
cargo bench --locked -p benches --bench protocols -- --test
# Three runs, rotating rpkt/pnet/smoltcp execution order:
RPKT_BENCH_CPU=2 bash dev/bench_protocols.sh protocols
# Include larger working sets (at least 16 MiB of packet bytes):
RPKT_BENCH_FULL=1 RPKT_BENCH_CPU=2 bash dev/bench_protocols.sh protocols-full
```

Use the same idle native CPU and unchanged compiler, dependencies, flags and
power settings for comparisons. The script preserves logs, Criterion samples,
confidence intervals, source hashes and environment metadata. It
can also run in a synced tree without `.git`: set `RPKT_BENCH_REVISION` to the
source revision and describe any local changes (file hashes are still recorded).
The benchmark uses 30 samples, 200 ms warmup and 500 ms measurement per case; repeat longer
runs when small differences matter. Three order rotations do not eliminate
thermal, scheduling, SMT or frequency noise. CI checks correctness, not timing.

All libraries use checked public APIs. Missing validation in a library's
constructor is supplied in its adapter to match the common contract. IPv4
version and complete header/packet lengths are checked; pipelines additionally
check Ethernet type, IP protocol, reject fragments and exclude Ethernet padding.
UDP declared lengths and TCP data offsets are checked. Checksums are read but
not verified. Identical fields feed the same output digest; no output allocation,
payload copying or assertions occur in the timed path. See `protocols.rs` for
the exact consumed fields. Inputs vary and both inputs and outputs are black-boxed.

For contiguous IPv4 storage, the rpkt adapter uses the existing checked
`Ipv4::parse_from_cursor(Cursor::new(bytes))` specialization. It knows that the
whole packet is in one chunk. Use generic `Ipv4::parse` for segmented storage;
it must additionally ensure that the header fits the first chunk. Neither API
verifies the IP version or checksum by itself: the benchmark checks version
explicitly. TCP options use rpkt's typed borrowed iterator, pnet's borrowed
`get_options_iter` (not its allocating `get_options`) and smoltcp's
`TcpOption::parse`. All consume option values, including every SACK edge, and
stop at EOL. The shared benchmark subset rejects unknown options and more than
three SACK blocks on **every** path because smoltcp 0.12 materializes at most
three blocks. This is a comparison contract, not a general-purpose TCP option
policy: a TCP implementation must handle unknown options as specified by
[RFC 9293](https://datatracker.ietf.org/doc/html/rfc9293#section-3.1).

Before timing, adapters are checked against one another on varying packets,
all prefix truncations and header-byte mutations. These agreement checks are
not an independent protocol reference implementation. Default working sets
contain 1024 misaligned frames of 64 or 1500 bytes; the three option sets use
128-byte frames. Full mode adds larger sets for the six protocol workloads,
not the option workloads. A larger set can still fit in last-level cache.
The timed loop processes 32 packets: divide Criterion's ns/iteration by 32
for ns/packet. Input traversal and output consumption are included.

The `inspect_*` functions retain standalone optimized symbols for assembly
inspection; they are **not** the functions dispatched inside timed loops.
Avoid expensive normalization artifacts: the same MAC conversion is used by
all three adapters. Do not infer a library speedup from changing this shared
benchmark code. See [the native-host report](results/2026-09-18-common-protocols.md)
for all outcomes, including ties and losses. No universal fastest claim or
hardware-independent performance threshold is established.
