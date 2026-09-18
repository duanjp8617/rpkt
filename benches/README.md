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

Live DPDK runs additionally need port/link map, NIC/firmware/driver and DPDK
versions, worker and pool NUMA placement, offered and received rates, RX errors,
drops, partial TX bursts, and round-trip p50/p95/p99 latency. Microbenchmarks do
not establish live forwarding throughput or tail latency.
