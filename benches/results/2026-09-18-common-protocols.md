# Common-protocol parsing: measured wins and limits

The requested blanket result, “rpkt is faster than both libraries for every
common protocol,” is **not established**. TCP option extraction clearly leads
both competitors in this workload. Complete checked Ethernet/IPv4/TCP parsing
also has lower median times on both supplied native hosts. Individual headers
are often near parity, and pnet beats rpkt in some cases, especially standalone
IPv4 on tg. No production parser or generator change is retained by this PR.

## Method and environment

Three full runs per native host, with library order rotated on each run;
81 cases per run, 486 measured results overall. See
[the benchmark contract](../README.md#common-protocols-and-tcp-options) and
[every per-run estimate and 95% confidence interval](2026-09-18-common-protocols.json).
The raw JSON also includes source hashes, tool versions and host metadata.

- Base implementation: commit `460cc7a`; new workload in `benches/protocols.rs`.
- Rust 1.98.0 / LLVM 22.1.8, committed lockfile, pnet 0.35.0,
  smoltcp 0.12.0, Criterion 0.5.1.
- Portable x86-64, no RUSTFLAGS, fat LTO, one codegen unit, default rpkt features.
- tg: Xeon Gold 6230, CPU 2 / NUMA 0, SMT sibling 82, Linux 5.15.0-185;
  schedutil, reported min/max both 2101000 kHz, boost enabled.
- duanjp: Xeon Platinum 8580, CPU 60 / NUMA 2, SMT sibling 180,
  Linux 6.17.0-35; powersave, reported min/max 800000/4000000 kHz.
- Affinity is pinned, not exclusive CPU reservation. Memory uses ordinary
  first-touch allocation on the pinned thread, not enforced NUMA binding.
  Background services were present; temperature and continuous SMT-sibling
  utilization were not measured. Do not treat small differences as universal.
- 30 samples, 200 ms warmup, 500 ms measurement, 1000 bootstrap resamples.
  This is a repeatable short comparison, not a performance regression threshold.

Small sets contain 1024 separately allocated frames. Large sets contain
262144 64-byte frames (16 MiB) or 16384 1500-byte frames (23.4375 MiB), excluding
one guard byte per allocation, allocator and Vec overhead. Large does not mean
cold: the hosts have substantial last-level caches. The option datasets use
1024 128-byte frames. Ethernet starts one byte into each allocation.
All timed work is checked parsing and consumption of matching fields; no
checksum verification, output allocation, payload copying or NIC I/O.

The final rpkt adapter uses existing `Ipv4::parse_from_cursor` for contiguous
IPv4 input. This avoids a logically redundant contiguous-length check, but
does **not** imply a measured win for every case. Generic segmented parsing
still requires that the complete header fit the first chunk. TCP option
comparison uses pnet's borrowed iterator, not its allocating convenience API.
Unknown options and more than three SACK blocks are rejected by every adapter
to give the same supported subset; see the benchmark contract for its limits.

## Results

Each time is the median of three Criterion point estimates, divided by 32:
**ns/packet, lower is better**. Ratios are competitor time / rpkt time;
greater than 1 favors rpkt. They are ratios of medians, not confidence bounds.
Raw intervals remain in the JSON; near-1 ratios should not be called wins.
Every measured workload is included, including negative results.

### tg

| Workload | Frame / set | rpkt ns | pnet ns | smoltcp ns | vs pnet | vs smoltcp |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| ethernet | 64 / small | 8.28 | 8.24 | 8.63 | 0.99x | 1.04x |
| ipv4 | 64 / small | 9.14 | 8.30 | 9.93 | 0.91x | 1.09x |
| udp | 64 / small | 8.26 | 8.42 | 8.30 | 1.02x | 1.00x |
| tcp | 64 / small | 9.66 | 9.42 | 15.12 | 0.98x | 1.57x |
| stack_udp | 64 / small | 10.25 | 11.03 | 17.06 | 1.08x | 1.66x |
| stack_tcp | 64 / small | 14.44 | 16.77 | 21.57 | 1.16x | 1.49x |
| ethernet | 64 / large | 9.18 | 9.28 | 9.66 | 1.01x | 1.05x |
| ipv4 | 64 / large | 9.80 | 9.36 | 10.92 | 0.96x | 1.11x |
| udp | 64 / large | 9.25 | 9.16 | 9.27 | 0.99x | 1.00x |
| tcp | 64 / large | 10.20 | 10.12 | 15.86 | 0.99x | 1.56x |
| stack_udp | 64 / large | 11.26 | 12.08 | 17.95 | 1.07x | 1.59x |
| stack_tcp | 64 / large | 15.28 | 17.45 | 21.67 | 1.14x | 1.42x |
| ethernet | 1500 / small | 9.11 | 9.03 | 9.30 | 0.99x | 1.02x |
| ipv4 | 1500 / small | 10.17 | 10.06 | 12.08 | 0.99x | 1.19x |
| udp | 1500 / small | 9.44 | 9.47 | 9.68 | 1.00x | 1.03x |
| tcp | 1500 / small | 10.89 | 11.52 | 15.97 | 1.06x | 1.47x |
| stack_udp | 1500 / small | 12.43 | 13.01 | 19.90 | 1.05x | 1.60x |
| stack_tcp | 1500 / small | 16.05 | 18.20 | 23.99 | 1.13x | 1.50x |
| ethernet | 1500 / large | 11.99 | 11.86 | 12.75 | 0.99x | 1.06x |
| ipv4 | 1500 / large | 15.10 | 14.48 | 19.06 | 0.96x | 1.26x |
| udp | 1500 / large | 12.59 | 12.72 | 12.76 | 1.01x | 1.01x |
| tcp | 1500 / large | 17.56 | 18.71 | 21.60 | 1.07x | 1.23x |
| stack_udp | 1500 / large | 19.98 | 20.62 | 28.96 | 1.03x | 1.45x |
| stack_tcp | 1500 / large | 22.47 | 25.05 | 32.80 | 1.11x | 1.46x |
| options: timestamp | 128 / small | 11.02 | 21.94 | 25.96 | 1.99x | 2.36x |
| options: syn | 128 / small | 17.52 | 35.04 | 41.83 | 2.00x | 2.39x |
| options: sack3_timestamp | 128 / small | 18.60 | 31.15 | 64.40 | 1.68x | 3.46x |

### duanjp

| Workload | Frame / set | rpkt ns | pnet ns | smoltcp ns | vs pnet | vs smoltcp |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| ethernet | 64 / small | 6.49 | 6.69 | 6.92 | 1.03x | 1.07x |
| ipv4 | 64 / small | 6.66 | 6.76 | 7.47 | 1.02x | 1.12x |
| udp | 64 / small | 6.67 | 6.79 | 6.81 | 1.02x | 1.02x |
| tcp | 64 / small | 7.04 | 7.13 | 8.92 | 1.01x | 1.27x |
| stack_udp | 64 / small | 7.36 | 7.43 | 10.50 | 1.01x | 1.43x |
| stack_tcp | 64 / small | 8.03 | 8.88 | 14.89 | 1.11x | 1.85x |
| ethernet | 64 / large | 6.51 | 6.69 | 6.92 | 1.03x | 1.06x |
| ipv4 | 64 / large | 6.68 | 6.70 | 7.51 | 1.00x | 1.12x |
| udp | 64 / large | 6.71 | 6.81 | 6.83 | 1.01x | 1.02x |
| tcp | 64 / large | 7.05 | 7.17 | 8.95 | 1.02x | 1.27x |
| stack_udp | 64 / large | 7.38 | 7.46 | 11.28 | 1.01x | 1.53x |
| stack_tcp | 64 / large | 8.00 | 8.94 | 14.90 | 1.12x | 1.86x |
| ethernet | 1500 / small | 6.49 | 6.68 | 6.94 | 1.03x | 1.07x |
| ipv4 | 1500 / small | 6.69 | 6.82 | 7.55 | 1.02x | 1.13x |
| udp | 1500 / small | 6.68 | 6.80 | 6.81 | 1.02x | 1.02x |
| tcp | 1500 / small | 7.07 | 7.13 | 8.96 | 1.01x | 1.27x |
| stack_udp | 1500 / small | 7.36 | 7.43 | 10.57 | 1.01x | 1.44x |
| stack_tcp | 1500 / small | 8.03 | 8.95 | 15.67 | 1.12x | 1.95x |
| ethernet | 1500 / large | 6.58 | 6.71 | 6.99 | 1.02x | 1.06x |
| ipv4 | 1500 / large | 7.58 | 7.90 | 9.52 | 1.04x | 1.26x |
| udp | 1500 / large | 6.77 | 6.88 | 6.85 | 1.02x | 1.01x |
| tcp | 1500 / large | 7.96 | 8.67 | 10.97 | 1.09x | 1.38x |
| stack_udp | 1500 / large | 8.96 | 9.28 | 12.38 | 1.04x | 1.38x |
| stack_tcp | 1500 / large | 11.44 | 12.27 | 19.60 | 1.07x | 1.71x |
| options: timestamp | 128 / small | 7.93 | 14.42 | 26.50 | 1.82x | 3.34x |
| options: syn | 128 / small | 10.89 | 26.59 | 44.20 | 2.44x | 4.06x |
| options: sack3_timestamp | 128 / small | 12.81 | 26.91 | 73.41 | 2.10x | 5.73x |

## Interpretation and rejected experiments

- TCP options: 1.68–2.44x relative to pnet and 2.36–5.73x relative to smoltcp,
  across both hosts and the timestamp, SYN and three-SACK-plus-timestamp sets.
  This confirms the existing borrowed typed-iterator advantage for these
  cases; it is not a new speedup introduced by this PR.
- Ethernet/IPv4/TCP: median ratios 1.07–1.16x relative to pnet and
  1.42–1.95x relative to smoltcp, across both sizes and working sets.
- Ethernet/IPv4/UDP: median ratios 1.01–1.08x relative to pnet and
  1.38–1.66x relative to smoltcp. The smallest pnet differences are too small
  to establish a durable advantage.
- Standalone headers: several near-ties and losses remain. For example,
  tg's small-set 64-byte IPv4 workload is about 10% slower than pnet by
  median point estimates. It would be incorrect to say rpkt always wins.

An initial MAC-to-integer normalization formed an eight-byte array with two
leading zeros. Optimized standalone diagnostic symbols showed an expensive
shuffle sequence for array-returning accessors. Replacing it with identical
16-bit-plus-32-bit normalization for **all three** adapters removed that
benchmark artifact. This is not a production Ethernet optimization. Diagnostic
wrapper sizes became equal (97 bytes for rpkt and pnet in the local fat-LTO
pilot); these wrappers are not dispatched in the timed loop, and equal size
does not establish identical instructions or performance.

A six-element-pattern rewrite of `EtherAddr::from_bytes` did not demonstrate
an improvement and was reverted. Generated iterator `#[inline]` annotations
were also tried and reverted. In a local no-LTO/16-codegen-unit pilot,
rpkt timestamp/SYN/SACK point times before were 337.40/520.71/516.13 ns per
batch and after were 337.99/516.13/519.15 ns. Intervals overlapped and there
was no consistent improvement; this pilot is not evidence for adding hints.
No unconditional inlining, unchecked parsing, SIMD gather, protocol-check
removal or benchmark-specific production fast path is shipped.

## Reproduction and validation

```sh
cargo bench --locked -p benches --bench protocols -- --test
RPKT_BENCH_FULL=1 RPKT_BENCH_CPU=2 bash dev/bench_protocols.sh protocols-checked-cursor
# Use CPU 60 on duanjp; for a synced tree without .git also set RPKT_BENCH_REVISION.
```

The runner requires Bash, Cargo/rustc, taskset, jq and sha256sum. All three
measurement runs completed on both hosts. On tg, jq was missing at the final
artifact-copy step, so the existing Criterion directory was copied manually
after checking the third named baseline existed. The runner now checks its
dependencies before timing. No measurements were substituted or omitted.

Complete logs, samples and metadata are retained at:

- tg: `/root/rpkt-ws/bench-results-protocols-checked-cursor.C5YV2J`
- duanjp: `/home/duanjp/rpkt-ws/bench-results-protocols-checked-cursor.lYdhba`
- Local copies: `bench-results-common-protocols/{tg,duanjp}` (ignored).

Validation passed: optimized equivalence smoke (all 81 full-mode cases),
core/compiler tests and doctests with all features, diagnostic fixtures,
generation drift, bare-metal no_std with batch/simd, existing cursor/property
Miri checks, and all 12 TCP integration tests under Miri. The TCP fixtures
read files, so that Miri run used `-Zmiri-disable-isolation`.
Scoped core formatting and benchmark-file formatting pass; the historical
benchmark files still have unrelated formatting differences. Clippy completes
with existing generated-code warnings and three benchmark style suggestions.

CI now compiles this benchmark and runs its optimized equivalence checks.
It does not assert a timing threshold. No DPDK code or device configuration
changed in this PR; these results do not establish live forwarding throughput,
TCP stack throughput, ARM performance or another compiler/profile's ranking.
