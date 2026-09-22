# NAT with Cargo's default release profile

Default release widens the small-packet gap to smoltcp, but does not establish
a broad 1.15x advantage over both competitors. At 4096 flows, ordinary UDP/TCP
ratios are 1.102x/1.129x versus smoltcp and 1.013x/1.021x versus libpnet.

This reruns the equalized NAT experiment using **ordinary Cargo release
settings**, not explicit cross-crate ThinLTO: `opt-level=3`, `lto=false`,
`codegen-units=16`, no debug information and no native-target override.
Cargo documents `lto=false` as permitting local ThinLTO across codegen units
within a crate; it is different from both `lto="thin"` and `lto="off"`.
[Cargo profile reference](https://doc.rust-lang.org/cargo/reference/profiles.html#lto).

## Controlled build and workload

The runtime is rebuilt from the exact earlier source snapshot `725d45b`, not
the later TCP changes. Both hosts use fresh `git archive` extractions;
65 core/DPDK source and manifest inputs were SHA-256 checked against that
commit on each host, with exact matches. The earlier report disclosed two
formatting-only differences in its remote source tree; these fresh extractions
have neither difference. No NAT algorithm, accessor or inlining annotation is
modified for this experiment.

Both hosts use Rust 1.98.0 (`88d9e12ae`, LLVM 22.1.8), locked dependencies and
DPDK 24.11.7. Verbose build logs record the compiler commands. For `rpkt`,
`rpkt_dpdk`, `pnet_packet`, `smoltcp` and the NAT executable, the default build
has `-C opt-level=3 -C embed-bitcode=no -C codegen-units=16` and no cross-crate
`-C lto` flag. A fresh control uses the prior `performance` profile: fat LTO
and one codegen unit. This compares complete profile choices, not LTO alone.

All three NAT libraries are selected from **one frozen executable per DUT
profile**. The generator and sink always use the same frozen performance-
profile executable: changing the traffic engine's optimization at the same
time would confound a DUT comparison. Old artifacts are not overwritten.
The source/build locations are `/home/duanjp/rpkt-nat-release-20260922` and
`/root/rpkt-nat-release-20260922`; executables are under `frozen/`.

The live setup matches the [earlier equalized NAT report](2026-09-20-nat-equalized.md):

- Two 100-Gb/s links: tg generator `17:00.0` → duanjp `b8:00.1`, then
  duanjp `b8:00.0` → tg sink `25:00.1`.
- One DUT thread on CPU 60, NUMA 2, two RX/TX queues, mlx5 vector RX, burst 64.
  Four generator workers on tg CPUs 0–3 and four sink workers on CPUs 4–7.
- Same established-flow full NAT, fixed-seed aHash table, shared prefix
  specialization, validation, checksum handling and header prefetch policy.
  TCP option contents are not decoded, including in the IPv4/TCP-options case.
- Five-second offered traffic intervals with receiver drain. Returned Mpps
  uses all accepted sink packets divided by generator elapsed time, not the
  fastest one-second bin. This is lossy offered-load goodput, not zero-loss
  forwarding capacity.
- Pause is temporarily disabled identically on all four dedicated ports under
  the user's prior approval; original states and node-2 hugepages are restored
  and checked after each invocation. MTU, drivers and host networking are not
  changed. Other users' jobs are not stopped; hosts are not globally isolated.
- No concurrent builds or live experiments. Profiling runs are separate from
  throughput repetitions and use the exact frozen default-release DUT binary.

## Default-release throughput

All 90 trials completed: three rotated-order repetitions of ten workloads and
three libraries. Cells show the median returned Mpps and individual min–max;
ratios use medians, not selected peak bins or confidence bounds.

| Pattern | Bytes | Flows | rpkt Mpps [range] | libpnet Mpps [range] | smoltcp Mpps [range] | rpkt/libpnet | rpkt/smoltcp |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| udp | 64 | 64 | 34.888 [34.698–34.890] | 34.760 [34.691–34.794] | 33.081 [32.969–33.157] | 1.004x | 1.055x |
| udp | 64 | 4096 | 31.972 [31.970–32.086] | 31.576 [31.268–31.715] | 29.002 [28.911–29.035] | 1.013x | 1.102x |
| tcp | 64 | 64 | 35.647 [35.409–35.660] | 35.298 [35.239–35.311] | 33.754 [33.729–33.805] | 1.010x | 1.056x |
| tcp | 64 | 4096 | 32.581 [32.452–32.598] | 31.904 [31.842–31.952] | 28.857 [28.786–28.892] | 1.021x | 1.129x |
| mixed | 64 | 4096 | 26.917 [26.907–26.924] | 26.497 [26.444–26.498] | 24.304 [24.274–24.354] | 1.016x | 1.107x |
| udp | 512 | 4096 | 22.766 [22.760–22.970] | 22.986 [22.769–23.000] | 23.002 [22.864–23.031] | 0.990x | 0.990x |
| tcp | 512 | 4096 | 22.967 [22.854–23.036] | 23.031 [22.823–23.054] | 23.004 [22.853–23.063] | 0.997x | 0.998x |
| udp | 1500 | 4096 | 8.144 [8.136–8.148] | 8.146 [8.145–8.151] | 8.140 [8.138–8.145] | 1.000x | 1.001x |
| tcp | 1500 | 4096 | 8.144 [8.139–8.147] | 8.146 [8.140–8.153] | 8.147 [8.143–8.152] | 1.000x | 1.000x |
| tcpopts | 128 | 4096 | 29.386 [29.295–29.401] | 20.159 [20.103–20.211] | 24.892 [24.859–24.951] | 1.458x | 1.181x |

For ordinary 64-byte UDP/TCP, rpkt is 0.4–2.1% ahead of libpnet and 5.5–12.9%
ahead of smoltcp. The gap to smoltcp is larger than in the earlier fat-LTO
matrix, but there is still no broad 1.15x lead over both libraries.

The `tcpopts` case contains IPv4 options and therefore uses the general parser
fallback: its 1.458x / 1.181x ratios must not be substituted for ordinary
UDP/TCP. TCP option contents are not extracted in any of these NAT workloads.
The 512/1500-byte cases approach the physical-link ceiling and include sink
loss/variation; their near-ties and small regressions are retained.

Across the 90 runs, the generator offered 19,868,038,592 packets, the DUT
accepted 10,984,297,253 and the sink accepted 10,974,971,439. The sink checked
10,749,059 full output samples with zero bad-output/bad-checksum counts.
It also rejected 117 packets before sampling; their contents are not recorded
by this frozen source and are not retrospectively classified. Zero failed
samples is not exhaustive verification of every forwarded packet.

DUT counters recorded 25,143 unsent packets, 3,093,426,876 RX misses and zero
allocation/TX errors. The sink recorded 2,158,964 RX misses; the largest
per-trial sink miss fraction was about 1.000%. Hardware counters do not
fully reconcile offered and received totals. This remains delivered goodput
under overload, not zero-loss capacity.

## Fresh fat-LTO control

A separate 18-trial control uses the freshly rebuilt fat-LTO, one-codegen-unit
DUT and the **same** generator/sink binary, queues, CPUs and link settings.
It covers 64-byte packets with 64 flows, three rotated repetitions:

| Pattern | rpkt Mpps [range] | libpnet Mpps [range] | smoltcp Mpps [range] | rpkt/libpnet | rpkt/smoltcp |
| --- | ---: | ---: | ---: | ---: | ---: |
| UDP | 35.113 [34.903–35.151] | 34.953 [34.945–34.965] | 34.038 [34.015–34.113] | 1.005x | 1.032x |
| TCP | 36.273 [36.102–36.288] | 35.929 [35.854–35.930] | 34.932 [34.906–34.940] | 1.010x | 1.038x |

These are close to the earlier fat-LTO common-path results. Default release
reduces absolute goodput for all three libraries in these cases, with a
larger reduction for smoltcp. Its relative rpkt/smoltcp gaps become
1.055x/1.056x, while the libpnet gap stays small. This is consistent with the
inlining differences below; it is not a randomized LTO-only causal estimate.
The profiles also differ in codegen-unit count, and whole matrices were run
sequentially rather than interleaving release and fat builds.

All 18 control trials passed the same checks: zero DUT/sink checksum errors,
zero bad output samples, 3,101,561 full sink samples. Three pre-sampling sink
rejections remain unclassified. This limited control is not a fresh fat-LTO
rerun of the other eight workloads.

## Compiler-visible field-access differences

Disassembly of the exact default-release DUT binary shows:

| Common-path operation | rpkt | libpnet | smoltcp |
| --- | --- | --- | --- |
| IPv4 source/destination extraction | Combined 64-bit load and byte swap | Same combined load after optimization | Two calls to `AddressExt::from_bytes`, then combination/byte swap |
| Port-pair extraction | Combined 32-bit load and byte swap | Same | Same |
| IPv4 source/destination rewrite | One 64-bit store | Two 32-bit stores | Two 32-bit stores |
| Port-pair rewrite | One 32-bit store | Four byte stores | Two 16-bit stores |

The smoltcp helper's successful path checks that its slice length is four,
loads a 32-bit value and returns. Two calls execute per common UDP or TCP
packet; there are four static call sites across the two specialized branches.
The caller already passes a constant length of four, but without cross-crate
inlining the helper retains that check and call boundary. Its GOT relocation
was resolved to the named function rather than guessed from a disassembler
label. The prior fat-LTO build instead inlined the address extraction.

This is a concrete default-build distinction, not evidence that smoltcp needs
a fundamentally more expensive address-parsing algorithm. Likewise, libpnet
already gets the combined address load, so that operation is not uniquely
an rpkt advantage. The shared specialized fixed-header parsing remains in
place for all libraries; do not generalize fallback accessor costs to the
common path. No library's inlining annotations were changed for this rerun.

Exact-address excerpts and relocation evidence are in
`address-access-disassembly.txt` and `field-access-disassembly.txt` in the raw
directory. Default-release DUT SHA-256:
`1fbf4a1892c1e2db5a76affcb970562f14ca3d542e4ff226aa29c14784a7bf1f`.
Fresh performance-control DUT SHA-256:
`edbe0172bd16adc6121c0fca882460cf28f527287162287465470ada455b1844`.

## Active-traffic profiles

Profiles use `perf record -F 999 --clockid mono`, reporting self samples of
`cycles:P` only between first traffic + 0.25 s and last traffic - 0.25 s.
The runner now rejects missing/invalid active windows instead of silently
including initialization. These are separate instrumented trials, not part
of the 90-run throughput matrix. Embedded `perf stat` counters cover whole
process lifetimes, including startup/idle; they are not active cycles/packet.

For the ordinary 64-byte, 4096-flow cases, percentages of active-window cycle
samples are:

| Pattern | Library | Forwarding loop | Vector RX entry | Address helper |
| --- | --- | ---: | ---: | ---: |
| UDP | rpkt | 54.75% | 12.18% | 0% |
| UDP | libpnet | 54.10% | 14.39% | 0% |
| UDP | smoltcp | 55.06% | 11.32% | 2.05% |
| TCP | rpkt | 53.30% | 13.89% | 0% |
| TCP | libpnet | 54.94% | 13.28% | 0% |
| TCP | smoltcp | 55.75% | 11.86% | 2.09% |

The symbols are `nat_loop::run::<2, ...>`, `mlx5_rx_burst_vec` and smoltcp's
`AddressExt::from_bytes`. The loop includes inlined parsing, table lookup,
checksum work, rewriting and bookkeeping: its percentage is **not a
parser-only cost**. RX entry is only one driver function, not total I/O cost.
The helper's roughly 2% self share excludes caller/spill overhead; it does
not establish that the helper causes the entire throughput difference.
Across all four small UDP/TCP cases the helper's self share is 2.05–2.54%.

The IPv4/TCP-options fallback exposes a different inlining boundary:

| Library | General NAT function self share | Separate library accessor/helper self share |
| --- | ---: | ---: |
| rpkt | 23.94% | No separately sampled rpkt accessors |
| libpnet | 28.42% | 22.08% |
| smoltcp | 27.53% | 6.70% |

Libpnet's separate symbols include address/port getters, checksum accessors,
fragment-offset extraction and Ethernet/address setters. Smoltcp's include
IPv4 payload access, source/destination address access and `from_bytes`.
Rpkt's accessors are incorporated into its general NAT function. All three
also spend samples in the same table lookup; separate lookup shares differ
because their packet rates and total costs differ. Percentages are not
per-packet costs and should not be subtracted as if they were an ablation.
These observations support a **build-sensitive accessor/inlining advantage**
in this fallback, not a TCP-options-decoding claim or proof that competitors
could not obtain similar code after adding inlining annotations.

### Retained profiling anomaly

The first profiling invocation stopped after its 24th record: smoltcp,
1500-byte TCP, 4096 flows. It recorded one DUT `bad_checksum` and one software
checksum fallback; sink `bad_checksum` and `bad_output` were both zero.
The source drops invalid input before calling any library's NAT kernel.
The log does not retain the offending frame, so its cause cannot be assigned
to background traffic, hardware, the generator or a parsing implementation.
The failed record remains in `release-profiles.jsonl`; it is not silently
removed or counted as a passing trial. All three libraries' 1500-byte TCP
profiles are repeated in a separate follow-up file, followed by the two
workloads not reached in the initial invocation. This anomaly does not
affect the independently completed, zero-checksum-error throughput matrix.
All nine follow-up trials passed. Across both files there are 33 recorded
profiles (32 passing, one failed), covering all 30 workload/library pairs;
every profile reports zero lost samples. Neither file contributes samples
to the uninstrumented throughput medians.

## Validation

- Frozen default-release NAT equivalence/checksum/malformed-input tests:
  six passed (`benches --test nat_support --features nat-fast-table`).
- Frozen DPDK example unit tests: three passed on default release and three
  on the performance-profile traffic host; these do not exercise live ports.
- Runner tests: six passed, including selected-binary provenance, bounded
  profiling windows, workload selection and restoration after failure.
- `bash -n dev/build_nat_release.sh` passed.
- The 90-trial matrix passed `dev/summarize_nat_live.py`; all 65 manifest
  hashes were independently rechecked against Git. All recorded environments
  match the selected frozen executables.

Final read-only checks confirmed all four ports back at autoneg off / RX on /
TX on, node-2 hugepage reservation back at zero, no matching live NAT
processes, and unchanged frozen-binary hashes. The outputs are retained in
`final-restoration.json`; the runner also verified restoration after every
invocation, including the failed profile.

No packet parser, NAT kernel or workspace profile defaults were modified.
The changes are an isolated build helper, runner/profiling support and the
measurement record. The new runner's selection feature writes separate
files and keeps correctness checks enabled when repeating failed cases.

## Reproduction

Extract `git archive 725d45b` into a fresh directory on each host, load its Rust
environment and export its own DPDK `PKG_CONFIG_PATH`. From that directory run
the current repository's `dev/build_nat_release.sh`: `release 64-67` and
`performance 64-67` on duanjp, `performance 10-13` on tg. The script refuses
to overwrite frozen executables and explicitly pins the ordinary release
defaults. It does not edit Cargo manifests.

From the current repository, with `RPKT_DUT_SUDO_PASSWORD` supplied securely:

```sh
python3 dev/nat_lab.py \
  --output /tmp/nat-release-matrix.jsonl --repeats 3 \
  --dut-binary /home/duanjp/rpkt-nat-release-20260922/frozen/nat_loop-release \
  --traffic-binary /root/rpkt-nat-release-20260922/frozen/nat_loop-performance \
  --dut-source /home/duanjp/rpkt-nat-release-20260922 \
  --traffic-source /root/rpkt-nat-release-20260922 \
  --vector-rx --sink-workers 4 --gen-workers 4 --disable-pause --dut-queues 2
```

Use `--perf --repeats 1` and a fresh output path for separate profiles of all
ten cases. Use the DUT `frozen/nat_loop-performance` with `--pilot --repeats 3`
for the fresh fat-LTO common-path control. Run these sequentially.
The follow-up profiling invocation adds
`--cases tcp:1500:4096 mixed:64:4096 tcpopts:128:4096` and uses a new output
path, preserving the original incomplete invocation and its failed record.

Raw records, environment metadata and build logs are in
[the artifact directory](2026-09-22-nat-release/).
