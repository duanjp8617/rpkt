# Equalized live NAT: the 1.15x target is not demonstrated

The promising rpkt-only specialization did **not** survive the essential
fairness control: applying the same parsing strategy to the other libraries.
Do not cite its apparent advantage over their older adapters as a distinguishing
rpkt library optimization. The target remains unmet, not "approximately met."

Source snapshot: `725d45b` on `dev/nat-live-optimization`, stacked on PR27.
An audit of 60 core/DPDK build inputs found two formatting-only differences on
the DUT: `rpkt-dpdk/src/ffi.rs` has a terminal newline, and one blank doc-comment
line in `service.rs` lacks a trailing space. No functional differences were
found in that audit. Later CI/test-only commits are not the measured snapshot.
This is established-flow full NAT, not a complete NAT gateway. All versions
check the same lengths/selectors/TTL/fragments, look up the same five-tuple,
rewrite both MACs/addresses/ports, decrement TTL and update both checksums.
Ingress NIC checksum validation and software fallback are identical. Packet
rejection and table misses leave bytes unchanged. TCP data-offset bounds are
checked; TCP option contents are **not decoded** by this workload.

## What changed in the experiment

With the user's approval, RX/TX Ethernet pause was disabled on the four
dedicated ports during each run. Each original state is saved before mutation;
cleanup attempts all four restores and verifies readback, even if another
restore fails. The original settings are autoneg off, RX on, TX on. The runner
also restores the DUT node-2 hugepage reservation to zero.

The one-queue MAC-only control achieved only about 28–29 Mpps, even without NAT.
Two RX/TX queues serviced by the **same single DUT thread** raised the diagnostic
DUT rate to about 49 Mpps. That diagnostic overwhelmed the sink (returned
37–39 Mpps), so it is not a 49 Mpps end-to-end result. It establishes that the
old one-queue configuration masked processing capacity. It is not a packet-
library optimization and it is not included in NAT ratios.

All final adapters use the same:

- One DUT thread on CPU 60, two RSS-distributed RX/TX queues, burst 64 and mlx5
  vector RX. Generator uses four workers on tg CPUs 0–3; sink uses four on 4–7.
- Portable performance profile, fat LTO, one codegen unit, aHash with identical
  fixed seeds/table layout. Native-target probes were not selected as final.
- SSE2 common-prefix check (scalar fallback off x86-64), UDP/TCP specialization,
  disjoint fixed-header slices and identical remaining length checks. Each
  library uses its own field accessors. IPv4 options and short UDP frames use
  each library's general-parser fallback. No mutable payload helper is needed
  on any common fast path.
- Header prefetch, packed two-word tuple hashing and native-carry incremental
  checksum arithmetic. None is credited uniquely to rpkt.

Sender/sink are independent hosts/roles in the documented two-link 100 Gb/s
loop. Other users' CPU-heavy jobs were left running, so this is not a fully
isolated machine. Final measurement runs use frozen binaries and no concurrent
builds. Earlier exploratory probes are not controlled causal ablations.

## Pause-off probes, including the fairness control

These are **one trial per library/case**, 64-byte frames, 64 flows. Rates are
all accepted sink packets divided by generator duration, in Mpps. They are
lossy offered-load measurements, not RFC 2544 zero-loss throughput.

| Probe | UDP rpkt / pnet / smoltcp | TCP rpkt / pnet / smoltcp |
| --- | --- | --- |
| One queue, pause off | 29.271 / 23.278 / 29.481 | 29.407 / 23.847 / 29.256 |
| Two queues, general parsers | 32.087 / 23.874 / 31.437 | 34.158 / 24.453 / 31.768 |
| rpkt-only SIMD prefix | 33.766 / 23.815 / 31.388 | 35.128 / 24.534 / 31.768 |
| rpkt-only interval length checks | 33.358 / 23.688 / 30.976 | 34.872 / 24.239 / 31.498 |
| Native target plus shared carry arithmetic | 34.069 / 21.903 / 31.442 | 33.489 / 22.526 / 31.918 |
| rpkt-only combined TTL/protocol selector | 35.083 / 22.389 / 31.775 | 36.242 / 23.008 / 32.047 |
| **Same specialization for all libraries**, profiled | **35.051 / 34.746 / 33.768** | **35.883 / 35.769 / 34.802** |

The rpkt-only selector gave a tempting 1.131x TCP result versus the older
smoltcp adapter. Equalizing the parsing strategy reduced this to 1.031x; the
libpnet ratio became 1.003x. Neither is close enough to claim the 1.15x target.
Every failed/negative probe is retained in the
[raw artifact directory](2026-09-20-nat-investigation/).

## Repeated matrix

All 90 trials completed: three rotated-order repetitions of ten cases and
three libraries. The table contains median returned Mpps, not peak bins.
Ratios are ratios of three-run medians, not confidence intervals.

| Pattern | Bytes | Flows | rpkt Mpps | pnet Mpps | smoltcp Mpps | rpkt/pnet | rpkt/smoltcp |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| UDP | 64 | 64 | 35.045 | 34.814 | 34.057 | 1.007x | 1.029x |
| UDP | 64 | 4096 | 32.291 | 31.844 | 30.901 | 1.014x | 1.045x |
| TCP | 64 | 64 | 36.221 | 35.839 | 34.989 | 1.011x | 1.035x |
| TCP | 64 | 4096 | 32.922 | 32.513 | 31.638 | 1.013x | 1.041x |
| Mixed | 64 | 4096 | 27.240 | 26.602 | 26.064 | 1.024x | 1.045x |
| UDP | 512 | 4096 | 23.020 | 22.988 | 23.012 | 1.001x | 1.000x |
| TCP | 512 | 4096 | 22.945 | 22.911 | 22.946 | 1.001x | 1.000x |
| UDP | 1500 | 4096 | 8.130 | 8.131 | 8.146 | 1.000x | 0.998x |
| TCP | 1500 | 4096 | 8.127 | 8.136 | 8.126 | 0.999x | 1.000x |
| IPv4 + TCP options | 128 | 4096 | 29.580 | 21.206 | 26.628 | 1.395x | 1.111x |

The options case uses the general parser because it contains IPv4 options;
it still does not extract TCP option contents. It must not be substituted for
the ordinary TCP/UDP cases to declare the target met. For 64-flow 64-byte
UDP, the three-run rpkt range is 35.036–35.192 Mpps, pnet 34.773–34.910,
smoltcp 34.046–34.139. TCP ranges are 36.184–36.251, 35.745–35.874,
34.793–35.002 respectively. All other individual results remain in the raw file.

The matrix offered 19,826,964,096 packets; DUT accepted 11,211,591,378 and
sink accepted 11,202,393,206. There were 10,971,797 full output samples with
zero bad-output/bad-checksum counts. The sink also rejected **128** packets
before sampling; the original counter does not identify their bytes/reason.
Do not describe this as a zero-error, exhaustively validated packet stream.
The DUT recorded 36,822 unsent packets, 2,738,148,812 RX misses and zero
allocation/TX errors; sink recorded 1,464,350 RX misses. Maximum per-trial
sink miss fraction was 0.134%. Driver miss counters do not account for the
entire offered/accepted difference, so no complete packet-loss accounting or
zero-loss capacity claim is made. Returned rates include these losses.

A later, separate diagnostic adds bounded reject logging on the sink only;
the DUT remains the frozen matrix binary. Its first captured rejects are
62-byte IPv6 ICMPv6 type-133 multicast traffic, 107-byte IPv6 UDP 5353→5353
multicast traffic, and a 329-byte IPv4 UDP 68→67 broadcast. These are router
solicitation, mDNS and DHCP traffic with non-workload MACs, not NAT output.
They show background host traffic on the bifurcated interfaces. Host network
services were **not** stopped or reconfigured. Full diagnostic header logs
remain on tg; public records omit unrelated host addresses. This does not
retroactively classify every one of the original 128 unrecorded rejects.
Diagnostic trials are not included in the 90-run medians.
All 12 diagnostic trials completed: 27 rejects, of which 23 were captured by
the per-worker sample bound; none of those 23 matched the NAT MAC pair. See
the [address-minimized classification](2026-09-20-nat-investigation/reject-classification.json).

Reproduce the table with `python3 dev/summarize_nat_live.py` and
`2026-09-20-nat-investigation/opt-equalized-final-matrix.jsonl`.

The maximum theoretical packet rate on a 100 Gb/s link, for these sizes
excluding FCS, is `100e9 / (8 * (frame_bytes + 24))`: about 23.321 Mpps at
512 bytes and 8.202 Mpps at 1500 bytes. A result already near those rates
cannot support a 15% processing-speed claim from live throughput alone.

## Parsing/accessor distinctions that remain in optimized code

The equalized pilot was sampled at 999 Hz with `perf record --clockid mono`.
Reports use first/last-traffic timestamps, excluding 250 ms at either edge.
No lost samples were reported. Whole-process `perf stat` counters include
startup/idle time and are **not** active cycles per packet.

| Common-path observation | rpkt | smoltcp | libpnet |
| --- | --- | --- | --- |
| Address-pair extraction | One 64-bit load + byte swap | Two 32-bit loads + shift/or + byte swap | LLVM already combines to one 64-bit load + byte swap |
| Port-pair extraction | One 32-bit load + byte swap | Same combined load | Same combined load |
| Address-pair rewrite | One 64-bit store | Two 32-bit stores | Two 32-bit stores |
| Port-pair rewrite | One 32-bit store | Two 16-bit stores | Separate byte stores in this build |
| Common-path payload/accessor calls | Inlined | Inlined; no payload helper | Inlined; no accessor calls |

The compiler extension generates packed access for adjacent, unrestricted
custom types backed by full-width u8/u16/u32 fields. It uses the same
custom-to-integer conversions as scalar setters, excludes fixed/narrow fields
and retains collision checks. For example:

```rust
let addresses = ip.src_addr_and_dst_addr_bits();
ip.set_src_addr_and_dst_addr(new_src, new_dst);
```

For IPv4 this emits the equivalent of:

```rust
u64::from_be_bytes(header[12..20].try_into().unwrap())
// Setter:
let value = ((u32::from(new_src) as u64) << 32) | u32::from(new_dst) as u64;
header[12..20].copy_from_slice(&value.to_be_bytes());
```

This is the defensible remaining **field-access distinction**, not proof of
a 15% live gain. Disjoint fixed-size parsing views are an rpkt API convenience
and give the optimizer explicit bounds/noalias information; their machine-code
benefit is not exclusive when competitors are given equivalent fixed slices.
Earlier outlined builds exposed pnet accessor calls and smoltcp payload calls;
those observations must not be generalized to this equalized common path.

In the equalized pilot, the monomorphic forwarding-loop symbol receives about
49–53% of active cycle samples for every library, and the major mlx5 RX/TX/
completion/decompression routines about 41–45%. The loop includes hashing,
checksums, counters and buffer management, not just parsing. Sample fractions
are neither parser-only costs nor throughput ratios. Borrowed TCP-option
iteration cannot explain these NAT results because options are not decoded.

Profile binary: `nat_loop-fair-select`, SHA-256
`0c22861ea125ed599e7e7a0ac2b51d18121d7c6632886f4260e954980979845a`.
The repeated-matrix binary is `nat_loop-equalized-final`, SHA-256
`1e41118f4368a4a9425fac9a1143eb03dc612bbb52c0b8dc86418125f3bd810b`.
They have the same retained algorithm; the latter includes the final test/
comment/source-line snapshot. Do not silently interchange their profiles.

After the repeated matrix, the **exact matrix binary** was profiled again
in six separate UDP/TCP trials, with identical pause/queue/worker settings.
The records are `opt-equalized-final-perf.jsonl`; no lost samples were reported.
The forwarding-loop sample shares were UDP 51.61% / 52.35% / 54.40%, TCP
50.87% / 50.69% / 52.68% for rpkt / pnet / smoltcp. This confirms the same
broad cost distribution without attributing the whole loop to parsing.
These profiled trials are not mixed into the 90-run throughput medians.

After the matrix, profiling and diagnostics, a final independent read-only
check confirmed autoneg off / RX on / TX on on all four ports and a zero
node-2 hugepage reservation. The [check output](2026-09-20-nat-investigation/restoration-check.txt)
is retained. No pause or hugepage changes remain active.

## Validation

- Core/compiler tests and doctests; compiler diagnostic fixtures; regeneration
  and diff checks passed locally.
- All six NAT tests passed locally and on both remote hosts with the shared
  fast-table feature. Tests cover independent reference output, all truncations,
  malformed selectors/lengths, omitted/computed-zero UDP checksums, all checksum
  values, padding, and misalignment. Prefix selection is checked against scalar
  predicates over all single-byte mutations and every TTL/protocol pair.
- Miri passed the bounded/unaligned SIMD-prefix test and typed address-pair test.
  The SIMD load has an explicit length guard and uses baseline x86-64 SSE2.
- A seventh, later local regression test covers valid 42–54-byte UDP frames and
  TCP options without IPv4 options. It passed both release tests and Miri; it
  changes no timed code and is not part of the frozen remote test snapshot.
- no_std checks passed on the host and `thumbv7em-none-eabi`.
- Three pure Python tests cover pause-state parsing, readback mismatch, and
  continuing to restore other ports after one restoration fails.

These checks justify correctness work and a reviewable experiment, not a
performance acceptance claim. A broad 1.15x advantage over equally optimized
competitors has not been demonstrated.
