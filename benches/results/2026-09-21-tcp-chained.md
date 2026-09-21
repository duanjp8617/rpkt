# TCP TSO/LRO: direct Pbuf ingress versus chain linearization

This experiment compares two derivatives of smoltcp 0.12 over the same
rpkt-dpdk adapter. The native build retains the contiguous TCP wire API; the
rpkt build uses rpkt TCP header/options and accepts chained payloads through
`Pbuf`. Connection state, Reno, retransmission, stream assembly and application
work remain shared. This is not an independent TCP state-machine comparison.

The clearest main-matrix improvement is 64-KiB single-stream bulk on tg:
**56.395 versus 45.045 Gbit/s, 1.252x (+25.2%)**. Reverse-placement 64-KiB echo
improves 17.3%. This is not a universal win: the complete matrix includes
near-ties and a 7.0% median regression in reverse-placement 4-KiB single-stream
bulk. Those outcomes are retained below.

## Method and reproducibility

Measured runtime source is `0a07285`, on `dev/tcp-chained-offloads`, stacked on
the TCP comparison in PR29. Frozen executables are in
`bench-results-tcp-chained-final` on each host. Each environment JSON records
15 source hashes, both executable hashes, Rust/DPDK versions and link settings.
Both variants use Rust 1.98, locked dependencies, fat LTO and one codegen unit
(`performance` profile), without a Rust native-target override; DPDK is 24.11.7.

- One full-duplex 100-Gb/s link: duanjp `b8:00.1`, CPU 60, NUMA 2 (Xeon
  Platinum 8580) to tg `17:00.0`, CPU 4, NUMA 0 (Xeon Gold 6230).
- One thread and one RX/TX queue per endpoint; 2048 descriptors, burst 64,
  physical MTU 1500. Both endpoints enable the same checksum, TSO, LRO and
  scatter offloads, with explicit hardware capability checks.
- Logical IPv4 TCP packets up to 64512 bytes; LRO limit 65280. SYN advertises
  MSS 1460; timestamp-enabled TSO uses 1448-byte payload segments on the wire.
  A smaller peer MSS disables the large-packet path.
- Main matrix uses identical 8192-byte RX data rooms, 4095 RX buffers and
  4095 separate large TX buffers, within 384 MiB per endpoint. The default
  2048-byte RX configuration uses 16383 buffers (similar RX payload storage).
  Large LRO packets remain chained with either configuration.
- Reno, immediate ACKs, Nagle off, 256-KiB send/receive buffers per connection;
  every application byte is checked. Native chain linearization reuses a
  preallocated scratch buffer: there is no per-packet allocation handicap.
- The DUT/server alternates backend order between repetitions. Its peer is
  always the same native smoltcp client. Both host placements are tested.
  A slower peer may cap throughput; these are paired application measurements,
  not universally isolated DUT capacities.
- Establish all connections, warm up two seconds, measure five seconds using
  recorded actual elapsed time, then drain. Three repetitions per main case.
  Bulk measures verified receiver Gbit/s; echo measures completed client
  responses/s. Write size is application size, not Ethernet frame size.
- Runs and builds are sequential. Other users' jobs are not stopped, so hosts
  are not globally isolated. Ratios of medians are not confidence bounds.
  Pause, MTU, drivers, IP addresses and CPU-frequency policy are unchanged.
  Temporary duanjp node-2 hugepages are restored after every invocation.

Reproduction commands are in [tcp-eval/README.md](../../tcp-eval/README.md).
Raw data and metadata are in [the result directory](2026-09-21-tcp-chained/).
Use `dev/tcp_report.py` for actual-interval medians and ranges; do not mix
instrumented profiles, pilot builds or extra-copy controls into the main table.

## Live results

All 96 main trials completed with zero application mismatches, TX errors or
TX-buffer allocation failures. Ranges below are min–max, not confidence
intervals; each cell contains three repetitions. All cases use TCP timestamps.

| DUT | Mode / write bytes / connections | Unit | smoltcp median [range] | rpkt median [range] | Ratio |
| --- | --- | --- | ---: | ---: | ---: |
| duanjp | bulk / 4096 / 1 | Gbit/s | 28.073 [27.631–28.962] | 26.097 [25.255–29.034] | 0.930x |
| duanjp | bulk / 4096 / 16 | Gbit/s | 21.310 [21.231–21.601] | 22.726 [21.521–23.620] | 1.066x |
| duanjp | bulk / 16384 / 1 | Gbit/s | 29.311 [28.697–29.562] | 29.313 [28.846–29.462] | 1.000x |
| duanjp | bulk / 16384 / 16 | Gbit/s | 23.342 [23.163–23.486] | 23.281 [22.899–23.400] | 0.997x |
| duanjp | bulk / 65536 / 1 | Gbit/s | 31.399 [31.034–31.624] | 31.322 [31.134–31.354] | 0.998x |
| duanjp | bulk / 65536 / 16 | Gbit/s | 24.124 [24.057–24.164] | 24.052 [23.876–24.147] | 0.997x |
| duanjp | echo / 16384 / 16 | k responses/s | 75.836 [75.590–76.755] | 77.073 [76.015–77.953] | 1.016x |
| duanjp | echo / 65536 / 16 | k responses/s | 17.641 [17.547–17.718] | 20.693 [20.594–20.721] | 1.173x |
| tg | bulk / 4096 / 1 | Gbit/s | 33.285 [32.709–36.011] | 35.320 [33.885–35.381] | 1.061x |
| tg | bulk / 4096 / 16 | Gbit/s | 24.990 [24.526–25.094] | 24.661 [24.539–26.759] | 0.987x |
| tg | bulk / 16384 / 1 | Gbit/s | 42.241 [41.997–42.300] | 45.439 [44.835–45.499] | 1.076x |
| tg | bulk / 16384 / 16 | Gbit/s | 31.952 [29.819–33.318] | 35.599 [35.588–35.730] | 1.114x |
| tg | bulk / 65536 / 1 | Gbit/s | 45.045 [44.810–45.836] | 56.395 [56.310–56.976] | 1.252x |
| tg | bulk / 65536 / 16 | Gbit/s | 36.690 [36.487–37.130] | 38.175 [37.919–38.408] | 1.040x |
| tg | echo / 16384 / 16 | k responses/s | 78.160 [77.817–79.399] | 81.334 [80.636–81.549] | 1.041x |
| tg | echo / 65536 / 16 | k responses/s | 17.514 [17.328–17.542] | 17.735 [17.626–17.738] | 1.013x |

The tg 64-KiB single-stream bulk ranges do not overlap. Its native receiver
linearized 38.14–38.98 GB over each complete trial; rpkt linearized zero bytes.
Both received logical frames up to 65226 bytes, with hundreds of thousands of
chains, and neither endpoint recorded RX misses in these six headline trials.
These cumulative counters include warmup/drain, unlike the goodput interval.
Twelve tg receiver trials record RX misses (up to 486419 per trial); ten
duanjp receiver trials do too (up to 8883). The matrix is delivered TCP goodput,
not a claim of zero-loss forwarding capacity. Adapter rejections range from
zero to 12 per endpoint/trial; this aggregate counter does not distinguish
unsupported background traffic from invalid checksums or malformed frames.

Reverse-placement bulk largely plateaus around the fixed slower sender's
capacity, consistent with peer limitation, although that attribution is not
proved by throughput alone. Larger single-stream gains cannot be extrapolated
to every connection count, request size, CPU or NIC. The 4-KiB reverse-placement
single-stream regression is variable and is not explained away or excluded.

## Extra-copy control

Same frozen binaries, host/core, 8192-byte RX configuration and workload; three
fresh alternating repetitions. Set `--linearize-rpkt` to retain rpkt's TCP
parser but restore the full chain-to-scratch copy and contiguous ingress.
Native smoltcp is rerun alongside it, not borrowed from the earlier matrix.

| tg workload | Unit | Native median [range] | Rpkt with extra copy median [range] | Ratio |
| --- | --- | ---: | ---: | ---: |
| bulk / 65536 / 1 | Gbit/s | 44.823 [44.511–45.245] | 45.775 [44.853–45.940] | 1.021x |
| bulk / 65536 / 16 | Gbit/s | 36.253 [36.048–36.997] | 36.205 [35.838–36.367] | 0.999x |
| echo / 16384 / 16 | M responses/s | 0.079 [0.078–0.080] | 0.079 [0.078–0.079] | 1.002x |

The single-stream advantage shrinks from 25.2% in the direct-path matrix to
2.1% with linearization restored. Native performance remains similar between
the two invocations. This supports the direct chained-buffer receive path as
the principal cause of that gain. It is not a perfect instruction-level
ablation of `memcpy` alone: it also restores contiguous interface dispatch.
It does show that retaining only rpkt's wire parser does not reproduce the
25% live gain. All 18 control trials have zero application errors and no TX
allocation failures; copy counters confirm actual linearization in both builds.

## Profiles

Six separate final-build runs sample user-space cycles at 997 Hz on tg CPU 4
for three seconds within the active window. They are excluded from throughput
medians. All six reports record zero lost samples. These are flat sample
shares, not call-graph attribution or exact CPU time saved.

| tg workload | Native large-copy instruction | Rpkt large-copy instruction | Native `mlx5_rx_burst` | Rpkt `mlx5_rx_burst` |
| --- | ---: | ---: | ---: | ---: |
| bulk / 65536 / 1 | 28.31% | 19.96% | 17.15% | 17.07% |
| bulk / 65536 / 16 | 38.39% | 27.77% | 6.62% | 9.05% |
| echo / 16384 / 16 | 9.46% | 7.92% | 5.99% | 6.44% |

The copy instruction is libc offset `0x1af1cc`, verified by disassembly as
`rep movsb` rather than trusting an unrelated nearest exported symbol in a
stripped library. It is still prominent in rpkt: the final socket-buffer copy
remains, and echo also copies for transmission. The instruction can serve
multiple callers, so its entire native share is not assigned to linearization.
Pbuf's `copy_to_slice` wrapper itself has 0.56%, 1.57% and 0.13% self samples
respectively; those small numbers exclude libc work called by the wrapper.

These profiles and the extra-copy control agree that data movement is material
here. They do not establish that TCP option parsing alone explains the live
improvement, nor that eliminating linearization eliminates all copy cost.
The driver, allocator, application verification, timers and remaining copies
continue to consume CPU.

Profiler: workspace-local `perf` 5.15.200, executable SHA-256
`9fb2475d2fa97f36098568c8981acd148fdad5b882f51ee970d33a6cc79612be`.
It was extracted from Ubuntu's matching kernel-tools package, without a
system package install or host-setting change. Profiled libc SHA-256:
`b2cf6c33b74d2f22543b7a469a75b538911e690f769d0b238843a49465b83793`.
Raw perf files remain at each server log path plus `.perf`; text reports are
checked in beside `tg-profile-final.jsonl`.

## What changes, and what does not

The distinguishing change is removal of the extra chain-to-scratch copy:

```text
native: NIC mbuf chain -> contiguous scratch -> TCP parser -> socket RX ring
rpkt:   NIC mbuf chain -> Pbuf/header views   -> socket RX ring
```

`DpdkRx::consume_pbuf` lends the real mbuf chain. Contiguous headers are
borrowed, including rpkt's TCP option views; split headers use at most 60 bytes
of scratch. Accepted payload ranges copy directly from `Pbuf` into final socket
storage. Ring-offset work is performed at most twice per packet (at ring wrap),
not once per source mbuf. A zero-length `Pbuf::trim_off` no longer walks the
chain. This is **one fewer full-frame copy**, not zero-copy TCP: the socket ring,
application verification and TX path still copy or read data.

TSO/LRO, checksum offloads, RX buffer sizing, the TX-pool capacity correction,
and timestamp alignment are shared improvements and are not credited to rpkt.
The lab NICs did not aggregate the original `TS,EOL,pad` timestamp layout;
both builds identically rewrite timestamp-only options to `NOP,NOP,TS` before
TX checksum offload. This is an observed interoperability requirement on these
NICs, not a general claim about all LRO implementations.

The prior TCP comparison already implemented borrowed option parsing and
generated paired field accessors. This experiment does not independently
attribute its live gain to option parsing. The extra-copy control retains
rpkt's parser while restoring chain linearization, to separate those effects.
Smoltcp could also be extended with a segmented receive API; this result is
not an inherent limitation of its TCP algorithms. Libpnet is not a TCP stack
and is not a comparator here.

## Correctness and scope

The experimental scatter ingress supports Ethernet/IPv4/TCP only. Chained
non-TCP protocols, raw sockets and IP-fragment reassembly are outside its
scope; the ordinary contiguous path is retained. RX BAD checksums are rejected;
UNKNOWN/NONE status triggers software verification across the chain. Headers,
lengths, options and relevant IP/address policies are still checked.

Validation includes six application tests for each backend, with byte-checked
connections, timestamps/SACK, loss/reordering, corrupted checksums, close,
logical large packets, split-header/odd chunk boundaries and small peer MSS;
448 native and 449 rpkt vendor tests; core/compiler tests and documentation
tests; an IPv6-only compile check; an isolated no-NIC DPDK test covering real
chains, RX checksum rejection, untouched direct-path scratch and TSO metadata;
the zero-trim Pbuf Miri regression; and six Python reporting tests.

An additional 16-trial, one-repetition matrix on duanjp checks the default
2048-byte RX data rooms with the corrected final TX pool. Every trial has
positive verified goodput, actual LRO chains/TSO, zero application/TX errors
and zero TX allocation failures, including the 4-KiB/16-connection workload
that previously stalled. This is a configuration regression check, not a
three-repetition performance result; its raw file is
`duanjp-default-rx-check.jsonl`. It is not pooled into the main 8192-byte table.

Final cleanup checks found no surviving TCP benchmark processes and duanjp
node-2 hugepages back at zero. All four dedicated link ports retained MTU
1500 and original pause settings (autoneg off, RX on, TX on). No pause or
host-network changes were needed for this TCP experiment.

Pilot failures are retained separately rather than silently dropped. An early
2047-buffer TX pool could starve behind a 2048-descriptor queue; the final
4095-buffer pool fixes that capacity error for both builds. Two exploratory
larger-memory configurations failed initialization; the final 384-MiB setup
checks hugepage allocation readback. Pilot timing/profile data use different
builds or settings and must not be pooled with final results.
