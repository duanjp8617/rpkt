# Live NAT optimization checkpoint — target NOT met

Historical exploratory log. The later, approved pause-off experiments and
equalized competitors are documented in [the follow-up report](2026-09-20-nat-equalized.md).
The earlier outlined profiles below must not be used to describe the final
inlined, equally specialized adapters.

This is an exploratory checkpoint, not a completed performance result. The
requested approximately 1.15x live advantage over **both** libraries remains
unmet. In particular, the faster vector-RX configurations often make smoltcp
faster than rpkt. Do not select the favorable scalar result and call the target
achieved. None of these changes is justified as a 15% live improvement over
smoltcp.

The probes below use 64-byte UDP/TCP, 64 flows, a single DUT worker on duanjp
CPU 60, and the original two-link loop through tg. They are **one run per
library per case**, not repeated, randomized acceptance measurements. The
original 512/1500-byte, 4096-flow, mixed and options acceptance matrix must be
rerun after a promising candidate is found. The existing large-frame link-rate
limit still applies; see [the prior report](2026-09-18-nat.md).

## Experiments, including failures

Returned Mpps use all accepted sink packets divided by the generator duration.
All sizes exclude FCS. Sender/sink worker changes apply to all competitors;
the DUT always has one worker. Pause flow control was enabled and unchanged
in the historical probes in this table.
All runs include loss; they are not zero-loss forwarding-capacity measurements.

| Probe | UDP rpkt / pnet / smoltcp Mpps | TCP rpkt / pnet / smoltcp Mpps | Interpretation |
| --- | --- | --- | --- |
| PR27 baseline, whole-process profiling | 22.552 / 17.869 / 22.193 | 22.884 / 18.326 / 20.371 | Baseline; profiling includes startup and idle time. |
| Shared hash packing + header prefetch | 24.818 / 19.365 / 23.598 | 25.618 / 19.045 / 24.632 | Absolute gains, not a distinguishing packet-API optimization. |
| Typed adjacent address accesses | 24.493 / 18.738 / 24.162 | 25.295 / 19.649 / 24.664 | No demonstrated extra live gain. |
| Same code, vector RX | 26.233 / 23.056 / 26.714 | 24.814 / 22.899 / 26.498 | Two-worker sink drops millions of packets. |
| Outlined kernels + vector RX | 25.915 / 22.905 / 27.646 | 27.269 / 21.422 / 27.786 | Also sink-limited; outlining not retained. |
| Active-window profile, vector RX, four sink workers | 27.726 / 23.105 / 28.752 | 26.789 / 21.211 / 28.735 | Removes the large sink loss, but not the smoltcp gap. |
| Native target, vector RX, four sender/four sink workers | 27.787 / 22.470 / 29.058 | 28.349 / 22.138 / 28.433 | Same target settings for all adapters; no target win. |
| Checked fixed-prefix specialization, four/four workers | 26.450 / 22.331 / 29.233 | 28.386 / 21.564 / 29.188 | Rejected; no improvement, removed from source. |
| Restore inlined kernels, vector RX, four/four workers | 26.373 / 22.603 / 28.628 | 27.806 / 23.867 / 28.426 | Still misses smoltcp, not an accepted final configuration. |
| Outlined scalar RX, four/four workers | 23.389 / 19.433 / 22.780 | **Invalid/incomplete** | pnet traffic ended after 3.30 s; runner aborted, no TCP ratio is valid. |

Raw records, including that invalid trial and all drop/error counters, are in
[the adjacent investigation directory](2026-09-20-nat-investigation/). No bad
packet/checksum samples were detected. This is sampled payload checking, not
exhaustive validation of every received byte. Sender unsent packets and DUT/sink
misses remain in the raw data.

These probes were sequential, not controlled ablations: some compilation
overlapped preliminary runs, and other users' CPU-heavy jobs remained active.
The shared-pilot binary was rebuilt near the last trial; that row is particularly
unsuitable for causal attribution. Later probes used frozen, separately named
binaries. Environment files from early runner versions hash the current build
path, which need not be the frozen DUT path; use the binary inventory below.
The raw experiment snapshots are **not** a claim that every frozen binary has
an archived, exactly reproducible source revision. A final acceptance run needs
a committed source snapshot, exact binary hashes, no simultaneous builds and
rotated repeated trials. The runner now records the selected binary's hash and
its options explicitly.

A header-snapshot/store-coalescing prototype was built and removed. It has no
separate live result and no performance claim. Specialized fixed-prefix parsing
needs equivalently specialized competitor adapters before supporting a fair
library comparison. The follow-up report includes that essential control.

## What the profiling actually distinguishes

For the outlined diagnostic binary, `perf record` sampled cycles at 999 Hz using
the monotonic clock. The application records first/last accepted-burst times;
reports discard 250 ms at either edge. These are profiles of **that diagnostic
binary**, not a claim about the exact costs of the final inlined code. The
separate `perf stat` counters still cover the whole process and must not be
divided by packet counts to claim active cycles/packet.

Observed assembly-level distinctions limited to parsing and field access:

1. **Disjoint exact-size header views.** rpkt separates fixed headers from
   payload at checked parsing boundaries. The outlined rpkt kernel does not
   call a payload-slicing function. smoltcp's `Ipv4Packet::payload_mut` remains
   out of line in this binary, with dynamic range construction/checking and
   additional live register state. It accounts for approximately 4% of sampled
   active cycles. This is a compiler/build observation, not an inherent claim
   that smoltcp cannot inline it or eliminate bounds checks.
2. **Packed adjacent field access.** The typed-address generator extension
   reads the two IPv4 addresses with one 64-bit load/byte swap, instead of the
   two 32-bit loads/conversions seen in this smoltcp kernel. rpkt writes the
   port pair with one 32-bit store and address pair with one 64-bit store;
   this smoltcp binary uses separate 16-bit port stores and 32-bit address
   stores. Importantly, LLVM already combines smoltcp's two **port reads** into
   one 32-bit read here: that read is not a distinguishing rpkt optimization.
3. **Accessor inlining.** Numerous libpnet getters/setters remain separate
   calls in the profiled optimized binary. Generated rpkt field access is
   inlined into the packet kernel. This removes call/return and some state
   preservation overhead in this build. It is not evidence that every pnet
   accessor is necessarily out of line on every compiler or target.

The outlined packet-kernel symbol sizes are 617 bytes for rpkt, 780 bytes for
smoltcp and 992 bytes for pnet. These exclude called helpers and are not total
library footprints or throughput estimates. The UDP profile attributes 22.36%
of active cycle samples to the rpkt kernel, 27.07% to smoltcp's kernel plus 4.14%
to its IPv4 payload helper, and 32.34% to pnet's kernel plus accessor callees.
These kernels include checksum arithmetic; their different sample fractions
must not be presented as isolated parsing speedup percentages. RX/TX, queue
completion/decompression, hashing and the common forwarding loop consume much
of the remaining time. The profiles guide investigation; they do not establish
the requested live advantage.

Not distinguishing packet-library optimizations: the shared two-word tuple
hashing, shared precomputed checksum deltas, shared prefetch pass, NIC vector
RX, sender/sink worker count, target-cpu flags, and equivalent inlining policy.
Do not credit those exclusively to rpkt. NAT checks TCP data-offset bounds but
does not decode option contents, so borrowed TCP-option iteration cannot
explain a gain in these NAT trials.

## Correctness and next gate

The typed-pair generator follows the same custom-type-to-integer conversions as
individual setters, excludes fixed/constrained-width fields and preserves
neighboring bytes. Compiler regression tests and packet byte-equivalence tests
cover those rules. The NAT correctness sweep is now a Cargo test, including
truncations, malformed headers, all checksum values, UDP omitted/computed-zero
checksums, padding and unaligned buffers. Core/compiler tests, doctests, no_std
check and compiler diagnostic fixtures passed locally. The typed-pair generator
uses safe fixed-slice operations.

The user subsequently approved temporarily disabling pause on the **four
dedicated test-link ports**, testing libraries identically and restoring the
settings. Those follow-up runs are separately recorded. They do not turn these
historical probes into controlled ablations or establish a 1.15x win.

## Frozen DUT binary inventory

All reside under `/home/duanjp/rpkt-ws/bench-results-live-opt/`.

| Binary | SHA-256 |
| --- | --- |
| nat_loop-pr27 | dd916440f3e7c3bd40b9db6e203fb7f36559364716891a7b96edde8832c3f2ce |
| nat_loop-shared | 159f09a8dce4d798b0fd16d18de21308ca07dd7d2b6da45e3a838952dbfa494c |
| nat_loop-pairs | cbbc9014f273354ff359db8bdd4c1798a8bf94ff9f0bef1f08997dca7225a918 |
| nat_loop-outline | 67bace2a5ee5ba327ee5f470b494534893418ce0eb2a8f412370ec8988813397 |
| nat_loop-profile | 6227e211e1b4fd5a8b1bb74b44aa926af171e33eea7151c4638983dd8d05c679 |
| nat_loop-native | 09b3fb1f4a7cda56e412d18905988f120a09e86375875b8792b60a25f2347af7 |
| nat_loop-snapshot | 016a5f0e1849d65da80d8e5eb95a73667b37818d105e80a1bd06ced48bef0474 |
| nat_loop-fixed | 4b87a13df9ae49c8dd5e8962ed2fc1bf6fef098554d25d3cfb39b0d9e6e32335 |
| nat_loop-inline | 13c678324f1234fbbb9554c0d534ccdeec279e877307443c868446e43e6c8d3c |
