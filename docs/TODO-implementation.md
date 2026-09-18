# TODO implementation and review map

The first repair feature was merged as PR #11. CI PR #12 remains the base of
this review stack. The remaining prioritized features and the performance
experiments are covered below. No PR has been merged by the implementation
agent; review/merge the stack in numerical order, retargeting each next PR to
main as needed. Each PR's current base is the preceding feature branch so its
diff stays focused.

| TODO area | PR | Outcome |
| --- | --- | --- |
| 3. Reproducible generation | [#13](https://github.com/duanjp8617/rpkt/pull/13) | Atomic staged regeneration, target-directory support, drift check and protocol status |
| 4. no_std boundary | [#14](https://github.com/duanjp8617/rpkt/pull/14) | bytes feature forwarding, core-only generated paths, bare-metal CI |
| 5. Workspace/examples | [#15](https://github.com/duanjp8617/rpkt/pull/15) | Explicit legacy exclusion, opt-in performance profile, all maintained DPDK examples migrated/compiled |
| 6. Parser/unsafe validation | [#16](https://github.com/duanjp8617/rpkt/pull/16) | Deterministic properties, fuzz target, Miri core/segmented-buffer path, unsafe invariants |
| 7. Onboarding/diagnostics | [#17](https://github.com/duanjp8617/rpkt/pull/17) | Compiling README examples, setup/jumbo/test guidance, actionable pkg-config/Clang diagnostics |
| 8 and performance 1. Repeatable measurements | [#18](https://github.com/duanjp8617/rpkt/pull/18) | Pinned toolchain/lockfile, equivalent-work matrix, artifact capture |
| Performance 2. Checksums | [#19](https://github.com/duanjp8617/rpkt/pull/19) | Overflow-safe scalar/segmented sums and optional measured AVX2 backend |
| Performance 5. Incremental edits | [#20](https://github.com/duanjp8617/rpkt/pull/20) | RFC 1624 word/address replacement, UDP-zero rules, recomputation tests |
| Performance 4. Repeated construction | [#21](https://github.com/duanjp8617/rpkt/pull/21) | Prepared Ethernet/IPv4/UDP template, initialized output, byte-equivalence and performance tests |
| Performance 3 and 4. Common/batch parsing | [#22](https://github.com/duanjp8617/rpkt/pull/22) | Optional safe borrowed batch API, immutable cached facts, explicit fallback/order/partial handling |
| Performance 5 and 6. Offload/local batched I/O | [#23](https://github.com/duanjp8617/rpkt/pull/23) | Bounded two-link harness, NUMA fix, software/offload/burst/RTT/drop measurements on both hosts |
| Performance 4 and acceptance experiments | [#24](https://github.com/duanjp8617/rpkt/pull/24) | Full-field initializer prototype, separate LTO/codegen-unit comparisons, raw confidence intervals and this review map |
| Follow-up: common protocols and TCP options | [#25](https://github.com/duanjp8617/rpkt/pull/25) | Equivalent checked Ethernet/IPv4/UDP/TCP workloads, borrowed option comparison, 486 native measurements and CI equivalence checks; blanket fastest-for-every-header target remains unmet |

## Measured acceptance, not unconditional optimization

The performance section describes hypotheses. Experiments with negative or
inconclusive results are completed work, not enabled production optimizations:

- AVX2 checksums are opt-in, safely dispatched and used only at 512 bytes and
  above. A multiple-accumulator scalar variant was rejected after measurement.
  Portable/no_std/Miri fallbacks remain. No NEON backend is shipped: the supplied
  native machines are x86-64, so ARM performance/correctness was not validated.
- The checked batch API provides useful error/fallback semantics but was slower
  than the existing scalar parser loop in this workload. The SIMD packing
  prototype remains benchmark-only; no gather/automatic SIMD batch path is
  selected. Forced inlining did not justify production annotations.
- Prepared templates improve repeated small-flow construction here, but ordinary
  building remains preferable for the measured 9000-byte case. Variable options,
  TCP and general composition stay on existing builders.
- The grouped full-field initializer prototype did not materially beat generated
  setters under the selected benchmark profile. No generator-wide rewrite or
  explicit vector stores are retained. Independent setters preserve unrelated bits.
- LTO is an explicit profile choice, not a universal speedup. The profile study
  separates codegen-unit count from LTO. No timing regression threshold is imposed.
- Live counters did not establish a memory-stall bottleneck requiring application
  prefetch tuning. No speculative prefetch or unchecked parser shortcut was added.

Reports and reproducible workloads are under [benches](../benches/README.md)
and [benches/results](../benches/results). Their environments, confidence
intervals, negative results and scope limits are part of the deliverable.

## Validation scope

Core/compiler tests and doctests, compiler diagnostic fixtures, generation
drift, bare-metal no_std (including optional features), Miri, fuzz smoke, and
optimized matrix correctness were exercised. DPDK examples/tests compile
against 21.11 locally and 24.11 on the two remote machines. Both machines passed
the isolated native DPDK suite after the NUMA fix. The final live matrix returned
334,248,607 marked packets with zero checksum errors. Temporary duanjp hugepages
were restored to zero; MTUs remain 1500 and test traffic processes were stopped.

GitHub's hardware job remains explicitly provisioned/opt-in; its normal PR skip
does not mean the live tests ran in hosted CI. The checked-in lab report records
the separately executed hardware tests. Other NICs/PMDs, jumbo live traffic,
multi-worker scaling and ARM SIMD are not claimed to have been benchmarked.
