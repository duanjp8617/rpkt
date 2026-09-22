# Default-release NAT artifacts

See [the report](../2026-09-22-nat-release.md) for interpretation and methods.

Runtime source: `725d45b` on both hosts, extracted into separate fresh build
directories. `build-*.log` contains verbose compiler commands and frozen
binary hashes. The default-release DUT and fat-LTO control use the same
source; the traffic engine stays on one fixed fat-LTO executable throughout.

- `release-matrix.jsonl`: 90 uninstrumented default-release trials, three
  rotated-order repetitions of ten cases and three libraries.
- `release-profiles.jsonl`: first 24 instrumented default-release trials.
  The final record has one input checksum failure and stopped the invocation;
  it is retained, not a passing result.
- `release-profiles-followup.jsonl`: nine passing instrumented trials:
  repeat TCP/1500/4096 for all libraries, then mixed and options workloads.
  Across both files all 30 workload/library pairs are covered. Embedded
  `perf_report` is active-window cycle sampling; `perf_stat` covers the whole
  process and is not cycles per packet. Never pool these with throughput runs.
- `performance-control.jsonl`: separate uninstrumented fat-LTO control,
  three rotated repetitions of UDP/TCP with 64-byte packets and 64 flows.
- `source-manifest.json`: 65 source/manifest inputs checked against Git on
  both hosts. Disassembly excerpts identify exact addresses in the frozen DUT.
- `*.environment.json`: selected source paths, executable hashes and initial
  pause/link/hugepage settings. Do not mix profiles or configurations.
- `final-restoration.json`: independent final pause/hugepage/process checks
  and frozen executable hashes after every measurement had finished.

Rates are accepted sink packets divided by generator elapsed seconds. Driver
miss counters do not completely account for offered/received differences;
these data do not establish zero-loss capacity. Rejected traffic is retained
as counts, not assumed to be valid NAT output or retroactively classified.
