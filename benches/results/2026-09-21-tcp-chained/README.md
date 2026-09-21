# Raw chained-TCP evaluation data

The interpretation and methods are in [the report](../2026-09-21-tcp-chained.md).

- `tg-final.jsonl`, `duanjp-final.jsonl`: main three-repetition matrices,
  8192-byte RX data rooms, final frozen performance-profile executables.
- `copy-control.jsonl`: three fresh paired repetitions with linearization
  restored in rpkt; the native backend is rerun alongside it.
- `tg-profile-final.jsonl` and associated `*.perf.txt`: separate instrumented
  active-window runs. Do not use these as throughput repetitions.
- `duanjp-default-rx-check.jsonl`: one repetition of all eight cases for both
  backends with default 2048-byte RX data rooms and the final TX pool. A
  configuration regression check, not part of the main three-repetition table.
- `*.environment.json`: source/executable hashes and environment captured
  before each invocation. Runtime source hashes match commit `0a07285` for
  final runs; later commits contain reporting/runner changes only.
- `pilot/`: exploratory runs, including older pool sizes/builds, initialization
  failures and the recorded TX-pool-starvation failure. These are not part of
  the final medians. `rx8192-pilot3` is a successful early check of the final
  configuration, also excluded from the main matrix.

JSON device counters cover the whole process, including warmup and drain.
Application `bytes`/`responses` and `measured_ns` cover the measurement window.
Perf text reports have trailing whitespace removed for clean version control;
sample values and symbols are unchanged.
Do not divide cumulative copy/NIC counters by the measured five seconds and
present that as an active-window rate. Remote log paths in each record identify
the complete original process output.

Use the report script, which checks backend pairs, frozen binary hashes and
actual offload/copy-path evidence:

```sh
python3 dev/tcp_report.py \
  benches/results/2026-09-21-tcp-chained/tg-final.jsonl \
  benches/results/2026-09-21-tcp-chained/duanjp-final.jsonl
```
