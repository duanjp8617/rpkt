# Full-field initialization and compiler-profile experiments

The benchmark-only `initializer_matrix` models the output of a proposed
full-field IPv4 initializer, grouping adjacent fields into complete stores.
It compares against the real generated `Ipv4` setters after `prepend_header`.
Both paths validate widths, initialize exactly 20 bytes, vary every supplied
field, and consume outputs. All 65536 input variants are byte-compared outside
timing with six guard bytes on either side. It does not change generated APIs,
independent setter semantics, or the general builder.

Three runs per profile on local WSL2, i5-13500H, logical CPU 2 (sibling 3), Linux
6.6.87.2-microsoft-standard-WSL2, Rust 1.98.0, committed lockfile, portable target,
no SIMD/batch features or RUSTFLAGS. WSL does not expose governor/temperature
control; host scheduling and turbo were not isolated. Treat small differences
as inconclusive. Criterion: 20 samples, 100 ms warmup, 200 ms measurement,
1000 resamples. Both initializer helpers have the same non-inlined call boundary
to retain assembly symbols. Input selection and output consumption are timed.

Reproduce and retain environment, flags, confidence intervals and baselines:

```sh
RPKT_BENCH_CPU=2 bash dev/bench_profiles.sh
```

The original runs used the same filter and explicit Cargo environment overrides
shown in that script; run order was fat, normal, single. The script groups them
normal, single, fat to make the one-setting-at-a-time comparison clear. Repeat
with alternating order and a dedicated native host before setting thresholds.

Median of three central estimates, ns/iteration:

| Workload | No LTO, 16 units | No LTO, 1 unit | Fat LTO, 1 unit |
| --- | ---: | ---: | ---: |
| Generated setters | 4.1881 | 4.3068 | 4.0718 |
| Full-field prototype | 4.0607 | 4.1846 | 4.0354 |
| Prepared complete 64-byte frame | 9.2274 | 8.9821 | 8.7493 |
| General complete 64-byte frame | 27.542 | 28.471 | 23.906 |
| Common parser, batch 32 | 215.18 | 218.79 | 231.33 |
| Mixed parser, batch 32 | 161.53 | 166.63 | 169.39 |

Per-run estimates and confidence intervals are in the adjacent JSON file.
Parser rows are per **batch**, not per packet; divide by 32. For example, the
fat-LTO common parser is 7.23 ns/packet, about 138 million packets/s in this
in-cache microbenchmark, not live I/O. No CPU-cycle claim is inferred from clock
frequency. The separate live report includes hardware performance counters.

## Decisions

- Under the chosen fat-LTO benchmark profile, full-field initialization is
  within 1% of setters with overlapping per-run intervals. No generated full-field
  API or grouped-store rewrite is retained in production. The benchmark prototype
  remains available to evaluate other protocols/platforms before API expansion.
- `nm -S` reports 188 bytes for the full-field helper and 301 for setters in the
  fat-LTO binary, including their assertion paths. `objdump -d -C` shows redundant
  template/staging stores in setters but no extra payload copy. LLVM already
  combines the two address stores into an ordinary 8-byte move and uses a
  16-byte unaligned template move; no explicit SIMD stores are justified.
- LTO helps the complete general builder here, but is not a universal parsing
  speedup. Keep normal release inexpensive and the `performance` profile opt-in;
  do not change release defaults or impose regression thresholds from these data.
- The cached common parser's separate forced-inlining experiment is recorded in
  the batch report; it did not justify production annotations. These compiler
  settings are evaluated independently of introducing a new parser/checksum API.

The complete benchmark executable (including Criterion/plotting, not just rpkt)
has 2,412,944 text bytes under fat LTO. This is a whole-program size observation,
not the library's incremental footprint.
