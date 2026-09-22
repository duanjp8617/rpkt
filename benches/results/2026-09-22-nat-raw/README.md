# Raw-slice accessor experiment

Runtime snapshot: `fbe5d2a`. Raw source archives on duanjp and tg and the
pre-transformation checked archive match 65 runtime source/manifest hashes
in `source-manifest.json`.

The checked ablation changes generated `.get_unchecked[_mut](constant)` to
`.get[_mut](constant).unwrap()`, with an unused-unsafe warning suppression.
Everything else, including the new slice-backed representation, structural
checks, NAT adapters, table and checksums, stays identical. The script's
`rg` calls were replaced by standard grep/find for the lab host; this changes
no runtime source. This is a controlled comparison, not the old array-view
binary from the previous report.

Both profiles keep the previous frozen tg generator/sink executable:
`/root/rpkt-nat-release-20260922/frozen/nat_loop-performance`, SHA-256
`da96d0ff68df6f4a22f4a34c2c7e21e22db9871eeeafe1111ccc24a7f6950579`.

All DUT libraries use the selected raw binary, except `rpkt-checked`, which
uses the checked binary's rpkt mode. This control is interleaved with the
library comparison, not measured on a different day. Runs are sequential;
profiling runs do not enter throughput medians. The runner records both DUT
hashes in environment metadata and the actual binary in each row.

The selected workloads are UDP/TCP at 64 and 1500 bytes with 4096 flows, plus
IPv4/TCP options at 128 bytes with 4096 flows. The options workload does not
decode TCP option contents. Results measure returned goodput under overload,
not zero-loss capacity.

`release-matrix.jsonl` and `performance-matrix.jsonl` each contain 60 trials;
their separate `*-profiles.jsonl` files each contain 12 instrumented trials.
Environment metadata records compiler inputs, binary hashes and original
port state. Build logs retain verbose compiler invocations; codegen text files
compare raw and checked accessor-bearing functions. Final independent state
and executable hash readback is in `final-restoration.json`.

See [the report](../2026-09-22-nat-raw.md) for results, caveats and reproduction.
