# Incremental checksum smoke comparison

Local i5-13500H, CPU 2 affinity, Rust 1.98, default portable features, bench
profile (fat LTO, one codegen unit), 20 samples, 100 ms warmup and 200 ms
measurement. `cargo bench --locked -p benches --bench matrix -- forward_checksum
--noplot --nresamples 1000` measured TTL-word replacement at 0.951 ns (95% CI
0.937–0.963 ns), versus a complete 20-byte IPv4 checksum scan at 3.460 ns
(3.346–3.558 ns). This is a small-kernel smoke comparison, not a forwarding
speedup estimate; both paths exclude packet loads/stores outside the checksum.

The update follows [RFC 1624 equation 3](https://datatracker.ietf.org/doc/html/rfc1624).
It requires a verified initial checksum. An offload-pending checksum or arbitrary
unverified input is not a valid starting point. IPv4 UDP checksum zero means
omitted; `replace_udp_ipv4_word` preserves that state and maps computed zero to
0xffff. The general helpers leave protocol-specific normalization to callers.
Address changes must also update the transport pseudo-header checksum.

The RFC worked example and 10,000 generated TTL/address/pseudo-header changes
match complete recomputation. SIMD is unnecessary for this constant-size update.
