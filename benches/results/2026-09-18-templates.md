# Prepared UDP flow experiment

Three runs on tg's Xeon Gold 6230, taskset CPU 2, Rust 1.98, committed lockfile,
portable default features, fat LTO and one codegen unit. Command:
`cargo bench --locked -p benches --bench matrix -- prepared_build --noplot
--nresamples 1000`. Both methods copy the same payload, write identical headers
and compute valid IP/UDP checksums; equality is checked before timing. Buffers
and templates are allocated/prepared outside timing; identification changes on
each iteration. Entries are medians of three central estimates, ns/frame.

| Ethernet bytes excluding FCS | Prepared | General | General / prepared |
| --- | ---: | ---: | ---: |
| 64 | 15.08 | 32.35 | 2.15 |
| 128 | 19.23 | 39.46 | 2.05 |
| 512 | 49.25 | 69.19 | 1.40 |
| 1500 | 114.70 | 137.56 | 1.20 |
| 9000 | 657.13 | 631.39 | 0.96 |

The prepared API is retained for repeated small/standard-MTU UDP flows, where
all three runs showed a benefit. It does not replace the general builders;
the general path was about 4% faster for the 9000-byte case. Header work is a
small part of that large-payload workload. No explicit vector stores are added:
ordinary fixed-size copy already lets the compiler select stores without
overwriting neighboring bytes. Options, VLAN, fragments and TCP continue to
use general composition. No universal speedup or regression threshold is claimed.

Correctness: general-builder byte equality for lengths 0–259, 511, 1500, 9000,
and the maximum 65507-byte payload; guard bytes, output unchanged on errors,
and checksum-zero normalization. Native tests and all three Miri tests pass.
