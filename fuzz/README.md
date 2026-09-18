# Parser and buffer safety checks

`cargo test -p rpkt --test properties` deterministically exercises thousands of
random, zero-filled and all-ones inputs, parser length bounds, option iterator
progress, cursor movement, odd checksum segment boundaries and Ethernet/IPv4/UDP
build/parse round trips. The same properties drive `checked_packets`:

```sh
cargo install cargo-fuzz --locked
cargo +nightly fuzz run checked_packets -- -max_len=65536 -max_total_time=60
```

Run from the repository root. Keep minimized failures as regression tests;
corpus/artifacts are intentionally untracked. A bounded smoke run is not proof
that arbitrary malformed input is safe.

Install nightly with `miri` and `rust-src`, then run `bash dev/check_safety.sh`.
The core path needs no DPDK. With DPDK headers/libraries available for the build,
`bash dev/check_safety.sh --dpdk` also checks the real Mbuf/Pbuf implementations
using their existing `cfg(miri)` Rust allocator; it never initializes EAL or
calls a native DPDK function during interpretation. The small segment sweep
covers odd chunks, exact ends, backward movement and truncation. Native SIMD
and NIC DMA require separate native tests. Set `MIRI_TOOLCHAIN` to pin a nightly.
