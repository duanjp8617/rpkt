#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
# Override MIRI_TOOLCHAIN to reproduce a particular nightly.
toolchain=${MIRI_TOOLCHAIN:-nightly}
cargo +"$toolchain" miri test -p rpkt --lib cursors
cargo +"$toolchain" miri test -p rpkt --test properties
if [[ ${1:-} == --dpdk ]]; then
  cargo +"$toolchain" miri test -p rpkt-dpdk --test mbuf_miri mbuf_data_append_remove
  cargo +"$toolchain" miri test -p rpkt-dpdk --test segment_properties
fi
