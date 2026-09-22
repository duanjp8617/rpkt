#!/usr/bin/env bash
# Run inside the frozen NAT source checkout, with PKG_CONFIG_PATH set for DPDK.
# Keep normal-release and fat-LTO control executables separate and immutable.
set -euo pipefail
profile=${1:?release or performance}
cores=${2:?build CPU list}
case "$profile" in release|performance) ;; *) exit 2 ;; esac
: "${PKG_CONFIG_PATH:?Set the host-specific DPDK pkg-config directory}"
mkdir -p frozen
test ! -e "frozen/nat_loop-$profile"
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
unset CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS
# Explicitly pin Cargo's ordinary release defaults, not cross-crate ThinLTO.
export CARGO_PROFILE_RELEASE_LTO=false
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
export CARGO_PROFILE_RELEASE_OPT_LEVEL=3
export CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_PROFILE_RELEASE_INCREMENTAL=false
export CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false
export CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS=false
export CARGO_PROFILE_RELEASE_PANIC=unwind
export CARGO_PROFILE_RELEASE_STRIP=none
# The control reproduces the earlier workspace performance profile.
export CARGO_PROFILE_PERFORMANCE_LTO=fat
export CARGO_PROFILE_PERFORMANCE_CODEGEN_UNITS=1
rustc -Vv
cargo -V
pkg-config --modversion libdpdk
printf 'profile=%s build_cpus=%s\n' "$profile" "$cores"
taskset -c "$cores" cargo build --locked --offline -vv -j 4 --profile "$profile" \
    -p rpkt-dpdk --example nat_loop --features nat-fast-table
cp "target/$profile/examples/nat_loop" "frozen/nat_loop-$profile"
sha256sum "frozen/nat_loop-$profile"
