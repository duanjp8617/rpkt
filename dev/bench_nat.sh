#!/usr/bin/env bash
# Equivalent established-flow NAT, both shared hash policies, rotated order.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
cpu=${RPKT_BENCH_CPU:?Set RPKT_BENCH_CPU to an idle logical CPU}
label=${1:?Usage: RPKT_BENCH_CPU=N bash dev/bench_nat.sh LABEL [criterion arguments]}
shift
[[ $label =~ ^[a-zA-Z0-9._-]+$ ]] || exit 2
result=$(mktemp -d "$PWD/bench-results-$label.XXXXXX")
{
  date -u
  git rev-parse HEAD 2>/dev/null || echo "Synced snapshot: ${RPKT_BENCH_REVISION:?Set source revision}"
  rustc -Vv
  cargo -V
  sha256sum Cargo.lock Cargo.toml benches/Cargo.toml benches/nat_forward.rs \
    benches/nat_support/mod.rs rpkt/src/{ether,ipv4,tcp,udp}/generated.rs
  uname -a
  lscpu
  for setting in scaling_governor scaling_min_freq scaling_max_freq; do
    file="/sys/devices/system/cpu/cpu$cpu/cpufreq/$setting"
    if [[ -r $file ]]; then echo "$setting=$(<"$file")"; fi
  done
  file="/sys/devices/system/cpu/cpu$cpu/topology/thread_siblings_list"
  if [[ -r $file ]]; then echo "SMT siblings=$(<"$file")"; fi
  ps -eo pid,psr,pcpu,comm --sort=-pcpu | head -20 || true
  echo "CPU=$cpu RUSTFLAGS=${RUSTFLAGS:-}"
  cargo tree --locked -p benches --features nat-fast-table
} > "$result/environment.txt"
cp Cargo.lock rust-toolchain.toml "$result/"
for policy in siphash ahash; do
  features=()
  if [[ $policy == ahash ]]; then features=(--features nat-fast-table); fi
  for run in 0 1 2 3; do
    RPKT_BENCH_ORDER=$run taskset -c "$cpu" cargo bench --locked -p benches \
      "${features[@]}" --bench nat_forward -- --save-baseline "$label-$policy-$run" \
      --noplot --nresamples 1000 "$@" 2>&1 | tee "$result/$policy-$run.log"
  done
done
target_dir=$(cargo metadata --locked --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
cp -a "$target_dir/criterion" "$result/criterion"
echo "Results: $result"
