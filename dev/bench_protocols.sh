#!/usr/bin/env bash
# Run on each native host on an idle pinned CPU; preserve inputs and all runs.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
cpu=${RPKT_BENCH_CPU:?Set RPKT_BENCH_CPU to an idle logical CPU}
label=${1:?Usage: RPKT_BENCH_CPU=N bash dev/bench_protocols.sh LABEL [criterion arguments]}
shift
[[ $label =~ ^[a-zA-Z0-9._-]+$ ]] || { echo 'Invalid label' >&2; exit 2; }
for program in cargo rustc taskset jq sha256sum; do
  command -v "$program" >/dev/null || { echo "Required tool missing: $program" >&2; exit 2; }
done
result=$(mktemp -d "$PWD/bench-results-$label.XXXXXX")
{
  date -u
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git rev-parse HEAD
    git status --short
  else
    echo "Synced snapshot: ${RPKT_BENCH_REVISION:?Set RPKT_BENCH_REVISION for a source tree without .git}"
  fi
  rustc -Vv
  cargo -V
  sha256sum Cargo.lock Cargo.toml benches/Cargo.toml benches/protocols.rs \
    rpkt/src/ipv4/generated.rs rpkt/src/tcp/generated.rs
  uname -a
  lscpu
  for setting in scaling_governor scaling_min_freq scaling_max_freq; do
    file="/sys/devices/system/cpu/cpu$cpu/cpufreq/$setting"
    if [[ -r $file ]]; then echo "$setting=$(<"$file")"; fi
  done
  file="/sys/devices/system/cpu/cpu$cpu/topology/thread_siblings_list"
  if [[ -r $file ]]; then echo "SMT siblings=$(<"$file")"; fi
  ps -eo pid,psr,pcpu,comm --sort=-pcpu | head -20 || true
  echo "CPU=$cpu RUSTFLAGS=${RUSTFLAGS:-} RPKT_BENCH_FULL=${RPKT_BENCH_FULL:-}"
  echo "CARGO_PROFILE_BENCH_LTO=${CARGO_PROFILE_BENCH_LTO:-manifest} CARGO_PROFILE_BENCH_CODEGEN_UNITS=${CARGO_PROFILE_BENCH_CODEGEN_UNITS:-manifest}"
  cargo tree --locked -p benches
} > "$result/environment.txt"
cp Cargo.lock rust-toolchain.toml "$result/"
for run in 0 1 2; do
  RPKT_BENCH_ORDER=$run taskset -c "$cpu" cargo bench --locked -p benches --bench protocols -- \
    --save-baseline "$label-$run" --noplot --nresamples 1000 "$@" 2>&1 | tee "$result/run-$run.log"
done
target_dir=$(cargo metadata --locked --no-deps --format-version 1 | jq -r .target_directory)
cp -a "$target_dir/criterion" "$result/criterion"
echo "Results: $result"
