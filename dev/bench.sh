#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
cpu=${RPKT_BENCH_CPU:?Set RPKT_BENCH_CPU to an idle logical CPU}
label=${1:?Usage: RPKT_BENCH_CPU=N dev/bench.sh LABEL [criterion arguments]}
shift
[[ $label =~ ^[a-zA-Z0-9._-]+$ ]] || { echo 'Invalid baseline label' >&2; exit 2; }
result=$(mktemp -d "$PWD/bench-results-$label.XXXXXX")
{
  date -u
  git rev-parse HEAD
  git status --short
  rustc -Vv
  cargo -V
  sha256sum Cargo.lock
  uname -a
  lscpu
  taskset -pc $$
  echo "CPU=$cpu RUSTFLAGS=${RUSTFLAGS:-} RPKT_BENCH_FULL=${RPKT_BENCH_FULL:-}"
  cargo tree --locked -p benches
} > "$result/environment.txt"
cp Cargo.lock rust-toolchain.toml "$result/"
baseline_args=(--save-baseline "$label")
for arg in "$@"; do
  if [[ $arg == --baseline || $arg == --baseline=* ]]; then baseline_args=(); fi
done
taskset -c "$cpu" cargo bench --locked -p benches --bench matrix -- "${baseline_args[@]}" "$@" 2>&1 | tee "$result/run.log"
target_dir=$(cargo metadata --locked --no-deps --format-version 1 | jq -r .target_directory)
cp -a "$target_dir/criterion" "$result/criterion"
echo "Results: $result"
