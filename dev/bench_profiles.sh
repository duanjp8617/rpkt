#!/usr/bin/env bash
# Compare one compiler-profile setting at a time, preserving all nine runs.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
: "${RPKT_BENCH_CPU:?Set RPKT_BENCH_CPU to an idle logical CPU}"
filter='field_initialization|prepared_build/64/|parse/warm/mixed(false|true)/64/rpkt_generic/32$'
for profile in normal single fat; do
  export CARGO_PROFILE_BENCH_LTO=false
  export CARGO_PROFILE_BENCH_CODEGEN_UNITS=16
  if [[ $profile != normal ]]; then export CARGO_PROFILE_BENCH_CODEGEN_UNITS=1; fi
  if [[ $profile == fat ]]; then export CARGO_PROFILE_BENCH_LTO=fat; fi
  for run in 1 2 3; do
    bash dev/bench.sh "profile-$profile-$run" "$filter" --noplot --nresamples 1000 "$@"
  done
done
