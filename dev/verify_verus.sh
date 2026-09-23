#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
verus=${VERUS:-verus}
"$verus" --version
"$verus" --version | grep -Fq 'Version: 0.2026.09.20.aef82ed'
bash dev/gen_verus.sh --check
# No local axioms or admitted function bodies in the proof inputs.
if grep -En 'assume\(|admit\(|verifier::external|external_body|assume_specification' \
    verification/buffers.rs verification/packet.rs verification/clients.rs rpkt/src/buffer_math.rs \
    verification/generated/*.rs; then
  echo 'Unexpected trusted/admitted item in proof inputs' >&2
  exit 1
fi
"$verus" --no-cheating --triggers-mode silent verification/main.rs
PYTHONDONTWRITEBYTECODE=1 python3 dev/test_verus_negative.py "$verus"
