#!/usr/bin/env bash
# Generate paired runtime/proof output; never silently accept runtime drift.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
case "${1:-}" in
  '') mode=write ;;
  --check) mode=check ;;
  *) echo 'Usage: dev/gen_verus.sh [--check]' >&2; exit 2 ;;
esac
if (( $# > 1 )); then exit 2; fi
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
cd "$root"
protocols=(arp ether ipv4 llc mpls stp tcp udp vlan vxlan pppoe gre ipv6 gtpv1 gtpv2 icmpv4)
for protocol in "${protocols[@]}"; do
  cargo run --quiet --locked --offline -p pktfmt --bin pktfmt -- \
    "pktfmt/protocols/$protocol.pktfmt" -o "$stage/$protocol-runtime.rs" \
    --verus "$stage/$protocol.rs"
  rustfmt --edition 2021 "$stage/$protocol-runtime.rs"
  diff -u "rpkt/src/$protocol/generated.rs" "$stage/$protocol-runtime.rs"
done
mkdir -p verification/generated
status=0
for protocol in "${protocols[@]}"; do
  if [[ $mode == check ]]; then
    diff -u "verification/generated/$protocol.rs" "$stage/$protocol.rs" || status=1
  else
    cp -- "$stage/$protocol.rs" "verification/generated/$protocol.rs"
  fi
done
exit "$status"
