#!/usr/bin/env bash
# Generate all supported protocols, or check without modifying the source tree.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
case "${1:-}" in
  '') mode=write ;;
  --check) mode=check ;;
  *) echo 'Usage: gen_cmds.sh [--check]' >&2; exit 2 ;;
esac
if (( $# > 1 )); then echo 'Usage: gen_cmds.sh [--check]' >&2; exit 2; fi
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
protocols=(arp ether ipv4 llc mpls stp tcp udp vlan vxlan pppoe gre ipv6 gtpv1 gtpv2 icmpv4)
cd "$root"
for protocol in "${protocols[@]}"; do
  # Cargo resolves the executable, including CARGO_TARGET_DIR and Cargo config.
  cargo run --quiet --manifest-path "$root/Cargo.toml" -p pktfmt --bin pktfmt -- \
    "$root/pktfmt/protocols/$protocol.pktfmt" -o "$stage/$protocol.rs"
  rustfmt --edition 2021 "$stage/$protocol.rs"
done
# Finish all generation successfully before touching any tracked file.
status=0
for protocol in "${protocols[@]}"; do
  destination="$root/rpkt/src/$protocol/generated.rs"
  if [[ $mode == check ]]; then
    diff -u "$destination" "$stage/$protocol.rs" || status=1
  else
    cp -- "$stage/$protocol.rs" "$destination"
  fi
done
exit "$status"
