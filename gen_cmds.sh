#!/bin/bash

# Define a list of strings
strings=("arp" "ether" "ipv4" "llc" "mpls" "stp" "tcp" "udp" "vlan" "vxlan" "pppoe" "gre" \
         "ipv6" "gtpv1" "gtpv2")
# strings=("stp")

# Iterate over the list
for item in "${strings[@]}"; do
  echo $item
  ./target/debug/pktfmt ./pktfmt/protocols/$item.pktfmt -o ./rpkt/src/$item/generated.rs
  rustfmt ./rpkt/src/$item/generated.rs
done

