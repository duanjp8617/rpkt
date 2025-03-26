#!/bin/bash

# Define a list of strings
# strings=("arp" "ether" "ipv4" "llc" "stp" "tcp" "udp" "vlan")
strings=("stp")

# Iterate over the list
for item in "${strings[@]}"; do
  echo $item
  ./target/debug/pktfmt ./pktfmt/etc/$item.pktfmt -o ./rpkt/src/$item/generated.rs
done

