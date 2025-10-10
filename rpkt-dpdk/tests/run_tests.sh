#!/bin/sh

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
cd $SCRIPT_DIR/../

cargo test --package rpkt-dpdk --test service_init -- init_fail --exact
cargo test --package rpkt-dpdk --test service_init -- init_ok --exact

cargo test --package rpkt-dpdk --test lcore_bind -- bind_2_cores --exact
cargo test --package rpkt-dpdk --test lcore_bind -- register_rte_thread --exact
cargo test --package rpkt-dpdk --test lcore_bind -- bind_2_threads_to_the_same_lcore --exact