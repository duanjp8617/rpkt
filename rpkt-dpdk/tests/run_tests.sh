#!/bin/sh

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
cd $SCRIPT_DIR/../

cargo test --package rpkt-dpdk --test service_init -- init_fail --exact
cargo test --package rpkt-dpdk --test service_init -- init_ok --exact

cargo test --package rpkt-dpdk --test lcore_bind -- bind_2_cores --exact
cargo test --package rpkt-dpdk --test lcore_bind -- register_rte_thread --exact
cargo test --package rpkt-dpdk --test lcore_bind -- bind_2_threads_to_the_same_lcore --exact

cargo test --package rpkt-dpdk --test mempool -- create_mempool_with_same_name --exact
cargo test --package rpkt-dpdk --test mempool -- mbuf_alloc_and_size_check --exact
cargo test --package rpkt-dpdk --test mempool -- mbuf_data_unchanged_after_realloc --exact
cargo test --package rpkt-dpdk --test mempool -- alloc_mbuf_from_multiple_threads --exact
cargo test --package rpkt-dpdk --test mempool -- secondary_process_mempool --exact

cargo test --package rpkt-dpdk --test mbuf -- tests::mbuf_data_append_remove --exact

cargo test --package rpkt-dpdk --test mbuf_cache -- cache_enabled_batch --exact
cargo test --package rpkt-dpdk --test mbuf_cache -- set_all_mbufs_in_a_pool --exact