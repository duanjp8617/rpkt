#!/usr/bin/env sh

set -eu

script_dir=$(dirname "$(readlink -f "$0")")
cd "$script_dir/.."

if [ -n "${DPDK_TEST_RUNNER:-}" ]; then
    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER=$DPDK_TEST_RUNNER
fi

cargo build --package rpkt-dpdk --example mempool_primary

case "${CARGO_TARGET_DIR:-}" in
    /*) target_dir=$CARGO_TARGET_DIR ;;
    "") target_dir="$script_dir/../../target" ;;
    *) target_dir="$PWD/$CARGO_TARGET_DIR" ;;
esac

primary_log=$(mktemp)
primary_pid=
cleanup() {
    if [ -n "$primary_pid" ]; then
        kill -INT "$primary_pid" 2>/dev/null || true
        wait "$primary_pid" 2>/dev/null || true
    fi
    rm -f "$primary_log"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -n "${DPDK_TEST_RUNNER:-}" ]; then
    # DPDK_TEST_RUNNER is intentionally split into a command and its arguments.
    # shellcheck disable=SC2086
    $DPDK_TEST_RUNNER "$target_dir/debug/examples/mempool_primary" >"$primary_log" 2>&1 &
else
    "$target_dir/debug/examples/mempool_primary" >"$primary_log" 2>&1 &
fi
primary_pid=$!

sleep 2
if ! kill -0 "$primary_pid" 2>/dev/null; then
    cat "$primary_log" >&2
    exit 1
fi

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
