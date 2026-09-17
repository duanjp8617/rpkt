#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <pktfmt-binary>" >&2
    exit 2
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
compiler=$(realpath "$1")
tmp_dir=$(mktemp -d)

cleanup() {
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

while IFS= read -r input; do
    category_dir=$(dirname "$input")
    fixture=$(basename "$input")
    result_name=${fixture#error_}
    result_name=${result_name%.pktfmt}
    expected="$category_dir/parse_results/result_$result_name"
    actual="$tmp_dir/$(basename "$category_dir")_$result_name"

    if [[ ! -f "$expected" ]]; then
        echo "missing expected output for $input" >&2
        exit 1
    fi

    if (
        cd "$category_dir"
        "$compiler" "./$fixture" -o "$tmp_dir/generated.rs" >"$actual" 2>&1
    ); then
        echo "expected $input to fail, but compilation succeeded" >&2
        exit 1
    fi

    if ! diff -u "$expected" "$actual"; then
        echo "diagnostic output changed for $input" >&2
        exit 1
    fi

    echo "ok: ${input#"$script_dir/"}"
done < <(find "$script_dir" -mindepth 2 -maxdepth 2 -name 'error_*.pktfmt' -print | sort -V)
