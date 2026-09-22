#!/usr/bin/env bash
# Mechanical experimental control, ONLY in an isolated git-archive extraction.
# Keep the same slice-backed API/NAT implementation and restore field checks.
set -euo pipefail
test ! -e .git
test -f Cargo.toml
test -f rpkt/src/traits.rs
rg -q 'pub unsafe trait StableBuf' rpkt/src/traits.rs
mapfile -t generated < <(rg --files rpkt/src -g generated.rs | sort)
test "${#generated[@]}" -eq 16
rg -q get_unchecked "${generated[@]}"
printf 'before checked-accessor transformation\n'
sha256sum "${generated[@]}"
perl -pi -e 's/\.get_unchecked(_mut)?\((\d+(?:\.\.\d+)?)\)/".get".($1\/\/"")."(".$2.").unwrap()"/ge' "${generated[@]}"
perl -0777 -pi -e 's/\A/#![allow(unused_unsafe)]\n/' "${generated[@]}"
if rg -n get_unchecked "${generated[@]}"; then
  echo 'Unrecognized unchecked accessor remains; do not benchmark this control.' >&2
  exit 1
fi
printf 'after checked-accessor transformation\n'
sha256sum "${generated[@]}"
