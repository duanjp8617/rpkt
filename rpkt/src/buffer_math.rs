//! Shared executable arithmetic for the buffer implementations and Verus model.
//!
//! Normal Rust builds erase the specification attributes. Verification checks
//! these same function bodies, not a separately transcribed arithmetic model.
//! The pointer/FFI callers must still establish the documented preconditions.
#![allow(unexpected_cfgs)]

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

/// Requires `count <= len`. Used by forward movement and tail trimming.
#[inline]
#[cfg_attr(verus_keep_ghost, verus_spec(out =>
    requires count <= len,
    ensures out == len - count, out + count == len,
))]
pub fn shorten(len: usize, count: usize) -> usize {
    len - count
}

/// Requires `count <= headroom` and `headroom + len <= usize::MAX`.
#[inline]
#[cfg_attr(verus_keep_ghost, verus_spec(out =>
    requires count <= _headroom, _headroom + len <= usize::MAX,
    ensures out == len + count, out <= _headroom + len,
))]
pub fn extend(len: usize, count: usize, _headroom: usize) -> usize {
    len + count
}

/// Requires `position <= end` and `count <= end - position`.
#[inline]
#[cfg_attr(verus_keep_ghost, verus_spec(out =>
    requires position <= _end, count <= _end - position,
    ensures out == position + count, position <= out <= _end,
))]
pub fn advance_target(position: usize, count: usize, _end: usize) -> usize {
    position + count
}

/// Requires `chunk_len <= segment_end`.
#[inline]
#[cfg_attr(verus_keep_ghost, verus_spec(out =>
    requires chunk_len <= segment_end,
    ensures out == segment_end - chunk_len, out + chunk_len == segment_end,
))]
pub fn position(segment_end: usize, chunk_len: usize) -> usize {
    segment_end - chunk_len
}
