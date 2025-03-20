#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]
#![no_std]

//! Provide utilities for parsing and constructing network packets.

#[macro_use]
mod macros;

mod traits;
pub use traits::{Buf, PktBuf, PktBufMut};

mod cursors;
pub use cursors::{Cursor, CursorMut};

pub mod checksum_utils;

pub mod ether;
// pub mod arp;
// pub mod ether;
// pub mod icmpv4;
// pub mod icmpv6;
// pub mod ipsec;
// pub mod ipv4;
// pub mod ipv6;
// pub mod tcp;
// pub mod udp;
