//! UDP (User Datagram Protocol) Implementation
//!
//! This module provides support for parsing and constructing UDP packets as defined in RFC 768.
//! UDP is a simple, connectionless transport layer protocol that provides minimal overhead
//! for applications that don't require reliable delivery.
//!
//! # Features
//!
//! - Parse UDP headers from byte buffers
//! - Construct UDP packets with proper checksumming
//! - Access to source and destination ports
//! - Payload access for higher-layer protocols
//!
//! # Example
//!
//! ```rust
//! use rpkt::udp::*;
//! use rpkt::{Cursor, CursorMut, Buf};
//!
//! // Parse a UDP packet
//! let packet_data = [/* UDP packet bytes */];
//! let cursor = Cursor::new(&packet_data);
//! let udp = Udp::parse(cursor)?;
//!
//! println!("Source port: {}", udp.src_port());
//! println!("Destination port: {}", udp.dst_port());
//! println!("Length: {}", udp.length());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod generated;
pub use generated::{Udp, UDP_HEADER_LEN, UDP_HEADER_TEMPLATE};
