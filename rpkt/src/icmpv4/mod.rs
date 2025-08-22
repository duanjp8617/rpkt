//! ICMPv4 (Internet Control Message Protocol for IPv4) Implementation
//!
//! This module provides comprehensive support for parsing and constructing ICMPv4 messages as 
//! defined in RFC 792 and related standards. ICMPv4 is used for error reporting and diagnostic
//! functions in IPv4 networks, providing essential feedback about network conditions and 
//! packet delivery issues.
//!
//! # Features
//!
//! - Parse and construct all standard ICMPv4 message types
//! - Support for Echo Request/Reply (ping functionality)
//! - Error reporting messages (Destination Unreachable, Time Exceeded, etc.)
//! - Network discovery messages (Router Advertisement/Solicitation)
//! - Timestamp and Information Request/Reply messages
//! - Address Mask Request/Reply for subnet discovery
//! - Extended Echo Request/Reply (RFC 8335) for enhanced diagnostics
//! - Comprehensive error code enumerations for each message type
//! - ICMP checksum calculation utilities
//!
//! # ICMP Message Types
//!
//! This implementation supports the following ICMPv4 message types:
//!
//! ## Echo Messages (Types 0, 8)
//! - **Echo Reply (0)**: Response to Echo Request (ping reply)
//! - **Echo Request (8)**: Request for Echo Reply (ping request)
//!
//! ## Error Messages (Types 3, 4, 5, 11, 12)
//! - **Destination Unreachable (3)**: Packet cannot reach destination
//! - **Source Quench (4)**: Deprecated congestion control message
//! - **Redirect (5)**: Route optimization message
//! - **Time Exceeded (11)**: TTL expired or fragment reassembly timeout
//! - **Parameter Problem (12)**: IP header parameter error
//!
//! ## Router Discovery (Types 9, 10)
//! - **Router Advertisement (9)**: Router announces its presence
//! - **Router Solicitation (10)**: Host requests router information
//!
//! ## Timestamp Messages (Types 13, 14)
//! - **Timestamp Request (13)**: Request for timestamp information
//! - **Timestamp Reply (14)**: Response with timestamp data
//!
//! ## Information Messages (Types 15, 16) - Deprecated
//! - **Information Request (15)**: Legacy network address request
//! - **Information Reply (16)**: Legacy network address response
//!
//! ## Address Mask Messages (Types 17, 18)
//! - **Address Mask Request (17)**: Request for subnet mask information
//! - **Address Mask Reply (18)**: Response with subnet mask data
//!
//! ## Extended Echo Messages (Types 42, 43) - RFC 8335
//! - **Extended Echo Request (42)**: Enhanced ping with additional capabilities
//! - **Extended Echo Reply (43)**: Response to Extended Echo Request
//!
//! # Error Codes
//!
//! Each ICMP message type has specific error codes that provide detailed information:
//!
//! - **Destination Unreachable codes**: Network/Host/Protocol/Port unreachable, etc.
//! - **Redirect codes**: Network/Host redirection for different ToS values
//! - **Time Exceeded codes**: TTL exceeded in transit or fragment reassembly timeout
//! - **Parameter Problem codes**: Pointer indicates error, missing option, bad length
//!
//! # Example Usage
//!
//! ```rust
//! use rpkt::icmpv4::*;
//! use rpkt::{Cursor, CursorMut};
//!
//! // Parse an ICMPv4 packet
//! let packet_data = [/* ICMPv4 packet bytes */];
//! let cursor = Cursor::new(&packet_data);
//! 
//! // Parse as ICMP group to handle different message types
//! match Icmpv4::group_parse(cursor) {
//!     Ok(Icmpv4::EchoRequest_(echo_req)) => {
//!         println!("Ping request - ID: {}, Seq: {}", 
//!                  echo_req.identifier(), echo_req.sequence());
//!         
//!         // Access payload data
//!         let payload = echo_req.payload();
//!     }
//!     Ok(Icmpv4::DestUnreachable_(dest_unreach)) => {
//!         println!("Destination unreachable - Code: {}", dest_unreach.code());
//!         match dest_unreach.code() {
//!             3 => println!("Port unreachable"),
//!             1 => println!("Host unreachable"),
//!             _ => println!("Other unreachable code"),
//!         }
//!     }
//!     Ok(Icmpv4::TimeExceeded_(time_exceeded)) => {
//!         println!("Time exceeded - Code: {}", time_exceeded.code());
//!         match time_exceeded.code() {
//!             0 => println!("TTL exceeded in transit"),
//!             1 => println!("Fragment reassembly time exceeded"),
//!             _ => println!("Other time exceeded code"),
//!         }
//!     }
//!     Err(buf) => println!("Failed to parse ICMP packet"),
//!     _ => println!("Other ICMP message type"),
//! }
//!
//! // Create an Echo Request (ping)
//! let mut header = EchoRequest::default_header();
//! let mut echo_req = EchoRequest::from_header_array_mut(&mut header);
//! echo_req.set_identifier(0x1234);
//! echo_req.set_sequence(1);
//! 
//! // Calculate and set checksum
//! let checksum = calculate_icmp_checksum(echo_req.fix_header_slice());
//! echo_req.set_checksum(checksum);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod generated;
pub use generated::*;