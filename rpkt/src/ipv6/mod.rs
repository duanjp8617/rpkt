//! IPv6 (Internet Protocol version 6) Implementation
//!
//! This module provides support for parsing and constructing IPv6 packets as defined in RFC 8200
//! and related RFCs. IPv6 is the sixth version of the Internet Protocol, designed to eventually
//! replace IPv4 with a much larger address space and improved features.
//!
//! # Features
//!
//! - Parse IPv6 headers and extension headers
//! - Construct IPv6 packets with proper formatting
//! - Support for IPv6 extension headers (Hop-by-Hop, Routing, Fragment, Destination Options, AH)
//! - IPv6 options parsing within extension headers
//! - 128-bit address support
//!
//! # IPv6 Extension Headers
//!
//! IPv6 uses extension headers to provide optional features:
//! - **Hop-by-Hop Options**: Options that must be processed by every hop
//! - **Routing Header**: Source routing functionality
//! - **Fragment Header**: Fragmentation information
//! - **Destination Options**: Options processed only by the destination
//! - **Authentication Header (AH)**: IPsec authentication
//!
//! # IPv6 Options
//!
//! Within extension headers, various options are supported:
//! - **Pad0**: Single byte padding
//! - **PadN**: Multi-byte padding
//! - **Router Alert**: Special handling indication
//! - **Generic**: Extensible option format
//!
//! # Example
//!
//! ```rust
//! use rpkt::ipv6::*;
//! use rpkt::{Cursor, CursorMut};
//!
//! // Parse an IPv6 packet
//! let packet_data = [/* IPv6 packet bytes */];
//! let cursor = Cursor::new(&packet_data);
//! let ipv6 = Ipv6::parse(cursor)?;
//!
//! println!("Source: {:?}", ipv6.src_addr());
//! println!("Destination: {:?}", ipv6.dst_addr());
//! println!("Next header: {}", ipv6.next_header());
//! println!("Hop limit: {}", ipv6.hop_limit());
//! println!("Payload length: {}", ipv6.payload_length());
//!
//! // Process extension headers if present
//! let mut next_header = ipv6.next_header();
//! let mut payload = ipv6.payload();
//!
//! // Extension header processing would continue here
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod generated;
pub use generated::{Ipv6, IPV6_HEADER_LEN, IPV6_HEADER_TEMPLATE};

/// The Ipv6 extentions.
pub mod extentions {
    pub use super::generated::{
        AuthenticationHeader, AUTHENTICATION_HEADER_HEADER_LEN,
        AUTHENTICATION_HEADER_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        DestOptions, DEST_OPTIONS_HEADER_LEN, DEST_OPTIONS_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        FragmentHeader, FRAGMENT_HEADER_HEADER_LEN, FRAGMENT_HEADER_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        HopByHopOption, HOP_BY_HOP_OPTION_HEADER_LEN, HOP_BY_HOP_OPTION_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        RoutingHeader, ROUTING_HEADER_HEADER_LEN, ROUTING_HEADER_HEADER_TEMPLATE,
    };
}

/// The ipv6 options for certain extentions.
pub mod options {
    pub use super::generated::{Generic, GENERIC_HEADER_LEN, GENERIC_HEADER_TEMPLATE};
    pub use super::generated::{Ipv6Options, Ipv6OptionsIter, Ipv6OptionsIterMut};
    pub use super::generated::{Pad0, PAD0_HEADER_LEN, PAD0_HEADER_TEMPLATE};
    pub use super::generated::{Padn, PADN_HEADER_LEN, PADN_HEADER_TEMPLATE};
    pub use super::generated::{
        RouterAlert, ROUTER_ALERT_HEADER_LEN, ROUTER_ALERT_HEADER_TEMPLATE,
    };
}
