//! IPv4 (Internet Protocol version 4) Implementation
//!
//! This module provides support for parsing and constructing IPv4 packets as defined in RFC 791
//! and related RFCs. IPv4 is the fourth version of the Internet Protocol and the most widely
//! used version for routing packets across networks.
//!
//! # Features
//!
//! - Parse IPv4 headers with comprehensive option support
//! - Construct IPv4 packets with proper checksumming
//! - Access to all IPv4 header fields (addresses, TTL, protocol, fragmentation info, etc.)
//! - Extensive IPv4 options support
//! - Protocol type enumeration for next-layer protocol identification
//! - Integration with standard library's `Ipv4Addr` type
//!
//! # IPv4 Options Support
//!
//! This implementation supports the following IPv4 options:
//! - **EOL (End of Option List)**: Marks the end of options
//! - **NOP (No Operation)**: Padding option
//! - **Timestamp**: RFC 781 timestamp option
//! - **Record Route**: Records route taken by packet
//! - **Router Alert**: Indicates packet requires special handling
//! - **Commercial Security**: Security and handling restrictions
//! - **Strict/Loose Source Routing**: Source-specified routing
//!
//! # Protocol Types
//!
//! The `IpProtocol` enum provides constants for common next-layer protocols:
//! - TCP, UDP, ICMP, IGMP
//! - IPv6 extension headers (for tunneling scenarios)
//! - GRE, ESP, AH (for VPN and security protocols)
//!
//! # Example
//!
//! ```rust
//! use rpkt::ipv4::*;
//! use rpkt::{Cursor, CursorMut};
//! use std::net::Ipv4Addr;
//!
//! // Parse an IPv4 packet
//! let packet_data = [/* IPv4 packet bytes */];
//! let cursor = Cursor::new(&packet_data);
//! let ipv4 = Ipv4::parse(cursor)?;
//!
//! println!("Source: {}", ipv4.src_addr());
//! println!("Destination: {}", ipv4.dst_addr());
//! println!("Protocol: {:?}", ipv4.protocol());
//! println!("TTL: {}", ipv4.ttl());
//! println!("Fragment offset: {}", ipv4.fragment_offset());
//!
//! // Check for specific protocols
//! match ipv4.protocol() {
//!     IpProtocol::TCP => println!("This is a TCP packet"),
//!     IpProtocol::UDP => println!("This is a UDP packet"),
//!     IpProtocol::ICMP => println!("This is an ICMP packet"),
//!     _ => println!("Other protocol"),
//! }
//!
//! // Access IPv4 options if present
//! if let Some(options) = ipv4.options() {
//!     for option in options.iter() {
//!         // Process IPv4 options
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod generated;
pub use generated::{Ipv4, IPV4_HEADER_LEN, IPV4_HEADER_TEMPLATE};

/// The Ipv4 options.
pub mod options {
    // The Ipv4 Eol option
    pub use super::generated::{Eol, EOL_HEADER_LEN, EOL_HEADER_TEMPLATE};

    // The Ipv4 Nop option
    pub use super::generated::{Nop, NOP_HEADER_LEN, NOP_HEADER_TEMPLATE};

    pub use super::generated::{Timestamp, TIMESTAMP_HEADER_LEN, TIMESTAMP_HEADER_TEMPLATE};

    pub use super::generated::{
        RecordRoute, RECORD_ROUTE_HEADER_LEN, RECORD_ROUTE_HEADER_TEMPLATE,
    };

    pub use super::generated::{RouteAlert, ROUTE_ALERT_HEADER_LEN, ROUTE_ALERT_HEADER_TEMPLATE};

    pub use super::generated::{
        CommercialSecurity, CommercialSecurityTag, COMMERCIAL_SECURITY_HEADER_LEN,
        COMMERCIAL_SECURITY_HEADER_TEMPLATE, COMMERCIAL_SECURITY_TAG_HEADER_LEN,
        COMMERCIAL_SECURITY_TAG_HEADER_TEMPLATE,
    };

    pub use super::generated::{
        StrictSourceRoute, STRICT_SOURCE_ROUTE_HEADER_LEN, STRICT_SOURCE_ROUTE_HEADER_TEMPLATE,
    };

    pub use super::generated::{
        LooseSourceRoute, LOOSE_SOURCE_ROUTE_HEADER_LEN, LOOSE_SOURCE_ROUTE_HEADER_TEMPLATE,
    };

    pub use super::generated::{Ipv4Options, Ipv4OptionsIter, Ipv4OptionsIterMut};
}

pub use core::net::Ipv4Addr;

enum_sim! {
    /// An enum-like type for representing different protocols in IPv4/v6.
    pub struct IpProtocol (u8) {
        /// IP packet payload is ICMP protocol.
        ICMP = 1,

        /// IGMP protocol
        IGMP = 2,

        /// IP in IP
        IPIP = 4,

        /// IP packet payload is TCP protocol.
        TCP = 6,

        /// IP packet payload is UDP protocol.
        UDP =  17,

        /// IP packet payload is Hop-by-hop extention number.
        HOPOPT = 0,

        /// IP packet payload is IPv6 Route.
        IPV6_ROUTE = 43,

        /// IP packet payload is IPv6 Fragmentation.
        IPV6_FRAG = 44,

        /// IP packet payload is ESP.
        ESP = 50,

        /// IP packet payload is AH.
        AH = 51,

        /// IP packet payload is IPv6 no extention.
        IPV6_NO_NXT = 59,

        /// IP packet payload is IPv6 OPTS.
        IPV6_OPTS = 60,

        /// Generic Routing Encapsulation
        GRE = 47
    }
}
