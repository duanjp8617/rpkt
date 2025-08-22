//! ARP (Address Resolution Protocol) Implementation
//!
//! This module provides support for parsing and constructing ARP packets as defined in RFC 826.
//! ARP is used to resolve network layer addresses (like IPv4 addresses) to link layer addresses
//! (like Ethernet MAC addresses) within a local network segment.
//!
//! # Features
//!
//! - Parse ARP request and reply packets
//! - Construct ARP packets for requests and responses
//! - Support for Ethernet hardware type
//! - IPv4 protocol address mapping
//!
//! # Supported Operations
//!
//! - **ARP Request**: Ask "who has IP address X?"
//! - **ARP Reply**: Response "IP address X is at MAC address Y"
//!
//! # Example
//!
//! ```rust
//! use rpkt::arp::*;
//! use rpkt::{Cursor, CursorMut};
//!
//! // Parse an ARP packet
//! let packet_data = [/* ARP packet bytes */];
//! let cursor = Cursor::new(&packet_data);
//! let arp = Arp::parse(cursor)?;
//!
//! match arp.operation() {
//!     Operation::REQUEST => println!("ARP Request"),
//!     Operation::REPLY => println!("ARP Reply"),
//!     _ => println!("Unknown operation"),
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod generated;
pub use generated::{Arp, ARP_HEADER_LEN, ARP_HEADER_TEMPLATE};

enum_sim! {
    /// Hardware type of the arp protocol.
    pub struct Hardware (u16) {
        /// The contained hardware address is Ethernet address.
        ETHERNET = 1
    }
}

enum_sim! {
    /// Operation type of the arp protocol.
    pub struct Operation (u16) {
        /// Arp request.
        REQUEST = 1,
        /// Arp response.
        REPLY = 2
    }
}
