//! GRE (Generic Routing Encapsulation) Implementation
//!
//! This module provides support for parsing and constructing GRE packets as defined in RFC 2784,
//! RFC 2890, and RFC 2637. GRE is a tunneling protocol that can encapsulate various network
//! layer protocols inside IP packets, commonly used for VPNs and network overlays.
//!
//! # Features
//!
//! - Parse standard GRE headers (RFC 2784)
//! - Support for GRE options (checksum, key, sequence number)
//! - PPTP-specific GRE variant support (RFC 2637)
//! - Variable-length header handling based on flag bits
//! - Support for both GRE v0 and enhanced GRE for PPTP
//!
//! # GRE Header Variants
//!
//! This implementation supports multiple GRE header types:
//! - **Standard GRE**: Basic GRE encapsulation with optional fields
//! - **GRE for PPTP**: Enhanced GRE used specifically for PPTP VPN connections
//! - **GRE Group**: Container for parsing different GRE variants
//!
//! # Optional Fields
//!
//! GRE headers can include various optional fields based on flag bits:
//! - **Checksum**: Optional checksum for error detection
//! - **Key**: Optional key field for tunnel identification
//! - **Sequence Number**: Optional sequence numbering for ordered delivery
//! - **Acknowledgment** (PPTP only): Acknowledgment number for PPTP
//!
//! # Example
//!
//! ```rust
//! use rpkt::gre::*;
//! use rpkt::{Cursor, CursorMut};
//!
//! // Parse a GRE packet
//! let packet_data = [/* GRE packet bytes */];
//! let cursor = Cursor::new(&packet_data);
//!
//! // Try parsing as a GRE group (handles multiple variants)
//! let gre_group = GreGroup::parse(cursor)?;
//! match gre_group {
//!     GreGroup::Gre(gre) => {
//!         println!("Standard GRE packet");
//!         println!("Protocol type: 0x{:04x}", gre.protocol_type());
//!         if gre.checksum_present() {
//!             println!("Checksum: 0x{:04x}", gre.checksum().unwrap());
//!         }
//!         if gre.key_present() {
//!             println!("Key: 0x{:08x}", gre.key().unwrap());
//!         }
//!     }
//!     GreGroup::GreForPPTP(gre_pptp) => {
//!         println!("GRE for PPTP");
//!         println!("Call ID: {}", gre_pptp.call_id());
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod generated;
pub use generated::GreGroup;
pub use generated::{Gre, GRE_HEADER_LEN, GRE_HEADER_TEMPLATE};
pub use generated::{GreForPPTP, GRE_FOR_PPTP_HEADER_LEN, GRE_FOR_PPTP_HEADER_TEMPLATE};
pub use generated::{PPTP, PPTP_HEADER_LEN, PPTP_HEADER_TEMPLATE};

#[inline]
fn gre_header_len(indicator_field: u16) -> usize {
    let options = [
        // checksum
        ((indicator_field & (1 << 15) != 0) | (indicator_field & (1 << 14) != 0)),
        // key
        indicator_field & (1 << 13) != 0,
        // seq
        indicator_field & (1 << 12) != 0,
    ];

    options.iter().fold(4, |mut aggre, item| {
        if *item {
            aggre += 4;
        }
        aggre
    })
}

#[inline]
fn gre_pptp_header_len(indicator_field: u16) -> usize {
    let options = [
        // seq
        indicator_field & (1 << 12) != 0,
        // ack
        indicator_field & (1 << 7) != 0,
    ];

    options.iter().fold(8, |mut aggre, item| {
        if *item {
            aggre += 4;
        }
        aggre
    })
}
