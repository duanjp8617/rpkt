//! VLAN (Virtual Local Area Network) Implementation
//!
//! This module provides support for parsing and constructing VLAN-tagged Ethernet frames
//! as defined in IEEE 802.1Q and IEEE 802.1ad standards. VLAN tagging allows logical
//! segmentation of Ethernet networks by adding VLAN header information to Ethernet frames.
//!
//! # Features
//!
//! - Parse 802.1Q VLAN-tagged Ethernet frames
//! - Support for both Ethernet II and 802.3 frame formats with VLAN tags
//! - QinQ (802.1ad) support for double VLAN tagging
//! - Priority Code Point (PCP) and Drop Eligible Indicator (DEI) support
//! - 12-bit VLAN ID range (0-4095)
//!
//! # VLAN Frame Types
//!
//! This implementation supports multiple VLAN frame variants:
//! - **VlanFrame**: Standard Ethernet II frame with 802.1Q VLAN tag
//! - **VlanDot3Frame**: 802.3 frame format with VLAN tag
//! - **VlanGroup**: Container for parsing different VLAN frame types
//!
//! # VLAN Header Fields
//!
//! The VLAN header contains several important fields:
//! - **TPID (Tag Protocol Identifier)**: Usually 0x8100 for 802.1Q, 0x88a8 for 802.1ad
//! - **PCP (Priority Code Point)**: 3-bit field for QoS priority (0-7)
//! - **DEI (Drop Eligible Indicator)**: 1-bit field indicating frame can be dropped under congestion
//! - **VID (VLAN Identifier)**: 12-bit VLAN ID (0-4095, with 0 and 4095 reserved)
//!
//! # Example
//!
//! ```rust
//! use rpkt::vlan::*;
//! use rpkt::ether::EtherType;
//! use rpkt::{Cursor, CursorMut};
//!
//! // Parse a VLAN-tagged frame
//! let packet_data = [/* VLAN frame bytes */];
//! let cursor = Cursor::new(&packet_data);
//!
//! // Try parsing as a VLAN group (handles multiple frame types)
//! let vlan_group = VlanGroup::parse(cursor)?;
//! match vlan_group {
//!     VlanGroup::VlanFrame(vlan) => {
//!         println!("VLAN Ethernet II frame");
//!         println!("VLAN ID: {}", vlan.vid());
//!         println!("Priority: {}", vlan.pcp());
//!         println!("DEI: {}", vlan.dei());
//!         println!("EtherType: 0x{:04x}", vlan.ethertype().0);
//!     }
//!     VlanGroup::VlanDot3Frame(vlan_dot3) => {
//!         println!("VLAN 802.3 frame");
//!         println!("VLAN ID: {}", vlan_dot3.vid());
//!         println!("Length: {}", vlan_dot3.length());
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod generated;

pub use generated::VlanGroup;
pub use generated::{VlanDot3Frame, VLAN_DOT3_FRAME_HEADER_LEN, VLAN_DOT3_FRAME_HEADER_TEMPLATE};
pub use generated::{VlanFrame, VLAN_FRAME_HEADER_LEN, VLAN_FRAME_HEADER_TEMPLATE};
