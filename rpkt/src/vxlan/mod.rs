//! VXLAN (Virtual Extensible LAN) Implementation
//!
//! This module provides support for parsing and constructing VXLAN packets as defined in RFC 7348.
//! VXLAN is a network virtualization technology that enables the creation of virtual Layer 2
//! networks over existing Layer 3 infrastructure, commonly used in data centers and cloud environments.
//!
//! # Features
//!
//! - Parse VXLAN headers with VNI (VXLAN Network Identifier) extraction
//! - Support for VXLAN flags and reserved field validation
//! - 24-bit VNI space support (16.7 million virtual networks)
//! - UDP encapsulation handling (typically UDP port 4789)
//! - Inner Ethernet frame access for L2 payload
//!
//! # VXLAN Header Structure
//!
//! The VXLAN header contains the following fields:
//! - **Flags**: 8-bit field with VXLAN-specific flags (typically 0x08 for valid VNI)
//! - **Reserved fields**: Multiple reserved fields set to zero
//! - **VNI (VXLAN Network Identifier)**: 24-bit identifier for the virtual network
//! - **Reserved**: Final 8-bit reserved field
//!
//! # Network Virtualization
//!
//! VXLAN enables:
//! - **Multi-tenancy**: Up to 16.7M isolated virtual networks
//! - **L2 over L3**: Ethernet frames tunneled over IP networks
//! - **VM mobility**: VMs can move across physical boundaries
//! - **Data center interconnect**: Connect L2 domains across sites
//!
//! # Typical Usage Scenario
//!
//! VXLAN packets are typically structured as:
//! 1. Outer Ethernet header (physical network)
//! 2. Outer IP header (transport network)
//! 3. Outer UDP header (typically destination port 4789)
//! 4. VXLAN header (this module)
//! 5. Inner Ethernet frame (virtual network payload)
//!
//! # Example
//!
//! ```rust
//! use rpkt::vxlan::*;
//! use rpkt::{Cursor, CursorMut};
//!
//! // Parse a VXLAN packet
//! let packet_data = [/* VXLAN packet bytes */];
//! let cursor = Cursor::new(&packet_data);
//! let vxlan = Vxlan::parse(cursor)?;
//!
//! // Extract VXLAN information
//! println!("VXLAN Flags: 0x{:02x}", vxlan.flags());
//! println!("VNI: {}", vxlan.vni());
//!
//! // Validate VXLAN header
//! if vxlan.flags() & 0x08 != 0 {
//!     println!("Valid VXLAN packet with VNI: {}", vxlan.vni());
//!     
//!     // Access inner Ethernet frame
//!     let inner_frame = vxlan.payload();
//!     // Parse inner Ethernet frame using ether module
//!     // let eth_frame = EtherFrame::parse(inner_frame)?;
//! } else {
//!     println!("Invalid VXLAN packet - VNI flag not set");
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod generated;
pub use generated::{Vxlan, VXLAN_HEADER_LEN, VXLAN_HEADER_TEMPLATE};
