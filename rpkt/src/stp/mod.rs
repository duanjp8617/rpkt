//! STP (Spanning Tree Protocol) Implementation
//!
//! This module provides comprehensive support for parsing and constructing Spanning Tree Protocol
//! packets as defined in IEEE 802.1D, IEEE 802.1w (RSTP), and IEEE 802.1s (MSTP). STP prevents
//! network loops in Ethernet networks by creating a spanning tree topology.
//!
//! # Features
//!
//! - Support for multiple STP variants (STP, RSTP, MSTP)
//! - Parse and construct Configuration BPDUs and Topology Change Notification BPDUs
//! - Bridge ID handling with priority, system ID extension, and MAC address
//! - Multiple Spanning Tree Instance (MSTI) support for MSTP
//! - Comprehensive BPDU type and version detection
//!
//! # STP Protocol Variants
//!
//! This implementation supports three main STP variants:
//! - **STP (802.1D)**: Original Spanning Tree Protocol
//! - **RSTP (802.1w)**: Rapid Spanning Tree Protocol for faster convergence
//! - **MSTP (802.1s)**: Multiple Spanning Tree Protocol for per-VLAN spanning trees
//!
//! # BPDU Types
//!
//! The module supports various BPDU (Bridge Protocol Data Unit) types:
//! - **Configuration BPDU**: Carries spanning tree information
//! - **TCN BPDU**: Topology Change Notification
//! - **RSTP BPDU**: Enhanced configuration BPDU for RSTP
//! - **MSTP BPDU**: Multiple Spanning Tree configuration
//!
//! # Bridge Identification
//!
//! The `BridgeId` type provides access to:
//! - **Priority**: 4-bit priority value (multiples of 4096)
//! - **System ID Extension**: 12-bit VLAN ID or instance identifier
//! - **MAC Address**: 48-bit bridge MAC address
//!
//! # Example
//!
//! ```rust
//! use rpkt::stp::*;
//! use rpkt::{Cursor, CursorMut};
//! use rpkt::ether::EtherAddr;
//!
//! // Parse an STP BPDU
//! let packet_data = [/* STP BPDU bytes */];
//! let cursor = Cursor::new(&packet_data);
//!
//! // Parse STP group to handle different BPDU types
//! let stp_group = StpGroup::parse(cursor)?;
//! match stp_group {
//!     StpGroup::StpConfBpdu(stp_conf) => {
//!         println!("STP Configuration BPDU");
//!         println!("Root ID Priority: {}", stp_conf.root_id().priority());
//!         println!("Root ID MAC: {}", stp_conf.root_id().mac_addr());
//!         println!("Root Path Cost: {}", stp_conf.root_path_cost());
//!         println!("Bridge ID: {:?}", stp_conf.bridge_id());
//!     }
//!     StpGroup::StpTcnBpdu(_tcn) => {
//!         println!("STP Topology Change Notification");
//!     }
//!     StpGroup::RstpConfBpdu(rstp_conf) => {
//!         println!("RSTP Configuration BPDU");
//!         println!("Version: {:?}", rstp_conf.version());
//!     }
//!     StpGroup::MstpConfBpdu(mstp_conf) => {
//!         println!("MSTP Configuration BPDU");
//!         println!("Version 3 Length: {}", mstp_conf.version_3_len());
//!         // Access MSTI configurations
//!     }
//! }
//!
//! // Working with Bridge IDs
//! let mut bridge_id = BridgeId::default();
//! bridge_id.set_priority(32768);  // Must be multiple of 4096
//! bridge_id.set_sys_id_ext(100);  // VLAN ID
//! bridge_id.set_mac_addr(EtherAddr([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]));
//!
//! println!("Priority: {}", bridge_id.priority());
//! println!("System ID Ext: {}", bridge_id.sys_id_ext());
//! println!("MAC Address: {}", bridge_id.mac_addr());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod generated;

pub use generated::StpGroup;
pub use generated::{MstiConf, MSTI_CONF_HEADER_LEN, MSTI_CONF_HEADER_TEMPLATE};
pub use generated::{MstpConfBpdu, MSTP_CONF_BPDU_HEADER_LEN, MSTP_CONF_BPDU_HEADER_TEMPLATE};
pub use generated::{RstpConfBpdu, RSTP_CONF_BPDU_HEADER_LEN, RSTP_CONF_BPDU_HEADER_TEMPLATE};
pub use generated::{StpConfBpdu, STP_CONF_BPDU_HEADER_LEN, STP_CONF_BPDU_HEADER_TEMPLATE};
pub use generated::{StpTcnBpdu, STP_TCN_BPDU_HEADER_LEN, STP_TCN_BPDU_HEADER_TEMPLATE};

use crate::ether::EtherAddr;

enum_sim! {
    /// An enum-like type for representing Stp version.
    pub struct StpVersion (u8) {
        /// The underlying buffer contains `StpConfBpdu`.
        STP = 0x00,

        /// The underlying buffer contains `StpTcnBpdu`.
        RSTP = 0x2,

        /// The underlying buffer contains `RstpConfBpdu` or `MstpConfBpdu`.
        MSTP =  0x3,
    }
}

enum_sim! {
    /// An enum-like type for representing Stp types.
    pub struct StpType (u8) {
        /// The underlying buffer contains `StpConfBpdu`.
        STP_CONF = 0x00,

        /// The underlying buffer contains `StpTcnBpdu`.
        STP_TCN = 0x80,

        /// The underlying buffer contains `RstpConfBpdu` or `MstpConfBpdu`.
        RSTP_OR_MSTP =  0x02,
    }
}

/// `BridgeId` represents the root/bridge identifier from the stp protocol.
///
/// The root/bridge identifier contains the following fields:
/// * Priority: 4 bits, accessed with `priority`/`set_prioirty`.
/// * System ID extention: 12 bits, accessed with `sys_id_ext`/`set_sys_id_ext`.
/// * MAC address: 48 bits, accessed with `mac_addr`/`set_mac_addr`.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct BridgeId(pub [u8; 8]);

impl BridgeId {
    /// Convert byte slice to `BridgeId`.
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut buf = [0; 8];
        buf.copy_from_slice(bytes);
        Self(buf)
    }

    /// Create a byte slice from the `BridgeId`.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get the prioity from the `BridgeId`.
    ///
    /// Note: the result is a a multiple of 4096.
    #[inline]
    pub fn priority(&self) -> u16 {
        ((self.0[0] >> 4) as u16) << 12
    }

    /// Get the system id extention from the `BridgeId`.
    #[inline]
    pub fn sys_id_ext(&self) -> u16 {
        u16::from_be_bytes((&self.0[0..2]).try_into().unwrap()) & 0xfff
    }

    /// Get the mac address from the `BridgeId`.
    #[inline]
    pub fn mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.0[2..8])
    }

    /// Set the prioity for the `BridgeId`.
    ///
    /// Note: the input `value` must be a multiple of 4096.
    ///
    /// # Panics
    ///
    /// The lower 12 bits of `value` is not all zero.
    #[inline]
    pub fn set_priority(&mut self, value: u16) {
        assert!(value & 0x0fff == 0);
        let value = (value >> 12) as u8;
        self.0[0] = (self.0[0] & 0x0f) | (value << 4);
    }

    /// Set the system id extention for the `BridgeId`.
    #[inline]
    pub fn set_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = ((self.0[0] & 0xf0) as u16) << 8 | value;
        (&mut self.0[0..2]).copy_from_slice(&write_value.to_be_bytes());
    }

    /// Set the mac address for the `BridgeId`.
    #[inline]
    pub fn set_mac_addr(&mut self, value: EtherAddr) {
        (&mut self.0[2..8]).copy_from_slice(value.as_bytes());
    }
}
