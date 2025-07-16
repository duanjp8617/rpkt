mod generated;

pub use generated::StpMessageGroup;
pub use generated::{MstiConf, MSTICONF_HEADER_LEN, MSTICONF_HEADER_TEMPLATE};
pub use generated::{MstpConfBpdu, MSTPCONFBPDU_HEADER_LEN, MSTPCONFBPDU_HEADER_TEMPLATE};
pub use generated::{RstpConfBpdu, RSTPCONFBPDU_HEADER_LEN, RSTPCONFBPDU_HEADER_TEMPLATE};
pub use generated::{StpConfBpdu, STPCONFBPDU_HEADER_LEN, STPCONFBPDU_HEADER_TEMPLATE};
pub use generated::{StpTcnBpdu, STPTCNBPDU_HEADER_LEN, STPTCNBPDU_HEADER_TEMPLATE};

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
