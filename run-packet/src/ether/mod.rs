use std::fmt;

///  This is copied directly from smoltcp.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The broadcast address.
    pub const BROADCAST: MacAddr = MacAddr([0xff; 6]);

    /// Construct an Ethernet address from a sequence of octets, in big-endian.
    ///
    /// inline is required to improve performance
    ///
    /// # Panics
    /// The function panics if `data` is not six octets long.
    #[inline]
    pub fn from_bytes(data: &[u8]) -> MacAddr {
        let mut bytes = [0; 6];
        bytes.copy_from_slice(data);
        MacAddr(bytes)
    }

    /// Return an Ethernet address as a sequence of octets, in big-endian.
    ///
    /// inline is required to improve performance
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Query whether the address is an unicast address.
    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast())
    }

    /// Query whether this address is the broadcast address.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Query whether the "multicast" bit in the OUI is set.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Query whether the "locally administered" bit in the OUI is set.
    pub fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}

enum_sim! {
    pub struct EtherType (u16) {
        VLAN = 0x8100,
        QINQ = 0x88A8,
        ARP =  0x0806,
        IPV4 = 0x0800,
        IPV6 = 0x86DD,
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EtherType::VLAN => write!(f, "VLAN"),
            EtherType::QINQ => write!(f, "QINQ"),
            EtherType::ARP => write!(f, "ARP"),
            EtherType::IPV4 => write!(f, "IPv4"),
            EtherType::IPV6 => write!(f, "IPv6"),
            _ => write!(f, "0x{:04x}", u16::from(*self)),
        }
    }
}

mod header;
pub use header::{EtherHeader, ETHER_HEADER_LEN, ETHER_HEADER_TEMPLATE};

mod packet;
pub use self::packet::{
    EtherPacket, ETHER_MAX_JUMBO_PKT_LEN, ETHER_MAX_LEN, ETHER_MIN_LEN, ETHER_MTU, ETHER_OVERHEAD,
};
