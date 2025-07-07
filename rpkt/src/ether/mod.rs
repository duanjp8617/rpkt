//! Ethernet II frame.

use core::fmt;

enum_sim! {
    /// An enum-like type for representing Ethertype in Ethernet frame.
    pub struct EtherType (u16) {
        /// Ethernet frame payload is Arp protocol.
        ARP =  0x0806,
        /// Ethernet frame payload is Ipv4 protocol.
        IPV4 = 0x0800,
        /// Ethernet frame payloadis Ipv6 protocol.
        IPV6 = 0x86DD,
        /// Ethernet frame payload contains vlan tag.
        VLAN = 0x8100,
        /// Ethernet frame payload contains 802.1ad QinQ tag.
        QINQ = 0x88a8,
        /// Ethernet frame payload contains MPLS tag.
        MPLS = 0x8847,
        /// Ethernet frame payload contains PPPoE session packet.
        PPPOE_SESSION = 0x8864,
        /// Ethernet frame payload contains PPPoE discovery packet.
        PPPOE_DISCOVERY = 0x8863
    }
}

/// A six-octet Ethernet II address.
///
/// This is copied from smoltcp and renamed to `EtherAddr`.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct EtherAddr(pub [u8; 6]);

impl EtherAddr {
    /// The broadcast address.
    pub const BROADCAST: EtherAddr = EtherAddr([0xff; 6]);

    /// Construct an Ethernet address from a sequence of octets, in big-endian.
    ///
    /// # Panics
    /// The function panics if `data` is not six octets long.
    pub fn from_bytes(data: &[u8]) -> EtherAddr {
        let mut bytes = [0; 6];
        bytes.copy_from_slice(data);
        EtherAddr(bytes)
    }

    /// Return an Ethernet address as a sequence of octets, in big-endian.
    pub const fn as_bytes(&self) -> &[u8] {
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

    /// Query whether the 'multicast' bit in the OUI is set.
    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// Query whether the 'locally administered' bit in the OUI is set.
    pub const fn is_local(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Parse a string with the form 'Aa:0b:Cc:11:02:33' into `EtherAddr`.
    pub fn parse_from<T: AsRef<str>>(s: T) -> Option<Self> {
        fn convert(c: char) -> Option<u8> {
            match c {
                '0' => Some(0),
                '1' => Some(1),
                '2' => Some(2),
                '3' => Some(3),
                '4' => Some(4),
                '5' => Some(5),
                '6' => Some(6),
                '7' => Some(7),
                '8' => Some(8),
                '9' => Some(9),
                'A' => Some(10),
                'a' => Some(10),
                'B' => Some(11),
                'b' => Some(11),
                'C' => Some(12),
                'c' => Some(12),
                'D' => Some(13),
                'd' => Some(13),
                'E' => Some(14),
                'e' => Some(14),
                'F' => Some(15),
                'f' => Some(15),
                _ => None,
            }
        }

        let mut result = [0; 6];
        let mut s = s.as_ref().split(":");
        for i in 0..6 {
            let mut hex = s.next()?.chars();
            let n = convert(hex.next()?)? << 4;
            result[i] = n | (convert(hex.next()?)?);
            if hex.next().is_some() {
                return None;
            }
        }
        Some(Self(result))
    }
}

impl fmt::Display for EtherAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}

mod generated;

pub use generated::{Ethernet, ETHERNET_HEADER_LEN, ETHERNET_HEADER_TEMPLATE};

/// Check if the byte slice stores valid Ethernet II frame.
pub fn store_ether_frame<T: AsRef<[u8]>>(buf: T) -> bool {
    if buf.as_ref().len() >= 14 {
        // Ethertypes: These are 16-bit identifiers appearing as the initial
        // two octets after the MAC destination and source (or after a
        // tag) which, when considered as an unsigned integer, are equal
        // to or larger than 0x0600.
        //
        // From: https://tools.ietf.org/html/rfc5342#section-2.3.2.1
        // More: IEEE Std 802.3 Clause 3.2.6
        let value = u16::from_be_bytes((&buf.as_ref()[12..14]).try_into().unwrap());
        value >= 0x0600
    } else {
        false
    }
}

pub use generated::{EthernetDot3, ETHERNETDOT3_HEADER_LEN, ETHERNETDOT3_HEADER_TEMPLATE};

/// Check if the byte slice stores valid IEEE 802.3 frame.
pub fn store_ieee_dot3_frame<T: AsRef<[u8]>>(buf: T) -> bool {
    if buf.as_ref().len() >= 14 {
        // LSAPs: ... Such a length must, when considered as an
        // unsigned integer, be less than 0x5DC or it could be mistaken as
        // an Ethertype...
        //
        // From: https://tools.ietf.org/html/rfc5342#section-2.3.2.1
        // More: IEEE Std 802.3 Clause 3.2.6
        let value = u16::from_be_bytes((&buf.as_ref()[12..14]).try_into().unwrap());
        value <= 0x05DC
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Buf, Cursor, CursorMut};
    use bytes::BufMut;

    static FRAME_BYTES: [u8; 64] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x08, 0x00, 0xaa,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff,
    ];

    #[test]
    fn packet_parse() {
        let pres = Ethernet::parse(Cursor::new(&FRAME_BYTES[..]));
        assert_eq!(pres.is_ok(), true);
        let ethpkt = pres.unwrap();
        assert_eq!(
            ethpkt.dst_addr(),
            EtherAddr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        );
        assert_eq!(
            ethpkt.src_addr(),
            EtherAddr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16])
        );
        assert_eq!(ethpkt.ethertype(), EtherType::IPV4);

        let next = ethpkt.payload();
        assert_eq!(next.chunk(), &FRAME_BYTES[ETHERNET_HEADER_LEN..]);
    }

    #[test]
    fn packet_build() {
        let mut bytes = [0xff; 64];
        use core::convert::TryInto;
        (&mut bytes[ETHERNET_HEADER_LEN..]).put(&FRAME_BYTES[ETHERNET_HEADER_LEN..]);

        let mut buf = CursorMut::new(&mut bytes[..]);
        buf.advance(ETHERNET_HEADER_LEN);
        let slice: &[u8] = &[0; 14][..];
        let mut ethpkt = Ethernet::prepend_header(buf, slice.try_into().unwrap());
        ethpkt.set_dst_addr(EtherAddr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]));
        ethpkt.set_src_addr(EtherAddr([0x11, 0x12, 0x13, 0x14, 0x15, 0x16]));
        ethpkt.set_ethertype(EtherType::IPV4);

        assert_eq!(ethpkt.buf().chunk(), &FRAME_BYTES[..]);
    }

    #[test]
    fn etheraddr_parse_from() {
        let s = "Aa:Bb:Cc:11:22:33";
        assert_eq!(
            EtherAddr::parse_from(s),
            Some(EtherAddr::from_bytes(&[0xAa, 0xBb, 0xCc, 0x11, 0x22, 0x33]))
        );
        let s = "Aa:Bb:Cc:11:22";
        assert_eq!(EtherAddr::parse_from(s), None);
        let s = "Aaa:Bb:Cc:11:22:33";
        assert_eq!(EtherAddr::parse_from(s), None);
        let s = "Zaa:Bb:Cc:11:22:33";
        assert_eq!(EtherAddr::parse_from(s), None);
        let s = "a:Bb:Cc:11:22:33";
        assert_eq!(EtherAddr::parse_from(s), None);
    }
}
