use std::fmt;

use bytes::Buf;

use crate::tcp::TcpPacket;
use crate::udp::UdpPacket;

/// A four-octet IPv4 address.
///
/// This is copied directly from smoltcp.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    pub const UNSPECIFIED: Ipv4Addr = Ipv4Addr([0x00; 4]);

    pub const BROADCAST: Ipv4Addr = Ipv4Addr([0xff; 4]);

    pub const MULTICAST_ALL_SYSTEMS: Ipv4Addr = Ipv4Addr([224, 0, 0, 1]);

    pub const MULTICAST_ALL_ROUTERS: Ipv4Addr = Ipv4Addr([224, 0, 0, 2]);

    #[inline]
    pub const fn new(a0: u8, a1: u8, a2: u8, a3: u8) -> Ipv4Addr {
        Ipv4Addr([a0, a1, a2, a3])
    }

    #[inline]
    pub fn from_bytes(data: &[u8]) -> Ipv4Addr {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(data);
        Ipv4Addr(bytes)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast() || self.is_unspecified())
    }

    pub fn is_broadcast(&self) -> bool {
        self.0[0..4] == [255; 4]
    }

    pub const fn is_multicast(&self) -> bool {
        self.0[0] & 0xf0 == 224
    }

    pub const fn is_unspecified(&self) -> bool {
        self.0[0] == 0
    }

    pub fn is_link_local(&self) -> bool {
        self.0[0..2] == [169, 254]
    }

    pub const fn is_loopback(&self) -> bool {
        self.0[0] == 127
    }
}

impl From<std::net::Ipv4Addr> for Ipv4Addr {
    #[inline]
    fn from(x: std::net::Ipv4Addr) -> Ipv4Addr {
        Ipv4Addr(x.octets())
    }
}

impl From<Ipv4Addr> for std::net::Ipv4Addr {
    #[inline]
    fn from(Ipv4Addr(x): Ipv4Addr) -> std::net::Ipv4Addr {
        x.into()
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.0;
        write!(f, "{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    }
}

enum_sim! {
    /// See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    pub struct IpProtocol (u8) {
        ICMP = 1,
        TCP = 6,
        UDP =  17,
        /// The IPv6 Hop-by-hop extention number
        HOPOPT = 0,
        IPV6_ROUTE = 43,
        IPV6_FRAG = 44,
        ESP = 50,
        AH = 51,
        IPV6_NO_NXT = 59,
        IPV6_OPTS = 60,
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IpProtocol::ICMP => write!(f, "ICMP"),
            IpProtocol::TCP => write!(f, "TCP"),
            IpProtocol::UDP => write!(f, "UDP"),
            _ => write!(f, "0x{:02x}", u8::from(*self)),
        }
    }
}

pub struct Ipv4PseudoHeader {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    proto_len: [u8; 4],
}

impl Ipv4PseudoHeader {
    pub fn from_udp_pkt<T: Buf>(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, pkt: &UdpPacket<T>) -> Self {
        use byteorder::{ByteOrder, NetworkEndian};

        let mut proto_len = [0u8; 4];
        proto_len[1] = IpProtocol::UDP.into();
        NetworkEndian::write_u16(&mut proto_len[2..4], pkt.packet_len());

        Self {
            src_ip,
            dst_ip,
            proto_len,
        }
    }

    pub fn from_tcp_pkt<T: Buf>(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, pkt: &TcpPacket<T>) -> Self {
        use byteorder::{ByteOrder, NetworkEndian};

        let mut proto_len = [0u8; 4];
        proto_len[1] = IpProtocol::TCP.into();
        NetworkEndian::write_u16(
            &mut proto_len[2..4],
            u16::try_from(pkt.buf().remaining()).unwrap(),
        );

        Self {
            src_ip,
            dst_ip,
            proto_len,
        }
    }

    pub fn calc_checksum(&self) -> u16 {
        use crate::checksum_utils::{combine, from_slice};

        combine(&[
            from_slice(self.src_ip.as_bytes()),
            from_slice(self.dst_ip.as_bytes()),
            from_slice(&self.proto_len[..]),
        ])
    }
}

mod header;
pub use header::{Ipv4Header, IPV4_HEADER_LEN, IPV4_HEADER_LEN_MAX, IPV4_HEADER_TEMPLATE};

mod packet;
pub use self::packet::Ipv4Packet;

mod option;
pub use option::{
    Ipv4Option, Ipv4OptionIter, Ipv4OptionIterMut, Ipv4OptionMut, Ipv4OptionWriter, RecordRoute,
    RouteAlert, Timestamp,
};
