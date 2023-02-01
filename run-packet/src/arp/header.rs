use byteorder::{ByteOrder, NetworkEndian};

use crate::ether::{EtherType, MacAddr};
use crate::ipv4::Ipv4Addr;

use super::{Hardware, Operation};

header_field_range_accessors! {
    (htype, htype_mut, 0..2),
    (ptype, ptype_mut, 2..4),
    (oper, oper_mut, 6..8),
    (sha, sha_mut, 8..14),
    (spa, spa_mut, 14..18),
    (tha, tha_mut, 18..24),
    (tpa, tpa_mut, 24..28)
}

header_field_val_accessors! {
    (hlen, hlen_mut, 4),
    (plen, plen_mut, 5),
}

pub const ARP_HEADER_LEN: usize = 28;

pub const ARP_HEADER_TEMPLATE: ArpHeader<[u8; ARP_HEADER_LEN]> = ArpHeader {
    buf: [
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ],
};

#[derive(Clone, Copy, Debug)]
pub struct ArpHeader<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> ArpHeader<T> {
    #[inline]
    pub fn new(buf: T) -> Result<Self, T> {
        if buf.as_ref().len() >= ARP_HEADER_LEN {
            Ok(Self { buf })
        } else {
            Err(buf)
        }
    }

    #[inline]
    pub fn new_unchecked(buf: T) -> Self {
        Self { buf }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf.as_ref()[0..ARP_HEADER_LEN]
    }

    #[inline]
    pub fn to_owned(&self) -> ArpHeader<[u8; ARP_HEADER_LEN]> {
        let mut buf = [0; ARP_HEADER_LEN];
        buf.copy_from_slice(self.as_bytes());
        ArpHeader { buf }
    }

    #[inline]
    fn hardware_type(&self) -> Hardware {
        let data = htype(self.buf.as_ref());
        NetworkEndian::read_u16(data).into()
    }

    #[inline]
    fn protocol_type(&self) -> EtherType {
        let data = ptype(self.buf.as_ref());
        NetworkEndian::read_u16(data).into()
    }

    #[inline]
    fn hardware_len(&self) -> u8 {
        *hlen(self.buf.as_ref())
    }

    #[inline]
    fn protocol_len(&self) -> u8 {
        *plen(self.buf.as_ref())
    }

    #[inline]
    pub fn check_arp_format(&self) -> bool {
        self.hardware_type() == Hardware::ETHERNET
            && self.protocol_type() == EtherType::IPV4
            && self.hardware_len() == 6
            && self.protocol_len() == 4
    }

    #[inline]
    pub fn operation(&self) -> Operation {
        let data = oper(self.buf.as_ref());
        NetworkEndian::read_u16(data).into()
    }

    #[inline]
    pub fn source_mac_addr(&self) -> MacAddr {
        let data = sha(self.buf.as_ref());
        MacAddr::from_bytes(data)
    }

    #[inline]
    pub fn source_ipv4_addr(&self) -> Ipv4Addr {
        let data = spa(self.buf.as_ref());
        Ipv4Addr::from_bytes(data)
    }

    #[inline]
    pub fn target_mac_addr(&self) -> MacAddr {
        let data = tha(self.buf.as_ref());
        MacAddr::from_bytes(data)
    }

    #[inline]
    pub fn target_ipv4_addr(&self) -> Ipv4Addr {
        let data = tpa(self.buf.as_ref());
        Ipv4Addr::from_bytes(data)
    }
}

impl<T: AsMut<[u8]>> ArpHeader<T> {
    #[inline]
    fn set_hardware_type(&mut self, value: Hardware) {
        let data = htype_mut(self.buf.as_mut());
        NetworkEndian::write_u16(data, value.into())
    }

    #[inline]
    fn set_protocol_type(&mut self, value: EtherType) {
        let data = ptype_mut(self.buf.as_mut());
        NetworkEndian::write_u16(data, value.into())
    }

    #[inline]
    fn set_hardware_len(&mut self, value: u8) {
        *hlen_mut(self.buf.as_mut()) = value;
    }

    #[inline]
    fn set_protocol_len(&mut self, value: u8) {
        *plen_mut(self.buf.as_mut()) = value;
    }

    #[inline]
    pub fn adjust_arp_format(&mut self) {
        self.set_hardware_type(Hardware::ETHERNET);
        self.set_protocol_type(EtherType::IPV4);

        self.set_hardware_len(6);
        self.set_protocol_len(4);
    }

    #[inline]
    pub fn set_operation(&mut self, value: Operation) {
        let data = oper_mut(self.buf.as_mut());
        NetworkEndian::write_u16(data, value.into())
    }

    #[inline]
    pub fn set_source_mac_addr(&mut self, value: MacAddr) {
        let data = sha_mut(self.buf.as_mut());
        data.copy_from_slice(value.as_bytes());
    }

    #[inline]
    pub fn set_source_ipv4_addr(&mut self, value: Ipv4Addr) {
        let data = spa_mut(self.buf.as_mut());
        data.copy_from_slice(value.as_bytes())
    }

    #[inline]
    pub fn set_target_mac_addr(&mut self, value: MacAddr) {
        let data = tha_mut(self.buf.as_mut());
        data.copy_from_slice(value.as_bytes())
    }

    #[inline]
    pub fn set_target_ipv4_addr(&mut self, value: Ipv4Addr) {
        let data = tpa_mut(self.buf.as_mut());
        data.copy_from_slice(value.as_bytes())
    }
}
