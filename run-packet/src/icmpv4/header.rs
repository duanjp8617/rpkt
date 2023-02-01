use byteorder::{ByteOrder, NetworkEndian};

use crate::ipv4::Ipv4Addr;

use super::IcmpType;

header_field_val_accessors! {
    (type_, type_mut, 0),
    (code, code_mut, 1),
}

header_field_range_accessors! {
    (checksum, checksum_mut, 2..4),
    (rest_of_header, rest_of_header_mut, 4..8),
    (fst_half, fst_half_mut, 4..6),
    (snd_half, snd_half_mut, 6..8),
}

pub const ICMPV4_HEADER_LEN: usize = 8;

pub const ICMPV4_HEADER_TEMPLATE: Icmpv4Header<[u8; ICMPV4_HEADER_LEN]> = Icmpv4Header {
    buf: [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
};

#[derive(Clone, Copy, Debug)]
pub struct Icmpv4Header<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> Icmpv4Header<T> {
    #[inline]
    pub fn new(buf: T) -> Result<Self, T> {
        if buf.as_ref().len() >= ICMPV4_HEADER_LEN {
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
        &self.buf.as_ref()[0..ICMPV4_HEADER_LEN]
    }

    #[inline]
    pub fn to_owned(&self) -> Icmpv4Header<[u8; ICMPV4_HEADER_LEN]> {
        let mut buf = [0; ICMPV4_HEADER_LEN];
        buf.copy_from_slice(self.as_bytes());
        Icmpv4Header { buf }
    }

    #[inline]
    pub fn icmp_type(&self) -> IcmpType {
        let data = *type_(self.buf.as_ref());
        IcmpType::from(data)
    }

    #[inline]
    pub fn code(&self) -> u8 {
        *code(self.buf.as_ref())
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = checksum(self.buf.as_ref());
        NetworkEndian::read_u16(data)
    }

    #[inline]
    pub fn rest_of_header(&self) -> [u8; 4] {
        let mut data: [u8; 4] = [0; 4];
        data.copy_from_slice(rest_of_header(self.buf.as_ref()));
        data
    }

    #[inline]
    pub fn ipv4_addr(&self) -> Ipv4Addr {
        let data = rest_of_header(self.buf.as_ref());
        Ipv4Addr::from_bytes(data)
    }

    #[inline]
    pub fn ident(&self) -> u16 {
        let data = fst_half(self.buf.as_ref());
        NetworkEndian::read_u16(data)
    }

    #[inline]
    pub fn seq_num(&self) -> u16 {
        let data = snd_half(self.buf.as_ref());
        NetworkEndian::read_u16(data)
    }

    #[inline]
    pub fn next_hop_mtu(&self) -> u16 {
        let data = snd_half(self.buf.as_ref());
        NetworkEndian::read_u16(data)
    }
}

impl<T: AsMut<[u8]>> Icmpv4Header<T> {
    #[inline]
    pub fn set_icmp_type(&mut self, value: IcmpType) {
        *type_mut(self.buf.as_mut()) = value.into();
    }

    #[inline]
    pub fn set_code(&mut self, value: u8) {
        *code_mut(self.buf.as_mut()) = value;
    }

    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = checksum_mut(self.buf.as_mut());
        NetworkEndian::write_u16(data, value)
    }

    #[inline]
    pub fn set_rest_of_header(&mut self, value: &[u8]) {
        let data = rest_of_header_mut(self.buf.as_mut());
        data.copy_from_slice(value);
    }

    #[inline]
    pub fn set_ipv4_addr(&mut self, value: Ipv4Addr) {
        let data = rest_of_header_mut(self.buf.as_mut());
        data.copy_from_slice(value.as_bytes());
    }

    #[inline]
    pub fn set_ident(&mut self, value: u16) {
        let data = fst_half_mut(self.buf.as_mut());
        NetworkEndian::write_u16(data, value)
    }

    #[inline]
    pub fn set_seq_num(&mut self, value: u16) {
        let data = snd_half_mut(self.buf.as_mut());
        NetworkEndian::write_u16(data, value)
    }

    #[inline]
    pub fn set_next_hop_mtu(&mut self, value: u16) {
        let data = snd_half_mut(self.buf.as_mut());
        NetworkEndian::write_u16(data, value)
    }
}
