use byteorder::{ByteOrder, NetworkEndian};

use crate::ipv4::IpProtocol;

use super::Ipv6Addr;

header_field_val_accessors! {
    (next_header, next_header_mut, 6),
    (hop_limit, hop_limit_mut, 7),
}

header_field_range_accessors! {
    (f_label, f_label_mut, 1..4),
    (payload_len, payload_len_mut, 4..6),
    (src_ip, src_ip_mut, 8..24),
    (dst_ip, dst_ip_mut, 24..40),
}

pub const IPV6_HEADER_LEN: usize = 40;

#[derive(Clone, Copy, Debug)]
pub struct Ipv6Header<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> Ipv6Header<T> {
    #[inline]
    pub fn new(buf: T) -> Result<Self, T> {
        if buf.as_ref().len() >= IPV6_HEADER_LEN {
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
        &self.buf.as_ref()[0..IPV6_HEADER_LEN]
    }

    #[inline]
    pub fn to_owned(&self) -> Ipv6Header<[u8; IPV6_HEADER_LEN]> {
        let mut buf = [0; IPV6_HEADER_LEN];
        buf.copy_from_slice(self.as_bytes());
        Ipv6Header { buf }
    }

    #[inline]
    pub fn check_version(&self) -> bool {
        (self.buf.as_ref()[0] >> 4) == 6
    }

    #[inline]
    pub fn traffic_class(&self) -> u8 {
        (self.buf.as_ref()[0] << 4) | (self.buf.as_ref()[1] >> 4)
    }

    #[inline]
    pub fn flow_label(&self) -> u32 {
        let data = f_label(self.buf.as_ref());
        NetworkEndian::read_u24(data) & 0x0fffff
    }

    #[inline]
    pub fn payload_len(&self) -> u16 {
        let data = payload_len(self.buf.as_ref());
        NetworkEndian::read_u16(data)
    }

    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        let data = next_header(self.buf.as_ref());
        (*data).into()
    }

    #[inline]
    pub fn hop_limit(&self) -> u8 {
        let data = hop_limit(self.buf.as_ref());
        *data
    }

    #[inline]
    pub fn source_ip(&self) -> Ipv6Addr {
        let data = src_ip(self.buf.as_ref());
        Ipv6Addr::from_bytes(data)
    }

    #[inline]
    pub fn dest_ip(&self) -> Ipv6Addr {
        let data = dst_ip(self.buf.as_ref());
        Ipv6Addr::from_bytes(data)
    }
}

impl<T: AsMut<[u8]>> Ipv6Header<T> {
    #[inline]
    pub fn adjust_version(&mut self) {
        self.buf.as_mut()[0] = (self.buf.as_mut()[0] & 0x0f) | (6 << 4);
    }

    #[inline]
    pub fn set_traffic_class(&mut self, value: u8) {
        self.buf.as_mut()[0] = (self.buf.as_mut()[0] & 0xf0) | (value >> 4);
        self.buf.as_mut()[1] = (self.buf.as_mut()[1] & 0x0f) | (value << 4);
    }

    #[inline]
    pub fn set_flow_label(&mut self, value: u32) {
        assert!(value <= 0xfffff);
        let data = NetworkEndian::read_u24(f_label_mut(self.buf.as_mut()));
        NetworkEndian::write_u24(f_label_mut(self.buf.as_mut()), (data & 0xf00000) | value);
    }

    #[inline]
    pub fn set_payload_len(&mut self, value: u16) {
        let data = payload_len_mut(self.buf.as_mut());
        NetworkEndian::write_u16(data, value);
    }

    #[inline]
    pub fn set_next_header(&mut self, value: IpProtocol) {
        let data = next_header_mut(self.buf.as_mut());
        *data = value.into();
    }

    #[inline]
    pub fn set_hop_limit(&mut self, value: u8) {
        let data = hop_limit_mut(self.buf.as_mut());
        *data = value;
    }

    #[inline]
    pub fn set_source_ip(&mut self, value: &Ipv6Addr) {
        let data = src_ip_mut(self.buf.as_mut());
        data.copy_from_slice(value.as_bytes());
    }

    #[inline]
    pub fn set_dest_ip(&mut self, value: &Ipv6Addr) {
        let data = dst_ip_mut(self.buf.as_mut());
        data.copy_from_slice(value.as_bytes());
    }
}