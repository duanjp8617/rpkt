use byteorder::{ByteOrder, NetworkEndian};

header_field_range_accessors! {
    (source_port, source_port_mut, 0..2),
    (dest_port, dest_port_mut, 2..4),
    (length, length_mut, 4..6),
    (checksum, checksum_mut, 6..8),
}

pub const UDP_HEADER_LEN: usize = 8;

pub const UDP_HEADER_TEMPLATE: UdpHeader<[u8; 8]> = UdpHeader {
    buf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
};

#[derive(Clone, Copy, Debug)]
pub struct UdpHeader<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> UdpHeader<T> {
    #[inline]
    pub fn new(buf: T) -> Result<Self, T> {
        if buf.as_ref().len() >= UDP_HEADER_LEN {
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
        &self.buf.as_ref()[0..UDP_HEADER_LEN]
    }

    #[inline]
    pub fn to_owned(&self) -> UdpHeader<[u8; UDP_HEADER_LEN]> {
        let mut buf = [0; UDP_HEADER_LEN];
        buf.copy_from_slice(self.as_bytes());
        UdpHeader { buf }
    }

    #[inline]
    pub fn source_port(&self) -> u16 {
        let data = source_port(self.buf.as_ref());
        NetworkEndian::read_u16(data)
    }

    #[inline]
    pub fn dest_port(&self) -> u16 {
        let data = dest_port(self.buf.as_ref());
        NetworkEndian::read_u16(data)
    }

    #[inline]
    pub fn packet_len(&self) -> u16 {
        let data = length(self.buf.as_ref());
        NetworkEndian::read_u16(data)
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = checksum(self.buf.as_ref());
        NetworkEndian::read_u16(data)
    }
}

impl<T: AsMut<[u8]>> UdpHeader<T> {
    #[inline]
    pub fn set_source_port(&mut self, value: u16) {
        let data = source_port_mut(self.buf.as_mut());
        NetworkEndian::write_u16(data, value)
    }

    #[inline]
    pub fn set_dest_port(&mut self, value: u16) {
        let data = dest_port_mut(self.buf.as_mut());
        NetworkEndian::write_u16(data, value)
    }

    #[inline]
    pub fn set_packet_len(&mut self, value: u16) {
        let data = length_mut(self.buf.as_mut());
        NetworkEndian::write_u16(data, value)
    }

    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = checksum_mut(self.buf.as_mut());
        NetworkEndian::write_u16(data, value)
    }
}
