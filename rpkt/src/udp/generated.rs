#![allow(missing_docs)]
#![allow(unused_parens)]

use byteorder::{ByteOrder, NetworkEndian};

use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

/// A constant that defines the fixed byte length of the Udp protocol header.
pub const UDP_HEADER_LEN: usize = 8;
/// A fixed Udp header.
pub const UDP_HEADER_TEMPLATE: UdpHeader<[u8; 8]> = UdpHeader {
    buf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00],
};

#[derive(Debug, Clone, Copy)]
pub struct UdpHeader<T> {
    buf: T,
}
impl<T: AsRef<[u8]>> UdpHeader<T> {
    #[inline]
    pub fn parse_unchecked(buf: T) -> Self {
        Self { buf }
    }
    #[inline]
    pub fn buf(&self) -> &T {
        &self.buf
    }
    #[inline]
    pub fn release(self) -> T {
        self.buf
    }
    #[inline]
    pub fn parse(buf: T) -> Result<Self, T> {
        let remaining_len = buf.as_ref().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.as_ref()[0..8]
    }
    #[inline]
    pub fn src_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[0..2])
    }
    #[inline]
    pub fn dst_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[2..4])
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[6..8])
    }
    #[inline]
    pub fn packet_len(&self) -> u16 {
        (NetworkEndian::read_u16(&self.buf.as_ref()[4..6]))
    }
}
impl<T: AsMut<[u8]>> UdpHeader<T> {
    #[inline]
    pub fn header_slice_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[0..8]
    }
    #[inline]
    pub fn set_src_port(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[0..2], value);
    }
    #[inline]
    pub fn set_dst_port(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[2..4], value);
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[6..8], value);
    }
    #[inline]
    pub fn set_packet_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[4..6], (value));
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UdpPacket<T> {
    buf: T,
}
impl<T: Buf> UdpPacket<T> {
    #[inline]
    pub fn parse_unchecked(buf: T) -> Self {
        Self { buf }
    }
    #[inline]
    pub fn buf(&self) -> &T {
        &self.buf
    }
    #[inline]
    pub fn release(self) -> T {
        self.buf
    }
    #[inline]
    pub fn parse(buf: T) -> Result<Self, T> {
        let chunk_len = buf.chunk().len();
        if chunk_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.packet_len() as usize) < 8)
            || ((container.packet_len() as usize) > container.buf.remaining())
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..8]
    }
    #[inline]
    pub fn src_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.chunk()[0..2])
    }
    #[inline]
    pub fn dst_port(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.chunk()[2..4])
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.chunk()[6..8])
    }
    #[inline]
    pub fn packet_len(&self) -> u16 {
        (NetworkEndian::read_u16(&self.buf.chunk()[4..6]))
    }
}
impl<T: PktBuf> UdpPacket<T> {
    #[inline]
    pub fn payload(self) -> T {
        assert!((self.packet_len() as usize) <= self.buf.remaining());
        let trim_size = self.buf.remaining() - self.packet_len() as usize;
        let mut buf = self.buf;
        if trim_size > 0 {
            buf.trim_off(trim_size);
        }
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> UdpPacket<T> {
    #[inline]
    pub fn prepend_header<HT: AsRef<[u8]>>(mut buf: T, header: &UdpHeader<HT>) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        let packet_len = buf.remaining();
        assert!(packet_len <= 65535);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(header.header_slice());
        let mut container = Self { buf };
        container.set_packet_len(packet_len as u16);
        container
    }
    #[inline]
    pub fn set_src_port(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.chunk_mut()[0..2], value);
    }
    #[inline]
    pub fn set_dst_port(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.chunk_mut()[2..4], value);
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.chunk_mut()[6..8], value);
    }
    #[inline]
    pub fn set_packet_len(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.chunk_mut()[4..6], (value));
    }
}
impl<'a> UdpPacket<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.packet_len() as usize) < 8)
            || ((container.packet_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let packet_len = self.packet_len() as usize;
        Cursor::new(&self.buf.chunk()[8..packet_len])
    }
}
impl<'a> UdpPacket<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.packet_len() as usize) < 8)
            || ((container.packet_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let packet_len = self.packet_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[8..packet_len])
    }
}
