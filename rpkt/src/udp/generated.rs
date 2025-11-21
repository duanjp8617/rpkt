#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

/// A constant that defines the fixed byte length of the Udp protocol header.
pub const UDP_HEADER_LEN: usize = 8;
/// A fixed Udp header.
pub const UDP_HEADER_TEMPLATE: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct Udp<T> {
    buf: T,
}
impl<T: Buf> Udp<T> {
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
        let packet_len = container.packet_len() as usize;
        if (packet_len < 8) || (packet_len > container.buf.remaining()) {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..8]
    }
    #[inline]
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[0..2]).try_into().unwrap())
    }
    #[inline]
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[6..8]).try_into().unwrap())
    }
    #[inline]
    pub fn packet_len(&self) -> u16 {
        (u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap()))
    }
}
impl<T: PktBuf> Udp<T> {
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
impl<T: PktBufMut> Udp<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        let packet_len = buf.remaining();
        assert!(packet_len <= 65535);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_packet_len(packet_len as u16);
        container
    }
    #[inline]
    pub fn set_src_port(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_dst_port(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[6..8]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_packet_len(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&(value).to_be_bytes());
    }
}
impl<'a> Udp<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        let packet_len = container.packet_len() as usize;
        if (packet_len < 8) || (packet_len > remaining_len) {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let packet_len = self.packet_len() as usize;
        Cursor::new(&self.buf.chunk()[8..packet_len])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 8]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 8] {
        UDP_HEADER_TEMPLATE.clone()
    }
}
impl<'a> Udp<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        let packet_len = container.packet_len() as usize;
        if (packet_len < 8) || (packet_len > remaining_len) {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let packet_len = self.packet_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[8..packet_len])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 8]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}
