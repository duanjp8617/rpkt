#![allow(missing_docs)]

use byteorder::{ByteOrder, NetworkEndian};

use crate::ether::{EtherAddr, EtherType};
use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

/// A constant that defines the fixed byte length of the Ether protocol header.
pub const ETHER_HEADER_LEN: usize = 14;
/// A fixed Ether header.
pub const ETHER_HEADER_TEMPLATE: EtherHeader<[u8; 14]> = EtherHeader {
    buf: [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
    ],
};
#[derive(Debug, Clone, Copy)]
pub struct EtherHeader<T> {
    buf: T,
}
impl<T: AsRef<[u8]>> EtherHeader<T> {
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
        if remaining_len < 14 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.as_ref()[0..14]
    }
    #[inline]
    pub fn dst_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.as_ref()[0..6])
    }
    #[inline]
    pub fn src_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.as_ref()[6..12])
    }
    #[inline]
    pub fn ethertype(&self) -> EtherType {
        EtherType::from(NetworkEndian::read_u16(&self.buf.as_ref()[12..14]))
    }
}
impl<T: AsMut<[u8]>> EtherHeader<T> {
    #[inline]
    pub fn header_slice_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[0..14]
    }
    #[inline]
    pub fn set_dst_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.as_mut()[0..6]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_src_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.as_mut()[6..12]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_ethertype(&mut self, value: EtherType) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[12..14], u16::from(value));
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EtherPacket<T> {
    buf: T,
}
impl<T: Buf> EtherPacket<T> {
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
        if chunk_len < 14 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..14]
    }
    #[inline]
    pub fn dst_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.chunk()[0..6])
    }
    #[inline]
    pub fn src_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.chunk()[6..12])
    }
    #[inline]
    pub fn ethertype(&self) -> EtherType {
        EtherType::from(NetworkEndian::read_u16(&self.buf.chunk()[12..14]))
    }
}
impl<T: PktBuf> EtherPacket<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(14);
        buf
    }
}
impl<T: PktBufMut> EtherPacket<T> {
    #[inline]
    pub fn prepend_header<HT: AsRef<[u8]>>(mut buf: T, header: &EtherHeader<HT>) -> Self {
        assert!(buf.chunk_headroom() >= 14);
        buf.move_back(14);
        (&mut buf.chunk_mut()[0..14]).copy_from_slice(header.header_slice());
        Self { buf }
    }
    #[inline]
    pub fn set_dst_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.chunk_mut()[0..6]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_src_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.chunk_mut()[6..12]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_ethertype(&mut self, value: EtherType) {
        NetworkEndian::write_u16(&mut self.buf.chunk_mut()[12..14], u16::from(value));
    }
}
impl<'a> EtherPacket<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 14 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[14..])
    }
}
impl<'a> EtherPacket<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 14 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[14..])
    }
}
