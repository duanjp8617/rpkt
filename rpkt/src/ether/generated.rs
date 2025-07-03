#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::ether::{EtherAddr, EtherType};
use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

/// A constant that defines the fixed byte length of the Ether protocol header.
pub const ETHER_HEADER_LEN: usize = 14;
/// A fixed Ether header.
pub const ETHER_HEADER_TEMPLATE: [u8; 14] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
];

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
    pub fn fix_header_slice(&self) -> &[u8] {
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
        EtherType::from(u16::from_be_bytes(
            (&self.buf.chunk()[12..14]).try_into().unwrap(),
        ))
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
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 14]) -> Self {
        assert!(buf.chunk_headroom() >= 14);
        buf.move_back(14);
        (&mut buf.chunk_mut()[0..14]).copy_from_slice(&header.as_ref()[..]);
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
        (&mut self.buf.chunk_mut()[12..14]).copy_from_slice(&u16::from(value).to_be_bytes());
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

/// A constant that defines the fixed byte length of the EthDot3 protocol header.
pub const ETHDOT3_HEADER_LEN: usize = 14;
/// A fixed EthDot3 header.
pub const ETHDOT3_HEADER_TEMPLATE: [u8; 14] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e,
];

#[derive(Debug, Clone, Copy)]
pub struct EthDot3Packet<T> {
    buf: T,
}
impl<T: Buf> EthDot3Packet<T> {
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
        if (container.payload_len() as usize) + 14 > container.buf.remaining() {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
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
    pub fn payload_len(&self) -> u16 {
        (u16::from_be_bytes((&self.buf.chunk()[12..14]).try_into().unwrap()))
    }
}
impl<T: PktBuf> EthDot3Packet<T> {
    #[inline]
    pub fn payload(self) -> T {
        assert!(14 + self.payload_len() as usize <= self.buf.remaining());
        let trim_size = self.buf.remaining() - (14 + self.payload_len() as usize);
        let mut buf = self.buf;
        if trim_size > 0 {
            buf.trim_off(trim_size);
        }
        buf.advance(14);
        buf
    }
}
impl<T: PktBufMut> EthDot3Packet<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 14]) -> Self {
        assert!(buf.chunk_headroom() >= 14);
        let payload_len = buf.remaining();
        assert!(payload_len <= 65535);
        buf.move_back(14);
        (&mut buf.chunk_mut()[0..14]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_payload_len(payload_len as u16);
        container
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
    pub fn set_payload_len(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[12..14]).copy_from_slice(&(value).to_be_bytes());
    }
}
impl<'a> EthDot3Packet<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 14 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.payload_len() as usize) + 14 > remaining_len {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let payload_len = self.payload_len() as usize;
        Cursor::new(&self.buf.chunk()[14..(14 + payload_len)])
    }
}
impl<'a> EthDot3Packet<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 14 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.payload_len() as usize) + 14 > remaining_len {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let payload_len = self.payload_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[14..(14 + payload_len)])
    }
}
