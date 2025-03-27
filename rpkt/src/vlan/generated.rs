#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::ether::EtherType;
use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

/// A constant that defines the fixed byte length of the Vlan protocol header.
pub const VLAN_HEADER_LEN: usize = 4;
/// A fixed Vlan header.
pub const VLAN_HEADER_TEMPLATE: [u8; 4] = [0x00, 0x01, 0x08, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct VlanPacket<T> {
    buf: T,
}
impl<T: Buf> VlanPacket<T> {
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
        if chunk_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..4]
    }
    #[inline]
    pub fn priority(&self) -> u8 {
        self.buf.chunk()[0] >> 5
    }
    #[inline]
    pub fn dei_flag(&self) -> bool {
        self.buf.chunk()[0] & 0x10 != 0
    }
    #[inline]
    pub fn vlan_id(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[0..2]).try_into().unwrap()) & 0xfff
    }
    #[inline]
    pub fn ethertype(&self) -> EtherType {
        EtherType::from(u16::from_be_bytes(
            (&self.buf.chunk()[2..4]).try_into().unwrap(),
        ))
    }
}
impl<T: PktBuf> VlanPacket<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(4);
        buf
    }
}
impl<T: PktBufMut> VlanPacket<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        assert!(buf.chunk_headroom() >= 4);
        buf.move_back(4);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_priority(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x1f) | (value << 5);
    }
    #[inline]
    pub fn set_dei_flag(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] | 0x10
        } else {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] & 0xef
        }
    }
    #[inline]
    pub fn set_vlan_id(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = ((self.buf.chunk_mut()[0] & 0xf0) as u16) << 8 | value;
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_ethertype(&mut self, value: EtherType) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&u16::from(value).to_be_bytes());
    }
}
impl<'a> VlanPacket<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[4..])
    }
}
impl<'a> VlanPacket<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[4..])
    }
}

/// A constant that defines the fixed byte length of the VlanDot3 protocol
/// header.
pub const VLANDOT3_HEADER_LEN: usize = 4;
/// A fixed VlanDot3 header.
pub const VLANDOT3_HEADER_TEMPLATE: [u8; 4] = [0x00, 0x01, 0x00, 0x04];

#[derive(Debug, Clone, Copy)]
pub struct VlanDot3Packet<T> {
    buf: T,
}
impl<T: Buf> VlanDot3Packet<T> {
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
        if chunk_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.payload_len() as usize) + 4 > container.buf.remaining() {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..4]
    }
    #[inline]
    pub fn priority(&self) -> u8 {
        self.buf.chunk()[0] >> 5
    }
    #[inline]
    pub fn dei_flag(&self) -> bool {
        self.buf.chunk()[0] & 0x10 != 0
    }
    #[inline]
    pub fn vlan_id(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[0..2]).try_into().unwrap()) & 0xfff
    }
    #[inline]
    pub fn payload_len(&self) -> u16 {
        (u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap()))
    }
}
impl<T: PktBuf> VlanDot3Packet<T> {
    #[inline]
    pub fn payload(self) -> T {
        assert!(4 + self.payload_len() as usize <= self.buf.remaining());
        let trim_size = self.buf.remaining() - (4 + self.payload_len() as usize);
        let mut buf = self.buf;
        if trim_size > 0 {
            buf.trim_off(trim_size);
        }
        buf.advance(4);
        buf
    }
}
impl<T: PktBufMut> VlanDot3Packet<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        assert!(buf.chunk_headroom() >= 4);
        let payload_len = buf.remaining();
        assert!(payload_len <= 65535);
        buf.move_back(4);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_payload_len(payload_len as u16);
        container
    }
    #[inline]
    pub fn set_priority(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x1f) | (value << 5);
    }
    #[inline]
    pub fn set_dei_flag(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] | 0x10
        } else {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] & 0xef
        }
    }
    #[inline]
    pub fn set_vlan_id(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = ((self.buf.chunk_mut()[0] & 0xf0) as u16) << 8 | value;
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_payload_len(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&(value).to_be_bytes());
    }
}
impl<'a> VlanDot3Packet<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.payload_len() as usize) + 4 > remaining_len {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let payload_len = self.payload_len() as usize;
        Cursor::new(&self.buf.chunk()[4..(4 + payload_len)])
    }
}
impl<'a> VlanDot3Packet<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.payload_len() as usize) + 4 > remaining_len {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let payload_len = self.payload_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[4..(4 + payload_len)])
    }
}
