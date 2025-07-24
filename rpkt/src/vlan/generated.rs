#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::ether::EtherType;
use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

/// A constant that defines the fixed byte length of the VlanFrame protocol header.
pub const VLAN_FRAME_HEADER_LEN: usize = 4;
/// A fixed VlanFrame header.
pub const VLAN_FRAME_HEADER_TEMPLATE: [u8; 4] = [0x00, 0x01, 0x08, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct VlanFrame<T> {
    buf: T,
}
impl<T: Buf> VlanFrame<T> {
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
    pub fn default_header() -> [u8; 4] {
        VLAN_FRAME_HEADER_TEMPLATE.clone()
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
    pub fn fix_header_slice(&self) -> &[u8] {
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
impl<T: PktBuf> VlanFrame<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(4);
        buf
    }
}
impl<T: PktBufMut> VlanFrame<T> {
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
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xef) | (value << 4);
    }
    #[inline]
    pub fn set_vlan_id(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value | (((self.buf.chunk_mut()[0] & 0xf0) as u16) << 8);
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_ethertype(&mut self, value: EtherType) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&u16::from(value).to_be_bytes());
    }
}
impl<'a> VlanFrame<Cursor<'a>> {
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
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 4]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> VlanFrame<CursorMut<'a>> {
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
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 4]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the VlanDot3Frame protocol header.
pub const VLAN_DOT3_FRAME_HEADER_LEN: usize = 4;
/// A fixed VlanDot3Frame header.
pub const VLAN_DOT3_FRAME_HEADER_TEMPLATE: [u8; 4] = [0x00, 0x01, 0x00, 0x04];

#[derive(Debug, Clone, Copy)]
pub struct VlanDot3Frame<T> {
    buf: T,
}
impl<T: Buf> VlanDot3Frame<T> {
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
    pub fn default_header() -> [u8; 4] {
        VLAN_DOT3_FRAME_HEADER_TEMPLATE.clone()
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
    pub fn fix_header_slice(&self) -> &[u8] {
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
impl<T: PktBuf> VlanDot3Frame<T> {
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
impl<T: PktBufMut> VlanDot3Frame<T> {
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
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xef) | (value << 4);
    }
    #[inline]
    pub fn set_vlan_id(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value | (((self.buf.chunk_mut()[0] & 0xf0) as u16) << 8);
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_payload_len(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&(value).to_be_bytes());
    }
}
impl<'a> VlanDot3Frame<Cursor<'a>> {
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
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 4]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> VlanDot3Frame<CursorMut<'a>> {
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
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 4]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

#[derive(Debug)]
pub enum VlanGroup<T> {
    VlanFrame_(VlanFrame<T>),
    VlanDot3Frame_(VlanDot3Frame<T>),
}
impl<T: Buf> VlanGroup<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 4 {
            return Err(buf);
        }
        let cond_value0 = u16::from_be_bytes((&buf.chunk()[2..4]).try_into().unwrap());
        match cond_value0 {
            1536..=65535 => VlanFrame::parse(buf).map(|pkt| VlanGroup::VlanFrame_(pkt)),
            ..=1500 => VlanDot3Frame::parse(buf).map(|pkt| VlanGroup::VlanDot3Frame_(pkt)),
            _ => Err(buf),
        }
    }
}
