#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::endian::{read_uint_from_be_bytes, write_uint_as_be_bytes};
use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

/// A constant that defines the fixed byte length of the Vxlan protocol header.
pub const VXLAN_HEADER_LEN: usize = 8;
/// A fixed Vxlan header.
pub const VXLAN_HEADER_TEMPLATE: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct Vxlan<T> {
    buf: T,
}
impl<T: Buf> Vxlan<T> {
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
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..8]
    }
    #[inline]
    pub fn gbp_extention(&self) -> bool {
        self.buf.chunk()[0] & 0x80 != 0
    }
    #[inline]
    pub fn reserved_0(&self) -> u8 {
        (self.buf.chunk()[0] >> 4) & 0x7
    }
    #[inline]
    pub fn vni_present(&self) -> bool {
        self.buf.chunk()[0] & 0x8 != 0
    }
    #[inline]
    pub fn reserved_1(&self) -> u8 {
        ((u16::from_be_bytes((&self.buf.chunk()[0..2]).try_into().unwrap()) >> 7) & 0xf) as u8
    }
    #[inline]
    pub fn dont_learn(&self) -> bool {
        self.buf.chunk()[1] & 0x40 != 0
    }
    #[inline]
    pub fn reserved_2(&self) -> u8 {
        (self.buf.chunk()[1] >> 4) & 0x3
    }
    #[inline]
    pub fn policy_applied(&self) -> bool {
        self.buf.chunk()[1] & 0x8 != 0
    }
    #[inline]
    pub fn reserved_3(&self) -> u8 {
        self.buf.chunk()[1] & 0x7
    }
    #[inline]
    pub fn group_id(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn vni(&self) -> u32 {
        (read_uint_from_be_bytes(&self.buf.chunk()[4..7])) as u32
    }
    #[inline]
    pub fn reserved_4(&self) -> u8 {
        self.buf.chunk()[7]
    }
}
impl<T: PktBuf> Vxlan<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> Vxlan<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_gbp_extention(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x7f) | (value << 7);
    }
    #[inline]
    pub fn set_reserved_0(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x8f) | (value << 4);
    }
    #[inline]
    pub fn set_vni_present(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_reserved_1(&mut self, value: u8) {
        assert!(value <= 0xf);
        let write_value = ((value << 7) as u16)
            | (((self.buf.chunk_mut()[0] & 0xf8) as u16) << 8)
            | ((self.buf.chunk_mut()[1] & 0x7f) as u16);
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_dont_learn(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xbf) | (value << 6);
    }
    #[inline]
    pub fn set_reserved_2(&mut self, value: u8) {
        assert!(value <= 0x3);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xcf) | (value << 4);
    }
    #[inline]
    pub fn set_policy_applied(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_reserved_3(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xf8) | value;
    }
    #[inline]
    pub fn set_group_id(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_vni(&mut self, value: u32) {
        assert!(value <= 0xffffff);
        write_uint_as_be_bytes(&mut self.buf.chunk_mut()[4..7], (value as u64));
    }
    #[inline]
    pub fn set_reserved_4(&mut self, value: u8) {
        self.buf.chunk_mut()[7] = value;
    }
}
impl<'a> Vxlan<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[8..])
    }
}
impl<'a> Vxlan<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[8..])
    }
}
