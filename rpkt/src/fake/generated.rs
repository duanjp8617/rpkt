#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::endian::{read_uint_from_be_bytes, write_uint_as_be_bytes};
use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

/// A constant that defines the fixed byte length of the Fake protocol header.
pub const FAKE_HEADER_LEN: usize = 12;
/// A fixed Fake header.
pub const FAKE_HEADER_TEMPLATE: [u8; 12] = [
    0x60, 0xa0, 0x15, 0xc7, 0xf7, 0xf8, 0xf9, 0x4a, 0xa1, 0xb3, 0xfd, 0x85,
];

#[derive(Debug, Clone, Copy)]
pub struct FakePacket<T> {
    buf: T,
}
impl<T: Buf> FakePacket<T> {
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
        if chunk_len < 12 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..12]
    }
    #[inline]
    pub fn f1(&self) -> u8 {
        self.buf.chunk()[0] >> 5
    }
    #[inline]
    pub fn f2(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[0..2]).try_into().unwrap()) & 0x1fff
    }
    #[inline]
    pub fn f3(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap()) >> 5
    }
    #[inline]
    pub fn f4(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[3..5]).try_into().unwrap()) & 0x1fff
    }
    #[inline]
    pub fn f5(&self) -> bool {
        self.buf.chunk()[5] & 0x80 != 0
    }
    #[inline]
    pub fn f6(&self) -> u16 {
        ((read_uint_from_be_bytes(&self.buf.chunk()[5..8]) >> 7) & 0xffff) as u16
    }
    #[inline]
    pub fn f7(&self) -> u8 {
        self.buf.chunk()[7] & 0x7f
    }
    #[inline]
    pub fn f8(&self) -> &[u8] {
        &self.buf.chunk()[8..10]
    }
    #[inline]
    pub fn f9(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[10..12]).try_into().unwrap()) >> 3
    }
    #[inline]
    pub fn f10(&self) -> u8 {
        self.buf.chunk()[11] & 0x7
    }
}
impl<T: PktBuf> FakePacket<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(12);
        buf
    }
}
impl<T: PktBufMut> FakePacket<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 12]) -> Self {
        assert!(buf.chunk_headroom() >= 12);
        buf.move_back(12);
        (&mut buf.chunk_mut()[0..12]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_f1(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x1f) | (value << 5);
    }
    #[inline]
    pub fn set_f2(&mut self, value: u16) {
        assert!(value <= 0x1fff);
        let write_value = value | (((self.buf.chunk_mut()[0] & 0xe0) as u16) << 8);
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_f3(&mut self, value: u16) {
        assert!(value <= 0x7ff);
        let write_value = (value << 5) | ((self.buf.chunk_mut()[3] & 0x1f) as u16);
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_f4(&mut self, value: u16) {
        assert!(value <= 0x1fff);
        let write_value = value | (((self.buf.chunk_mut()[3] & 0xe0) as u16) << 8);
        (&mut self.buf.chunk_mut()[3..5]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_f5(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[5] = self.buf.chunk_mut()[5] | 0x80
        } else {
            self.buf.chunk_mut()[5] = self.buf.chunk_mut()[5] & 0x7f
        }
    }
    #[inline]
    pub fn set_f6(&mut self, value: u16) {
        let write_value = ((value << 7) as u64)
            | (((self.buf.chunk_mut()[5] & 0x80) as u64) << 16)
            | ((self.buf.chunk_mut()[7] & 0x7f) as u64);
        write_uint_as_be_bytes(&mut self.buf.chunk_mut()[5..8], write_value);
    }
    #[inline]
    pub fn set_f7(&mut self, value: u8) {
        assert!(value <= 0x7f);
        self.buf.chunk_mut()[7] = (self.buf.chunk_mut()[7] & 0x80) | value;
    }
    #[inline]
    pub fn set_f8(&mut self, value: &[u8]) {
        (&mut self.buf.chunk_mut()[8..10]).copy_from_slice(value);
    }
    #[inline]
    pub fn set_f9(&mut self, value: u16) {
        assert!(value <= 0x1fff);
        let write_value = (value << 3) | ((self.buf.chunk_mut()[11] & 0x7) as u16);
        (&mut self.buf.chunk_mut()[10..12]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_f10(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[11] = (self.buf.chunk_mut()[11] & 0xf8) | value;
    }
}
impl<'a> FakePacket<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 12 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[12..])
    }
}
impl<'a> FakePacket<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 12 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[12..])
    }
}
