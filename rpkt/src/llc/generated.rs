#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

/// A constant that defines the fixed byte length of the Llc protocol header.
pub const LLC_HEADER_LEN: usize = 3;
/// A fixed Llc header.
pub const LLC_HEADER_TEMPLATE: [u8; 3] = [0x42, 0x42, 0x03];

#[derive(Debug, Clone, Copy)]
pub struct Llc<T> {
    buf: T,
}
impl<T: Buf> Llc<T> {
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
        if chunk_len < 3 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..3]
    }
    #[inline]
    pub fn dsap(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn ssap(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn control(&self) -> u8 {
        self.buf.chunk()[2]
    }
}
impl<T: PktBuf> Llc<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(3);
        buf
    }
}
impl<T: PktBufMut> Llc<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 3]) -> Self {
        assert!(buf.chunk_headroom() >= 3);
        buf.move_back(3);
        (&mut buf.chunk_mut()[0..3]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_dsap(&mut self, value: u8) {
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_ssap(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_control(&mut self, value: u8) {
        self.buf.chunk_mut()[2] = value;
    }
}
impl<'a> Llc<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 3 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[3..])
    }
}
impl<'a> Llc<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 3 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[3..])
    }
}
