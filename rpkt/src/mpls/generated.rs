#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::endian::{read_uint_from_be_bytes, write_uint_as_be_bytes};
use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

/// A constant that defines the fixed byte length of the Mpls protocol header.
pub const MPLS_HEADER_LEN: usize = 4;
/// A fixed Mpls header.
pub const MPLS_HEADER_TEMPLATE: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct Mpls<T> {
    buf: T,
}
impl<T: Buf> Mpls<T> {
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
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..4]
    }
    #[inline]
    pub fn label(&self) -> u32 {
        (read_uint_from_be_bytes(&self.buf.chunk()[0..3]) >> 4) as u32
    }
    #[inline]
    pub fn experimental_bits(&self) -> u8 {
        (self.buf.chunk()[2] >> 1) & 0x7
    }
    #[inline]
    pub fn bottom_of_stack(&self) -> bool {
        self.buf.chunk()[2] & 0x1 != 0
    }
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.buf.chunk()[3]
    }
}
impl<T: PktBuf> Mpls<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(4);
        buf
    }
}
impl<T: PktBufMut> Mpls<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        assert!(buf.chunk_headroom() >= 4);
        buf.move_back(4);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_label(&mut self, value: u32) {
        assert!(value <= 0xfffff);
        let write_value = ((value << 4) as u64) | ((self.buf.chunk_mut()[2] & 0xf) as u64);
        write_uint_as_be_bytes(&mut self.buf.chunk_mut()[0..3], write_value);
    }
    #[inline]
    pub fn set_experimental_bits(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[2] = (self.buf.chunk_mut()[2] & 0xf1) | (value << 1);
    }
    #[inline]
    pub fn set_bottom_of_stack(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[2] = (self.buf.chunk_mut()[2] & 0xfe) | value;
    }
    #[inline]
    pub fn set_ttl(&mut self, value: u8) {
        self.buf.chunk_mut()[3] = value;
    }
}
impl<'a> Mpls<Cursor<'a>> {
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
    #[inline]
    pub fn default_header() -> [u8; 4] {
        MPLS_HEADER_TEMPLATE.clone()
    }
}
impl<'a> Mpls<CursorMut<'a>> {
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
