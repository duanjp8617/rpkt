#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::cursors::*;
use crate::ether::EtherType;
use crate::traits::*;

/// A constant that defines the fixed byte length of the Gtpv1 protocol header.
pub const GTPV1_HEADER_LEN: usize = 8;
/// A fixed Gtpv1 header.
pub const GTPV1_HEADER_TEMPLATE: [u8; 8] = [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct Gtpv1<T> {
    buf: T,
}
impl<T: Buf> Gtpv1<T> {
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
        if ((container.header_len() as usize) < 8)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..8]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[8..header_len]
    }
    #[inline]
    pub fn version(&self) -> u8 {
        self.buf.chunk()[0] >> 5
    }
    #[inline]
    pub fn protocol_type(&self) -> u8 {
        (self.buf.chunk()[0] >> 4) & 0x1
    }
    #[inline]
    pub fn reserved(&self) -> u8 {
        (self.buf.chunk()[0] >> 3) & 0x1
    }
    #[inline]
    pub fn extention_header_present(&self) -> bool {
        self.buf.chunk()[0] & 0x4 != 0
    }
    #[inline]
    pub fn sequence_present(&self) -> bool {
        self.buf.chunk()[0] & 0x2 != 0
    }
    #[inline]
    pub fn npdu_present(&self) -> bool {
        self.buf.chunk()[0] & 0x1 != 0
    }
    #[inline]
    pub fn message_type(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn message_len(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn teid(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[4..8]).try_into().unwrap())
    }
}
impl<T: PktBuf> Gtpv1<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> Gtpv1<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        let header_len = Gtpv1::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 8) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[8..header_len]
    }
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x1f) | (value << 5);
    }
    #[inline]
    pub fn set_protocol_type(&mut self, value: u8) {
        assert!(value == 1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xef) | (value << 4);
    }
    #[inline]
    pub fn set_reserved(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_extention_header_present(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfb) | (value << 2);
    }
    #[inline]
    pub fn set_sequence_present(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfd) | (value << 1);
    }
    #[inline]
    pub fn set_npdu_present(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfe) | value;
    }
    #[inline]
    pub fn set_message_type(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_message_len(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_teid(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[4..8]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> Gtpv1<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 8)
            || ((container.header_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        Cursor::new(&self.buf.chunk()[header_len..])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 8]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> Gtpv1<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 8)
            || ((container.header_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[header_len..])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 8]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

impl<T: Buf> Gtpv1<T> {
    #[inline]
    pub fn header_len(&self) -> usize {
        if self.sequence_present() || self.extention_header_present() || self.npdu_present() {
            12
        } else {
            8
        }
    }

    /// Return the sequence value.
    ///
    /// # Panics
    /// This function panics if `self.sequence_present()`, `self.extention_header_present()`
    /// and `self.npdu_present()` are all false.
    #[inline]
    pub fn sequence(&self) -> u16 {
        assert!(self.sequence_present() || self.extention_header_present() || self.npdu_present());
        u16::from_be_bytes(self.buf.chunk()[8..10].try_into().unwrap())
    }

    /// Return the n-pdu value.
    ///
    /// # Panics
    /// This function panics if `self.sequence_present()`, `self.extention_header_present()`
    /// and `self.npdu_present()` are all false.
    #[inline]
    pub fn npdu(&self) -> u8 {
        assert!(self.sequence_present() || self.extention_header_present() || self.npdu_present());
        self.buf.chunk()[10]
    }

    /// Return the next extention header.
    ///
    /// # Panics
    /// This function panics if `self.sequence_present()`, `self.extention_header_present()`
    /// and `self.npdu_present()` are all false.
    #[inline]
    pub fn next_extention_header(&self) -> u8 {
        assert!(self.sequence_present() || self.extention_header_present() || self.npdu_present());
        self.buf.chunk()[11]
    }
}

impl<T: PktBufMut> Gtpv1<T> {
    /// Set the sequence value.
    ///
    /// # Panics
    /// This function panics if `self.sequence_present()`, `self.extention_header_present()`
    /// and `self.npdu_present()` are all false.
    #[inline]
    pub fn set_sequence(&mut self, value: u16) {
        assert!(self.sequence_present() || self.extention_header_present() || self.npdu_present());
        self.buf.chunk_mut()[8..10].copy_from_slice(&value.to_be_bytes());
    }

    /// Set the npdu value.
    ///
    /// # Panics
    /// This function panics if `self.sequence_present()`, `self.extention_header_present()`
    /// and `self.npdu_present()` are all false.
    #[inline]
    pub fn set_npdu(&mut self, value: u8) {
        assert!(self.sequence_present() || self.extention_header_present() || self.npdu_present());
        self.buf.chunk_mut()[10] = value;
    }

    /// Set the next extention header value.
    ///
    /// # Panics
    /// This function panics if `self.sequence_present()`, `self.extention_header_present()`
    /// and `self.npdu_present()` are all false.
    #[inline]
    #[inline]
    pub fn set_next_extention_header(&mut self, value: u8) {
        assert!(self.sequence_present() || self.extention_header_present() || self.npdu_present());
        self.buf.chunk_mut()[11] = value;
    }
}
