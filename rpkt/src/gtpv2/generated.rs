#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::cursors::*;
use crate::endian::{read_uint_from_be_bytes, write_uint_as_be_bytes};
use crate::traits::*;

/// A constant that defines the fixed byte length of the Gtpv2 protocol header.
pub const GTPV2_HEADER_LEN: usize = 4;
/// A fixed Gtpv2 header.
pub const GTPV2_HEADER_TEMPLATE: [u8; 4] = [0x40, 0x00, 0x00, 0x04];

#[derive(Debug, Clone, Copy)]
pub struct Gtpv2<T> {
    buf: T,
}
impl<T: Buf> Gtpv2<T> {
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
        if ((container.header_len() as usize) < 4)
            || ((container.header_len() as usize) > chunk_len)
            || ((container.packet_len() as usize) < (container.header_len() as usize))
            || ((container.packet_len() as usize) > container.buf.remaining())
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..4]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[4..header_len]
    }
    #[inline]
    pub fn version(&self) -> u8 {
        self.buf.chunk()[0] >> 5
    }
    #[inline]
    pub fn piggybacking_flag(&self) -> bool {
        self.buf.chunk()[0] & 0x10 != 0
    }
    #[inline]
    pub fn teid_present(&self) -> bool {
        self.buf.chunk()[0] & 0x8 != 0
    }
    #[inline]
    pub fn spare(&self) -> u8 {
        self.buf.chunk()[0] & 0x7
    }
    #[inline]
    pub fn message_type(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn packet_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())) as u32 + 4
    }
}
impl<T: PktBuf> Gtpv2<T> {
    #[inline]
    pub fn payload(self) -> T {
        assert!((self.packet_len() as usize) <= self.buf.remaining());
        let trim_size = self.buf.remaining() - self.packet_len() as usize;
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        if trim_size > 0 {
            buf.trim_off(trim_size);
        }
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> Gtpv2<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        let header_len = Gtpv2::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 4) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        let packet_len = buf.remaining();
        assert!(packet_len <= 65539);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_packet_len(packet_len as u32);
        container
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[4..header_len]
    }
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        assert!(value == 2);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x1f) | (value << 5);
    }
    #[inline]
    pub fn set_piggybacking_flag(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xef) | (value << 4);
    }
    #[inline]
    pub fn set_teid_present(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_spare(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf8) | value;
    }
    #[inline]
    pub fn set_message_type(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_packet_len(&mut self, value: u32) {
        assert!((value <= 65539) && (value >= 4));
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&((value - 4) as u16).to_be_bytes());
    }
}
impl<'a> Gtpv2<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 4)
            || ((container.packet_len() as usize) < (container.header_len() as usize))
            || ((container.packet_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        let packet_len = self.packet_len() as usize;
        Cursor::new(&self.buf.chunk()[header_len..packet_len])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 4]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> Gtpv2<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 4)
            || ((container.packet_len() as usize) < (container.header_len() as usize))
            || ((container.packet_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        let packet_len = self.packet_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[header_len..packet_len])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 4]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

impl<T: Buf> Gtpv2<T> {
    /// A customized `header_len` function.
    /// The header length of Gtpv1 protocol is either 8 or 12 bytes, depending
    /// on the values of the sequence_present, extention_header_present and npdu_present
    /// flag bits.
    #[inline]
    pub fn header_len(&self) -> usize {
        if self.teid_present() {
            12
        } else {
            8
        }
    }

    /// Return the teid value.
    ///
    /// # Panics
    /// This function panics if `self.teid_present()` is false.
    #[inline]
    pub fn teid(&self) -> u32 {
        assert!(self.teid_present());
        u32::from_be_bytes(self.buf.chunk()[4..8].try_into().unwrap())
    }

    /// Return the sequence number.
    #[inline]
    pub fn seq_number(&self) -> u32 {
        if self.teid_present() {
            read_uint_from_be_bytes(&self.buf.chunk()[8..11]) as u32
        } else {
            read_uint_from_be_bytes(&self.buf.chunk()[4..7]) as u32
        }
    }
}

impl<T: PktBufMut> Gtpv2<T> {
    /// Set the teid value.
    ///
    /// # Panics
    /// This function panics if `self.teid_present()` is false.
    #[inline]
    pub fn set_teid(&mut self, value: u32) {
        assert!(self.teid_present());
        self.buf.chunk_mut()[4..8].copy_from_slice(&value.to_be_bytes());
    }

    /// Set the npdu value.
    ///
    /// # Panics
    /// This function panics if `self.sequence_present()`, `self.extention_header_present()`
    /// and `self.npdu_present()` are all false.
    #[inline]
    pub fn set_seq_number(&mut self, value: u32) {
        assert!(value < (1 << 24));
        if self.teid_present() {
            write_uint_as_be_bytes(&mut self.buf.chunk_mut()[8..11], value as u64);
        } else {
            write_uint_as_be_bytes(&mut self.buf.chunk_mut()[4..7], value as u64);
        }
    }
}
