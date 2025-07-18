#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::cursors::*;
use crate::endian::{read_uint_from_be_bytes, write_uint_as_be_bytes};
use crate::traits::*;

use super::GtpNextExtention;

/// A constant that defines the fixed byte length of the Gtpv1 protocol header.
pub const GTPV1_HEADER_LEN: usize = 8;
/// A fixed Gtpv1 header.
pub const GTPV1_HEADER_TEMPLATE: [u8; 8] = [0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

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
        assert!(value == 1);
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
    /// A customized `header_len` function.
    /// The header length of Gtpv1 protocol is either 8 or 12 bytes, depending
    /// on the values of the sequence_present, extention_header_present and npdu_present
    /// flag bits.
    #[inline]
    pub fn header_len(&self) -> usize {
        let first_byte = self.buf.chunk()[0];
        if first_byte & 0b00000111 == 0 {
            // sequence_present, extention_header_present and npdu_present
            // are all set to zero, the header length is 8
            8
        } else {
            12
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
    pub fn next_extention_header(&self) -> GtpNextExtention {
        assert!(self.sequence_present() || self.extention_header_present() || self.npdu_present());
        self.buf.chunk()[11].into()
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
    pub fn set_next_extention_header(&mut self, value: GtpNextExtention) {
        assert!(self.sequence_present() || self.extention_header_present() || self.npdu_present());
        self.buf.chunk_mut()[11] = value.into();
    }
}

/// A constant that defines the fixed byte length of the ExtUDPPort protocol header.
pub const EXTUDPPORT_HEADER_LEN: usize = 4;
/// A fixed ExtUDPPort header.
pub const EXTUDPPORT_HEADER_TEMPLATE: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct ExtUDPPort<T> {
    buf: T,
}
impl<T: Buf> ExtUDPPort<T> {
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
    pub fn len(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn udp_port(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())
    }
    #[inline]
    pub fn next_extention_header(&self) -> GtpNextExtention {
        GtpNextExtention::from(self.buf.chunk()[3])
    }
}
impl<T: PktBuf> ExtUDPPort<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(4);
        buf
    }
}
impl<T: PktBufMut> ExtUDPPort<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        assert!(buf.chunk_headroom() >= 4);
        buf.move_back(4);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_len(&mut self, value: u8) {
        assert!(value == 1);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_udp_port(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_next_extention_header(&mut self, value: GtpNextExtention) {
        self.buf.chunk_mut()[3] = u8::from(value);
    }
}
impl<'a> ExtUDPPort<Cursor<'a>> {
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
impl<'a> ExtUDPPort<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the ExtPDUNumber protocol header.
pub const EXTPDUNUMBER_HEADER_LEN: usize = 4;
/// A fixed ExtPDUNumber header.
pub const EXTPDUNUMBER_HEADER_TEMPLATE: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct ExtPDUNumber<T> {
    buf: T,
}
impl<T: Buf> ExtPDUNumber<T> {
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
    pub fn len(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn udp_port(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())
    }
    #[inline]
    pub fn next_extention_header(&self) -> GtpNextExtention {
        GtpNextExtention::from(self.buf.chunk()[3])
    }
}
impl<T: PktBuf> ExtPDUNumber<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(4);
        buf
    }
}
impl<T: PktBufMut> ExtPDUNumber<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        assert!(buf.chunk_headroom() >= 4);
        buf.move_back(4);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_len(&mut self, value: u8) {
        assert!(value == 1);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_udp_port(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_next_extention_header(&mut self, value: GtpNextExtention) {
        self.buf.chunk_mut()[3] = u8::from(value);
    }
}
impl<'a> ExtPDUNumber<Cursor<'a>> {
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
impl<'a> ExtPDUNumber<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the ExtLongPDUNumber protocol header.
pub const EXTLONGPDUNUMBER_HEADER_LEN: usize = 8;
/// A fixed ExtLongPDUNumber header.
pub const EXTLONGPDUNUMBER_HEADER_TEMPLATE: [u8; 8] =
    [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct ExtLongPDUNumber<T> {
    buf: T,
}
impl<T: Buf> ExtLongPDUNumber<T> {
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
    pub fn len(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn spare1(&self) -> u8 {
        self.buf.chunk()[1] >> 2
    }
    #[inline]
    pub fn pdu_number(&self) -> u32 {
        (read_uint_from_be_bytes(&self.buf.chunk()[1..4]) & 0x3ffff) as u32
    }
    #[inline]
    pub fn spare2(&self) -> u8 {
        self.buf.chunk()[4]
    }
    #[inline]
    pub fn spare3(&self) -> u8 {
        self.buf.chunk()[5]
    }
    #[inline]
    pub fn spare4(&self) -> u8 {
        self.buf.chunk()[6]
    }
    #[inline]
    pub fn next_extention_header(&self) -> GtpNextExtention {
        GtpNextExtention::from(self.buf.chunk()[7])
    }
}
impl<T: PktBuf> ExtLongPDUNumber<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> ExtLongPDUNumber<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_len(&mut self, value: u8) {
        assert!(value == 2);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_spare1(&mut self, value: u8) {
        assert!(value <= 0x3f);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0x03) | (value << 2);
    }
    #[inline]
    pub fn set_pdu_number(&mut self, value: u32) {
        assert!(value <= 0x3ffff);
        let write_value = (value as u64) | (((self.buf.chunk_mut()[1] & 0xfc) as u64) << 16);
        write_uint_as_be_bytes(&mut self.buf.chunk_mut()[1..4], write_value);
    }
    #[inline]
    pub fn set_spare2(&mut self, value: u8) {
        self.buf.chunk_mut()[4] = value;
    }
    #[inline]
    pub fn set_spare3(&mut self, value: u8) {
        self.buf.chunk_mut()[5] = value;
    }
    #[inline]
    pub fn set_spare4(&mut self, value: u8) {
        self.buf.chunk_mut()[6] = value;
    }
    #[inline]
    pub fn set_next_extention_header(&mut self, value: GtpNextExtention) {
        self.buf.chunk_mut()[7] = u8::from(value);
    }
}
impl<'a> ExtLongPDUNumber<Cursor<'a>> {
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
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 8]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> ExtLongPDUNumber<CursorMut<'a>> {
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
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 8]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the ExtServiceClassIndicator protocol header.
pub const EXTSERVICECLASSINDICATOR_HEADER_LEN: usize = 4;
/// A fixed ExtServiceClassIndicator header.
pub const EXTSERVICECLASSINDICATOR_HEADER_TEMPLATE: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct ExtServiceClassIndicator<T> {
    buf: T,
}
impl<T: Buf> ExtServiceClassIndicator<T> {
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
    pub fn len(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn service_class_indicator(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn spare(&self) -> u8 {
        self.buf.chunk()[2]
    }
    #[inline]
    pub fn next_extention_header(&self) -> GtpNextExtention {
        GtpNextExtention::from(self.buf.chunk()[3])
    }
}
impl<T: PktBuf> ExtServiceClassIndicator<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(4);
        buf
    }
}
impl<T: PktBufMut> ExtServiceClassIndicator<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        assert!(buf.chunk_headroom() >= 4);
        buf.move_back(4);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_len(&mut self, value: u8) {
        assert!(value == 1);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_service_class_indicator(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_spare(&mut self, value: u8) {
        self.buf.chunk_mut()[2] = value;
    }
    #[inline]
    pub fn set_next_extention_header(&mut self, value: GtpNextExtention) {
        self.buf.chunk_mut()[3] = u8::from(value);
    }
}
impl<'a> ExtServiceClassIndicator<Cursor<'a>> {
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
impl<'a> ExtServiceClassIndicator<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the ExtContainer protocol header.
pub const EXTCONTAINER_HEADER_LEN: usize = 1;
/// A fixed ExtContainer header.
pub const EXTCONTAINER_HEADER_TEMPLATE: [u8; 1] = [0x04];

#[derive(Debug, Clone, Copy)]
pub struct ExtContainer<T> {
    buf: T,
}
impl<T: Buf> ExtContainer<T> {
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
        if chunk_len < 1 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 1)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..1]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[1..header_len]
    }
    #[inline]
    pub fn header_len(&self) -> u16 {
        (self.buf.chunk()[0]) as u16 * 4
    }
}
impl<T: PktBuf> ExtContainer<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> ExtContainer<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 1]) -> Self {
        let header_len = ExtContainer::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 1) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..1]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[1..header_len]
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u16) {
        assert!((value <= 1020) && (value % 4 == 0));
        self.buf.chunk_mut()[0] = ((value / 4) as u8);
    }
}
impl<'a> ExtContainer<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 1 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 1)
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
    pub fn from_header_array(header_array: &'a [u8; 1]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> ExtContainer<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 1 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 1)
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
    pub fn from_header_array_mut(header_array: &'a mut [u8; 1]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

impl<T: Buf> ExtContainer<T> {
    /// Return a byte slice covering the content of the extention header.
    #[inline]
    pub fn extention_header_content(&self) -> &[u8] {
        &self.buf.chunk()[1..(self.header_len() as usize - 1)]
    }

    /// Get the value of the next extention header type.
    #[inline]
    pub fn next_extention_header_type(&self) -> GtpNextExtention {
        self.buf.chunk()[self.header_len() as usize - 1].into()
    }
}

impl<T: PktBufMut> ExtContainer<T> {
    /// Return a mutable byte slice of covering the content of the
    /// extention header.
    #[inline]
    pub fn extention_header_content_mut(&mut self) -> &mut [u8] {
        let index = self.header_len() as usize - 1;
        &mut self.buf.chunk_mut()[1..index]
    }

    /// Set the next extention header type.
    #[inline]
    pub fn set_next_extention_header_type(&mut self, value: GtpNextExtention) {
        let index = self.header_len() as usize - 1;
        self.buf.chunk_mut()[index] = value.into();
    }
}

/// A constant that defines the fixed byte length of the PduSessionFrameDl protocol header.
pub const PDUSESSIONFRAMEDL_HEADER_LEN: usize = 2;
/// A fixed PduSessionFrameDl header.
pub const PDUSESSIONFRAMEDL_HEADER_TEMPLATE: [u8; 2] = [0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct PduSessionFrameDl<T> {
    buf: T,
}
impl<T: Buf> PduSessionFrameDl<T> {
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
        if chunk_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..2]
    }
    #[inline]
    pub fn pdu_type(&self) -> u8 {
        self.buf.chunk()[0] >> 4
    }
    #[inline]
    pub fn qmp(&self) -> u8 {
        (self.buf.chunk()[0] >> 3) & 0x1
    }
    #[inline]
    pub fn snp(&self) -> u8 {
        (self.buf.chunk()[0] >> 2) & 0x1
    }
    #[inline]
    pub fn msnp(&self) -> u8 {
        (self.buf.chunk()[0] >> 1) & 0x1
    }
    #[inline]
    pub fn spare(&self) -> u8 {
        self.buf.chunk()[0] & 0x1
    }
    #[inline]
    pub fn ppp(&self) -> u8 {
        self.buf.chunk()[1] >> 7
    }
    #[inline]
    pub fn rqi(&self) -> u8 {
        (self.buf.chunk()[1] >> 6) & 0x1
    }
    #[inline]
    pub fn qos_flow_identifier(&self) -> u8 {
        self.buf.chunk()[1] & 0x3f
    }
}
impl<T: PktBuf> PduSessionFrameDl<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(2);
        buf
    }
}
impl<T: PktBufMut> PduSessionFrameDl<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        assert!(buf.chunk_headroom() >= 2);
        buf.move_back(2);
        (&mut buf.chunk_mut()[0..2]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_pdu_type(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_qmp(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_snp(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfb) | (value << 2);
    }
    #[inline]
    pub fn set_msnp(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfd) | (value << 1);
    }
    #[inline]
    pub fn set_spare(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfe) | value;
    }
    #[inline]
    pub fn set_ppp(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0x7f) | (value << 7);
    }
    #[inline]
    pub fn set_rqi(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xbf) | (value << 6);
    }
    #[inline]
    pub fn set_qos_flow_identifier(&mut self, value: u8) {
        assert!(value <= 0x3f);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xc0) | value;
    }
}
impl<'a> PduSessionFrameDl<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[2..])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 2]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> PduSessionFrameDl<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[2..])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 2]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the PduSessionFrameUl protocol header.
pub const PDUSESSIONFRAMEUL_HEADER_LEN: usize = 2;
/// A fixed PduSessionFrameUl header.
pub const PDUSESSIONFRAMEUL_HEADER_TEMPLATE: [u8; 2] = [0x10, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct PduSessionFrameUl<T> {
    buf: T,
}
impl<T: Buf> PduSessionFrameUl<T> {
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
        if chunk_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..2]
    }
    #[inline]
    pub fn pdu_type(&self) -> u8 {
        self.buf.chunk()[0] >> 4
    }
    #[inline]
    pub fn qmp(&self) -> u8 {
        (self.buf.chunk()[0] >> 3) & 0x1
    }
    #[inline]
    pub fn dl_delay_ind(&self) -> u8 {
        (self.buf.chunk()[0] >> 2) & 0x1
    }
    #[inline]
    pub fn ul_delay_ind(&self) -> u8 {
        (self.buf.chunk()[0] >> 1) & 0x1
    }
    #[inline]
    pub fn snp(&self) -> u8 {
        self.buf.chunk()[0] & 0x1
    }
    #[inline]
    pub fn n3_n9_delay_ind(&self) -> u8 {
        self.buf.chunk()[1] >> 7
    }
    #[inline]
    pub fn new_ie_flag(&self) -> u8 {
        (self.buf.chunk()[1] >> 6) & 0x1
    }
    #[inline]
    pub fn qos_flow_identifier(&self) -> u8 {
        self.buf.chunk()[1] & 0x3f
    }
}
impl<T: PktBuf> PduSessionFrameUl<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(2);
        buf
    }
}
impl<T: PktBufMut> PduSessionFrameUl<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        assert!(buf.chunk_headroom() >= 2);
        buf.move_back(2);
        (&mut buf.chunk_mut()[0..2]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_pdu_type(&mut self, value: u8) {
        assert!(value == 1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_qmp(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_dl_delay_ind(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfb) | (value << 2);
    }
    #[inline]
    pub fn set_ul_delay_ind(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfd) | (value << 1);
    }
    #[inline]
    pub fn set_snp(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfe) | value;
    }
    #[inline]
    pub fn set_n3_n9_delay_ind(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0x7f) | (value << 7);
    }
    #[inline]
    pub fn set_new_ie_flag(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xbf) | (value << 6);
    }
    #[inline]
    pub fn set_qos_flow_identifier(&mut self, value: u8) {
        assert!(value <= 0x3f);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xc0) | value;
    }
}
impl<'a> PduSessionFrameUl<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[2..])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 2]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> PduSessionFrameUl<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[2..])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 2]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

#[derive(Debug)]
pub enum PduSessionFrameGroup<T> {
    PduSessionFrameDl_(PduSessionFrameDl<T>),
    PduSessionFrameUl_(PduSessionFrameUl<T>),
}
impl<T: Buf> PduSessionFrameGroup<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 1 {
            return Err(buf);
        }
        let cond_value0 = buf.chunk()[0] >> 4;
        match cond_value0 {
            0 => PduSessionFrameDl::parse(buf)
                .map(|pkt| PduSessionFrameGroup::PduSessionFrameDl_(pkt)),
            1 => PduSessionFrameUl::parse(buf)
                .map(|pkt| PduSessionFrameGroup::PduSessionFrameUl_(pkt)),
            _ => Err(buf),
        }
    }
}

/// A constant that defines the fixed byte length of the NrUpFrameDlUserData protocol header.
pub const NRUPFRAMEDLUSERDATA_HEADER_LEN: usize = 5;
/// A fixed NrUpFrameDlUserData header.
pub const NRUPFRAMEDLUSERDATA_HEADER_TEMPLATE: [u8; 5] = [0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct NrUpFrameDlUserData<T> {
    buf: T,
}
impl<T: Buf> NrUpFrameDlUserData<T> {
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
        if chunk_len < 5 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..5]
    }
    #[inline]
    pub fn pdu_type(&self) -> u8 {
        self.buf.chunk()[0] >> 4
    }
    #[inline]
    pub fn spare1(&self) -> u8 {
        (self.buf.chunk()[0] >> 3) & 0x1
    }
    #[inline]
    pub fn dl_discard_blocks(&self) -> u8 {
        (self.buf.chunk()[0] >> 2) & 0x1
    }
    #[inline]
    pub fn dl_flush(&self) -> u8 {
        (self.buf.chunk()[0] >> 1) & 0x1
    }
    #[inline]
    pub fn report_polling(&self) -> u8 {
        self.buf.chunk()[0] & 0x1
    }
    #[inline]
    pub fn spare2(&self) -> u8 {
        self.buf.chunk()[1] >> 5
    }
    #[inline]
    pub fn req_oos_report(&self) -> u8 {
        (self.buf.chunk()[1] >> 4) & 0x1
    }
    #[inline]
    pub fn report_deliverd(&self) -> u8 {
        (self.buf.chunk()[1] >> 3) & 0x1
    }
    #[inline]
    pub fn user_data_exist(&self) -> u8 {
        (self.buf.chunk()[1] >> 2) & 0x1
    }
    #[inline]
    pub fn assist_info_report_polling(&self) -> u8 {
        (self.buf.chunk()[1] >> 1) & 0x1
    }
    #[inline]
    pub fn retrans_on(&self) -> u8 {
        self.buf.chunk()[1] & 0x1
    }
    #[inline]
    pub fn nr_u_seq(&self) -> u32 {
        (read_uint_from_be_bytes(&self.buf.chunk()[2..5])) as u32
    }
}
impl<T: PktBuf> NrUpFrameDlUserData<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(5);
        buf
    }
}
impl<T: PktBufMut> NrUpFrameDlUserData<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 5]) -> Self {
        assert!(buf.chunk_headroom() >= 5);
        buf.move_back(5);
        (&mut buf.chunk_mut()[0..5]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_pdu_type(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_spare1(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_dl_discard_blocks(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfb) | (value << 2);
    }
    #[inline]
    pub fn set_dl_flush(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfd) | (value << 1);
    }
    #[inline]
    pub fn set_report_polling(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfe) | value;
    }
    #[inline]
    pub fn set_spare2(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0x1f) | (value << 5);
    }
    #[inline]
    pub fn set_req_oos_report(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xef) | (value << 4);
    }
    #[inline]
    pub fn set_report_deliverd(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_user_data_exist(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xfb) | (value << 2);
    }
    #[inline]
    pub fn set_assist_info_report_polling(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xfd) | (value << 1);
    }
    #[inline]
    pub fn set_retrans_on(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xfe) | value;
    }
    #[inline]
    pub fn set_nr_u_seq(&mut self, value: u32) {
        assert!(value <= 0xffffff);
        write_uint_as_be_bytes(&mut self.buf.chunk_mut()[2..5], (value as u64));
    }
}
impl<'a> NrUpFrameDlUserData<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 5 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[5..])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 5]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> NrUpFrameDlUserData<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 5 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[5..])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 5]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the NrUpFrameDlDataDeliveryStatus protocol header.
pub const NRUPFRAMEDLDATADELIVERYSTATUS_HEADER_LEN: usize = 5;
/// A fixed NrUpFrameDlDataDeliveryStatus header.
pub const NRUPFRAMEDLDATADELIVERYSTATUS_HEADER_TEMPLATE: [u8; 5] = [0x10, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct NrUpFrameDlDataDeliveryStatus<T> {
    buf: T,
}
impl<T: Buf> NrUpFrameDlDataDeliveryStatus<T> {
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
        if chunk_len < 5 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..5]
    }
    #[inline]
    pub fn pdu_type(&self) -> u8 {
        self.buf.chunk()[0] >> 4
    }
    #[inline]
    pub fn highest_trans_nr_pdcp_sn_ind(&self) -> u8 {
        (self.buf.chunk()[0] >> 3) & 0x1
    }
    #[inline]
    pub fn highest_deliverd_nr_pdcp_sn_ind(&self) -> u8 {
        (self.buf.chunk()[0] >> 2) & 0x1
    }
    #[inline]
    pub fn final_frame_ind(&self) -> u8 {
        (self.buf.chunk()[0] >> 1) & 0x1
    }
    #[inline]
    pub fn lost_packet_report(&self) -> u8 {
        self.buf.chunk()[0] & 0x1
    }
    #[inline]
    pub fn spare2(&self) -> u8 {
        self.buf.chunk()[1] >> 5
    }
    #[inline]
    pub fn delivered_nr_pdcp_sn_range_ind(&self) -> u8 {
        (self.buf.chunk()[1] >> 4) & 0x1
    }
    #[inline]
    pub fn data_rate_ind(&self) -> u8 {
        (self.buf.chunk()[1] >> 3) & 0x1
    }
    #[inline]
    pub fn retrans_nf_pdcp_sn_ind(&self) -> u8 {
        (self.buf.chunk()[1] >> 2) & 0x1
    }
    #[inline]
    pub fn delivered_retrans_nr_pdcp_sn_ind(&self) -> u8 {
        (self.buf.chunk()[1] >> 1) & 0x1
    }
    #[inline]
    pub fn cause_report(&self) -> u8 {
        self.buf.chunk()[1] & 0x1
    }
    #[inline]
    pub fn buf_size_for_data_radio_bearer(&self) -> u32 {
        (read_uint_from_be_bytes(&self.buf.chunk()[2..5])) as u32
    }
}
impl<T: PktBuf> NrUpFrameDlDataDeliveryStatus<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(5);
        buf
    }
}
impl<T: PktBufMut> NrUpFrameDlDataDeliveryStatus<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 5]) -> Self {
        assert!(buf.chunk_headroom() >= 5);
        buf.move_back(5);
        (&mut buf.chunk_mut()[0..5]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_pdu_type(&mut self, value: u8) {
        assert!(value == 1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_highest_trans_nr_pdcp_sn_ind(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_highest_deliverd_nr_pdcp_sn_ind(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfb) | (value << 2);
    }
    #[inline]
    pub fn set_final_frame_ind(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfd) | (value << 1);
    }
    #[inline]
    pub fn set_lost_packet_report(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfe) | value;
    }
    #[inline]
    pub fn set_spare2(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0x1f) | (value << 5);
    }
    #[inline]
    pub fn set_delivered_nr_pdcp_sn_range_ind(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xef) | (value << 4);
    }
    #[inline]
    pub fn set_data_rate_ind(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_retrans_nf_pdcp_sn_ind(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xfb) | (value << 2);
    }
    #[inline]
    pub fn set_delivered_retrans_nr_pdcp_sn_ind(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xfd) | (value << 1);
    }
    #[inline]
    pub fn set_cause_report(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xfe) | value;
    }
    #[inline]
    pub fn set_buf_size_for_data_radio_bearer(&mut self, value: u32) {
        assert!(value <= 0xffffff);
        write_uint_as_be_bytes(&mut self.buf.chunk_mut()[2..5], (value as u64));
    }
}
impl<'a> NrUpFrameDlDataDeliveryStatus<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 5 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[5..])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 5]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> NrUpFrameDlDataDeliveryStatus<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 5 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[5..])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 5]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the NrUpFrameAssistInfoData protocol header.
pub const NRUPFRAMEASSISTINFODATA_HEADER_LEN: usize = 2;
/// A fixed NrUpFrameAssistInfoData header.
pub const NRUPFRAMEASSISTINFODATA_HEADER_TEMPLATE: [u8; 2] = [0x20, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct NrUpFrameAssistInfoData<T> {
    buf: T,
}
impl<T: Buf> NrUpFrameAssistInfoData<T> {
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
        if chunk_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..2]
    }
    #[inline]
    pub fn pdu_type(&self) -> u8 {
        self.buf.chunk()[0] >> 4
    }
    #[inline]
    pub fn pdcp_dupl_ind(&self) -> u8 {
        (self.buf.chunk()[0] >> 3) & 0x1
    }
    #[inline]
    pub fn assist_info_ind(&self) -> u8 {
        (self.buf.chunk()[0] >> 2) & 0x1
    }
    #[inline]
    pub fn ul_delay_ind(&self) -> u8 {
        (self.buf.chunk()[0] >> 1) & 0x1
    }
    #[inline]
    pub fn dl_delay_ind(&self) -> u8 {
        self.buf.chunk()[0] & 0x1
    }
    #[inline]
    pub fn spare(&self) -> u8 {
        self.buf.chunk()[1] >> 1
    }
    #[inline]
    pub fn pdcp_duplication_activation_suggestion(&self) -> u8 {
        self.buf.chunk()[1] & 0x1
    }
}
impl<T: PktBuf> NrUpFrameAssistInfoData<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(2);
        buf
    }
}
impl<T: PktBufMut> NrUpFrameAssistInfoData<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        assert!(buf.chunk_headroom() >= 2);
        buf.move_back(2);
        (&mut buf.chunk_mut()[0..2]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_pdu_type(&mut self, value: u8) {
        assert!(value == 2);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_pdcp_dupl_ind(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_assist_info_ind(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfb) | (value << 2);
    }
    #[inline]
    pub fn set_ul_delay_ind(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfd) | (value << 1);
    }
    #[inline]
    pub fn set_dl_delay_ind(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfe) | value;
    }
    #[inline]
    pub fn set_spare(&mut self, value: u8) {
        assert!(value <= 0x7f);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0x01) | (value << 1);
    }
    #[inline]
    pub fn set_pdcp_duplication_activation_suggestion(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xfe) | value;
    }
}
impl<'a> NrUpFrameAssistInfoData<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[2..])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 2]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> NrUpFrameAssistInfoData<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[2..])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 2]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

#[derive(Debug)]
pub enum NrUpFrameGroup<T> {
    NrUpFrameDlUserData_(NrUpFrameDlUserData<T>),
    NrUpFrameDlDataDeliveryStatus_(NrUpFrameDlDataDeliveryStatus<T>),
    NrUpFrameAssistInfoData_(NrUpFrameAssistInfoData<T>),
}
impl<T: Buf> NrUpFrameGroup<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 1 {
            return Err(buf);
        }
        let cond_value0 = buf.chunk()[0] >> 4;
        match cond_value0 {
            0 => {
                NrUpFrameDlUserData::parse(buf).map(|pkt| NrUpFrameGroup::NrUpFrameDlUserData_(pkt))
            }
            1 => NrUpFrameDlDataDeliveryStatus::parse(buf)
                .map(|pkt| NrUpFrameGroup::NrUpFrameDlDataDeliveryStatus_(pkt)),
            2 => NrUpFrameAssistInfoData::parse(buf)
                .map(|pkt| NrUpFrameGroup::NrUpFrameAssistInfoData_(pkt)),
            _ => Err(buf),
        }
    }
}
