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

/// A constant that defines the fixed byte length of the ExtUdpPort protocol header.
pub const EXTUDPPORT_HEADER_LEN: usize = 4;
/// A fixed ExtUdpPort header.
pub const EXTUDPPORT_HEADER_TEMPLATE: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct ExtUdpPort<T> {
    buf: T,
}
impl<T: Buf> ExtUdpPort<T> {
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
impl<T: PktBuf> ExtUdpPort<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(4);
        buf
    }
}
impl<T: PktBufMut> ExtUdpPort<T> {
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
impl<'a> ExtUdpPort<Cursor<'a>> {
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
impl<'a> ExtUdpPort<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the ExtPduNumber protocol header.
pub const EXTPDUNUMBER_HEADER_LEN: usize = 4;
/// A fixed ExtPduNumber header.
pub const EXTPDUNUMBER_HEADER_TEMPLATE: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct ExtPduNumber<T> {
    buf: T,
}
impl<T: Buf> ExtPduNumber<T> {
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
impl<T: PktBuf> ExtPduNumber<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(4);
        buf
    }
}
impl<T: PktBufMut> ExtPduNumber<T> {
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
impl<'a> ExtPduNumber<Cursor<'a>> {
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
impl<'a> ExtPduNumber<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the ExtLongPduNumber protocol header.
pub const EXTLONGPDUNUMBER_HEADER_LEN: usize = 8;
/// A fixed ExtLongPduNumber header.
pub const EXTLONGPDUNUMBER_HEADER_TEMPLATE: [u8; 8] =
    [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct ExtLongPduNumber<T> {
    buf: T,
}
impl<T: Buf> ExtLongPduNumber<T> {
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
impl<T: PktBuf> ExtLongPduNumber<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> ExtLongPduNumber<T> {
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
impl<'a> ExtLongPduNumber<Cursor<'a>> {
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
impl<'a> ExtLongPduNumber<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the RecoveryIE protocol header.
pub const RECOVERYIE_HEADER_LEN: usize = 2;
/// A fixed RecoveryIE header.
pub const RECOVERYIE_HEADER_TEMPLATE: [u8; 2] = [0x0e, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct RecoveryIE<T> {
    buf: T,
}
impl<T: Buf> RecoveryIE<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn restart_counter(&self) -> u8 {
        self.buf.chunk()[1]
    }
}
impl<T: PktBuf> RecoveryIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(2);
        buf
    }
}
impl<T: PktBufMut> RecoveryIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        assert!(buf.chunk_headroom() >= 2);
        buf.move_back(2);
        (&mut buf.chunk_mut()[0..2]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 14);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_restart_counter(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }
}
impl<'a> RecoveryIE<Cursor<'a>> {
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
impl<'a> RecoveryIE<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the TunnelEndpointIdentDataIIE protocol header.
pub const TUNNELENDPOINTIDENTDATAIIE_HEADER_LEN: usize = 5;
/// A fixed TunnelEndpointIdentDataIIE header.
pub const TUNNELENDPOINTIDENTDATAIIE_HEADER_TEMPLATE: [u8; 5] = [0x10, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct TunnelEndpointIdentDataIIE<T> {
    buf: T,
}
impl<T: Buf> TunnelEndpointIdentDataIIE<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn endpoint_ident_data(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[1..5]).try_into().unwrap())
    }
}
impl<T: PktBuf> TunnelEndpointIdentDataIIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(5);
        buf
    }
}
impl<T: PktBufMut> TunnelEndpointIdentDataIIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 5]) -> Self {
        assert!(buf.chunk_headroom() >= 5);
        buf.move_back(5);
        (&mut buf.chunk_mut()[0..5]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 16);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_endpoint_ident_data(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[1..5]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> TunnelEndpointIdentDataIIE<Cursor<'a>> {
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
impl<'a> TunnelEndpointIdentDataIIE<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the GtpuPeerAddrIE protocol header.
pub const GTPUPEERADDRIE_HEADER_LEN: usize = 3;
/// A fixed GtpuPeerAddrIE header.
pub const GTPUPEERADDRIE_HEADER_TEMPLATE: [u8; 3] = [0x85, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct GtpuPeerAddrIE<T> {
    buf: T,
}
impl<T: Buf> GtpuPeerAddrIE<T> {
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
        if ((container.header_len() as usize) < 3)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..3]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[3..header_len]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 3
    }
}
impl<T: PktBuf> GtpuPeerAddrIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> GtpuPeerAddrIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 3]) -> Self {
        let header_len = GtpuPeerAddrIE::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 3) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..3]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[3..header_len]
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 133);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65538) && (value >= 3));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 3) as u16).to_be_bytes());
    }
}
impl<'a> GtpuPeerAddrIE<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 3 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 3)
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
    pub fn from_header_array(header_array: &'a [u8; 3]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> GtpuPeerAddrIE<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 3 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 3)
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
    pub fn from_header_array_mut(header_array: &'a mut [u8; 3]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the PrivateExtentionIE protocol header.
pub const PRIVATEEXTENTIONIE_HEADER_LEN: usize = 5;
/// A fixed PrivateExtentionIE header.
pub const PRIVATEEXTENTIONIE_HEADER_TEMPLATE: [u8; 5] = [0xff, 0x00, 0x05, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct PrivateExtentionIE<T> {
    buf: T,
}
impl<T: Buf> PrivateExtentionIE<T> {
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
        if ((container.header_len() as usize) < 5)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..5]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[5..header_len]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn extention_ident(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[3..5]).try_into().unwrap())
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 3
    }
}
impl<T: PktBuf> PrivateExtentionIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> PrivateExtentionIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 5]) -> Self {
        let header_len = PrivateExtentionIE::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 5) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..5]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[5..header_len]
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 255);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_extention_ident(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[3..5]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65538) && (value >= 3));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 3) as u16).to_be_bytes());
    }
}
impl<'a> PrivateExtentionIE<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 5 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 5)
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
    pub fn from_header_array(header_array: &'a [u8; 5]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> PrivateExtentionIE<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 5 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 5)
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
    pub fn from_header_array_mut(header_array: &'a mut [u8; 5]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the RecoveryTimeStampIE protocol header.
pub const RECOVERYTIMESTAMPIE_HEADER_LEN: usize = 7;
/// A fixed RecoveryTimeStampIE header.
pub const RECOVERYTIMESTAMPIE_HEADER_TEMPLATE: [u8; 7] = [0xe7, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct RecoveryTimeStampIE<T> {
    buf: T,
}
impl<T: Buf> RecoveryTimeStampIE<T> {
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
        if chunk_len < 7 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 7)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..7]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[7..header_len]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn recovery_time_stamp(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[3..7]).try_into().unwrap())
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 3
    }
}
impl<T: PktBuf> RecoveryTimeStampIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> RecoveryTimeStampIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 7]) -> Self {
        let header_len = RecoveryTimeStampIE::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 7) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..7]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[7..header_len]
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 231);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_recovery_time_stamp(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[3..7]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65538) && (value >= 3));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 3) as u16).to_be_bytes());
    }
}
impl<'a> RecoveryTimeStampIE<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 7 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 7)
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
    pub fn from_header_array(header_array: &'a [u8; 7]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> RecoveryTimeStampIE<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 7 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 7)
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
    pub fn from_header_array_mut(header_array: &'a mut [u8; 7]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

#[derive(Debug)]
pub enum Gtpv1IEGroup<T> {
    RecoveryIE_(RecoveryIE<T>),
    TunnelEndpointIdentDataIIE_(TunnelEndpointIdentDataIIE<T>),
    GtpuPeerAddrIE_(GtpuPeerAddrIE<T>),
    PrivateExtentionIE_(PrivateExtentionIE<T>),
    RecoveryTimeStampIE_(RecoveryTimeStampIE<T>),
}
impl<T: Buf> Gtpv1IEGroup<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 1 {
            return Err(buf);
        }
        let cond_value0 = buf.chunk()[0];
        match cond_value0 {
            14 => RecoveryIE::parse(buf).map(|pkt| Gtpv1IEGroup::RecoveryIE_(pkt)),
            16 => TunnelEndpointIdentDataIIE::parse(buf)
                .map(|pkt| Gtpv1IEGroup::TunnelEndpointIdentDataIIE_(pkt)),
            133 => GtpuPeerAddrIE::parse(buf).map(|pkt| Gtpv1IEGroup::GtpuPeerAddrIE_(pkt)),
            255 => PrivateExtentionIE::parse(buf).map(|pkt| Gtpv1IEGroup::PrivateExtentionIE_(pkt)),
            231 => {
                RecoveryTimeStampIE::parse(buf).map(|pkt| Gtpv1IEGroup::RecoveryTimeStampIE_(pkt))
            }
            _ => Err(buf),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Gtpv1IEGroupIter<'a> {
    buf: &'a [u8],
}
impl<'a> Gtpv1IEGroupIter<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Self {
        Self { buf: slice }
    }

    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }
}
impl<'a> Iterator for Gtpv1IEGroupIter<'a> {
    type Item = Gtpv1IEGroup<Cursor<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 1 {
            return None;
        }
        let cond_value0 = self.buf[0];
        match cond_value0 {
            14 => RecoveryIE::parse(self.buf)
                .map(|_pkt| {
                    let result = RecoveryIE {
                        buf: Cursor::new(&self.buf[..2]),
                    };
                    self.buf = &self.buf[2..];
                    Gtpv1IEGroup::RecoveryIE_(result)
                })
                .ok(),
            16 => TunnelEndpointIdentDataIIE::parse(self.buf)
                .map(|_pkt| {
                    let result = TunnelEndpointIdentDataIIE {
                        buf: Cursor::new(&self.buf[..5]),
                    };
                    self.buf = &self.buf[5..];
                    Gtpv1IEGroup::TunnelEndpointIdentDataIIE_(result)
                })
                .ok(),
            133 => GtpuPeerAddrIE::parse(self.buf)
                .map(|_pkt| {
                    let result = GtpuPeerAddrIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv1IEGroup::GtpuPeerAddrIE_(result)
                })
                .ok(),
            255 => PrivateExtentionIE::parse(self.buf)
                .map(|_pkt| {
                    let result = PrivateExtentionIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv1IEGroup::PrivateExtentionIE_(result)
                })
                .ok(),
            231 => RecoveryTimeStampIE::parse(self.buf)
                .map(|_pkt| {
                    let result = RecoveryTimeStampIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv1IEGroup::RecoveryTimeStampIE_(result)
                })
                .ok(),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Gtpv1IEGroupIterMut<'a> {
    buf: &'a mut [u8],
}
impl<'a> Gtpv1IEGroupIterMut<'a> {
    pub fn from_slice_mut(slice_mut: &'a mut [u8]) -> Self {
        Self { buf: slice_mut }
    }

    pub fn buf(&self) -> &[u8] {
        &self.buf[..]
    }
}
impl<'a> Iterator for Gtpv1IEGroupIterMut<'a> {
    type Item = Gtpv1IEGroup<CursorMut<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 1 {
            return None;
        }
        let cond_value0 = self.buf[0];
        match cond_value0 {
            14 => match RecoveryIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(2);
                    self.buf = snd;
                    let result = RecoveryIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv1IEGroup::RecoveryIE_(result))
                }
                Err(_) => None,
            },
            16 => match TunnelEndpointIdentDataIIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(5);
                    self.buf = snd;
                    let result = TunnelEndpointIdentDataIIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv1IEGroup::TunnelEndpointIdentDataIIE_(result))
                }
                Err(_) => None,
            },
            133 => match GtpuPeerAddrIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = GtpuPeerAddrIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv1IEGroup::GtpuPeerAddrIE_(result))
                }
                Err(_) => None,
            },
            255 => match PrivateExtentionIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = PrivateExtentionIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv1IEGroup::PrivateExtentionIE_(result))
                }
                Err(_) => None,
            },
            231 => match RecoveryTimeStampIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = RecoveryTimeStampIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv1IEGroup::RecoveryTimeStampIE_(result))
                }
                Err(_) => None,
            },
            _ => None,
        }
    }
}
