#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::cursors::*;
use crate::endian::{read_uint_from_be_bytes, write_uint_as_be_bytes};
use crate::traits::*;

use super::{Gtpv1MsgType, Gtpv1NextExtention};

/// A constant that defines the fixed byte length of the Gtpv1 protocol header.
pub const GTPV1_HEADER_LEN: usize = 8;
/// A fixed Gtpv1 header.
pub const GTPV1_HEADER_TEMPLATE: [u8; 8] = [0x30, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

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
            || ((container.packet_len() as usize) < (container.header_len() as usize))
            || ((container.packet_len() as usize) > container.buf.remaining())
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
    pub fn message_type(&self) -> Gtpv1MsgType {
        Gtpv1MsgType::from(self.buf.chunk()[1])
    }
    #[inline]
    pub fn teid(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[4..8]).try_into().unwrap())
    }
    #[inline]
    pub fn packet_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())) as u32 + 8
    }
}
impl<T: PktBuf> Gtpv1<T> {
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
impl<T: PktBufMut> Gtpv1<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        let header_len = Gtpv1::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 8) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        let packet_len = buf.remaining();
        assert!(packet_len <= 65543);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_packet_len(packet_len as u32);
        container
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
    pub fn set_message_type(&mut self, value: Gtpv1MsgType) {
        self.buf.chunk_mut()[1] = u8::from(value);
    }
    #[inline]
    pub fn set_teid(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[4..8]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_packet_len(&mut self, value: u32) {
        assert!((value <= 65543) && (value >= 8));
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&((value - 8) as u16).to_be_bytes());
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
    /// This function panics if `self.header_len() != 8`.
    #[inline]
    pub fn sequence(&self) -> u16 {
        assert!(self.header_len() == 12);
        u16::from_be_bytes(self.buf.chunk()[8..10].try_into().unwrap())
    }

    /// Return the n-pdu value.
    ///
    /// # Panics
    /// This function panics if `self.header_len() != 8`.
    #[inline]
    pub fn npdu(&self) -> u8 {
        assert!(self.header_len() == 12);
        self.buf.chunk()[10]
    }

    /// Return the next extention header.
    ///
    /// # Panics
    /// This function panics if `self.header_len() != 8`.
    #[inline]
    pub fn next_extention_header(&self) -> Gtpv1NextExtention {
        assert!(self.header_len() == 12);
        self.buf.chunk()[11].into()
    }
}

impl<T: PktBufMut> Gtpv1<T> {
    /// Set the sequence value.
    ///
    /// # Panics
    /// This function panics if `self.header_len() != 8`.
    #[inline]
    pub fn set_sequence(&mut self, value: u16) {
        assert!(self.header_len() == 12);
        self.buf.chunk_mut()[8..10].copy_from_slice(&value.to_be_bytes());
    }

    /// Set the npdu value.
    ///
    /// # Panics
    /// This function panics if `self.header_len() != 8`.
    #[inline]
    pub fn set_npdu(&mut self, value: u8) {
        assert!(self.header_len() == 12);
        self.buf.chunk_mut()[10] = value;
    }

    /// Set the next extention header value.
    ///
    /// # Panics
    /// This function panics if `self.header_len() != 8`.
    #[inline]
    pub fn set_next_extention_header(&mut self, value: Gtpv1NextExtention) {
        assert!(self.header_len() == 12);
        self.buf.chunk_mut()[11] = value.into();
    }
}

/// A constant that defines the fixed byte length of the ExtUdpPort protocol header.
pub const EXT_UDP_PORT_HEADER_LEN: usize = 4;
/// A fixed ExtUdpPort header.
pub const EXT_UDP_PORT_HEADER_TEMPLATE: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

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
    pub fn next_extention_header(&self) -> Gtpv1NextExtention {
        Gtpv1NextExtention::from(self.buf.chunk()[3])
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
    pub fn set_next_extention_header(&mut self, value: Gtpv1NextExtention) {
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
pub const EXT_PDU_NUMBER_HEADER_LEN: usize = 4;
/// A fixed ExtPduNumber header.
pub const EXT_PDU_NUMBER_HEADER_TEMPLATE: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

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
    pub fn pdcp_number(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())
    }
    #[inline]
    pub fn next_extention_header(&self) -> Gtpv1NextExtention {
        Gtpv1NextExtention::from(self.buf.chunk()[3])
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
    pub fn set_pdcp_number(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_next_extention_header(&mut self, value: Gtpv1NextExtention) {
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
pub const EXT_LONG_PDU_NUMBER_HEADER_LEN: usize = 8;
/// A fixed ExtLongPduNumber header.
pub const EXT_LONG_PDU_NUMBER_HEADER_TEMPLATE: [u8; 8] =
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
    pub fn next_extention_header(&self) -> Gtpv1NextExtention {
        Gtpv1NextExtention::from(self.buf.chunk()[7])
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
    pub fn set_next_extention_header(&mut self, value: Gtpv1NextExtention) {
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
pub const EXT_SERVICE_CLASS_INDICATOR_HEADER_LEN: usize = 4;
/// A fixed ExtServiceClassIndicator header.
pub const EXT_SERVICE_CLASS_INDICATOR_HEADER_TEMPLATE: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

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
    pub fn next_extention_header(&self) -> Gtpv1NextExtention {
        Gtpv1NextExtention::from(self.buf.chunk()[3])
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
    pub fn set_next_extention_header(&mut self, value: Gtpv1NextExtention) {
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
pub const EXT_CONTAINER_HEADER_LEN: usize = 1;
/// A fixed ExtContainer header.
pub const EXT_CONTAINER_HEADER_TEMPLATE: [u8; 1] = [0x04];

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
    pub fn next_extention_header_type(&self) -> Gtpv1NextExtention {
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
    pub fn set_next_extention_header_type(&mut self, value: Gtpv1NextExtention) {
        let index = self.header_len() as usize - 1;
        self.buf.chunk_mut()[index] = value.into();
    }
}

/// A constant that defines the fixed byte length of the DlPduSessionInfo protocol header.
pub const DL_PDU_SESSION_INFO_HEADER_LEN: usize = 2;
/// A fixed DlPduSessionInfo header.
pub const DL_PDU_SESSION_INFO_HEADER_TEMPLATE: [u8; 2] = [0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct DlPduSessionInfo<T> {
    buf: T,
}
impl<T: Buf> DlPduSessionInfo<T> {
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
    pub fn qmp(&self) -> bool {
        self.buf.chunk()[0] & 0x8 != 0
    }
    #[inline]
    pub fn snp(&self) -> bool {
        self.buf.chunk()[0] & 0x4 != 0
    }
    #[inline]
    pub fn msnp(&self) -> bool {
        self.buf.chunk()[0] & 0x2 != 0
    }
    #[inline]
    pub fn spare(&self) -> u8 {
        self.buf.chunk()[0] & 0x1
    }
    #[inline]
    pub fn ppp(&self) -> bool {
        self.buf.chunk()[1] & 0x80 != 0
    }
    #[inline]
    pub fn rqi(&self) -> bool {
        self.buf.chunk()[1] & 0x40 != 0
    }
    #[inline]
    pub fn qos_flow_identifier(&self) -> u8 {
        self.buf.chunk()[1] & 0x3f
    }
}
impl<T: PktBuf> DlPduSessionInfo<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(2);
        buf
    }
}
impl<T: PktBufMut> DlPduSessionInfo<T> {
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
    pub fn set_qmp(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_snp(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfb) | (value << 2);
    }
    #[inline]
    pub fn set_msnp(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfd) | (value << 1);
    }
    #[inline]
    pub fn set_spare(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xfe) | value;
    }
    #[inline]
    pub fn set_ppp(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0x7f) | (value << 7);
    }
    #[inline]
    pub fn set_rqi(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xbf) | (value << 6);
    }
    #[inline]
    pub fn set_qos_flow_identifier(&mut self, value: u8) {
        assert!(value <= 0x3f);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xc0) | value;
    }
}
impl<'a> DlPduSessionInfo<Cursor<'a>> {
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
impl<'a> DlPduSessionInfo<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the UlPduSessionInfo protocol header.
pub const UL_PDU_SESSION_INFO_HEADER_LEN: usize = 2;
/// A fixed UlPduSessionInfo header.
pub const UL_PDU_SESSION_INFO_HEADER_TEMPLATE: [u8; 2] = [0x10, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct UlPduSessionInfo<T> {
    buf: T,
}
impl<T: Buf> UlPduSessionInfo<T> {
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
impl<T: PktBuf> UlPduSessionInfo<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(2);
        buf
    }
}
impl<T: PktBufMut> UlPduSessionInfo<T> {
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
impl<'a> UlPduSessionInfo<Cursor<'a>> {
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
impl<'a> UlPduSessionInfo<CursorMut<'a>> {
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
pub enum PduSessionUp<T> {
    DlPduSessionInfo_(DlPduSessionInfo<T>),
    UlPduSessionInfo_(UlPduSessionInfo<T>),
}
impl<T: Buf> PduSessionUp<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 1 {
            return Err(buf);
        }
        let cond_value0 = buf.chunk()[0] >> 4;
        match cond_value0 {
            0 => DlPduSessionInfo::parse(buf).map(|pkt| PduSessionUp::DlPduSessionInfo_(pkt)),
            1 => UlPduSessionInfo::parse(buf).map(|pkt| PduSessionUp::UlPduSessionInfo_(pkt)),
            _ => Err(buf),
        }
    }
}

/// A constant that defines the fixed byte length of the DlUserData protocol header.
pub const DL_USER_DATA_HEADER_LEN: usize = 5;
/// A fixed DlUserData header.
pub const DL_USER_DATA_HEADER_TEMPLATE: [u8; 5] = [0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct DlUserData<T> {
    buf: T,
}
impl<T: Buf> DlUserData<T> {
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
impl<T: PktBuf> DlUserData<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(5);
        buf
    }
}
impl<T: PktBufMut> DlUserData<T> {
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
impl<'a> DlUserData<Cursor<'a>> {
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
impl<'a> DlUserData<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the DlDataDeliveryStatus protocol header.
pub const DL_DATA_DELIVERY_STATUS_HEADER_LEN: usize = 5;
/// A fixed DlDataDeliveryStatus header.
pub const DL_DATA_DELIVERY_STATUS_HEADER_TEMPLATE: [u8; 5] = [0x10, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct DlDataDeliveryStatus<T> {
    buf: T,
}
impl<T: Buf> DlDataDeliveryStatus<T> {
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
impl<T: PktBuf> DlDataDeliveryStatus<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(5);
        buf
    }
}
impl<T: PktBufMut> DlDataDeliveryStatus<T> {
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
impl<'a> DlDataDeliveryStatus<Cursor<'a>> {
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
impl<'a> DlDataDeliveryStatus<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the AssistanceInformationData protocol header.
pub const ASSISTANCE_INFORMATION_DATA_HEADER_LEN: usize = 2;
/// A fixed AssistanceInformationData header.
pub const ASSISTANCE_INFORMATION_DATA_HEADER_TEMPLATE: [u8; 2] = [0x20, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct AssistanceInformationData<T> {
    buf: T,
}
impl<T: Buf> AssistanceInformationData<T> {
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
impl<T: PktBuf> AssistanceInformationData<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(2);
        buf
    }
}
impl<T: PktBufMut> AssistanceInformationData<T> {
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
impl<'a> AssistanceInformationData<Cursor<'a>> {
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
impl<'a> AssistanceInformationData<CursorMut<'a>> {
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
pub enum NrUp<T> {
    DlUserData_(DlUserData<T>),
    DlDataDeliveryStatus_(DlDataDeliveryStatus<T>),
    AssistanceInformationData_(AssistanceInformationData<T>),
}
impl<T: Buf> NrUp<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 1 {
            return Err(buf);
        }
        let cond_value0 = buf.chunk()[0] >> 4;
        match cond_value0 {
            0 => DlUserData::parse(buf).map(|pkt| NrUp::DlUserData_(pkt)),
            1 => DlDataDeliveryStatus::parse(buf).map(|pkt| NrUp::DlDataDeliveryStatus_(pkt)),
            2 => AssistanceInformationData::parse(buf)
                .map(|pkt| NrUp::AssistanceInformationData_(pkt)),
            _ => Err(buf),
        }
    }
}

/// A constant that defines the fixed byte length of the CauseIE protocol header.
pub const CAUSE_IE_HEADER_LEN: usize = 2;
/// A fixed CauseIE header.
pub const CAUSE_IE_HEADER_TEMPLATE: [u8; 2] = [0x01, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct CauseIE<T> {
    buf: T,
}
impl<T: Buf> CauseIE<T> {
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
    pub fn cause_value(&self) -> u8 {
        self.buf.chunk()[1]
    }
}
impl<T: PktBuf> CauseIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(2);
        buf
    }
}
impl<T: PktBufMut> CauseIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        assert!(buf.chunk_headroom() >= 2);
        buf.move_back(2);
        (&mut buf.chunk_mut()[0..2]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 1);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_cause_value(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }
}
impl<'a> CauseIE<Cursor<'a>> {
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
impl<'a> CauseIE<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the RecoveryIE protocol header.
pub const RECOVERY_IE_HEADER_LEN: usize = 2;
/// A fixed RecoveryIE header.
pub const RECOVERY_IE_HEADER_TEMPLATE: [u8; 2] = [0x0e, 0x00];

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

/// A constant that defines the fixed byte length of the TunnelEndpointIdentData1IE protocol header.
pub const TUNNEL_ENDPOINT_IDENT_DATA1_IE_HEADER_LEN: usize = 5;
/// A fixed TunnelEndpointIdentData1IE header.
pub const TUNNEL_ENDPOINT_IDENT_DATA1_IE_HEADER_TEMPLATE: [u8; 5] = [0x10, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct TunnelEndpointIdentData1IE<T> {
    buf: T,
}
impl<T: Buf> TunnelEndpointIdentData1IE<T> {
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
impl<T: PktBuf> TunnelEndpointIdentData1IE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(5);
        buf
    }
}
impl<T: PktBufMut> TunnelEndpointIdentData1IE<T> {
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
impl<'a> TunnelEndpointIdentData1IE<Cursor<'a>> {
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
impl<'a> TunnelEndpointIdentData1IE<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the TunnelEndpointIdentControlPlaneIE protocol header.
pub const TUNNEL_ENDPOINT_IDENT_CONTROL_PLANE_IE_HEADER_LEN: usize = 5;
/// A fixed TunnelEndpointIdentControlPlaneIE header.
pub const TUNNEL_ENDPOINT_IDENT_CONTROL_PLANE_IE_HEADER_TEMPLATE: [u8; 5] =
    [0x11, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct TunnelEndpointIdentControlPlaneIE<T> {
    buf: T,
}
impl<T: Buf> TunnelEndpointIdentControlPlaneIE<T> {
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
    pub fn endpoint_ident_control_plane(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[1..5]).try_into().unwrap())
    }
}
impl<T: PktBuf> TunnelEndpointIdentControlPlaneIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(5);
        buf
    }
}
impl<T: PktBufMut> TunnelEndpointIdentControlPlaneIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 5]) -> Self {
        assert!(buf.chunk_headroom() >= 5);
        buf.move_back(5);
        (&mut buf.chunk_mut()[0..5]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 17);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_endpoint_ident_control_plane(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[1..5]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> TunnelEndpointIdentControlPlaneIE<Cursor<'a>> {
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
impl<'a> TunnelEndpointIdentControlPlaneIE<CursorMut<'a>> {
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
pub const GTPU_PEER_ADDR_IE_HEADER_LEN: usize = 3;
/// A fixed GtpuPeerAddrIE header.
pub const GTPU_PEER_ADDR_IE_HEADER_TEMPLATE: [u8; 3] = [0x85, 0x00, 0x00];

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

/// A constant that defines the fixed byte length of the ExtHeaderTypeListIE protocol header.
pub const EXT_HEADER_TYPE_LIST_IE_HEADER_LEN: usize = 2;
/// A fixed ExtHeaderTypeListIE header.
pub const EXT_HEADER_TYPE_LIST_IE_HEADER_TEMPLATE: [u8; 2] = [0x8d, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct ExtHeaderTypeListIE<T> {
    buf: T,
}
impl<T: Buf> ExtHeaderTypeListIE<T> {
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
        if ((container.header_len() as usize) < 2)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..2]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[2..header_len]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn header_len(&self) -> u16 {
        (self.buf.chunk()[1]) as u16 + 2
    }
}
impl<T: PktBuf> ExtHeaderTypeListIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> ExtHeaderTypeListIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        let header_len = ExtHeaderTypeListIE::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 2) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..2]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[2..header_len]
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 141);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u16) {
        assert!((value <= 257) && (value >= 2));
        self.buf.chunk_mut()[1] = ((value - 2) as u8);
    }
}
impl<'a> ExtHeaderTypeListIE<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 2)
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
    pub fn from_header_array(header_array: &'a [u8; 2]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> ExtHeaderTypeListIE<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 2)
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
    pub fn from_header_array_mut(header_array: &'a mut [u8; 2]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the PrivateExtentionIE protocol header.
pub const PRIVATE_EXTENTION_IE_HEADER_LEN: usize = 5;
/// A fixed PrivateExtentionIE header.
pub const PRIVATE_EXTENTION_IE_HEADER_TEMPLATE: [u8; 5] = [0xff, 0x00, 0x02, 0x00, 0x00];

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

/// A constant that defines the fixed byte length of the GtpuTunnelStatusInfoIE protocol header.
pub const GTPU_TUNNEL_STATUS_INFO_IE_HEADER_LEN: usize = 4;
/// A fixed GtpuTunnelStatusInfoIE header.
pub const GTPU_TUNNEL_STATUS_INFO_IE_HEADER_TEMPLATE: [u8; 4] = [0xe6, 0x00, 0x01, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct GtpuTunnelStatusInfoIE<T> {
    buf: T,
}
impl<T: Buf> GtpuTunnelStatusInfoIE<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn spare(&self) -> u8 {
        self.buf.chunk()[3] >> 1
    }
    #[inline]
    pub fn spoc(&self) -> u8 {
        self.buf.chunk()[3] & 0x1
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 3
    }
}
impl<T: PktBuf> GtpuTunnelStatusInfoIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> GtpuTunnelStatusInfoIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        let header_len = GtpuTunnelStatusInfoIE::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 4) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[4..header_len]
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 230);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_spare(&mut self, value: u8) {
        assert!(value <= 0x7f);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0x01) | (value << 1);
    }
    #[inline]
    pub fn set_spoc(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xfe) | value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65538) && (value >= 3));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 3) as u16).to_be_bytes());
    }
}
impl<'a> GtpuTunnelStatusInfoIE<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 4)
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
    pub fn from_header_array(header_array: &'a [u8; 4]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> GtpuTunnelStatusInfoIE<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 4)
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
    pub fn from_header_array_mut(header_array: &'a mut [u8; 4]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the RecoveryTimeStampIE protocol header.
pub const RECOVERY_TIME_STAMP_IE_HEADER_LEN: usize = 7;
/// A fixed RecoveryTimeStampIE header.
pub const RECOVERY_TIME_STAMP_IE_HEADER_TEMPLATE: [u8; 7] =
    [0xe7, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00];

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
    CauseIE_(CauseIE<T>),
    RecoveryIE_(RecoveryIE<T>),
    TunnelEndpointIdentData1IE_(TunnelEndpointIdentData1IE<T>),
    TunnelEndpointIdentControlPlaneIE_(TunnelEndpointIdentControlPlaneIE<T>),
    ExtHeaderTypeListIE_(ExtHeaderTypeListIE<T>),
    GtpuPeerAddrIE_(GtpuPeerAddrIE<T>),
    PrivateExtentionIE_(PrivateExtentionIE<T>),
    RecoveryTimeStampIE_(RecoveryTimeStampIE<T>),
    GtpuTunnelStatusInfoIE_(GtpuTunnelStatusInfoIE<T>),
}
impl<T: Buf> Gtpv1IEGroup<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 1 {
            return Err(buf);
        }
        let cond_value0 = buf.chunk()[0];
        match cond_value0 {
            1 => CauseIE::parse(buf).map(|pkt| Gtpv1IEGroup::CauseIE_(pkt)),
            14 => RecoveryIE::parse(buf).map(|pkt| Gtpv1IEGroup::RecoveryIE_(pkt)),
            16 => TunnelEndpointIdentData1IE::parse(buf)
                .map(|pkt| Gtpv1IEGroup::TunnelEndpointIdentData1IE_(pkt)),
            17 => TunnelEndpointIdentControlPlaneIE::parse(buf)
                .map(|pkt| Gtpv1IEGroup::TunnelEndpointIdentControlPlaneIE_(pkt)),
            141 => {
                ExtHeaderTypeListIE::parse(buf).map(|pkt| Gtpv1IEGroup::ExtHeaderTypeListIE_(pkt))
            }
            133 => GtpuPeerAddrIE::parse(buf).map(|pkt| Gtpv1IEGroup::GtpuPeerAddrIE_(pkt)),
            255 => PrivateExtentionIE::parse(buf).map(|pkt| Gtpv1IEGroup::PrivateExtentionIE_(pkt)),
            231 => {
                RecoveryTimeStampIE::parse(buf).map(|pkt| Gtpv1IEGroup::RecoveryTimeStampIE_(pkt))
            }
            230 => GtpuTunnelStatusInfoIE::parse(buf)
                .map(|pkt| Gtpv1IEGroup::GtpuTunnelStatusInfoIE_(pkt)),
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
            1 => CauseIE::parse(self.buf)
                .map(|_pkt| {
                    let result = CauseIE {
                        buf: Cursor::new(&self.buf[..2]),
                    };
                    self.buf = &self.buf[2..];
                    Gtpv1IEGroup::CauseIE_(result)
                })
                .ok(),
            14 => RecoveryIE::parse(self.buf)
                .map(|_pkt| {
                    let result = RecoveryIE {
                        buf: Cursor::new(&self.buf[..2]),
                    };
                    self.buf = &self.buf[2..];
                    Gtpv1IEGroup::RecoveryIE_(result)
                })
                .ok(),
            16 => TunnelEndpointIdentData1IE::parse(self.buf)
                .map(|_pkt| {
                    let result = TunnelEndpointIdentData1IE {
                        buf: Cursor::new(&self.buf[..5]),
                    };
                    self.buf = &self.buf[5..];
                    Gtpv1IEGroup::TunnelEndpointIdentData1IE_(result)
                })
                .ok(),
            17 => TunnelEndpointIdentControlPlaneIE::parse(self.buf)
                .map(|_pkt| {
                    let result = TunnelEndpointIdentControlPlaneIE {
                        buf: Cursor::new(&self.buf[..5]),
                    };
                    self.buf = &self.buf[5..];
                    Gtpv1IEGroup::TunnelEndpointIdentControlPlaneIE_(result)
                })
                .ok(),
            141 => ExtHeaderTypeListIE::parse(self.buf)
                .map(|_pkt| {
                    let result = ExtHeaderTypeListIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv1IEGroup::ExtHeaderTypeListIE_(result)
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
            230 => GtpuTunnelStatusInfoIE::parse(self.buf)
                .map(|_pkt| {
                    let result = GtpuTunnelStatusInfoIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv1IEGroup::GtpuTunnelStatusInfoIE_(result)
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
            1 => match CauseIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(2);
                    self.buf = snd;
                    let result = CauseIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv1IEGroup::CauseIE_(result))
                }
                Err(_) => None,
            },
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
            16 => match TunnelEndpointIdentData1IE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(5);
                    self.buf = snd;
                    let result = TunnelEndpointIdentData1IE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv1IEGroup::TunnelEndpointIdentData1IE_(result))
                }
                Err(_) => None,
            },
            17 => match TunnelEndpointIdentControlPlaneIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(5);
                    self.buf = snd;
                    let result = TunnelEndpointIdentControlPlaneIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv1IEGroup::TunnelEndpointIdentControlPlaneIE_(result))
                }
                Err(_) => None,
            },
            141 => match ExtHeaderTypeListIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = ExtHeaderTypeListIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv1IEGroup::ExtHeaderTypeListIE_(result))
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
            230 => match GtpuTunnelStatusInfoIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = GtpuTunnelStatusInfoIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv1IEGroup::GtpuTunnelStatusInfoIE_(result))
                }
                Err(_) => None,
            },
            _ => None,
        }
    }
}
