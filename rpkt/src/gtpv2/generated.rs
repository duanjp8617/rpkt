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

    /// Return the message priority present flag.
    ///
    /// # Panics
    /// This function panics if:
    /// 1. `self.teid_present()` is false.
    /// 2. The packet buffer has invalid form.
    #[inline]
    pub fn message_priority_present(&self) -> bool {
        assert!(self.teid_present());
        (self.buf.chunk()[0] & (1 << 2)) != 0
    }

    /// Return the teid value.
    ///
    /// # Panics
    /// This function panics if:
    /// 1. `self.teid_present()` is false.
    /// 2. The packet buffer has invalid form.
    #[inline]
    pub fn teid(&self) -> u32 {
        assert!(self.teid_present());
        u32::from_be_bytes(self.buf.chunk()[4..8].try_into().unwrap())
    }

    /// Return the sequence number.
    ///
    /// # Panics:
    /// This function panics if:
    /// 1. The packet buffer has invalid form.
    #[inline]
    pub fn seq_number(&self) -> u32 {
        if self.teid_present() {
            read_uint_from_be_bytes(&self.buf.chunk()[8..11]) as u32
        } else {
            read_uint_from_be_bytes(&self.buf.chunk()[4..7]) as u32
        }
    }

    /// Return the message priority.
    ///
    /// # Panics
    /// This function panics if:
    /// 1. `self.teid_present()` and `self.message_priority_present()` are both false.
    /// 2. The packet buffer has invalid form.
    #[inline]
    pub fn message_priority(&self) -> u8 {
        assert!(self.teid_present() && self.message_priority_present());
        (self.buf.chunk()[11] & 0xf0) >> 4
    }

    /// Return the last spare field.
    ///
    /// # Panics:
    /// This function panics if:
    /// 1. The packet buffer has invalid form.
    #[inline]
    pub fn spare_last(&self) -> u8 {
        if self.teid_present() {
            if self.message_priority_present() {
                self.buf.chunk()[11] & 0x0f
            } else {
                self.buf.chunk()[11]
            }
        } else {
            self.buf.chunk()[7]
        }
    }
}

impl<T: PktBufMut> Gtpv2<T> {
    /// Set the message priority present flag.
    ///
    /// # Panics
    /// This function panics if:
    /// 1. `self.teid_present()` is false.
    /// 2. The packet buffer has invalid form.
    #[inline]
    pub fn set_message_priority_present(&mut self, value: bool) {
        assert!(self.teid_present());
        if value {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] | (1 << 2);
        } else {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] & (!(1 << 2));
        }
    }

    /// Set the teid value.
    ///
    /// # Panics
    /// This function panics if:
    /// 1. `self.teid_present()` is false.
    /// 2. The packet buffer has invalid form.
    #[inline]
    pub fn set_teid(&mut self, value: u32) {
        assert!(self.teid_present());
        self.buf.chunk_mut()[4..8].copy_from_slice(&value.to_be_bytes());
    }

    /// Set the sequence number.
    ///
    /// # Panics
    /// This function panics if:
    /// 1. `value` is no less than `(1 << 24)`.
    /// 2. The packet buffer has invalid form.
    #[inline]
    pub fn set_seq_number(&mut self, value: u32) {
        assert!(value < (1 << 24));
        if self.teid_present() {
            write_uint_as_be_bytes(&mut self.buf.chunk_mut()[8..11], value as u64);
        } else {
            write_uint_as_be_bytes(&mut self.buf.chunk_mut()[4..7], value as u64);
        }
    }

    /// Set the message priority.
    ///
    /// # Panics
    /// This function panics if:
    /// 1. `self.teid_present()` and `self.message_priority_present()` are
    /// both false, and that `value` is no less than `(1 << 4)`.
    /// 2. The packet buffer has invalid form.
    #[inline]
    pub fn set_message_priority(&mut self, value: u8) {
        assert!(self.teid_present() && self.message_priority_present() && value < 1 << 4);
        self.buf.chunk_mut()[11] = (self.buf.chunk_mut()[11] & 0x0f) | (value << 4);
    }

    /// Set the message priority.
    ///
    /// # Panics
    /// This function panics if:
    /// 1. `self.message_priority_present()` is true, and
    /// that `value` is no less than `(1 << 4)`.
    /// 2. The packet buffer has invalid form.
    #[inline]
    pub fn set_spare_last(&mut self, value: u8) {
        if self.teid_present() {
            if self.message_priority_present() {
                assert!(value < 1 << 4);
                self.buf.chunk_mut()[11] = (self.buf.chunk_mut()[11] & 0xf0) | value;
            } else {
                self.buf.chunk_mut()[11] = value;
            }
        } else {
            self.buf.chunk_mut()[7] = value;
        }
    }
}

/// A constant that defines the fixed byte length of the UserLocationInfoIE protocol header.
pub const USERLOCATIONINFOIE_HEADER_LEN: usize = 5;
/// A fixed UserLocationInfoIE header.
pub const USERLOCATIONINFOIE_HEADER_TEMPLATE: [u8; 5] = [0x56, 0x00, 0x01, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct UserLocationInfoIE<T> {
    buf: T,
}
impl<T: Buf> UserLocationInfoIE<T> {
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
    pub fn cr_flag(&self) -> u8 {
        self.buf.chunk()[3] >> 4
    }
    #[inline]
    pub fn instance(&self) -> u8 {
        self.buf.chunk()[3] & 0xf
    }
    #[inline]
    pub fn extended_macro_enodeb_id(&self) -> bool {
        self.buf.chunk()[4] & 0x80 != 0
    }
    #[inline]
    pub fn macro_enodeb_id(&self) -> bool {
        self.buf.chunk()[4] & 0x40 != 0
    }
    #[inline]
    pub fn lai(&self) -> bool {
        self.buf.chunk()[4] & 0x20 != 0
    }
    #[inline]
    pub fn ecgi(&self) -> bool {
        self.buf.chunk()[4] & 0x10 != 0
    }
    #[inline]
    pub fn tai(&self) -> bool {
        self.buf.chunk()[4] & 0x8 != 0
    }
    #[inline]
    pub fn rai(&self) -> bool {
        self.buf.chunk()[4] & 0x4 != 0
    }
    #[inline]
    pub fn sai(&self) -> bool {
        self.buf.chunk()[4] & 0x2 != 0
    }
    #[inline]
    pub fn cgi(&self) -> bool {
        self.buf.chunk()[4] & 0x1 != 0
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 4
    }
}
impl<T: PktBuf> UserLocationInfoIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> UserLocationInfoIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 5]) -> Self {
        let header_len = UserLocationInfoIE::parse_unchecked(&header[..]).header_len() as usize;
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
        assert!(value == 86);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_cr_flag(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_instance(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xf0) | value;
    }
    #[inline]
    pub fn set_extended_macro_enodeb_id(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0x7f) | (value << 7);
    }
    #[inline]
    pub fn set_macro_enodeb_id(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0xbf) | (value << 6);
    }
    #[inline]
    pub fn set_lai(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0xdf) | (value << 5);
    }
    #[inline]
    pub fn set_ecgi(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0xef) | (value << 4);
    }
    #[inline]
    pub fn set_tai(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_rai(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0xfb) | (value << 2);
    }
    #[inline]
    pub fn set_sai(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0xfd) | (value << 1);
    }
    #[inline]
    pub fn set_cgi(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0xfe) | value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65539) && (value >= 4));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 4) as u16).to_be_bytes());
    }
}
impl<'a> UserLocationInfoIE<Cursor<'a>> {
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
impl<'a> UserLocationInfoIE<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the InternationalMobileSubscriberIdIE protocol header.
pub const INTERNATIONALMOBILESUBSCRIBERIDIE_HEADER_LEN: usize = 4;
/// A fixed InternationalMobileSubscriberIdIE header.
pub const INTERNATIONALMOBILESUBSCRIBERIDIE_HEADER_TEMPLATE: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct InternationalMobileSubscriberIdIE<T> {
    buf: T,
}
impl<T: Buf> InternationalMobileSubscriberIdIE<T> {
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
    pub fn cr_flag(&self) -> u8 {
        self.buf.chunk()[3] >> 4
    }
    #[inline]
    pub fn instance(&self) -> u8 {
        self.buf.chunk()[3] & 0xf
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 4
    }
}
impl<T: PktBuf> InternationalMobileSubscriberIdIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> InternationalMobileSubscriberIdIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        let header_len =
            InternationalMobileSubscriberIdIE::parse_unchecked(&header[..]).header_len() as usize;
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
        assert!(value == 1);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_cr_flag(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_instance(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xf0) | value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65539) && (value >= 4));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 4) as u16).to_be_bytes());
    }
}
impl<'a> InternationalMobileSubscriberIdIE<Cursor<'a>> {
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
impl<'a> InternationalMobileSubscriberIdIE<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the ServingNetworkIE protocol header.
pub const SERVINGNETWORKIE_HEADER_LEN: usize = 7;
/// A fixed ServingNetworkIE header.
pub const SERVINGNETWORKIE_HEADER_TEMPLATE: [u8; 7] = [0x53, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct ServingNetworkIE<T> {
    buf: T,
}
impl<T: Buf> ServingNetworkIE<T> {
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
    pub fn cr_flag(&self) -> u8 {
        self.buf.chunk()[3] >> 4
    }
    #[inline]
    pub fn instance(&self) -> u8 {
        self.buf.chunk()[3] & 0xf
    }
    #[inline]
    pub fn mcc_digit2(&self) -> u8 {
        self.buf.chunk()[4] >> 4
    }
    #[inline]
    pub fn mcc_digit1(&self) -> u8 {
        self.buf.chunk()[4] & 0xf
    }
    #[inline]
    pub fn mnc_digit3(&self) -> u8 {
        self.buf.chunk()[5] >> 4
    }
    #[inline]
    pub fn mcc_digit3(&self) -> u8 {
        self.buf.chunk()[5] & 0xf
    }
    #[inline]
    pub fn mnc_digit2(&self) -> u8 {
        self.buf.chunk()[6] >> 4
    }
    #[inline]
    pub fn mnc_digit1(&self) -> u8 {
        self.buf.chunk()[6] & 0xf
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 4
    }
}
impl<T: PktBuf> ServingNetworkIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> ServingNetworkIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 7]) -> Self {
        let header_len = ServingNetworkIE::parse_unchecked(&header[..]).header_len() as usize;
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
        assert!(value == 83);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_cr_flag(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_instance(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xf0) | value;
    }
    #[inline]
    pub fn set_mcc_digit2(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_mcc_digit1(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0xf0) | value;
    }
    #[inline]
    pub fn set_mnc_digit3(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[5] = (self.buf.chunk_mut()[5] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_mcc_digit3(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[5] = (self.buf.chunk_mut()[5] & 0xf0) | value;
    }
    #[inline]
    pub fn set_mnc_digit2(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[6] = (self.buf.chunk_mut()[6] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_mnc_digit1(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[6] = (self.buf.chunk_mut()[6] & 0xf0) | value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65539) && (value >= 4));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 4) as u16).to_be_bytes());
    }
}
impl<'a> ServingNetworkIE<Cursor<'a>> {
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
impl<'a> ServingNetworkIE<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the RatTypeIE protocol header.
pub const RATTYPEIE_HEADER_LEN: usize = 5;
/// A fixed RatTypeIE header.
pub const RATTYPEIE_HEADER_TEMPLATE: [u8; 5] = [0x52, 0x00, 0x01, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct RatTypeIE<T> {
    buf: T,
}
impl<T: Buf> RatTypeIE<T> {
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
    pub fn cr_flag(&self) -> u8 {
        self.buf.chunk()[3] >> 4
    }
    #[inline]
    pub fn instance(&self) -> u8 {
        self.buf.chunk()[3] & 0xf
    }
    #[inline]
    pub fn rat_type(&self) -> u8 {
        self.buf.chunk()[4]
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 4
    }
}
impl<T: PktBuf> RatTypeIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> RatTypeIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 5]) -> Self {
        let header_len = RatTypeIE::parse_unchecked(&header[..]).header_len() as usize;
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
        assert!(value == 82);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_cr_flag(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_instance(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xf0) | value;
    }
    #[inline]
    pub fn set_rat_type(&mut self, value: u8) {
        self.buf.chunk_mut()[4] = value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65539) && (value >= 4));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 4) as u16).to_be_bytes());
    }
}
impl<'a> RatTypeIE<Cursor<'a>> {
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
impl<'a> RatTypeIE<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the FullyQualifiedTeidIE protocol header.
pub const FULLYQUALIFIEDTEIDIE_HEADER_LEN: usize = 9;
/// A fixed FullyQualifiedTeidIE header.
pub const FULLYQUALIFIEDTEIDIE_HEADER_TEMPLATE: [u8; 9] =
    [0x57, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct FullyQualifiedTeidIE<T> {
    buf: T,
}
impl<T: Buf> FullyQualifiedTeidIE<T> {
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
        if chunk_len < 9 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 9)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..9]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[9..header_len]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn cr_flag(&self) -> u8 {
        self.buf.chunk()[3] >> 4
    }
    #[inline]
    pub fn instance(&self) -> u8 {
        self.buf.chunk()[3] & 0xf
    }
    #[inline]
    pub fn v4(&self) -> bool {
        self.buf.chunk()[4] & 0x80 != 0
    }
    #[inline]
    pub fn v6(&self) -> bool {
        self.buf.chunk()[4] & 0x40 != 0
    }
    #[inline]
    pub fn interface_type(&self) -> u8 {
        self.buf.chunk()[4] & 0x3f
    }
    #[inline]
    pub fn teid_gre_key(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[5..9]).try_into().unwrap())
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 4
    }
}
impl<T: PktBuf> FullyQualifiedTeidIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> FullyQualifiedTeidIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 9]) -> Self {
        let header_len = FullyQualifiedTeidIE::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 9) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..9]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[9..header_len]
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 87);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_cr_flag(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_instance(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xf0) | value;
    }
    #[inline]
    pub fn set_v4(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0x7f) | (value << 7);
    }
    #[inline]
    pub fn set_v6(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0xbf) | (value << 6);
    }
    #[inline]
    pub fn set_interface_type(&mut self, value: u8) {
        assert!(value <= 0x3f);
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0xc0) | value;
    }
    #[inline]
    pub fn set_teid_gre_key(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[5..9]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65539) && (value >= 4));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 4) as u16).to_be_bytes());
    }
}
impl<'a> FullyQualifiedTeidIE<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 9 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 9)
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
    pub fn from_header_array(header_array: &'a [u8; 9]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> FullyQualifiedTeidIE<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 9 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 9)
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
    pub fn from_header_array_mut(header_array: &'a mut [u8; 9]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the AggregateMaxBitRateIE protocol header.
pub const AGGREGATEMAXBITRATEIE_HEADER_LEN: usize = 12;
/// A fixed AggregateMaxBitRateIE header.
pub const AGGREGATEMAXBITRATEIE_HEADER_TEMPLATE: [u8; 12] = [
    0x48, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct AggregateMaxBitRateIE<T> {
    buf: T,
}
impl<T: Buf> AggregateMaxBitRateIE<T> {
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
        if ((container.header_len() as usize) < 12)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..12]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[12..header_len]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn cr_flag(&self) -> u8 {
        self.buf.chunk()[3] >> 4
    }
    #[inline]
    pub fn instance(&self) -> u8 {
        self.buf.chunk()[3] & 0xf
    }
    #[inline]
    pub fn apn_ambr_for_uplink(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[4..8]).try_into().unwrap())
    }
    #[inline]
    pub fn apn_ambr_for_downlink(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[8..12]).try_into().unwrap())
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 4
    }
}
impl<T: PktBuf> AggregateMaxBitRateIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> AggregateMaxBitRateIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 12]) -> Self {
        let header_len = AggregateMaxBitRateIE::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 12) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..12]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[12..header_len]
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 72);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_cr_flag(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_instance(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xf0) | value;
    }
    #[inline]
    pub fn set_apn_ambr_for_uplink(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[4..8]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_apn_ambr_for_downlink(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[8..12]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65539) && (value >= 4));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 4) as u16).to_be_bytes());
    }
}
impl<'a> AggregateMaxBitRateIE<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 12 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 12)
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
    pub fn from_header_array(header_array: &'a [u8; 12]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> AggregateMaxBitRateIE<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 12 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 12)
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
    pub fn from_header_array_mut(header_array: &'a mut [u8; 12]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the MobileEquipmentIdIE protocol header.
pub const MOBILEEQUIPMENTIDIE_HEADER_LEN: usize = 4;
/// A fixed MobileEquipmentIdIE header.
pub const MOBILEEQUIPMENTIDIE_HEADER_TEMPLATE: [u8; 4] = [0x4b, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct MobileEquipmentIdIE<T> {
    buf: T,
}
impl<T: Buf> MobileEquipmentIdIE<T> {
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
    pub fn cr_flag(&self) -> u8 {
        self.buf.chunk()[3] >> 4
    }
    #[inline]
    pub fn instance(&self) -> u8 {
        self.buf.chunk()[3] & 0xf
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 4
    }
}
impl<T: PktBuf> MobileEquipmentIdIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> MobileEquipmentIdIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        let header_len = MobileEquipmentIdIE::parse_unchecked(&header[..]).header_len() as usize;
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
        assert!(value == 75);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_cr_flag(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_instance(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xf0) | value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65539) && (value >= 4));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 4) as u16).to_be_bytes());
    }
}
impl<'a> MobileEquipmentIdIE<Cursor<'a>> {
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
impl<'a> MobileEquipmentIdIE<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the UeTimeZoneIE protocol header.
pub const UETIMEZONEIE_HEADER_LEN: usize = 6;
/// A fixed UeTimeZoneIE header.
pub const UETIMEZONEIE_HEADER_TEMPLATE: [u8; 6] = [0x72, 0x00, 0x02, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct UeTimeZoneIE<T> {
    buf: T,
}
impl<T: Buf> UeTimeZoneIE<T> {
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
        if chunk_len < 6 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 6)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..6]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[6..header_len]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn cr_flag(&self) -> u8 {
        self.buf.chunk()[3] >> 4
    }
    #[inline]
    pub fn instance(&self) -> u8 {
        self.buf.chunk()[3] & 0xf
    }
    #[inline]
    pub fn time_zone(&self) -> u8 {
        self.buf.chunk()[4]
    }
    #[inline]
    pub fn spare(&self) -> u8 {
        self.buf.chunk()[5] >> 2
    }
    #[inline]
    pub fn daylight_saving_time(&self) -> u8 {
        self.buf.chunk()[5] & 0x3
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 4
    }
}
impl<T: PktBuf> UeTimeZoneIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> UeTimeZoneIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 6]) -> Self {
        let header_len = UeTimeZoneIE::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 6) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..6]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[6..header_len]
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 114);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_cr_flag(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_instance(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xf0) | value;
    }
    #[inline]
    pub fn set_time_zone(&mut self, value: u8) {
        self.buf.chunk_mut()[4] = value;
    }
    #[inline]
    pub fn set_spare(&mut self, value: u8) {
        assert!(value <= 0x3f);
        self.buf.chunk_mut()[5] = (self.buf.chunk_mut()[5] & 0x03) | (value << 2);
    }
    #[inline]
    pub fn set_daylight_saving_time(&mut self, value: u8) {
        assert!(value <= 0x3);
        self.buf.chunk_mut()[5] = (self.buf.chunk_mut()[5] & 0xfc) | value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65539) && (value >= 4));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 4) as u16).to_be_bytes());
    }
}
impl<'a> UeTimeZoneIE<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 6 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 6)
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
    pub fn from_header_array(header_array: &'a [u8; 6]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> UeTimeZoneIE<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 6 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 6)
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
    pub fn from_header_array_mut(header_array: &'a mut [u8; 6]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the BearerContextIE protocol header.
pub const BEARERCONTEXTIE_HEADER_LEN: usize = 4;
/// A fixed BearerContextIE header.
pub const BEARERCONTEXTIE_HEADER_TEMPLATE: [u8; 4] = [0x5d, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct BearerContextIE<T> {
    buf: T,
}
impl<T: Buf> BearerContextIE<T> {
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
    pub fn cr_flag(&self) -> u8 {
        self.buf.chunk()[3] >> 4
    }
    #[inline]
    pub fn instance(&self) -> u8 {
        self.buf.chunk()[3] & 0xf
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 4
    }
}
impl<T: PktBuf> BearerContextIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> BearerContextIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        let header_len = BearerContextIE::parse_unchecked(&header[..]).header_len() as usize;
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
        assert!(value == 93);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_cr_flag(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_instance(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xf0) | value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65539) && (value >= 4));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 4) as u16).to_be_bytes());
    }
}
impl<'a> BearerContextIE<Cursor<'a>> {
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
impl<'a> BearerContextIE<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the EpsBearerIdIE protocol header.
pub const EPSBEARERIDIE_HEADER_LEN: usize = 5;
/// A fixed EpsBearerIdIE header.
pub const EPSBEARERIDIE_HEADER_TEMPLATE: [u8; 5] = [0x49, 0x00, 0x01, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct EpsBearerIdIE<T> {
    buf: T,
}
impl<T: Buf> EpsBearerIdIE<T> {
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
    pub fn cr_flag(&self) -> u8 {
        self.buf.chunk()[3] >> 4
    }
    #[inline]
    pub fn instance(&self) -> u8 {
        self.buf.chunk()[3] & 0xf
    }
    #[inline]
    pub fn spare(&self) -> u8 {
        self.buf.chunk()[4] >> 4
    }
    #[inline]
    pub fn eps_bearer_id(&self) -> u8 {
        self.buf.chunk()[4] & 0xf
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 4
    }
}
impl<T: PktBuf> EpsBearerIdIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> EpsBearerIdIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 5]) -> Self {
        let header_len = EpsBearerIdIE::parse_unchecked(&header[..]).header_len() as usize;
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
        assert!(value == 73);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_cr_flag(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_instance(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xf0) | value;
    }
    #[inline]
    pub fn set_spare(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_eps_bearer_id(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[4] = (self.buf.chunk_mut()[4] & 0xf0) | value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65539) && (value >= 4));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 4) as u16).to_be_bytes());
    }
}
impl<'a> EpsBearerIdIE<Cursor<'a>> {
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
impl<'a> EpsBearerIdIE<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the RecoveryIE protocol header.
pub const RECOVERYIE_HEADER_LEN: usize = 4;
/// A fixed RecoveryIE header.
pub const RECOVERYIE_HEADER_TEMPLATE: [u8; 4] = [0x03, 0x00, 0x00, 0x00];

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
    pub fn cr_flag(&self) -> u8 {
        self.buf.chunk()[3] >> 4
    }
    #[inline]
    pub fn instance(&self) -> u8 {
        self.buf.chunk()[3] & 0xf
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap())) as u32 + 4
    }
}
impl<T: PktBuf> RecoveryIE<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> RecoveryIE<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        let header_len = RecoveryIE::parse_unchecked(&header[..]).header_len() as usize;
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
        assert!(value == 3);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_cr_flag(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_instance(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xf0) | value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65539) && (value >= 4));
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&((value - 4) as u16).to_be_bytes());
    }
}
impl<'a> RecoveryIE<Cursor<'a>> {
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
impl<'a> RecoveryIE<CursorMut<'a>> {
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

#[derive(Debug)]
pub enum Gtpv2IEGroup<T> {
    UserLocationInfoIE_(UserLocationInfoIE<T>),
    InternationalMobileSubscriberIdIE_(InternationalMobileSubscriberIdIE<T>),
    ServingNetworkIE_(ServingNetworkIE<T>),
    RatTypeIE_(RatTypeIE<T>),
    FullyQualifiedTeidIE_(FullyQualifiedTeidIE<T>),
    AggregateMaxBitRateIE_(AggregateMaxBitRateIE<T>),
    MobileEquipmentIdIE_(MobileEquipmentIdIE<T>),
    UeTimeZoneIE_(UeTimeZoneIE<T>),
    BearerContextIE_(BearerContextIE<T>),
    EpsBearerIdIE_(EpsBearerIdIE<T>),
    RecoveryIE_(RecoveryIE<T>),
}
impl<T: Buf> Gtpv2IEGroup<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 1 {
            return Err(buf);
        }
        let cond_value0 = buf.chunk()[0];
        match cond_value0 {
            86 => UserLocationInfoIE::parse(buf).map(|pkt| Gtpv2IEGroup::UserLocationInfoIE_(pkt)),
            1 => InternationalMobileSubscriberIdIE::parse(buf)
                .map(|pkt| Gtpv2IEGroup::InternationalMobileSubscriberIdIE_(pkt)),
            83 => ServingNetworkIE::parse(buf).map(|pkt| Gtpv2IEGroup::ServingNetworkIE_(pkt)),
            82 => RatTypeIE::parse(buf).map(|pkt| Gtpv2IEGroup::RatTypeIE_(pkt)),
            87 => {
                FullyQualifiedTeidIE::parse(buf).map(|pkt| Gtpv2IEGroup::FullyQualifiedTeidIE_(pkt))
            }
            72 => AggregateMaxBitRateIE::parse(buf)
                .map(|pkt| Gtpv2IEGroup::AggregateMaxBitRateIE_(pkt)),
            75 => {
                MobileEquipmentIdIE::parse(buf).map(|pkt| Gtpv2IEGroup::MobileEquipmentIdIE_(pkt))
            }
            114 => UeTimeZoneIE::parse(buf).map(|pkt| Gtpv2IEGroup::UeTimeZoneIE_(pkt)),
            93 => BearerContextIE::parse(buf).map(|pkt| Gtpv2IEGroup::BearerContextIE_(pkt)),
            73 => EpsBearerIdIE::parse(buf).map(|pkt| Gtpv2IEGroup::EpsBearerIdIE_(pkt)),
            3 => RecoveryIE::parse(buf).map(|pkt| Gtpv2IEGroup::RecoveryIE_(pkt)),
            _ => Err(buf),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Gtpv2IEGroupIter<'a> {
    buf: &'a [u8],
}
impl<'a> Gtpv2IEGroupIter<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Self {
        Self { buf: slice }
    }

    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }
}
impl<'a> Iterator for Gtpv2IEGroupIter<'a> {
    type Item = Gtpv2IEGroup<Cursor<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 1 {
            return None;
        }
        let cond_value0 = self.buf[0];
        match cond_value0 {
            86 => UserLocationInfoIE::parse(self.buf)
                .map(|_pkt| {
                    let result = UserLocationInfoIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv2IEGroup::UserLocationInfoIE_(result)
                })
                .ok(),
            1 => InternationalMobileSubscriberIdIE::parse(self.buf)
                .map(|_pkt| {
                    let result = InternationalMobileSubscriberIdIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv2IEGroup::InternationalMobileSubscriberIdIE_(result)
                })
                .ok(),
            83 => ServingNetworkIE::parse(self.buf)
                .map(|_pkt| {
                    let result = ServingNetworkIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv2IEGroup::ServingNetworkIE_(result)
                })
                .ok(),
            82 => RatTypeIE::parse(self.buf)
                .map(|_pkt| {
                    let result = RatTypeIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv2IEGroup::RatTypeIE_(result)
                })
                .ok(),
            87 => FullyQualifiedTeidIE::parse(self.buf)
                .map(|_pkt| {
                    let result = FullyQualifiedTeidIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv2IEGroup::FullyQualifiedTeidIE_(result)
                })
                .ok(),
            72 => AggregateMaxBitRateIE::parse(self.buf)
                .map(|_pkt| {
                    let result = AggregateMaxBitRateIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv2IEGroup::AggregateMaxBitRateIE_(result)
                })
                .ok(),
            75 => MobileEquipmentIdIE::parse(self.buf)
                .map(|_pkt| {
                    let result = MobileEquipmentIdIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv2IEGroup::MobileEquipmentIdIE_(result)
                })
                .ok(),
            114 => UeTimeZoneIE::parse(self.buf)
                .map(|_pkt| {
                    let result = UeTimeZoneIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv2IEGroup::UeTimeZoneIE_(result)
                })
                .ok(),
            93 => BearerContextIE::parse(self.buf)
                .map(|_pkt| {
                    let result = BearerContextIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv2IEGroup::BearerContextIE_(result)
                })
                .ok(),
            73 => EpsBearerIdIE::parse(self.buf)
                .map(|_pkt| {
                    let result = EpsBearerIdIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv2IEGroup::EpsBearerIdIE_(result)
                })
                .ok(),
            3 => RecoveryIE::parse(self.buf)
                .map(|_pkt| {
                    let result = RecoveryIE {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Gtpv2IEGroup::RecoveryIE_(result)
                })
                .ok(),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Gtpv2IEGroupIterMut<'a> {
    buf: &'a mut [u8],
}
impl<'a> Gtpv2IEGroupIterMut<'a> {
    pub fn from_slice_mut(slice_mut: &'a mut [u8]) -> Self {
        Self { buf: slice_mut }
    }

    pub fn buf(&self) -> &[u8] {
        &self.buf[..]
    }
}
impl<'a> Iterator for Gtpv2IEGroupIterMut<'a> {
    type Item = Gtpv2IEGroup<CursorMut<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 1 {
            return None;
        }
        let cond_value0 = self.buf[0];
        match cond_value0 {
            86 => match UserLocationInfoIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = UserLocationInfoIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv2IEGroup::UserLocationInfoIE_(result))
                }
                Err(_) => None,
            },
            1 => match InternationalMobileSubscriberIdIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = InternationalMobileSubscriberIdIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv2IEGroup::InternationalMobileSubscriberIdIE_(result))
                }
                Err(_) => None,
            },
            83 => match ServingNetworkIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = ServingNetworkIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv2IEGroup::ServingNetworkIE_(result))
                }
                Err(_) => None,
            },
            82 => match RatTypeIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = RatTypeIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv2IEGroup::RatTypeIE_(result))
                }
                Err(_) => None,
            },
            87 => match FullyQualifiedTeidIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = FullyQualifiedTeidIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv2IEGroup::FullyQualifiedTeidIE_(result))
                }
                Err(_) => None,
            },
            72 => match AggregateMaxBitRateIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = AggregateMaxBitRateIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv2IEGroup::AggregateMaxBitRateIE_(result))
                }
                Err(_) => None,
            },
            75 => match MobileEquipmentIdIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = MobileEquipmentIdIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv2IEGroup::MobileEquipmentIdIE_(result))
                }
                Err(_) => None,
            },
            114 => match UeTimeZoneIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = UeTimeZoneIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv2IEGroup::UeTimeZoneIE_(result))
                }
                Err(_) => None,
            },
            93 => match BearerContextIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = BearerContextIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv2IEGroup::BearerContextIE_(result))
                }
                Err(_) => None,
            },
            73 => match EpsBearerIdIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = EpsBearerIdIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv2IEGroup::EpsBearerIdIE_(result))
                }
                Err(_) => None,
            },
            3 => match RecoveryIE::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = RecoveryIE {
                        buf: CursorMut::new(fst),
                    };
                    Some(Gtpv2IEGroup::RecoveryIE_(result))
                }
                Err(_) => None,
            },
            _ => None,
        }
    }
}
