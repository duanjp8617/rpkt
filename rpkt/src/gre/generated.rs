#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::cursors::*;
use crate::ether::EtherType;
use crate::traits::*;

use super::{gre_header_len, gre_pptp_header_len};

/// A constant that defines the fixed byte length of the Gre protocol header.
pub const GRE_HEADER_LEN: usize = 4;
/// A fixed Gre header.
pub const GRE_HEADER_TEMPLATE: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct Gre<T> {
    buf: T,
}
impl<T: Buf> Gre<T> {
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
    pub fn checksum_present(&self) -> bool {
        self.buf.chunk()[0] & 0x80 != 0
    }
    #[inline]
    pub fn routing_present(&self) -> bool {
        self.buf.chunk()[0] & 0x40 != 0
    }
    #[inline]
    pub fn key_present(&self) -> bool {
        self.buf.chunk()[0] & 0x20 != 0
    }
    #[inline]
    pub fn sequence_present(&self) -> bool {
        self.buf.chunk()[0] & 0x10 != 0
    }
    #[inline]
    pub fn strict_source_route(&self) -> bool {
        self.buf.chunk()[0] & 0x8 != 0
    }
    #[inline]
    pub fn recursion_control(&self) -> u8 {
        self.buf.chunk()[0] & 0x7
    }
    #[inline]
    pub fn flags(&self) -> u8 {
        self.buf.chunk()[1] >> 3
    }
    #[inline]
    pub fn version(&self) -> u8 {
        self.buf.chunk()[1] & 0x7
    }
    #[inline]
    pub fn protocol_type(&self) -> EtherType {
        EtherType::from(u16::from_be_bytes(
            (&self.buf.chunk()[2..4]).try_into().unwrap(),
        ))
    }
}
impl<T: PktBuf> Gre<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> Gre<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        let header_len = Gre::parse_unchecked(&header[..]).header_len() as usize;
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
    pub fn set_checksum_present(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x7f) | (value << 7);
    }
    #[inline]
    pub fn set_routing_present(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xbf) | (value << 6);
    }
    #[inline]
    pub fn set_key_present(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xdf) | (value << 5);
    }
    #[inline]
    pub fn set_sequence_present(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xef) | (value << 4);
    }
    #[inline]
    pub fn set_strict_source_route(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_recursion_control(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf8) | value;
    }
    #[inline]
    pub fn set_flags(&mut self, value: u8) {
        assert!(value <= 0x1f);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0x07) | (value << 3);
    }
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xf8) | value;
    }
    #[inline]
    pub fn set_protocol_type(&mut self, value: EtherType) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&u16::from(value).to_be_bytes());
    }
}
impl<'a> Gre<Cursor<'a>> {
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
impl<'a> Gre<CursorMut<'a>> {
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

impl<T: Buf> Gre<T> {
    /// Return the variable header length of Gre protocol.
    ///
    /// The header length of gre is determined by the bit value in the
    /// header, including the `checksum_present`, `routing_present`,
    /// `key_present` and `sequence_present` bit.
    ///
    /// So be careful when setting these bits, as it may pollute the underlying
    /// packet on the buffer.
    #[inline]
    pub fn header_len(&self) -> usize {
        let indicator = u16::from_be_bytes(self.buf.chunk()[..2].try_into().unwrap());
        gre_header_len(indicator)
    }

    /// Return the checksum value.
    ///
    /// # Panics
    /// This function panics if `self.checksum_present()` and `self.routing_present()`
    /// are both `false`.
    #[inline]
    pub fn checksum(&self) -> u16 {
        assert!(self.checksum_present() || self.routing_present());
        u16::from_be_bytes(self.buf.chunk()[4..6].try_into().unwrap())
    }

    /// Return the offset value.
    ///
    /// # Panics
    /// This function panics if `self.checksum_present()` and `self.routing_present()`
    /// are both `false`.
    #[inline]
    pub fn offset(&self) -> u16 {
        assert!(self.checksum_present() || self.routing_present());
        u16::from_be_bytes(self.buf.chunk()[6..8].try_into().unwrap())
    }

    /// Return the key value.
    ///
    /// # Panics
    /// This function panics if `self.key_present()` is `false`.
    #[inline]
    pub fn key(&self) -> u32 {
        assert!(self.key_present());
        if (self.checksum_present() || self.routing_present()) {
            u32::from_be_bytes(self.buf.chunk()[8..12].try_into().unwrap())
        } else {
            u32::from_be_bytes(self.buf.chunk()[4..8].try_into().unwrap())
        }
    }

    /// Return the sequence value.
    ///
    /// # Panics
    /// This function panics if `self.sequence_present()` is `false`.
    #[inline]
    pub fn sequence(&self) -> u32 {
        assert!(self.sequence_present());

        match (
            (self.checksum_present() || self.routing_present()),
            self.key_present(),
        ) {
            (false, false) => u32::from_be_bytes(self.buf.chunk()[4..8].try_into().unwrap()),
            (true, false) | (false, true) => {
                u32::from_be_bytes(self.buf.chunk()[8..12].try_into().unwrap())
            }
            (true, true) => u32::from_be_bytes(self.buf.chunk()[12..16].try_into().unwrap()),
        }
    }
}

impl<T: PktBufMut> Gre<T> {
    /// Set the checksum value.
    ///
    /// # Panics
    /// This function panics if `self.checksum_present()` and `self.routing_present()`
    /// are both `false`.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        assert!(self.checksum_present() || self.routing_present());
        self.buf.chunk_mut()[4..6].copy_from_slice(&value.to_be_bytes());
    }

    /// Set the offset value.
    ///
    /// # Panics
    /// This function panics if `self.checksum_present()` and `self.routing_present()`
    /// are both `false`.
    #[inline]
    pub fn set_offset(&mut self, value: u16) {
        assert!(self.checksum_present() || self.routing_present());
        self.buf.chunk_mut()[6..8].copy_from_slice(&value.to_be_bytes());
    }

    /// Set the key value.
    ///
    /// # Panics
    /// This function panics if `self.key_present()` is `false`.
    #[inline]
    pub fn set_key(&mut self, value: u32) {
        assert!(self.key_present());
        if (self.checksum_present() || self.routing_present()) {
            self.buf.chunk_mut()[8..12].copy_from_slice(&value.to_be_bytes());
        } else {
            self.buf.chunk_mut()[4..8].copy_from_slice(&value.to_be_bytes());
        }
    }

    /// Set the sequence value.
    ///
    /// # Panics
    /// This function panics if `self.sequence_present()` is `false`.
    #[inline]
    pub fn set_sequence(&mut self, value: u32) {
        assert!(self.sequence_present());

        match (
            (self.checksum_present() || self.routing_present()),
            self.key_present(),
        ) {
            (false, false) => self.buf.chunk_mut()[4..8].copy_from_slice(&value.to_be_bytes()),
            (true, false) | (false, true) => {
                self.buf.chunk_mut()[8..12].copy_from_slice(&value.to_be_bytes());
            }
            (true, true) => self.buf.chunk_mut()[12..16].copy_from_slice(&value.to_be_bytes()),
        }
    }
}

/// A constant that defines the fixed byte length of the GreForPPTP protocol header.
pub const GRE_FOR_PPTP_HEADER_LEN: usize = 8;
/// A fixed GreForPPTP header.
pub const GRE_FOR_PPTP_HEADER_TEMPLATE: [u8; 8] = [0x20, 0x01, 0x88, 0x0b, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct GreForPPTP<T> {
    buf: T,
}
impl<T: Buf> GreForPPTP<T> {
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
            || ((container.payload_len() as usize) + (container.header_len() as usize)
                > container.buf.remaining())
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
    pub fn checksum_present(&self) -> bool {
        self.buf.chunk()[0] & 0x80 != 0
    }
    #[inline]
    pub fn routing_present(&self) -> bool {
        self.buf.chunk()[0] & 0x40 != 0
    }
    #[inline]
    pub fn key_present(&self) -> bool {
        self.buf.chunk()[0] & 0x20 != 0
    }
    #[inline]
    pub fn sequence_present(&self) -> bool {
        self.buf.chunk()[0] & 0x10 != 0
    }
    #[inline]
    pub fn strict_source_route(&self) -> bool {
        self.buf.chunk()[0] & 0x8 != 0
    }
    #[inline]
    pub fn recursion_control(&self) -> u8 {
        self.buf.chunk()[0] & 0x7
    }
    #[inline]
    pub fn ack_present(&self) -> bool {
        self.buf.chunk()[1] & 0x80 != 0
    }
    #[inline]
    pub fn flags(&self) -> u8 {
        (self.buf.chunk()[1] >> 3) & 0xf
    }
    #[inline]
    pub fn version(&self) -> u8 {
        self.buf.chunk()[1] & 0x7
    }
    #[inline]
    pub fn protocol_type(&self) -> EtherType {
        EtherType::from(u16::from_be_bytes(
            (&self.buf.chunk()[2..4]).try_into().unwrap(),
        ))
    }
    #[inline]
    pub fn key_call_id(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[6..8]).try_into().unwrap())
    }
    #[inline]
    pub fn payload_len(&self) -> u16 {
        (u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap()))
    }
}
impl<T: PktBuf> GreForPPTP<T> {
    #[inline]
    pub fn payload(self) -> T {
        assert!((self.header_len() as usize) + self.payload_len() as usize <= self.buf.remaining());
        let trim_size =
            self.buf.remaining() - ((self.header_len() as usize) + self.payload_len() as usize);
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        if trim_size > 0 {
            buf.trim_off(trim_size);
        }
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> GreForPPTP<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        let header_len = GreForPPTP::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 8) && (header_len <= buf.chunk_headroom()));
        let payload_len = buf.remaining();
        assert!(payload_len <= 65535);
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_payload_len(payload_len as u16);
        container
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[8..header_len]
    }
    #[inline]
    pub fn set_checksum_present(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        assert!(value == 0);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x7f) | (value << 7);
    }
    #[inline]
    pub fn set_routing_present(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        assert!(value == 0);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xbf) | (value << 6);
    }
    #[inline]
    pub fn set_key_present(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        assert!(value == 1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xdf) | (value << 5);
    }
    #[inline]
    pub fn set_sequence_present(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xef) | (value << 4);
    }
    #[inline]
    pub fn set_strict_source_route(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_recursion_control(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf8) | value;
    }
    #[inline]
    pub fn set_ack_present(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0x7f) | (value << 7);
    }
    #[inline]
    pub fn set_flags(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0x87) | (value << 3);
    }
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        assert!(value == 1);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xf8) | value;
    }
    #[inline]
    pub fn set_protocol_type(&mut self, value: EtherType) {
        let value = u16::from(value);
        assert!(value == 34827);
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_key_call_id(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[6..8]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_payload_len(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&(value).to_be_bytes());
    }
}
impl<'a> GreForPPTP<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 8)
            || ((container.payload_len() as usize) + (container.header_len() as usize)
                > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        let payload_len = self.payload_len() as usize;
        Cursor::new(&self.buf.chunk()[header_len..(header_len + payload_len)])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 8]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> GreForPPTP<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 8)
            || ((container.payload_len() as usize) + (container.header_len() as usize)
                > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        let payload_len = self.payload_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[header_len..(header_len + payload_len)])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 8]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

impl<T: Buf> GreForPPTP<T> {
    /// Return the variable header length of Gre for PPTP protocol.
    ///
    /// The header length of gre is determined by the bit value in the
    /// header, including the `sequence_present` bit and the `ack_present` bit.
    ///
    /// So be careful when setting these bits, as it may pollute the underlying
    /// packet on the buffer.
    #[inline]
    pub fn header_len(&self) -> usize {
        let indicator = u16::from_be_bytes(self.buf.chunk()[..2].try_into().unwrap());
        gre_pptp_header_len(indicator)
    }

    /// Return the sequence value.
    ///
    /// # Panics
    /// This function panics if `self.sequence_present()` is `false`.
    #[inline]
    pub fn sequence(&self) -> u32 {
        assert!(self.sequence_present());
        u32::from_be_bytes(self.buf.chunk()[8..12].try_into().unwrap())
    }

    /// Return the ack value.
    ///
    /// # Panics
    /// This function panics if `self.ack_present()` is `false`.
    #[inline]
    pub fn ack(&self) -> u32 {
        assert!(self.ack_present());

        if self.sequence_present() {
            u32::from_be_bytes(self.buf.chunk()[12..16].try_into().unwrap())
        } else {
            u32::from_be_bytes(self.buf.chunk()[8..12].try_into().unwrap())
        }
    }
}

impl<T: PktBufMut> GreForPPTP<T> {
    /// Set the sequence value.
    ///
    /// # Panics
    /// This function panics if `self.sequence_present()` is `false`.
    #[inline]
    pub fn set_sequence(&mut self, value: u32) {
        assert!(self.sequence_present());
        self.buf.chunk_mut()[8..12].copy_from_slice(&value.to_be_bytes());
    }

    /// Set the ack value.
    ///
    /// # Panics
    /// This function panics if `self.ack_present()` is `false`.
    #[inline]
    pub fn set_ack(&mut self, value: u32) {
        assert!(self.ack_present());
        if self.sequence_present() {
            self.buf.chunk_mut()[12..16].copy_from_slice(&value.to_be_bytes());
        } else {
            self.buf.chunk_mut()[8..12].copy_from_slice(&value.to_be_bytes());
        }
    }
}

/// A constant that defines the fixed byte length of the PPTP protocol header.
pub const PPTP_HEADER_LEN: usize = 4;
/// A fixed PPTP header.
pub const PPTP_HEADER_TEMPLATE: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct PPTP<T> {
    buf: T,
}
impl<T: Buf> PPTP<T> {
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
    pub fn address(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn control(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn protocol(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
}
impl<T: PktBuf> PPTP<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(4);
        buf
    }
}
impl<T: PktBufMut> PPTP<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        assert!(buf.chunk_headroom() >= 4);
        buf.move_back(4);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_address(&mut self, value: u8) {
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_control(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_protocol(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> PPTP<Cursor<'a>> {
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
impl<'a> PPTP<CursorMut<'a>> {
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

#[derive(Debug)]
pub enum GreGroup<T> {
    GreForPPTP_(GreForPPTP<T>),
    Gre_(Gre<T>),
}
impl<T: Buf> GreGroup<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 4 {
            return Err(buf);
        }
        let cond_value0 = buf.chunk()[0] >> 7;
        let cond_value1 = (buf.chunk()[0] >> 6) & 0x1;
        let cond_value2 = (buf.chunk()[0] >> 5) & 0x1;
        let cond_value3 = buf.chunk()[1] & 0x7;
        let cond_value4 = u16::from_be_bytes((&buf.chunk()[2..4]).try_into().unwrap());
        match (
            cond_value0,
            cond_value1,
            cond_value2,
            cond_value3,
            cond_value4,
        ) {
            (0, 0, 1, 1, 34827) => GreForPPTP::parse(buf).map(|pkt| GreGroup::GreForPPTP_(pkt)),
            (_, _, _, 0, _) => Gre::parse(buf).map(|pkt| GreGroup::Gre_(pkt)),
            _ => Err(buf),
        }
    }
}
