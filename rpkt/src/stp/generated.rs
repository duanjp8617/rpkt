#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::cursors::*;
use crate::ether::EtherAddr;
use crate::traits::*;

use super::{StpType, StpVersion};

/// A constant that defines the fixed byte length of the StpTcnBpdu protocol header.
pub const STPTCNBPDU_HEADER_LEN: usize = 4;
/// A fixed StpTcnBpdu header.
pub const STPTCNBPDU_HEADER_TEMPLATE: [u8; 4] = [0x00, 0x00, 0x00, 0x80];

#[derive(Debug, Clone, Copy)]
pub struct StpTcnBpduMessage<T> {
    buf: T,
}
impl<T: Buf> StpTcnBpduMessage<T> {
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
    pub fn proto_id(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[0..2]).try_into().unwrap())
    }
    #[inline]
    pub fn version(&self) -> StpVersion {
        StpVersion::from(self.buf.chunk()[2])
    }
    #[inline]
    pub fn type_(&self) -> StpType {
        StpType::from(self.buf.chunk()[3])
    }
}
impl<T: PktBuf> StpTcnBpduMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(4);
        buf
    }
}
impl<T: PktBufMut> StpTcnBpduMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        assert!(buf.chunk_headroom() >= 4);
        buf.move_back(4);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_proto_id(&mut self, value: u16) {
        assert!(value == 0);
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_version(&mut self, value: StpVersion) {
        let value = u8::from(value);
        assert!(value == 0);
        self.buf.chunk_mut()[2] = value;
    }
    #[inline]
    pub fn set_type_(&mut self, value: StpType) {
        let value = u8::from(value);
        assert!(value == 128);
        self.buf.chunk_mut()[3] = value;
    }
}
impl<'a> StpTcnBpduMessage<Cursor<'a>> {
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
}
impl<'a> StpTcnBpduMessage<CursorMut<'a>> {
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
}

/// A constant that defines the fixed byte length of the StpConfBpdu protocol header.
pub const STPCONFBPDU_HEADER_LEN: usize = 35;
/// A fixed StpConfBpdu header.
pub const STPCONFBPDU_HEADER_TEMPLATE: [u8; 35] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct StpConfBpduMessage<T> {
    buf: T,
}
impl<T: Buf> StpConfBpduMessage<T> {
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
        if chunk_len < 35 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..35]
    }
    #[inline]
    pub fn proto_id(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[0..2]).try_into().unwrap())
    }
    #[inline]
    pub fn version(&self) -> StpVersion {
        StpVersion::from(self.buf.chunk()[2])
    }
    #[inline]
    pub fn type_(&self) -> StpType {
        StpType::from(self.buf.chunk()[3])
    }
    #[inline]
    pub fn flag(&self) -> u8 {
        self.buf.chunk()[4]
    }
    #[inline]
    pub fn root_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[5..7]).try_into().unwrap()) & 0xfff
    }
    #[inline]
    pub fn root_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.chunk()[7..13])
    }
    #[inline]
    pub fn path_cost(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[13..17]).try_into().unwrap())
    }
    #[inline]
    pub fn bridge_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[17..19]).try_into().unwrap()) & 0xfff
    }
    #[inline]
    pub fn bridge_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.chunk()[19..25])
    }
    #[inline]
    pub fn port_id(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[25..27]).try_into().unwrap())
    }
}
impl<T: PktBuf> StpConfBpduMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(35);
        buf
    }
}
impl<T: PktBufMut> StpConfBpduMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 35]) -> Self {
        assert!(buf.chunk_headroom() >= 35);
        buf.move_back(35);
        (&mut buf.chunk_mut()[0..35]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_proto_id(&mut self, value: u16) {
        assert!(value == 0);
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_version(&mut self, value: StpVersion) {
        let value = u8::from(value);
        assert!(value == 0);
        self.buf.chunk_mut()[2] = value;
    }
    #[inline]
    pub fn set_type_(&mut self, value: StpType) {
        let value = u8::from(value);
        assert!(value == 0);
        self.buf.chunk_mut()[3] = value;
    }
    #[inline]
    pub fn set_flag(&mut self, value: u8) {
        self.buf.chunk_mut()[4] = value;
    }
    #[inline]
    pub fn set_root_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value | (((self.buf.chunk_mut()[5] & 0xf0) as u16) << 8);
        (&mut self.buf.chunk_mut()[5..7]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_root_mac_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.chunk_mut()[7..13]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_path_cost(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[13..17]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_bridge_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value | (((self.buf.chunk_mut()[17] & 0xf0) as u16) << 8);
        (&mut self.buf.chunk_mut()[17..19]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_bridge_mac_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.chunk_mut()[19..25]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_port_id(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[25..27]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> StpConfBpduMessage<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 35 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[35..])
    }
}
impl<'a> StpConfBpduMessage<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 35 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[35..])
    }
}

impl<T: Buf> StpConfBpduMessage<T> {
    /// Get the root id priority from the `StpConfBpduMessage`.
    ///
    /// Note: the result is a a multiple of 4096.
    #[inline]
    pub fn root_priority(&self) -> u16 {
        ((self.buf.chunk()[5] >> 4) as u16) << 12
    }

    /// Get the root id as `u64`.
    #[inline]
    pub fn root_id(&self) -> u64 {
        u64::from_be_bytes((&self.buf.chunk()[5..13]).try_into().unwrap())
    }

    /// Get the bridge id priority from the `StpConfBpduMessage`.
    ///
    /// Note: the result is a a multiple of 4096.
    #[inline]
    pub fn bridge_priority(&self) -> u16 {
        ((self.buf.chunk()[17] >> 4) as u16) << 12
    }

    /// Get the bridge id as `u64`.
    #[inline]
    pub fn bridge_id(&self) -> u64 {
        u64::from_be_bytes((&self.buf.chunk()[17..25]).try_into().unwrap())
    }

    #[inline]
    pub fn msg_age(&self) -> u16 {
        u16::from_le_bytes((&self.buf.chunk()[27..29]).try_into().unwrap())
    }

    #[inline]
    pub fn max_age(&self) -> u16 {
        u16::from_le_bytes((&self.buf.chunk()[29..31]).try_into().unwrap())
    }

    #[inline]
    pub fn hello_time(&self) -> u16 {
        u16::from_le_bytes((&self.buf.chunk()[31..33]).try_into().unwrap())
    }

    #[inline]
    pub fn forward_delay(&self) -> u16 {
        u16::from_le_bytes((&self.buf.chunk()[33..35]).try_into().unwrap())
    }
}
impl<T: PktBufMut> StpConfBpduMessage<T> {
    /// Set the root priority for the `StpConfBpduMessage`.
    ///
    /// Note: the input `value` must be a multiple of 4096.
    ///
    /// # Panics
    ///
    /// The lower 12 bits of `value` is not all zero.
    #[inline]
    pub fn set_root_priority(&mut self, value: u16) {
        assert!(value & 0x0fff == 0);
        let value = (value >> 12) as u8;
        self.buf.chunk_mut()[5] = (self.buf.chunk_mut()[5] & 0x0f) | (value << 4);
    }

    /// Set the root id from `value`.
    #[inline]
    pub fn set_root_id(&mut self, value: u64) {
        (&mut self.buf.chunk_mut()[5..13]).copy_from_slice(&value.to_be_bytes());
    }

    /// Set the bridge priority for the `StpConfBpduMessage`.
    ///
    /// Note: the input `value` must be a multiple of 4096.
    ///
    /// # Panics
    ///
    /// The lower 12 bits of `value` is not all zero.
    #[inline]
    pub fn set_bridge_priority(&mut self, value: u16) {
        assert!(value & 0x0fff == 0);
        let value = (value >> 12) as u8;
        self.buf.chunk_mut()[17] = (self.buf.chunk_mut()[17] & 0x0f) | (value << 4);
    }

    /// Set the bridge id from `value`.
    #[inline]
    pub fn set_bridge_id(&mut self, value: u64) {
        (&mut self.buf.chunk_mut()[17..25]).copy_from_slice(&value.to_be_bytes());
    }

    #[inline]
    pub fn set_msg_age(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[27..29]).copy_from_slice(&value.to_le_bytes());
    }

    #[inline]
    pub fn set_max_age(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[29..31]).copy_from_slice(&value.to_le_bytes());
    }

    #[inline]
    pub fn set_hello_time(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[31..33]).copy_from_slice(&value.to_le_bytes());
    }

    #[inline]
    pub fn set_forward_delay(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[33..35]).copy_from_slice(&value.to_le_bytes());
    }
}

/// A constant that defines the fixed byte length of the RstpConfBpdu protocol header.
pub const RSTPCONFBPDU_HEADER_LEN: usize = 36;
/// A fixed RstpConfBpdu header.
pub const RSTPCONFBPDU_HEADER_TEMPLATE: [u8; 36] = [
    0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct RstpConfBpduMessage<T> {
    buf: T,
}
impl<T: Buf> RstpConfBpduMessage<T> {
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
        if chunk_len < 36 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..36]
    }
    #[inline]
    pub fn proto_id(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[0..2]).try_into().unwrap())
    }
    #[inline]
    pub fn version(&self) -> StpVersion {
        StpVersion::from(self.buf.chunk()[2])
    }
    #[inline]
    pub fn type_(&self) -> StpType {
        StpType::from(self.buf.chunk()[3])
    }
    #[inline]
    pub fn flag(&self) -> u8 {
        self.buf.chunk()[4]
    }
    #[inline]
    pub fn root_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[5..7]).try_into().unwrap()) & 0xfff
    }
    #[inline]
    pub fn root_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.chunk()[7..13])
    }
    #[inline]
    pub fn path_cost(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[13..17]).try_into().unwrap())
    }
    #[inline]
    pub fn bridge_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[17..19]).try_into().unwrap()) & 0xfff
    }
    #[inline]
    pub fn bridge_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.chunk()[19..25])
    }
    #[inline]
    pub fn port_id(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[25..27]).try_into().unwrap())
    }
    #[inline]
    pub fn version1_len(&self) -> u8 {
        self.buf.chunk()[35]
    }
}
impl<T: PktBuf> RstpConfBpduMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(36);
        buf
    }
}
impl<T: PktBufMut> RstpConfBpduMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 36]) -> Self {
        assert!(buf.chunk_headroom() >= 36);
        buf.move_back(36);
        (&mut buf.chunk_mut()[0..36]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_proto_id(&mut self, value: u16) {
        assert!(value == 0);
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_version(&mut self, value: StpVersion) {
        let value = u8::from(value);
        assert!(value == 2);
        self.buf.chunk_mut()[2] = value;
    }
    #[inline]
    pub fn set_type_(&mut self, value: StpType) {
        let value = u8::from(value);
        assert!(value == 2);
        self.buf.chunk_mut()[3] = value;
    }
    #[inline]
    pub fn set_flag(&mut self, value: u8) {
        self.buf.chunk_mut()[4] = value;
    }
    #[inline]
    pub fn set_root_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value | (((self.buf.chunk_mut()[5] & 0xf0) as u16) << 8);
        (&mut self.buf.chunk_mut()[5..7]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_root_mac_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.chunk_mut()[7..13]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_path_cost(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[13..17]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_bridge_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value | (((self.buf.chunk_mut()[17] & 0xf0) as u16) << 8);
        (&mut self.buf.chunk_mut()[17..19]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_bridge_mac_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.chunk_mut()[19..25]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_port_id(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[25..27]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_version1_len(&mut self, value: u8) {
        self.buf.chunk_mut()[35] = value;
    }
}
impl<'a> RstpConfBpduMessage<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 36 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[36..])
    }
}
impl<'a> RstpConfBpduMessage<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 36 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[36..])
    }
}

impl<T: Buf> RstpConfBpduMessage<T> {
    /// Get the root id priority from the `RstpConfBpduMessage`.
    ///
    /// Note: the result is a a multiple of 4096.
    #[inline]
    pub fn root_priority(&self) -> u16 {
        ((self.buf.chunk()[5] >> 4) as u16) << 12
    }

    /// Get the root id as `u64`.
    #[inline]
    pub fn root_id(&self) -> u64 {
        u64::from_be_bytes((&self.buf.chunk()[5..13]).try_into().unwrap())
    }

    /// Get the bridge id priority from the `RstpConfBpduMessage`.
    ///
    /// Note: the result is a a multiple of 4096.
    #[inline]
    pub fn bridge_priority(&self) -> u16 {
        ((self.buf.chunk()[17] >> 4) as u16) << 12
    }

    /// Get the bridge id as `u64`.
    #[inline]
    pub fn bridge_id(&self) -> u64 {
        u64::from_be_bytes((&self.buf.chunk()[17..25]).try_into().unwrap())
    }

    #[inline]
    pub fn msg_age(&self) -> u16 {
        u16::from_le_bytes((&self.buf.chunk()[27..29]).try_into().unwrap())
    }

    #[inline]
    pub fn max_age(&self) -> u16 {
        u16::from_le_bytes((&self.buf.chunk()[29..31]).try_into().unwrap())
    }

    #[inline]
    pub fn hello_time(&self) -> u16 {
        u16::from_le_bytes((&self.buf.chunk()[31..33]).try_into().unwrap())
    }

    #[inline]
    pub fn forward_delay(&self) -> u16 {
        u16::from_le_bytes((&self.buf.chunk()[33..35]).try_into().unwrap())
    }
}
impl<T: PktBufMut> RstpConfBpduMessage<T> {
    /// Set the root priority for the `RstpConfBpduMessage`.
    ///
    /// Note: the input `value` must be a multiple of 4096.
    ///
    /// # Panics
    ///
    /// The lower 12 bits of `value` is not all zero.
    #[inline]
    pub fn set_root_priority(&mut self, value: u16) {
        assert!(value & 0x0fff == 0);
        let value = (value >> 12) as u8;
        self.buf.chunk_mut()[5] = (self.buf.chunk_mut()[5] & 0x0f) | (value << 4);
    }

    /// Set the root id from `value`.
    #[inline]
    pub fn set_root_id(&mut self, value: u64) {
        (&mut self.buf.chunk_mut()[5..13]).copy_from_slice(&value.to_be_bytes());
    }

    /// Set the bridge priority for the `RstpConfBpduMessage`.
    ///
    /// Note: the input `value` must be a multiple of 4096.
    ///
    /// # Panics
    ///
    /// The lower 12 bits of `value` is not all zero.
    #[inline]
    pub fn set_bridge_priority(&mut self, value: u16) {
        assert!(value & 0x0fff == 0);
        let value = (value >> 12) as u8;
        self.buf.chunk_mut()[17] = (self.buf.chunk_mut()[17] & 0x0f) | (value << 4);
    }

    /// Set the bridge id from `value`.
    #[inline]
    pub fn set_bridge_id(&mut self, value: u64) {
        (&mut self.buf.chunk_mut()[17..25]).copy_from_slice(&value.to_be_bytes());
    }

    #[inline]
    pub fn set_msg_age(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[27..29]).copy_from_slice(&value.to_le_bytes());
    }

    #[inline]
    pub fn set_max_age(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[29..31]).copy_from_slice(&value.to_le_bytes());
    }

    #[inline]
    pub fn set_hello_time(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[31..33]).copy_from_slice(&value.to_le_bytes());
    }

    #[inline]
    pub fn set_forward_delay(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[33..35]).copy_from_slice(&value.to_le_bytes());
    }
}

/// A constant that defines the fixed byte length of the MstpConfBpdu protocol header.
pub const MSTPCONFBPDU_HEADER_LEN: usize = 102;
/// A fixed MstpConfBpdu header.
pub const MSTPCONFBPDU_HEADER_TEMPLATE: [u8; 102] = [
    0x00, 0x00, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct MstpConfBpduMessage<T> {
    buf: T,
}
impl<T: Buf> MstpConfBpduMessage<T> {
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
        if chunk_len < 102 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 102)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..102]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[102..header_len]
    }
    #[inline]
    pub fn proto_id(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[0..2]).try_into().unwrap())
    }
    #[inline]
    pub fn version(&self) -> StpVersion {
        StpVersion::from(self.buf.chunk()[2])
    }
    #[inline]
    pub fn type_(&self) -> StpType {
        StpType::from(self.buf.chunk()[3])
    }
    #[inline]
    pub fn flag(&self) -> u8 {
        self.buf.chunk()[4]
    }
    #[inline]
    pub fn root_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[5..7]).try_into().unwrap()) & 0xfff
    }
    #[inline]
    pub fn root_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.chunk()[7..13])
    }
    #[inline]
    pub fn path_cost(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[13..17]).try_into().unwrap())
    }
    #[inline]
    pub fn bridge_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[17..19]).try_into().unwrap()) & 0xfff
    }
    #[inline]
    pub fn bridge_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.chunk()[19..25])
    }
    #[inline]
    pub fn port_id(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[25..27]).try_into().unwrap())
    }
    #[inline]
    pub fn version1_len(&self) -> u8 {
        self.buf.chunk()[35]
    }
    #[inline]
    pub fn mst_config_format_selector(&self) -> u8 {
        self.buf.chunk()[38]
    }
    #[inline]
    pub fn mst_config_name(&self) -> &[u8] {
        &self.buf.chunk()[39..71]
    }
    #[inline]
    pub fn mst_config_revision(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[71..73]).try_into().unwrap())
    }
    #[inline]
    pub fn mst_config_digest(&self) -> &[u8] {
        &self.buf.chunk()[73..89]
    }
    #[inline]
    pub fn irpc(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[89..93]).try_into().unwrap())
    }
    #[inline]
    pub fn cist_bridge_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[93..95]).try_into().unwrap()) & 0xfff
    }
    #[inline]
    pub fn cist_bridge_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.chunk()[95..101])
    }
    #[inline]
    pub fn remain_id(&self) -> u8 {
        self.buf.chunk()[101]
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[36..38]).try_into().unwrap())) as u32 + 38
    }
}
impl<T: PktBuf> MstpConfBpduMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> MstpConfBpduMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 102], header_len: u32) -> Self {
        assert!((header_len >= 102) && (header_len as usize <= buf.chunk_headroom()));
        buf.move_back(header_len as usize);
        (&mut buf.chunk_mut()[0..102]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_header_len(header_len);
        container
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[102..header_len]
    }
    #[inline]
    pub fn set_proto_id(&mut self, value: u16) {
        assert!(value == 0);
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_version(&mut self, value: StpVersion) {
        let value = u8::from(value);
        assert!(value == 3);
        self.buf.chunk_mut()[2] = value;
    }
    #[inline]
    pub fn set_type_(&mut self, value: StpType) {
        let value = u8::from(value);
        assert!(value == 2);
        self.buf.chunk_mut()[3] = value;
    }
    #[inline]
    pub fn set_flag(&mut self, value: u8) {
        self.buf.chunk_mut()[4] = value;
    }
    #[inline]
    pub fn set_root_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value | (((self.buf.chunk_mut()[5] & 0xf0) as u16) << 8);
        (&mut self.buf.chunk_mut()[5..7]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_root_mac_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.chunk_mut()[7..13]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_path_cost(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[13..17]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_bridge_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value | (((self.buf.chunk_mut()[17] & 0xf0) as u16) << 8);
        (&mut self.buf.chunk_mut()[17..19]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_bridge_mac_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.chunk_mut()[19..25]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_port_id(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[25..27]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_version1_len(&mut self, value: u8) {
        self.buf.chunk_mut()[35] = value;
    }
    #[inline]
    pub fn set_mst_config_format_selector(&mut self, value: u8) {
        self.buf.chunk_mut()[38] = value;
    }
    #[inline]
    pub fn set_mst_config_name(&mut self, value: &[u8]) {
        (&mut self.buf.chunk_mut()[39..71]).copy_from_slice(value);
    }
    #[inline]
    pub fn set_mst_config_revision(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[71..73]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_mst_config_digest(&mut self, value: &[u8]) {
        (&mut self.buf.chunk_mut()[73..89]).copy_from_slice(value);
    }
    #[inline]
    pub fn set_irpc(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[89..93]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_cist_bridge_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value | (((self.buf.chunk_mut()[93] & 0xf0) as u16) << 8);
        (&mut self.buf.chunk_mut()[93..95]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_cist_bridge_mac_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.chunk_mut()[95..101]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_remain_id(&mut self, value: u8) {
        self.buf.chunk_mut()[101] = value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65573) && (value >= 38));
        (&mut self.buf.chunk_mut()[36..38]).copy_from_slice(&((value - 38) as u16).to_be_bytes());
    }
}
impl<'a> MstpConfBpduMessage<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 102 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 102)
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
}
impl<'a> MstpConfBpduMessage<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 102 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 102)
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
}

impl<T: Buf> MstpConfBpduMessage<T> {
    /// Get the **version3_len** field value.
    #[inline]
    pub fn version3_len(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[36..38]).try_into().unwrap())
    }

    /// Get the root id priority from the `MstpConfBpduMessage`.
    ///
    /// Note: the result is a a multiple of 4096.
    #[inline]
    pub fn root_priority(&self) -> u16 {
        ((self.buf.chunk()[5] >> 4) as u16) << 12
    }

    /// Get the root id as `u64`.
    #[inline]
    pub fn root_id(&self) -> u64 {
        u64::from_be_bytes((&self.buf.chunk()[5..13]).try_into().unwrap())
    }

    /// Get the bridge id priority from the `MstpConfBpduMessage`.
    ///
    /// Note: the result is a a multiple of 4096.
    #[inline]
    pub fn bridge_priority(&self) -> u16 {
        ((self.buf.chunk()[17] >> 4) as u16) << 12
    }

    /// Get the bridge id as `u64`.
    #[inline]
    pub fn bridge_id(&self) -> u64 {
        u64::from_be_bytes((&self.buf.chunk()[17..25]).try_into().unwrap())
    }

    /// Get the cist bridge id priority from the `MstpConfBpduMessage`.
    ///
    /// Note: the result is a a multiple of 4096.
    #[inline]
    pub fn cist_bridge_priority(&self) -> u16 {
        ((self.buf.chunk()[93] >> 4) as u16) << 12
    }

    /// Get the cist bridge id as `u64`.
    #[inline]
    pub fn cist_bridge_id(&self) -> u64 {
        u64::from_be_bytes((&self.buf.chunk()[93..101]).try_into().unwrap())
    }

    /// Get the number of the `MstiConfMessage` contained in the
    /// `MstpConfBpduMessage`.
    ///
    /// This method returns `None` if the `MstpConfBpduMessage` has an invalid
    /// format.
    #[inline]
    pub fn num_of_msti_msg(&self) -> Option<usize> {
        if (self.header_len() - 102) % 16 != 0 {
            None
        } else {
            Some(((self.header_len() - 102) / 16) as usize)
        }
    }

    /// Get the `index`-th `MstiConfMessage` from the `MstpConfBpduMessage`.
    ///
    /// # Panics
    ///
    /// This method panics if `MstpConfBpduMessage` does not have the `index`-th
    /// `MstiConfMessage`.
    #[inline]
    pub fn msti_conf_message(&self, index: usize) -> MstiConfMessage<Cursor<'_>> {
        let offset = 16 * index;
        MstiConfMessage::parse_unchecked(Cursor::new(&self.buf.chunk()[102 + offset..118 + offset]))
    }

    #[inline]
    pub fn msg_age(&self) -> u16 {
        u16::from_le_bytes((&self.buf.chunk()[27..29]).try_into().unwrap())
    }

    #[inline]
    pub fn max_age(&self) -> u16 {
        u16::from_le_bytes((&self.buf.chunk()[29..31]).try_into().unwrap())
    }

    #[inline]
    pub fn hello_time(&self) -> u16 {
        u16::from_le_bytes((&self.buf.chunk()[31..33]).try_into().unwrap())
    }

    #[inline]
    pub fn forward_delay(&self) -> u16 {
        u16::from_le_bytes((&self.buf.chunk()[33..35]).try_into().unwrap())
    }
}
impl<T: PktBufMut> MstpConfBpduMessage<T> {
    /// Set the root priority for the `MstpConfBpduMessage`.
    ///
    /// Note: the input `value` must be a multiple of 4096.
    ///
    /// # Panics
    ///
    /// The lower 12 bits of `value` is not all zero.
    #[inline]
    pub fn set_root_priority(&mut self, value: u16) {
        assert!(value & 0x0fff == 0);
        let value = (value >> 12) as u8;
        self.buf.chunk_mut()[5] = (self.buf.chunk_mut()[5] & 0x0f) | (value << 4);
    }

    /// Set the root id from `value`.
    #[inline]
    pub fn set_root_id(&mut self, value: u64) {
        (&mut self.buf.chunk_mut()[5..13]).copy_from_slice(&value.to_be_bytes());
    }

    /// Set the bridge priority for the `MstpConfBpduMessage`.
    ///
    /// Note: the input `value` must be a multiple of 4096.
    ///
    /// # Panics
    ///
    /// The lower 12 bits of `value` is not all zero.
    #[inline]
    pub fn set_bridge_priority(&mut self, value: u16) {
        assert!(value & 0x0fff == 0);
        let value = (value >> 12) as u8;
        self.buf.chunk_mut()[17] = (self.buf.chunk_mut()[17] & 0x0f) | (value << 4);
    }

    /// Set the bridge id from `value`.
    #[inline]
    pub fn set_bridge_id(&mut self, value: u64) {
        (&mut self.buf.chunk_mut()[17..25]).copy_from_slice(&value.to_be_bytes());
    }

    /// Set the cist bridge id priority for the `MstpConfBpduMessage`.
    ///
    /// Note: the input `value` must be a multiple of 4096.
    ///
    /// # Panics
    ///
    /// The lower 12 bits of `value` is not all zero.
    #[inline]
    pub fn set_cist_bridge_priority(&mut self, value: u16) {
        assert!(value & 0x0fff == 0);
        let value = (value >> 12) as u8;
        self.buf.chunk_mut()[93] = (self.buf.chunk_mut()[93] & 0x0f) | (value << 4);
    }

    /// Set the cist bridge id from `value`.
    #[inline]
    pub fn set_cist_bridge_id(&mut self, value: u64) {
        (&mut self.buf.chunk_mut()[93..101]).copy_from_slice(&value.to_be_bytes());
    }

    /// Set the number of the `MstiConfMessage` contained in the
    /// `MstpConfBpduMessage`.
    #[inline]
    pub fn set_num_of_msti_msg(&mut self, num: u32) {
        self.set_header_len(102 + num * 16);
    }

    /// Get the `index`-th mutable `MstiConfMessage` from the
    /// `MstpConfBpduMessage`.
    ///
    /// # Panics
    ///
    /// This method panics if `MstpConfBpduMessage` does not have the `index`-th
    /// `MstiConfMessage`.
    #[inline]
    pub fn msti_conf_message_mut(&mut self, index: usize) -> MstiConfMessage<CursorMut<'_>> {
        let offset = 16 * index;
        MstiConfMessage::parse_unchecked(CursorMut::new(
            &mut self.buf.chunk_mut()[102 + offset..118 + offset],
        ))
    }

    #[inline]
    pub fn set_msg_age(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[27..29]).copy_from_slice(&value.to_le_bytes());
    }

    #[inline]
    pub fn set_max_age(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[29..31]).copy_from_slice(&value.to_le_bytes());
    }

    #[inline]
    pub fn set_hello_time(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[31..33]).copy_from_slice(&value.to_le_bytes());
    }

    #[inline]
    pub fn set_forward_delay(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[33..35]).copy_from_slice(&value.to_le_bytes());
    }
}

/// A constant that defines the fixed byte length of the MstiConf protocol header.
pub const MSTICONF_HEADER_LEN: usize = 16;
/// A fixed MstiConf header.
pub const MSTICONF_HEADER_TEMPLATE: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct MstiConfMessage<T> {
    buf: T,
}
impl<T: Buf> MstiConfMessage<T> {
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
        if chunk_len < 16 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..16]
    }
    #[inline]
    pub fn flags(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn regional_root_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[1..3]).try_into().unwrap()) & 0xfff
    }
    #[inline]
    pub fn regional_root_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.chunk()[3..9])
    }
    #[inline]
    pub fn path_cost(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[9..13]).try_into().unwrap())
    }
    #[inline]
    pub fn bridge_priority(&self) -> u8 {
        self.buf.chunk()[13]
    }
    #[inline]
    pub fn port_priority(&self) -> u8 {
        self.buf.chunk()[14]
    }
    #[inline]
    pub fn remaining_hops(&self) -> u8 {
        self.buf.chunk()[15]
    }
}
impl<T: PktBuf> MstiConfMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(16);
        buf
    }
}
impl<T: PktBufMut> MstiConfMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 16]) -> Self {
        assert!(buf.chunk_headroom() >= 16);
        buf.move_back(16);
        (&mut buf.chunk_mut()[0..16]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_flags(&mut self, value: u8) {
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_regional_root_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value | (((self.buf.chunk_mut()[1] & 0xf0) as u16) << 8);
        (&mut self.buf.chunk_mut()[1..3]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_regional_root_mac_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.chunk_mut()[3..9]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_path_cost(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[9..13]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_bridge_priority(&mut self, value: u8) {
        self.buf.chunk_mut()[13] = value;
    }
    #[inline]
    pub fn set_port_priority(&mut self, value: u8) {
        self.buf.chunk_mut()[14] = value;
    }
    #[inline]
    pub fn set_remaining_hops(&mut self, value: u8) {
        self.buf.chunk_mut()[15] = value;
    }
}
impl<'a> MstiConfMessage<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 16 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[16..])
    }
}
impl<'a> MstiConfMessage<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 16 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[16..])
    }
}

impl<T: Buf> MstiConfMessage<T> {
    /// Get the regional root id priority from the `MstiConfMessage`.
    ///
    /// Note: the result is a a multiple of 4096.
    #[inline]
    pub fn regional_root_priority(&self) -> u16 {
        ((self.buf.chunk()[1] >> 4) as u16) << 12
    }

    /// Get the regional root id as `u64`.
    #[inline]
    pub fn regional_root_id(&self) -> u64 {
        u64::from_be_bytes((&self.buf.chunk()[1..9]).try_into().unwrap())
    }
}

impl<T: PktBufMut> MstiConfMessage<T> {
    /// Set the regional root id priority for the `MstiConfMessage`.
    ///
    /// Note: the input `value` must be a multiple of 4096.
    ///
    /// # Panics
    ///
    /// The lower 12 bits of `value` is not all zero.
    #[inline]
    pub fn set_regional_root_priority(&mut self, value: u16) {
        assert!(value & 0x0fff == 0);
        let value = (value >> 12) as u8;
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0x0f) | (value << 4);
    }

    /// Set the regional root id from `value`.
    #[inline]
    pub fn set_regional_root_id(&mut self, value: u64) {
        (&mut self.buf.chunk_mut()[1..9]).copy_from_slice(&value.to_be_bytes());
    }
}

#[derive(Debug)]
pub enum StpMessageGroup<T> {
    StpTcn(StpTcnBpduMessage<T>),
    StpConf(StpConfBpduMessage<T>),
    RstpConf(RstpConfBpduMessage<T>),
    MstpConf(MstpConfBpduMessage<T>),
}
impl<T: Buf> StpMessageGroup<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 3 {
            return Err(buf);
        }
        let v = buf.chunk()[2];
        let t = buf.chunk()[3];
        match (t, v) {
            (0, 0) => StpConfBpduMessage::parse(buf).map(|msg| StpMessageGroup::StpConf(msg)),
            (2, 2) => RstpConfBpduMessage::parse(buf).map(|msg| StpMessageGroup::RstpConf(msg)),
            (2, 3) => MstpConfBpduMessage::parse(buf).map(|msg| StpMessageGroup::MstpConf(msg)),
            (0x80, 0) => StpTcnBpduMessage::parse(buf).map(|msg| StpMessageGroup::StpTcn(msg)),
            _ => Err(buf),
        }
    }
}
