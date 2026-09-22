#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::cursors::*;
use crate::cursors::{CursorIndex, CursorIndexMut};
use crate::ether::EtherAddr;
use crate::traits::*;

use super::{StpType, StpVersion};

/// A constant that defines the fixed byte length of the StpTcnBpdu protocol header.
pub const STP_TCN_BPDU_HEADER_LEN: usize = 4;
/// A fixed StpTcnBpdu header.
pub const STP_TCN_BPDU_HEADER_TEMPLATE: [u8; 4] = [0x00, 0x00, 0x00, 0x80];

#[derive(Debug, Clone, Copy)]
pub struct StpTcnBpdu<T> {
    buf: T,
}
impl<T: Buf + crate::StableBuf> StpTcnBpdu<T> {
    /// Wrap a buffer without validating its protocol lengths.
    /// # Safety
    /// The current chunk must contain the complete fixed header. Before using
    /// variable-header or payload operations, the caller must also establish
    /// their declared length invariants. A fixed header template may be used
    /// for field access alone while its variable lengths are being initialized.
    #[inline]
    pub unsafe fn parse_unchecked(buf: T) -> Self {
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
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(0..2)
            })
            .try_into()
            .unwrap(),
        )
    }
    #[inline]
    pub fn version(&self) -> StpVersion {
        StpVersion::from(
            (unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk().get_unchecked(2)
            }),
        )
    }
    #[inline]
    pub fn type_(&self) -> StpType {
        StpType::from(
            (unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk().get_unchecked(3)
            }),
        )
    }
}
impl<T: PktBuf> StpTcnBpdu<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(4);
        buf
    }
}
impl<T: PktBufMut> StpTcnBpdu<T> {
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
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(0..2)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_version(&mut self, value: StpVersion) {
        let value = u8::from(value);
        assert!(value == 0);
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(2)
        } = value;
    }
    #[inline]
    pub fn set_type_(&mut self, value: StpType) {
        let value = u8::from(value);
        assert!(value == 128);
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(3)
        } = value;
    }
}
impl<'a> StpTcnBpdu<Cursor<'a>> {
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
        self.buf.index_(4..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 4]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 4] {
        STP_TCN_BPDU_HEADER_TEMPLATE.clone()
    }
}
impl<'a> StpTcnBpdu<CursorMut<'a>> {
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
        self.buf.index_mut_(4..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 4]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the StpConfBpdu protocol header.
pub const STP_CONF_BPDU_HEADER_LEN: usize = 35;
/// A fixed StpConfBpdu header.
pub const STP_CONF_BPDU_HEADER_TEMPLATE: [u8; 35] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct StpConfBpdu<T> {
    buf: T,
}
impl<T: Buf + crate::StableBuf> StpConfBpdu<T> {
    /// Wrap a buffer without validating its protocol lengths.
    /// # Safety
    /// The current chunk must contain the complete fixed header. Before using
    /// variable-header or payload operations, the caller must also establish
    /// their declared length invariants. A fixed header template may be used
    /// for field access alone while its variable lengths are being initialized.
    #[inline]
    pub unsafe fn parse_unchecked(buf: T) -> Self {
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
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(0..2)
            })
            .try_into()
            .unwrap(),
        )
    }
    #[inline]
    pub fn version(&self) -> StpVersion {
        StpVersion::from(
            (unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk().get_unchecked(2)
            }),
        )
    }
    #[inline]
    pub fn type_(&self) -> StpType {
        StpType::from(
            (unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk().get_unchecked(3)
            }),
        )
    }
    #[inline]
    pub fn flag(&self) -> u8 {
        (unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            *self.buf.chunk().get_unchecked(4)
        })
    }
    #[inline]
    pub fn root_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(5..7)
            })
            .try_into()
            .unwrap(),
        ) & 0xfff
    }
    #[inline]
    pub fn root_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk().get_unchecked(7..13)
        })
    }
    #[inline]
    pub fn path_cost(&self) -> u32 {
        u32::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(13..17)
            })
            .try_into()
            .unwrap(),
        )
    }
    #[inline]
    pub fn bridge_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(17..19)
            })
            .try_into()
            .unwrap(),
        ) & 0xfff
    }
    #[inline]
    pub fn bridge_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk().get_unchecked(19..25)
        })
    }
    #[inline]
    pub fn port_id(&self) -> u16 {
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(25..27)
            })
            .try_into()
            .unwrap(),
        )
    }
}
impl<T: PktBuf> StpConfBpdu<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(35);
        buf
    }
}
impl<T: PktBufMut> StpConfBpdu<T> {
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
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(0..2)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_version(&mut self, value: StpVersion) {
        let value = u8::from(value);
        assert!(value == 0);
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(2)
        } = value;
    }
    #[inline]
    pub fn set_type_(&mut self, value: StpType) {
        let value = u8::from(value);
        assert!(value == 0);
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(3)
        } = value;
    }
    #[inline]
    pub fn set_flag(&mut self, value: u8) {
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(4)
        } = value;
    }
    #[inline]
    pub fn set_root_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value
            | ((((unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk_mut().get_unchecked(5)
            }) & 0xf0) as u16)
                << 8);
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(5..7)
        })
        .copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_root_mac_addr(&mut self, value: EtherAddr) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(7..13)
        })
        .copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_path_cost(&mut self, value: u32) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(13..17)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_bridge_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value
            | ((((unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk_mut().get_unchecked(17)
            }) & 0xf0) as u16)
                << 8);
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(17..19)
        })
        .copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_bridge_mac_addr(&mut self, value: EtherAddr) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(19..25)
        })
        .copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_port_id(&mut self, value: u16) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(25..27)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> StpConfBpdu<Cursor<'a>> {
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
        self.buf.index_(35..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 35]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 35] {
        STP_CONF_BPDU_HEADER_TEMPLATE.clone()
    }
}
impl<'a> StpConfBpdu<CursorMut<'a>> {
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
        self.buf.index_mut_(35..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 35]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

impl<T: Buf + crate::StableBuf> StpConfBpdu<T> {
    /// Get the root id priority from the `StpConfBpdu`.
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

    /// Get the bridge id priority from the `StpConfBpdu`.
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
impl<T: PktBufMut> StpConfBpdu<T> {
    /// Set the root priority for the `StpConfBpdu`.
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

    /// Set the bridge priority for the `StpConfBpdu`.
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
pub const RSTP_CONF_BPDU_HEADER_LEN: usize = 36;
/// A fixed RstpConfBpdu header.
pub const RSTP_CONF_BPDU_HEADER_TEMPLATE: [u8; 36] = [
    0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct RstpConfBpdu<T> {
    buf: T,
}
impl<T: Buf + crate::StableBuf> RstpConfBpdu<T> {
    /// Wrap a buffer without validating its protocol lengths.
    /// # Safety
    /// The current chunk must contain the complete fixed header. Before using
    /// variable-header or payload operations, the caller must also establish
    /// their declared length invariants. A fixed header template may be used
    /// for field access alone while its variable lengths are being initialized.
    #[inline]
    pub unsafe fn parse_unchecked(buf: T) -> Self {
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
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(0..2)
            })
            .try_into()
            .unwrap(),
        )
    }
    #[inline]
    pub fn version(&self) -> StpVersion {
        StpVersion::from(
            (unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk().get_unchecked(2)
            }),
        )
    }
    #[inline]
    pub fn type_(&self) -> StpType {
        StpType::from(
            (unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk().get_unchecked(3)
            }),
        )
    }
    #[inline]
    pub fn flag(&self) -> u8 {
        (unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            *self.buf.chunk().get_unchecked(4)
        })
    }
    #[inline]
    pub fn root_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(5..7)
            })
            .try_into()
            .unwrap(),
        ) & 0xfff
    }
    #[inline]
    pub fn root_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk().get_unchecked(7..13)
        })
    }
    #[inline]
    pub fn path_cost(&self) -> u32 {
        u32::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(13..17)
            })
            .try_into()
            .unwrap(),
        )
    }
    #[inline]
    pub fn bridge_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(17..19)
            })
            .try_into()
            .unwrap(),
        ) & 0xfff
    }
    #[inline]
    pub fn bridge_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk().get_unchecked(19..25)
        })
    }
    #[inline]
    pub fn port_id(&self) -> u16 {
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(25..27)
            })
            .try_into()
            .unwrap(),
        )
    }
    #[inline]
    pub fn version1_len(&self) -> u8 {
        (unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            *self.buf.chunk().get_unchecked(35)
        })
    }
}
impl<T: PktBuf> RstpConfBpdu<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(36);
        buf
    }
}
impl<T: PktBufMut> RstpConfBpdu<T> {
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
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(0..2)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_version(&mut self, value: StpVersion) {
        let value = u8::from(value);
        assert!(value == 2);
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(2)
        } = value;
    }
    #[inline]
    pub fn set_type_(&mut self, value: StpType) {
        let value = u8::from(value);
        assert!(value == 2);
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(3)
        } = value;
    }
    #[inline]
    pub fn set_flag(&mut self, value: u8) {
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(4)
        } = value;
    }
    #[inline]
    pub fn set_root_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value
            | ((((unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk_mut().get_unchecked(5)
            }) & 0xf0) as u16)
                << 8);
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(5..7)
        })
        .copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_root_mac_addr(&mut self, value: EtherAddr) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(7..13)
        })
        .copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_path_cost(&mut self, value: u32) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(13..17)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_bridge_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value
            | ((((unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk_mut().get_unchecked(17)
            }) & 0xf0) as u16)
                << 8);
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(17..19)
        })
        .copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_bridge_mac_addr(&mut self, value: EtherAddr) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(19..25)
        })
        .copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_port_id(&mut self, value: u16) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(25..27)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_version1_len(&mut self, value: u8) {
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(35)
        } = value;
    }
}
impl<'a> RstpConfBpdu<Cursor<'a>> {
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
        self.buf.index_(36..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 36]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 36] {
        RSTP_CONF_BPDU_HEADER_TEMPLATE.clone()
    }
}
impl<'a> RstpConfBpdu<CursorMut<'a>> {
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
        self.buf.index_mut_(36..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 36]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

impl<T: Buf + crate::StableBuf> RstpConfBpdu<T> {
    /// Get the root id priority from the `RstpConfBpdu`.
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

    /// Get the bridge id priority from the `RstpConfBpdu`.
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
impl<T: PktBufMut> RstpConfBpdu<T> {
    /// Set the root priority for the `RstpConfBpdu`.
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
pub const MSTP_CONF_BPDU_HEADER_LEN: usize = 102;
/// A fixed MstpConfBpdu header.
pub const MSTP_CONF_BPDU_HEADER_TEMPLATE: [u8; 102] = [
    0x00, 0x00, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct MstpConfBpdu<T> {
    buf: T,
}
impl<T: Buf + crate::StableBuf> MstpConfBpdu<T> {
    /// Wrap a buffer without validating its protocol lengths.
    /// # Safety
    /// The current chunk must contain the complete fixed header. Before using
    /// variable-header or payload operations, the caller must also establish
    /// their declared length invariants. A fixed header template may be used
    /// for field access alone while its variable lengths are being initialized.
    #[inline]
    pub unsafe fn parse_unchecked(buf: T) -> Self {
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
        let header_len = container.header_len() as usize;
        if (header_len < 102) || (header_len > chunk_len) {
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
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(0..2)
            })
            .try_into()
            .unwrap(),
        )
    }
    #[inline]
    pub fn version(&self) -> StpVersion {
        StpVersion::from(
            (unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk().get_unchecked(2)
            }),
        )
    }
    #[inline]
    pub fn type_(&self) -> StpType {
        StpType::from(
            (unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk().get_unchecked(3)
            }),
        )
    }
    #[inline]
    pub fn flag(&self) -> u8 {
        (unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            *self.buf.chunk().get_unchecked(4)
        })
    }
    #[inline]
    pub fn root_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(5..7)
            })
            .try_into()
            .unwrap(),
        ) & 0xfff
    }
    #[inline]
    pub fn root_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk().get_unchecked(7..13)
        })
    }
    #[inline]
    pub fn path_cost(&self) -> u32 {
        u32::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(13..17)
            })
            .try_into()
            .unwrap(),
        )
    }
    #[inline]
    pub fn bridge_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(17..19)
            })
            .try_into()
            .unwrap(),
        ) & 0xfff
    }
    #[inline]
    pub fn bridge_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk().get_unchecked(19..25)
        })
    }
    #[inline]
    pub fn port_id(&self) -> u16 {
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(25..27)
            })
            .try_into()
            .unwrap(),
        )
    }
    #[inline]
    pub fn version1_len(&self) -> u8 {
        (unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            *self.buf.chunk().get_unchecked(35)
        })
    }
    #[inline]
    pub fn mst_config_format_selector(&self) -> u8 {
        (unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            *self.buf.chunk().get_unchecked(38)
        })
    }
    #[inline]
    pub fn mst_config_name(&self) -> &[u8] {
        unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk().get_unchecked(39..71)
        }
    }
    #[inline]
    pub fn mst_config_revision(&self) -> u16 {
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(71..73)
            })
            .try_into()
            .unwrap(),
        )
    }
    #[inline]
    pub fn mst_config_digest(&self) -> &[u8] {
        unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk().get_unchecked(73..89)
        }
    }
    #[inline]
    pub fn irpc(&self) -> u32 {
        u32::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(89..93)
            })
            .try_into()
            .unwrap(),
        )
    }
    #[inline]
    pub fn cist_bridge_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(93..95)
            })
            .try_into()
            .unwrap(),
        ) & 0xfff
    }
    #[inline]
    pub fn cist_bridge_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk().get_unchecked(95..101)
        })
    }
    #[inline]
    pub fn remain_id(&self) -> u8 {
        (unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            *self.buf.chunk().get_unchecked(101)
        })
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(36..38)
            })
            .try_into()
            .unwrap(),
        )) as u32
            + 38
    }
}
impl<T: PktBuf> MstpConfBpdu<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> MstpConfBpdu<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 102]) -> Self {
        // SAFETY: header is an exact-size fixed header; only its length field is read.
        let header_len =
            unsafe { MstpConfBpdu::parse_unchecked(&header[..]) }.header_len() as usize;
        assert!((header_len >= 102) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..102]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[102..header_len]
    }
    #[inline]
    pub fn set_proto_id(&mut self, value: u16) {
        assert!(value == 0);
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(0..2)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_version(&mut self, value: StpVersion) {
        let value = u8::from(value);
        assert!(value == 3);
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(2)
        } = value;
    }
    #[inline]
    pub fn set_type_(&mut self, value: StpType) {
        let value = u8::from(value);
        assert!(value == 2);
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(3)
        } = value;
    }
    #[inline]
    pub fn set_flag(&mut self, value: u8) {
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(4)
        } = value;
    }
    #[inline]
    pub fn set_root_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value
            | ((((unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk_mut().get_unchecked(5)
            }) & 0xf0) as u16)
                << 8);
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(5..7)
        })
        .copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_root_mac_addr(&mut self, value: EtherAddr) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(7..13)
        })
        .copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_path_cost(&mut self, value: u32) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(13..17)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_bridge_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value
            | ((((unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk_mut().get_unchecked(17)
            }) & 0xf0) as u16)
                << 8);
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(17..19)
        })
        .copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_bridge_mac_addr(&mut self, value: EtherAddr) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(19..25)
        })
        .copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_port_id(&mut self, value: u16) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(25..27)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_version1_len(&mut self, value: u8) {
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(35)
        } = value;
    }
    #[inline]
    pub fn set_mst_config_format_selector(&mut self, value: u8) {
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(38)
        } = value;
    }
    #[inline]
    pub fn set_mst_config_name(&mut self, value: &[u8]) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(39..71)
        })
        .copy_from_slice(value);
    }
    #[inline]
    pub fn set_mst_config_revision(&mut self, value: u16) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(71..73)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_mst_config_digest(&mut self, value: &[u8]) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(73..89)
        })
        .copy_from_slice(value);
    }
    #[inline]
    pub fn set_irpc(&mut self, value: u32) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(89..93)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_cist_bridge_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value
            | ((((unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk_mut().get_unchecked(93)
            }) & 0xf0) as u16)
                << 8);
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(93..95)
        })
        .copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_cist_bridge_mac_addr(&mut self, value: EtherAddr) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(95..101)
        })
        .copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_remain_id(&mut self, value: u8) {
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(101)
        } = value;
    }
    /// Change a structural length without resizing the buffer.
    /// # Safety
    /// Before variable-header or payload access, the caller must ensure
    /// the declared header fits the chunk and the declared packet fits
    /// the remaining buffer, with header length at least the fixed size.
    /// Fixed-header templates may be initialized before attaching payload.
    #[inline]
    pub unsafe fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65573) && (value >= 38));
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(36..38)
        })
        .copy_from_slice(&((value - 38) as u16).to_be_bytes());
    }
}
impl<'a> MstpConfBpdu<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 102 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if (header_len < 102) || (header_len > remaining_len) {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_(header_len..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 102]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 102] {
        MSTP_CONF_BPDU_HEADER_TEMPLATE.clone()
    }
}
impl<'a> MstpConfBpdu<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 102 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if (header_len < 102) || (header_len > remaining_len) {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_mut_(header_len..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 102]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

impl<T: Buf + crate::StableBuf> MstpConfBpdu<T> {
    /// Get the **version3_len** field value.
    #[inline]
    pub fn version3_len(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[36..38]).try_into().unwrap())
    }

    /// Get the root id priority from the `MstpConfBpdu`.
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

    /// Get the bridge id priority from the `MstpConfBpdu`.
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

    /// Get the cist bridge id priority from the `MstpConfBpdu`.
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
    /// `MstpConfBpdu`.
    ///
    /// This method returns `None` if the `MstpConfBpdu` has an invalid
    /// format.
    #[inline]
    pub fn num_of_msti_msg(&self) -> Option<usize> {
        if (self.header_len() - 102) % 16 != 0 {
            None
        } else {
            Some(((self.header_len() - 102) / 16) as usize)
        }
    }

    /// Get the `index`-th `MstiConf` from the `MstpConfBpdu`.
    ///
    /// # Panics
    ///
    /// This method panics if `MstpConfBpdu` does not have the `index`-th
    /// `MstiConf`.
    #[inline]
    pub fn msti_conf(&self, index: usize) -> MstiConf<Cursor<'_>> {
        let offset = 16 * index;
        // SAFETY: the checked slice contains exactly one fixed MstiConf header.
        unsafe {
            MstiConf::parse_unchecked(Cursor::new(&self.buf.chunk()[102 + offset..118 + offset]))
        }
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
impl<T: PktBufMut> MstpConfBpdu<T> {
    /// Set the root priority for the `MstpConfBpdu`.
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

    /// Set the bridge priority for the `MstpConfBpdu`.
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

    /// Set the cist bridge id priority for the `MstpConfBpdu`.
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

    /// Set the number of the `MstiConf` contained in the
    /// `MstpConfBpdu`.
    #[inline]
    /// # Safety
    /// The caller must provision the declared messages before accessing them.
    pub unsafe fn set_num_of_msti_msg(&mut self, num: u32) {
        // SAFETY: forwarded structural-length obligation is the caller's.
        unsafe {
            self.set_header_len(102 + num * 16);
        }
    }

    /// Get the `index`-th mutable `MstiConf` from the
    /// `MstpConfBpdu`.
    ///
    /// # Panics
    ///
    /// This method panics if `MstpConfBpdu` does not have the `index`-th
    /// `MstiConf`.
    #[inline]
    pub fn msti_conf_message_mut(&mut self, index: usize) -> MstiConf<CursorMut<'_>> {
        let offset = 16 * index;
        // SAFETY: the checked slice contains exactly one fixed MstiConf header.
        unsafe {
            MstiConf::parse_unchecked(CursorMut::new(
                &mut self.buf.chunk_mut()[102 + offset..118 + offset],
            ))
        }
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
pub const MSTI_CONF_HEADER_LEN: usize = 16;
/// A fixed MstiConf header.
pub const MSTI_CONF_HEADER_TEMPLATE: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct MstiConf<T> {
    buf: T,
}
impl<T: Buf + crate::StableBuf> MstiConf<T> {
    /// Wrap a buffer without validating its protocol lengths.
    /// # Safety
    /// The current chunk must contain the complete fixed header. Before using
    /// variable-header or payload operations, the caller must also establish
    /// their declared length invariants. A fixed header template may be used
    /// for field access alone while its variable lengths are being initialized.
    #[inline]
    pub unsafe fn parse_unchecked(buf: T) -> Self {
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
        (unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            *self.buf.chunk().get_unchecked(0)
        })
    }
    #[inline]
    pub fn regional_root_sys_id_ext(&self) -> u16 {
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(1..3)
            })
            .try_into()
            .unwrap(),
        ) & 0xfff
    }
    #[inline]
    pub fn regional_root_mac_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk().get_unchecked(3..9)
        })
    }
    #[inline]
    pub fn path_cost(&self) -> u32 {
        u32::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(9..13)
            })
            .try_into()
            .unwrap(),
        )
    }
    #[inline]
    pub fn bridge_priority(&self) -> u8 {
        (unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            *self.buf.chunk().get_unchecked(13)
        })
    }
    #[inline]
    pub fn port_priority(&self) -> u8 {
        (unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            *self.buf.chunk().get_unchecked(14)
        })
    }
    #[inline]
    pub fn remaining_hops(&self) -> u8 {
        (unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            *self.buf.chunk().get_unchecked(15)
        })
    }
    /// Read adjacent fields as a packed network-order integer; the first field occupies the high bits.
    #[inline]
    pub fn bridge_priority_and_port_priority_bits(&self) -> u16 {
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(13..15)
            })
            .try_into()
            .unwrap(),
        )
    }
    /// Read adjacent fields as a packed network-order integer; the first field occupies the high bits.
    #[inline]
    pub fn port_priority_and_remaining_hops_bits(&self) -> u16 {
        u16::from_be_bytes(
            (unsafe {
                /* SAFETY: schema range is within this validated header borrow. */
                self.buf.chunk().get_unchecked(14..16)
            })
            .try_into()
            .unwrap(),
        )
    }
}
impl<T: PktBuf> MstiConf<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(16);
        buf
    }
}
impl<T: PktBufMut> MstiConf<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 16]) -> Self {
        assert!(buf.chunk_headroom() >= 16);
        buf.move_back(16);
        (&mut buf.chunk_mut()[0..16]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_flags(&mut self, value: u8) {
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(0)
        } = value;
    }
    #[inline]
    pub fn set_regional_root_sys_id_ext(&mut self, value: u16) {
        assert!(value <= 0xfff);
        let write_value = value
            | ((((unsafe {
                /* SAFETY: schema offset is within this validated header borrow. */
                *self.buf.chunk_mut().get_unchecked(1)
            }) & 0xf0) as u16)
                << 8);
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(1..3)
        })
        .copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_regional_root_mac_addr(&mut self, value: EtherAddr) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(3..9)
        })
        .copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_path_cost(&mut self, value: u32) {
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(9..13)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_bridge_priority(&mut self, value: u8) {
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(13)
        } = value;
    }
    #[inline]
    pub fn set_port_priority(&mut self, value: u8) {
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(14)
        } = value;
    }
    #[inline]
    pub fn set_remaining_hops(&mut self, value: u8) {
        *unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(15)
        } = value;
    }
    /// Set two adjacent fields with one network-order store.
    #[inline]
    pub fn set_bridge_priority_and_port_priority(
        &mut self,
        bridge_priority: u8,
        port_priority: u8,
    ) {
        let value = ((bridge_priority as u16) << 8) | (port_priority as u16);
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(13..15)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
    /// Set two adjacent fields with one network-order store.
    #[inline]
    pub fn set_port_priority_and_remaining_hops(&mut self, port_priority: u8, remaining_hops: u8) {
        let value = ((port_priority as u16) << 8) | (remaining_hops as u16);
        (unsafe {
            /* SAFETY: schema range is within this validated header borrow. */
            self.buf.chunk_mut().get_unchecked_mut(14..16)
        })
        .copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> MstiConf<Cursor<'a>> {
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
        self.buf.index_(16..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 16]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 16] {
        MSTI_CONF_HEADER_TEMPLATE.clone()
    }
}
impl<'a> MstiConf<CursorMut<'a>> {
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
        self.buf.index_mut_(16..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 16]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

impl<T: Buf + crate::StableBuf> MstiConf<T> {
    /// Get the regional root id priority from the `MstiConf`.
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

impl<T: PktBufMut> MstiConf<T> {
    /// Set the regional root id priority for the `MstiConf`.
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
pub enum StpGroup<T> {
    StpTcnBpdu_(StpTcnBpdu<T>),
    StpConfBpdu_(StpConfBpdu<T>),
    RstpConfBpdu_(RstpConfBpdu<T>),
    MstpConfBpdu_(MstpConfBpdu<T>),
}
impl<T: Buf + crate::StableBuf> StpGroup<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        let cond_bytes = &buf.chunk()[..];
        if cond_bytes.len() < 4 {
            return Err(buf);
        }
        let cond_value0 = (unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            *cond_bytes.get_unchecked(2)
        });
        let cond_value1 = (unsafe {
            /* SAFETY: schema offset is within this validated header borrow. */
            *cond_bytes.get_unchecked(3)
        });
        match (cond_value0, cond_value1) {
            (0, 128) => StpTcnBpdu::parse(buf).map(|pkt| StpGroup::StpTcnBpdu_(pkt)),
            (0, 0) => StpConfBpdu::parse(buf).map(|pkt| StpGroup::StpConfBpdu_(pkt)),
            (2, 2) => RstpConfBpdu::parse(buf).map(|pkt| StpGroup::RstpConfBpdu_(pkt)),
            (3, 2) => MstpConfBpdu::parse(buf).map(|pkt| StpGroup::MstpConfBpdu_(pkt)),
            _ => Err(buf),
        }
    }
}
