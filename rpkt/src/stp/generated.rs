#![allow(missing_docs)]
#![allow(unused_parens)]

use byteorder::{ByteOrder, NetworkEndian};

use crate::ether::{EtherAddr, EtherType};
use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

/// A fixed StpTcnBpdu header array.
pub const STPTCNBPDU_HEADER_ARRAY: [u8; 4] = [0x00, 0x00, 0x00, 0x80];
#[derive(Debug, Clone, Copy)]
pub struct StpTcnBpduMessage<T> {
    buf: T,
}
impl<T: AsRef<[u8]>> StpTcnBpduMessage<T> {
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
        let remaining_len = buf.as_ref().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.buf.as_ref()[4..]
    }
    #[inline]
    pub fn proto_id(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[0..2])
    }
    #[inline]
    pub fn version(&self) -> u8 {
        self.buf.as_ref()[2]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.as_ref()[3]
    }
}
impl<T: AsRef<[u8]> + AsMut<[u8]>> StpTcnBpduMessage<T> {
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[4..]
    }
    #[inline]
    pub fn build_message(mut buf: T) -> Self {
        assert!(buf.as_mut().len() >= 4);
        (&mut buf.as_mut()[..4]).copy_from_slice(&STPTCNBPDU_HEADER_ARRAY[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_proto_id(&mut self, value: u16) {
        assert!(value == 0);
        NetworkEndian::write_u16(&mut self.buf.as_mut()[0..2], value);
    }
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.as_mut()[2] = value;
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 128);
        self.buf.as_mut()[3] = value;
    }
}

/// A fixed StpConfBpdu header array.
pub const STPCONFBPDU_HEADER_ARRAY: [u8; 35] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00,
];
#[derive(Debug, Clone, Copy)]
pub struct StpConfBpduMessage<T> {
    buf: T,
}
impl<T: AsRef<[u8]>> StpConfBpduMessage<T> {
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
        let remaining_len = buf.as_ref().len();
        if remaining_len < 35 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.buf.as_ref()[35..]
    }
    #[inline]
    pub fn proto_id(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[0..2])
    }
    #[inline]
    pub fn version(&self) -> u8 {
        self.buf.as_ref()[2]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.as_ref()[3]
    }
    #[inline]
    pub fn flag(&self) -> u8 {
        self.buf.as_ref()[4]
    }
    #[inline]
    pub fn root_id(&self) -> u64 {
        NetworkEndian::read_u64(&self.buf.as_ref()[5..13])
    }
    #[inline]
    pub fn path_cost(&self) -> u32 {
        NetworkEndian::read_u32(&self.buf.as_ref()[13..17])
    }
    #[inline]
    pub fn bridge_id(&self) -> u64 {
        NetworkEndian::read_u64(&self.buf.as_ref()[17..25])
    }
    #[inline]
    pub fn port_id(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[25..27])
    }
    #[inline]
    pub fn msg_age(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[27..29])
    }
    #[inline]
    pub fn max_age(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[29..31])
    }
    #[inline]
    pub fn hello_time(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[31..33])
    }
    #[inline]
    pub fn forward_delay(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[33..35])
    }
}
impl<T: AsRef<[u8]> + AsMut<[u8]>> StpConfBpduMessage<T> {
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[35..]
    }
    #[inline]
    pub fn build_message(mut buf: T) -> Self {
        assert!(buf.as_mut().len() >= 35);
        (&mut buf.as_mut()[..35]).copy_from_slice(&STPCONFBPDU_HEADER_ARRAY[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_proto_id(&mut self, value: u16) {
        assert!(value == 0);
        NetworkEndian::write_u16(&mut self.buf.as_mut()[0..2], value);
    }
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.as_mut()[2] = value;
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.as_mut()[3] = value;
    }
    #[inline]
    pub fn set_flag(&mut self, value: u8) {
        self.buf.as_mut()[4] = value;
    }
    #[inline]
    pub fn set_root_id(&mut self, value: u64) {
        NetworkEndian::write_u64(&mut self.buf.as_mut()[5..13], value);
    }
    #[inline]
    pub fn set_path_cost(&mut self, value: u32) {
        NetworkEndian::write_u32(&mut self.buf.as_mut()[13..17], value);
    }
    #[inline]
    pub fn set_bridge_id(&mut self, value: u64) {
        NetworkEndian::write_u64(&mut self.buf.as_mut()[17..25], value);
    }
    #[inline]
    pub fn set_port_id(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[25..27], value);
    }
    #[inline]
    pub fn set_msg_age(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[27..29], value);
    }
    #[inline]
    pub fn set_max_age(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[29..31], value);
    }
    #[inline]
    pub fn set_hello_time(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[31..33], value);
    }
    #[inline]
    pub fn set_forward_delay(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[33..35], value);
    }
}

/// A fixed RstpConfBpdu header array.
pub const RSTPCONFBPDU_HEADER_ARRAY: [u8; 36] = [
    0x00, 0x00, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];
#[derive(Debug, Clone, Copy)]
pub struct RstpConfBpduMessage<T> {
    buf: T,
}
impl<T: AsRef<[u8]>> RstpConfBpduMessage<T> {
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
        let remaining_len = buf.as_ref().len();
        if remaining_len < 36 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.buf.as_ref()[36..]
    }
    #[inline]
    pub fn proto_id(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[0..2])
    }
    #[inline]
    pub fn version(&self) -> u8 {
        self.buf.as_ref()[2]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.as_ref()[3]
    }
    #[inline]
    pub fn version1_len(&self) -> u8 {
        self.buf.as_ref()[35]
    }
}
impl<T: AsRef<[u8]> + AsMut<[u8]>> RstpConfBpduMessage<T> {
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[36..]
    }
    #[inline]
    pub fn build_message(mut buf: T) -> Self {
        assert!(buf.as_mut().len() >= 36);
        (&mut buf.as_mut()[..36]).copy_from_slice(&RSTPCONFBPDU_HEADER_ARRAY[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_proto_id(&mut self, value: u16) {
        assert!(value == 0);
        NetworkEndian::write_u16(&mut self.buf.as_mut()[0..2], value);
    }
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        assert!(value == 2);
        self.buf.as_mut()[2] = value;
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 2);
        self.buf.as_mut()[3] = value;
    }
    #[inline]
    pub fn set_version1_len(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.as_mut()[35] = value;
    }
}

impl<T: AsRef<[u8]>> RstpConfBpduMessage<T> {
    /// Get the `StpConfBpduMessage` part of the `RstpConfBpduMessage`.
    ///
    /// Stp protocol is a layered protocol. The `RstpConfBpduMessage` contains
    /// the `StpConfBpduMessage`, which is the first 35 bytes. This method
    /// retrieves the `StpConfBpduMessage` part.
    ///
    /// # Panics
    ///
    /// This method panics if `self.buf.len() < 35`.
    #[inline]
    pub fn stp_conf_bpdu_part(&self) -> StpConfBpduMessage<&[u8]> {
        StpConfBpduMessage::parse_unchecked(&self.buf.as_ref()[..35])
    }
}
impl<T: AsMut<[u8]>> RstpConfBpduMessage<T> {
    /// Get the mutable `StpConfBpduMessage` part of the `RstpConfBpduMessage`.
    ///
    /// Stp protocol is a layered protocol. The `RstpConfBpduMessage` contains
    /// the `StpConfBpduMessage`, which is the first 35 bytes. This method
    /// retrieves the mutable `StpConfBpduMessage` part.
    ///
    /// # Panics
    ///
    /// This method panics if `self.buf.len() < 35`.
    #[inline]
    pub fn stp_conf_bpdu_part_mut(&mut self) -> StpConfBpduMessage<&mut [u8]> {
        StpConfBpduMessage::parse_unchecked(&mut self.buf.as_mut()[..35])
    }
}

/// A fixed MstpConfBpdu header array.
pub const MSTPCONFBPDU_HEADER_ARRAY: [u8; 102] = [
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
impl<T: AsRef<[u8]>> MstpConfBpduMessage<T> {
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
        let remaining_len = buf.as_ref().len();
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
    pub fn payload(&self) -> &[u8] {
        let header_len = self.header_len() as usize;
        &self.buf.as_ref()[header_len..]
    }
    #[inline]
    pub fn option_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.as_ref()[102..header_len]
    }
    #[inline]
    pub fn proto_id(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[0..2])
    }
    #[inline]
    pub fn version(&self) -> u8 {
        self.buf.as_ref()[2]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.as_ref()[3]
    }
    #[inline]
    pub fn mst_config_format_selector(&self) -> u8 {
        self.buf.as_ref()[38]
    }
    #[inline]
    pub fn mst_config_name(&self) -> &[u8] {
        &self.buf.as_ref()[39..71]
    }
    #[inline]
    pub fn mst_config_revision(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[71..73])
    }
    #[inline]
    pub fn mst_config_digest(&self) -> &[u8] {
        &self.buf.as_ref()[73..89]
    }
    #[inline]
    pub fn irpc(&self) -> u32 {
        NetworkEndian::read_u32(&self.buf.as_ref()[89..93])
    }
    #[inline]
    pub fn cist_bridge_id(&self) -> u64 {
        NetworkEndian::read_u64(&self.buf.as_ref()[93..101])
    }
    #[inline]
    pub fn remain_id(&self) -> u8 {
        self.buf.as_ref()[101]
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (NetworkEndian::read_u16(&self.buf.as_ref()[36..38])) as u32 + 38
    }
}
impl<T: AsRef<[u8]> + AsMut<[u8]>> MstpConfBpduMessage<T> {
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let header_len = self.header_len() as usize;
        &mut self.buf.as_mut()[header_len..]
    }
    #[inline]
    pub fn build_message(mut buf: T) -> Self {
        assert!(buf.as_mut().len() >= 102);
        (&mut buf.as_mut()[..102]).copy_from_slice(&MSTPCONFBPDU_HEADER_ARRAY[..]);
        Self { buf }
    }
    #[inline]
    pub fn option_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.as_mut()[102..header_len]
    }
    #[inline]
    pub fn set_proto_id(&mut self, value: u16) {
        assert!(value == 0);
        NetworkEndian::write_u16(&mut self.buf.as_mut()[0..2], value);
    }
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        assert!(value == 3);
        self.buf.as_mut()[2] = value;
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 2);
        self.buf.as_mut()[3] = value;
    }
    #[inline]
    pub fn set_mst_config_format_selector(&mut self, value: u8) {
        self.buf.as_mut()[38] = value;
    }
    #[inline]
    pub fn set_mst_config_name(&mut self, value: &[u8]) {
        (&mut self.buf.as_mut()[39..71]).copy_from_slice(value);
    }
    #[inline]
    pub fn set_mst_config_revision(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[71..73], value);
    }
    #[inline]
    pub fn set_mst_config_digest(&mut self, value: &[u8]) {
        (&mut self.buf.as_mut()[73..89]).copy_from_slice(value);
    }
    #[inline]
    pub fn set_irpc(&mut self, value: u32) {
        NetworkEndian::write_u32(&mut self.buf.as_mut()[89..93], value);
    }
    #[inline]
    pub fn set_cist_bridge_id(&mut self, value: u64) {
        NetworkEndian::write_u64(&mut self.buf.as_mut()[93..101], value);
    }
    #[inline]
    pub fn set_remain_id(&mut self, value: u8) {
        self.buf.as_mut()[101] = value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65573) && (value >= 38));
        NetworkEndian::write_u16(&mut self.buf.as_mut()[36..38], ((value - 38) as u16));
    }
}

impl<T: AsRef<[u8]>> MstpConfBpduMessage<T> {
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

    /// Get the `RstpConfBpduMessage` part of the `MstpConfBpduMessage`.
    ///
    /// Stp protocol is a layered protocol. `MstpConfBpduMessage` contains the
    /// `RstpConfBpduMessage`, which is the first 36 bytes. This method
    /// retrieves the `RstpConfBpduMessage` part.
    ///
    /// # Panics
    ///
    /// This method panics if `self.buf.len() < 36`.
    #[inline]
    pub fn rstp_conf_bpdu_part(&self) -> RstpConfBpduMessage<&[u8]> {
        RstpConfBpduMessage::parse_unchecked(&self.buf.as_ref()[..36])
    }

    /// Get the `index`-th `MstiConfMessage` from the `MstpConfBpduMessage`.
    ///
    /// # Panics
    ///
    /// This method panics if `MstpConfBpduMessage` does not have the `index`-th
    /// `MstiConfMessage`.
    #[inline]
    pub fn msti_conf_message(&self, index: usize) -> MstiConfMessage<&[u8]> {
        let offset = 16 * index;
        MstiConfMessage::parse_unchecked(&self.buf.as_ref()[102 + offset..118 + offset])
    }
}
impl<T: AsRef<[u8]> + AsMut<[u8]>> MstpConfBpduMessage<T> {
    /// Set the number of the `MstiConfMessage` contained in the
    /// `MstpConfBpduMessage`.
    #[inline]
    pub fn set_num_of_msti_msg(&mut self, num: u32) {
        self.set_header_len(102 + num * 16);
    }

    /// Get the mutable `RstpConfBpduMessage` part of the `MstpConfBpduMessage`.
    ///
    /// Stp protocol is a layered protocol. `MstpConfBpduMessage` contains the
    /// `RstpConfBpduMessage`, which is the first 36 bytes. This method
    /// retrieves the mutable `RstpConfBpduMessage`  part.
    ///
    /// # Panics
    ///
    /// This method panics if `self.buf.len() < 36`.
    #[inline]
    pub fn rstp_conf_bpdu_part_mut(&mut self) -> RstpConfBpduMessage<&mut [u8]> {
        RstpConfBpduMessage::parse_unchecked(&mut self.buf.as_mut()[..36])
    }

    /// Get the `index`-th mutable `MstiConfMessage` from the
    /// `MstpConfBpduMessage`.
    ///
    /// # Panics
    ///
    /// This method panics if `MstpConfBpduMessage` does not have the `index`-th
    /// `MstiConfMessage`.
    #[inline]
    pub fn msti_conf_message_mut(&mut self, index: usize) -> MstiConfMessage<&mut [u8]> {
        let offset = 16 * index;
        MstiConfMessage::parse_unchecked(&mut self.buf.as_mut()[102 + offset..118 + offset])
    }
}

/// A fixed MstiConf header array.
pub const MSTICONF_HEADER_ARRAY: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
#[derive(Debug, Clone, Copy)]
pub struct MstiConfMessage<T> {
    buf: T,
}
impl<T: AsRef<[u8]>> MstiConfMessage<T> {
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
        let remaining_len = buf.as_ref().len();
        if remaining_len < 16 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.buf.as_ref()[16..]
    }
    #[inline]
    pub fn flags(&self) -> u8 {
        self.buf.as_ref()[0]
    }
    #[inline]
    pub fn regional_root_id(&self) -> u64 {
        NetworkEndian::read_u64(&self.buf.as_ref()[1..9])
    }
    #[inline]
    pub fn path_cost(&self) -> u32 {
        NetworkEndian::read_u32(&self.buf.as_ref()[9..13])
    }
    #[inline]
    pub fn bridge_priority(&self) -> u8 {
        self.buf.as_ref()[13]
    }
    #[inline]
    pub fn port_priority(&self) -> u8 {
        self.buf.as_ref()[14]
    }
    #[inline]
    pub fn remaining_hops(&self) -> u8 {
        self.buf.as_ref()[15]
    }
}
impl<T: AsRef<[u8]> + AsMut<[u8]>> MstiConfMessage<T> {
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[16..]
    }
    #[inline]
    pub fn build_message(mut buf: T) -> Self {
        assert!(buf.as_mut().len() >= 16);
        (&mut buf.as_mut()[..16]).copy_from_slice(&MSTICONF_HEADER_ARRAY[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_flags(&mut self, value: u8) {
        self.buf.as_mut()[0] = value;
    }
    #[inline]
    pub fn set_regional_root_id(&mut self, value: u64) {
        NetworkEndian::write_u64(&mut self.buf.as_mut()[1..9], value);
    }
    #[inline]
    pub fn set_path_cost(&mut self, value: u32) {
        NetworkEndian::write_u32(&mut self.buf.as_mut()[9..13], value);
    }
    #[inline]
    pub fn set_bridge_priority(&mut self, value: u8) {
        self.buf.as_mut()[13] = value;
    }
    #[inline]
    pub fn set_port_priority(&mut self, value: u8) {
        self.buf.as_mut()[14] = value;
    }
    #[inline]
    pub fn set_remaining_hops(&mut self, value: u8) {
        self.buf.as_mut()[15] = value;
    }
}
