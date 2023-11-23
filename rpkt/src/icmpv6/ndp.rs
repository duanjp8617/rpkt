use crate::PktMut;
use byteorder::{ByteOrder, NetworkEndian};
use bytes::Buf;

use super::Icmpv6MsgType;

pub struct NdpMsgRouterSolicit<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> NdpMsgRouterSolicit<T> {
    #[inline]
    pub fn check_reserved(&self) -> bool {
        &self.buf.as_ref()[4..8] == &[0, 0, 0, 0][..]
    }

    #[inline]
    pub fn option_bytes(&self) -> &[u8] {
        &self.buf.as_ref()[8..]
    }
}

impl<T: AsMut<[u8]>> NdpMsgRouterSolicit<T> {
    #[inline]
    pub fn adjust_reserved(&mut self) {
        (&mut self.buf.as_mut()[4..8]).fill(0);
    }

    #[inline]
    pub fn option_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[8..]
    }
}

pub struct NdpMsgRouterAdv<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> NdpMsgRouterAdv<T> {
    #[inline]
    pub fn cur_hop_limit(&self) -> u8 {
        self.buf.as_ref()[4]
    }

    #[inline]
    pub fn m_flag(&self) -> bool {
        self.buf.as_ref()[5] >> 7 == 1
    }

    #[inline]
    pub fn o_flag(&self) -> bool {
        (self.buf.as_ref()[5] >> 6) & 1 == 1
    }

    #[inline]
    pub fn check_reserved(&self) -> bool {
        self.buf.as_ref()[5] & 0x3f == 0
    }

    #[inline]
    pub fn router_lifetime(&self) -> u16 {
        let data = &self.buf.as_ref()[6..8];
        NetworkEndian::read_u16(data)
    }

    #[inline]
    pub fn reachable_time(&self) -> u32 {
        let data = &self.buf.as_ref()[8..12];
        NetworkEndian::read_u32(data)
    }

    #[inline]
    pub fn retrans_timer(&self) -> u32 {
        let data = &self.buf.as_ref()[12..16];
        NetworkEndian::read_u32(data)
    }

    #[inline]
    pub fn option_bytes(&self) -> &[u8] {
        &self.buf.as_ref()[16..]
    }
}

impl<T: AsMut<[u8]>> NdpMsgRouterAdv<T> {
    #[inline]
    pub fn set_cur_hop_limit(&mut self, value: u8) {
        self.buf.as_mut()[4] = value;
    }

    #[inline]
    pub fn set_m_flag(&mut self, value: bool) {
        if value {
            self.buf.as_mut()[5] = self.buf.as_mut()[5] | (1 << 7);
        } else {
            self.buf.as_mut()[5] = self.buf.as_mut()[5] & 0x7f;
        }
    }

    #[inline]
    pub fn set_o_flag(&mut self, value: bool) {
        if value {
            self.buf.as_mut()[5] = self.buf.as_mut()[5] | (1 << 6);
        } else {
            self.buf.as_mut()[5] = self.buf.as_mut()[5] & 0xbf;
        }
    }

    #[inline]
    pub fn adjust_reserved(&mut self) {
        self.buf.as_mut()[5] = self.buf.as_mut()[5] & 0xc0;
    }

    #[inline]
    pub fn set_router_lifetime(&mut self, value: u16) {
        let data = &mut self.buf.as_mut()[6..8];
        NetworkEndian::write_u16(data, value)
    }

    #[inline]
    pub fn set_reachable_time(&mut self, value: u32) {
        let data = &mut self.buf.as_mut()[8..12];
        NetworkEndian::write_u32(data, value);
    }

    #[inline]
    pub fn set_retrans_timer(&mut self, value: u32) {
        let data = &mut self.buf.as_mut()[12..16];
        NetworkEndian::write_u32(data, value);
    }

    #[inline]
    pub fn option_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[16..]
    }
}

pub struct NdpMsgNeighborSolicit<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> NdpMsgNeighborSolicit<T> {
    #[inline]
    pub fn check_reserved(&self) -> bool {
        &self.buf.as_ref()[4..8] == &[0, 0, 0, 0][..]
    }

    #[inline]
    pub fn target_addr(&self) -> &[u8] {
        &self.buf.as_ref()[8..24]
    }

    #[inline]
    pub fn option_bytes(&self) -> &[u8] {
        &self.buf.as_ref()[24..]
    }
}

impl<T: AsMut<[u8]>> NdpMsgNeighborSolicit<T> {
    #[inline]
    pub fn adjust_reserved(&mut self) {
        (&mut self.buf.as_mut()[4..8]).fill(0);
    }

    #[inline]
    pub fn set_target_addr(&mut self, addr: &[u8]) {
        (&mut self.buf.as_mut()[8..24]).copy_from_slice(addr);
    }

    #[inline]
    pub fn option_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[24..]
    }
}

pub struct NdpMsgNeighborAdv<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> NdpMsgNeighborAdv<T> {
    #[inline]
    pub fn r_flag(&self) -> bool {
        self.buf.as_ref()[4] >> 7 == 1
    }

    #[inline]
    pub fn s_flag(&self) -> bool {
        (self.buf.as_ref()[4] >> 6) & 1 == 1
    }

    #[inline]
    pub fn o_flag(&self) -> bool {
        (self.buf.as_ref()[4] >> 5) & 1 == 1
    }

    #[inline]
    pub fn check_reserved(&self) -> bool {
        let data = &self.buf.as_ref()[4..8];
        NetworkEndian::read_u32(data) & 0x1fffffff == 0
    }

    #[inline]
    pub fn target_addr(&self) -> &[u8] {
        &self.buf.as_ref()[8..24]
    }

    #[inline]
    pub fn option_bytes(&self) -> &[u8] {
        &self.buf.as_ref()[24..]
    }
}

impl<T: AsMut<[u8]>> NdpMsgNeighborAdv<T> {
    #[inline]
    pub fn set_r_flag(&mut self, value: bool) {
        if value {
            self.buf.as_mut()[4] = self.buf.as_mut()[4] | (1 << 7);
        } else {
            self.buf.as_mut()[4] = self.buf.as_mut()[4] & 0x7f;
        }
    }

    #[inline]
    pub fn set_s_flag(&mut self, value: bool) {
        if value {
            self.buf.as_mut()[4] = self.buf.as_mut()[4] | (1 << 6);
        } else {
            self.buf.as_mut()[4] = self.buf.as_mut()[4] & 0xbf;
        }
    }

    #[inline]
    pub fn set_o_flag(&mut self, value: bool) {
        if value {
            self.buf.as_mut()[4] = self.buf.as_mut()[4] | (1 << 5);
        } else {
            self.buf.as_mut()[4] = self.buf.as_mut()[4] & 0xdf;
        }
    }

    #[inline]
    pub fn adjust_reserved(&mut self) {
        let data = &mut self.buf.as_mut()[4..8];
        let raw = NetworkEndian::read_u32(data);
        NetworkEndian::write_u32(data, raw & 0xE0000000);
    }

    #[inline]
    pub fn set_target_addr(&mut self, addr: &[u8]) {
        (&mut self.buf.as_mut()[8..24]).copy_from_slice(addr);
    }

    #[inline]
    pub fn option_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[24..]
    }
}

pub struct NdpMsgRedirect<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> NdpMsgRedirect<T> {
    #[inline]
    pub fn check_reserved(&self) -> bool {
        &self.buf.as_ref()[4..8] == &[0, 0, 0, 0][..]
    }

    #[inline]
    pub fn target_addr(&self) -> &[u8] {
        &self.buf.as_ref()[8..24]
    }

    #[inline]
    pub fn dest_addr(&self) -> &[u8] {
        &self.buf.as_ref()[24..40]
    }

    #[inline]
    pub fn option_bytes(&self) -> &[u8] {
        &self.buf.as_ref()[40..]
    }
}

impl<T: AsMut<[u8]>> NdpMsgRedirect<T> {
    #[inline]
    pub fn adjust_reserved(&mut self) {
        (&mut self.buf.as_mut()[4..8]).fill(0);
    }

    #[inline]
    pub fn set_target_addr(&mut self, addr: &[u8]) {
        (&mut self.buf.as_mut()[8..24]).copy_from_slice(addr);
    }

    #[inline]
    pub fn set_dest_addr(&mut self, addr: &[u8]) {
        (&mut self.buf.as_mut()[24..40]).copy_from_slice(addr);
    }

    #[inline]
    pub fn option_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[40..]
    }
}

pub enum NdpOption<'a> {
    SrcLinkAddr(NdpOptionLinkAddr<&'a [u8]>),
    DstLinkAddr(NdpOptionLinkAddr<&'a [u8]>),
    PrefixInfo(NdpOptionPrefixInfo<&'a [u8]>),
    RedirectedHdr(NdpOptionRedirectedHdr<&'a [u8]>),
    Mtu(NdpOptionMtu<&'a [u8]>),
}

pub struct NdpOptionLinkAddr<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> NdpOptionLinkAddr<T> {
    #[inline]
    pub fn link_addr(&self) -> &[u8] {
        let opt_len = usize::from(self.buf.as_ref()[1]) * 8;
        &self.buf.as_ref()[2..opt_len]
    }
}

impl<T: AsMut<[u8]>> NdpOptionLinkAddr<T> {
    #[inline]
    pub fn set_link_addr(&mut self, link_addr: &[u8]) {
        let opt_len = usize::from(self.buf.as_mut()[1]) * 8;
        (&mut self.buf.as_mut()[2..opt_len]).copy_from_slice(link_addr);
    }
}

pub struct NdpOptionPrefixInfo<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> NdpOptionPrefixInfo<T> {
    #[inline]
    pub fn prefix_len(&self) -> u8 {
        self.buf.as_ref()[2]
    }

    #[inline]
    pub fn l_flag(&self) -> bool {
        self.buf.as_ref()[3] >> 7 == 1
    }

    #[inline]
    pub fn a_flag(&self) -> bool {
        (self.buf.as_ref()[3] >> 6) & 1 == 1
    }

    #[inline]
    pub fn check_reserved1(&self) -> bool {
        self.buf.as_ref()[3] & 0x3f == 0
    }

    #[inline]
    pub fn valid_lifetime(&self) -> u32 {
        let data = &self.buf.as_ref()[4..8];
        NetworkEndian::read_u32(data)
    }

    #[inline]
    pub fn preferred_lifetime(&self) -> u32 {
        let data = &self.buf.as_ref()[8..12];
        NetworkEndian::read_u32(data)
    }

    #[inline]
    pub fn check_reserved2(&self) -> bool {
        &self.buf.as_ref()[12..16] == &[0, 0, 0, 0][..]
    }

    #[inline]
    pub fn prefix(&self) -> &[u8] {
        &self.buf.as_ref()[16..32]
    }
}

impl<T: AsMut<[u8]>> NdpOptionPrefixInfo<T> {
    #[inline]
    pub fn set_prefix_len(&mut self, value: u8) {
        assert!(value <= 128);
        self.buf.as_mut()[2] = value;
    }

    #[inline]
    pub fn set_l_flag(&mut self, value: bool) {
        if value {
            self.buf.as_mut()[3] = self.buf.as_mut()[3] | (1 << 7);
        } else {
            self.buf.as_mut()[3] = self.buf.as_mut()[3] & 0x7f;
        }
    }

    #[inline]
    pub fn set_a_flag(&mut self, value: bool) {
        if value {
            self.buf.as_mut()[3] = self.buf.as_mut()[3] | (1 << 6);
        } else {
            self.buf.as_mut()[3] = self.buf.as_mut()[3] & 0xbf;
        }
    }

    #[inline]
    pub fn adjust_reserved1(&mut self) {
        self.buf.as_mut()[3] = self.buf.as_mut()[3] & 0xc0;
    }

    #[inline]
    pub fn set_valid_lifetime(&mut self, value: u32) {
        let data = &mut self.buf.as_mut()[4..8];
        NetworkEndian::write_u32(data, value);
    }

    #[inline]
    pub fn set_preferred_lifetime(&mut self, value: u32) {
        let data = &mut self.buf.as_mut()[8..12];
        NetworkEndian::write_u32(data, value);
    }

    #[inline]
    pub fn adjust_reserved2(&mut self) {
        (&mut self.buf.as_mut()[12..16]).fill(0);
    }

    #[inline]
    pub fn set_prefix(&mut self, addr: &[u8]) {
        (&mut self.buf.as_mut()[16..32]).copy_from_slice(addr);
    }
}

pub struct NdpOptionRedirectedHdr<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> NdpOptionRedirectedHdr<T> {
    #[inline]
    pub fn check_reserved(&self) -> bool {
        &self.buf.as_ref()[2..8] == &[0, 0, 0, 0, 0, 0][..]
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        let opt_len = usize::from(self.buf.as_ref()[1]) * 8;
        &self.buf.as_ref()[8..opt_len]
    }
}

impl<T: AsMut<[u8]>> NdpOptionRedirectedHdr<T> {
    #[inline]
    pub fn adjust_reserved(&mut self) {
        (&mut self.buf.as_mut()[2..8]).fill(0);
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let opt_len = usize::from(self.buf.as_mut()[1]) * 8;
        &mut self.buf.as_mut()[8..opt_len]
    }
}

pub struct NdpOptionMtu<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> NdpOptionMtu<T> {
    #[inline]
    pub fn check_reserved(&self) -> bool {
        &self.buf.as_ref()[2..4] == &[0, 0][..]
    }

    #[inline]
    pub fn mtu(&self) -> u32 {
        let data = &self.buf.as_ref()[4..8];
        NetworkEndian::read_u32(data)
    }
}

impl<T: AsMut<[u8]>> NdpOptionMtu<T> {
    #[inline]
    pub fn adjust_reserved(&mut self) {
        (&mut self.buf.as_mut()[2..4]).fill(0);
    }

    #[inline]
    pub fn set_mtu(&mut self, value: u32) {
        let data = &mut self.buf.as_mut()[4..8];
        NetworkEndian::write_u32(data, value);
    }
}
