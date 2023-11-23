use byteorder::{ByteOrder, NetworkEndian};

const SRC_LINK_ADDR: u8 = 1;
const DST_LINK_ADDR: u8 = 2;
const PREFIX_INFO: u8 = 3;
const REDIRECTED_HDR: u8 = 4;
const MTU: u8 = 5;

pub enum NdpOption<'a> {
    SrcLinkAddr(NdpOptionLinkAddr<&'a [u8]>),
    DstLinkAddr(NdpOptionLinkAddr<&'a [u8]>),
    PrefixInfo(NdpOptionPrefixInfo<&'a [u8]>),
    RedirectedHdr(NdpOptionRedirectedHdr<&'a [u8]>),
    Mtu(NdpOptionMtu<&'a [u8]>),
}

pub enum NdpOptionMut<'a> {
    SrcLinkAddr(NdpOptionLinkAddr<&'a mut [u8]>),
    DstLinkAddr(NdpOptionLinkAddr<&'a mut [u8]>),
    PrefixInfo(NdpOptionPrefixInfo<&'a mut [u8]>),
    RedirectedHdr(NdpOptionRedirectedHdr<&'a mut [u8]>),
    Mtu(NdpOptionMtu<&'a mut [u8]>),
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

pub struct NdpOptionIter<'a> {
    buf: &'a [u8],
    valid: bool,
}

impl<'a> NdpOptionIter<'a> {
    #[inline]
    pub fn from_option_bytes(buf: &'a [u8]) -> NdpOptionIter<'a> {
        Self { buf, valid: true }
    }

    #[inline]
    pub fn check_option_bytes(buf: &'a [u8]) -> bool {
        let mut reader = Self::from_option_bytes(buf);
        while let Some(_) = (&mut reader).next() {}
        reader.valid
    }
}

impl<'a> Iterator for NdpOptionIter<'a> {
    type Item = NdpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.valid || self.buf.len() == 0 {
            return None;
        }

        if self.buf.len() < 2 {
            self.valid = false;
            return None;
        }

        let opt_type = self.buf[0];
        match opt_type {
            SRC_LINK_ADDR => {
                let opt_len = usize::from(self.buf[1]) * 8;
                if self.buf.len() < opt_len {
                    self.valid = false;
                    None
                } else {
                    let opt = NdpOptionLinkAddr {
                        buf: &self.buf[..opt_len],
                    };
                    self.buf = &self.buf[opt_len..];
                    Some(NdpOption::SrcLinkAddr(opt))
                }
            }
            DST_LINK_ADDR => {
                let opt_len = usize::from(self.buf[1]) * 8;
                if self.buf.len() < opt_len {
                    self.valid = false;
                    None
                } else {
                    let opt = NdpOptionLinkAddr {
                        buf: &self.buf[..opt_len],
                    };
                    self.buf = &self.buf[opt_len..];
                    Some(NdpOption::DstLinkAddr(opt))
                }
            }
            PREFIX_INFO => {
                let opt_len = usize::from(self.buf[1]) * 8;
                if self.buf.len() < opt_len || opt_len != 32 {
                    self.valid = false;
                    None
                } else {
                    let opt = NdpOptionPrefixInfo {
                        buf: &self.buf[..opt_len],
                    };
                    self.buf = &self.buf[opt_len..];
                    Some(NdpOption::PrefixInfo(opt))
                }
            }
            REDIRECTED_HDR => {
                let opt_len = usize::from(self.buf[1]) * 8;
                if self.buf.len() < opt_len {
                    self.valid = false;
                    None
                } else {
                    let opt = NdpOptionRedirectedHdr {
                        buf: &self.buf[..opt_len],
                    };
                    self.buf = &self.buf[opt_len..];
                    Some(NdpOption::RedirectedHdr(opt))
                }
            }
            MTU => {
                let opt_len = usize::from(self.buf[1]) * 8;
                if self.buf.len() < opt_len || opt_len != 8 {
                    self.valid = false;
                    None
                } else {
                    let opt = NdpOptionMtu {
                        buf: &self.buf[..opt_len],
                    };
                    self.buf = &self.buf[opt_len..];
                    Some(NdpOption::Mtu(opt))
                }
            }
            _ => {
                self.valid = false;
                None
            }
        }
    }
}

pub struct NdpOptionIterMut<'a> {
    buf: &'a mut [u8],
    valid: bool,
}

impl<'a> NdpOptionIterMut<'a> {
    #[inline]
    pub fn from_option_bytes_mut(buf: &'a mut [u8]) -> NdpOptionIterMut<'a> {
        Self { buf, valid: true }
    }
}

impl<'a> Iterator for NdpOptionIterMut<'a> {
    type Item = NdpOptionMut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.valid || self.buf.len() == 0 {
            return None;
        }

        if self.buf.len() < 2 {
            self.valid = false;
            return None;
        }

        let opt_type = self.buf[0];
        match opt_type {
            SRC_LINK_ADDR => {
                let opt_len = usize::from(self.buf[1]) * 8;
                if self.buf.len() < opt_len {
                    self.valid = false;
                    None
                } else {
                    let (buf, remaining) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(opt_len);
                    let opt = NdpOptionLinkAddr { buf };
                    self.buf = remaining;
                    Some(NdpOptionMut::SrcLinkAddr(opt))
                }
            }
            DST_LINK_ADDR => {
                let opt_len = usize::from(self.buf[1]) * 8;
                if self.buf.len() < opt_len {
                    self.valid = false;
                    None
                } else {
                    let (buf, remaining) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(opt_len);
                    let opt = NdpOptionLinkAddr { buf };
                    self.buf = remaining;
                    Some(NdpOptionMut::DstLinkAddr(opt))
                }
            }
            PREFIX_INFO => {
                let opt_len = usize::from(self.buf[1]) * 8;
                if self.buf.len() < opt_len || opt_len != 32 {
                    self.valid = false;
                    None
                } else {
                    let (buf, remaining) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(opt_len);
                    let opt = NdpOptionPrefixInfo { buf };
                    self.buf = remaining;
                    Some(NdpOptionMut::PrefixInfo(opt))
                }
            }
            REDIRECTED_HDR => {
                let opt_len = usize::from(self.buf[1]) * 8;
                if self.buf.len() < opt_len {
                    self.valid = false;
                    None
                } else {
                    let (buf, remaining) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(opt_len);
                    let opt = NdpOptionRedirectedHdr { buf };
                    self.buf = remaining;
                    Some(NdpOptionMut::RedirectedHdr(opt))
                }
            }
            MTU => {
                let opt_len = usize::from(self.buf[1]) * 8;
                if self.buf.len() < opt_len || opt_len != 8 {
                    self.valid = false;
                    None
                } else {
                    let (buf, remaining) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(opt_len);
                    let opt = NdpOptionMtu { buf };
                    self.buf = remaining;
                    Some(NdpOptionMut::Mtu(opt))
                }
            }
            _ => {
                self.valid = false;
                None
            }
        }
    }
}

pub struct NdpOptionWriter<'a> {
    buf: &'a mut [u8],
}

impl<'a> NdpOptionWriter<'a> {
    #[inline]
    pub fn src_link_addr(&mut self) -> NdpOptionLinkAddr<&'a mut [u8]> {
        assert!(self.buf.len() > 8);

        self.buf[0] = SRC_LINK_ADDR;
        self.buf[1] = 1;

        let (buf, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(8);
        self.buf = remaining;

        let mut opt = NdpOptionLinkAddr { buf };
        opt.set_link_addr(&[0, 0, 0, 0, 0, 0][..]);

        opt
    }

    #[inline]
    pub fn dst_link_addr(&mut self) -> NdpOptionLinkAddr<&'a mut [u8]> {
        assert!(self.buf.len() > 8);

        self.buf[0] = DST_LINK_ADDR;
        self.buf[1] = 1;

        let (buf, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(8);
        self.buf = remaining;

        let mut opt = NdpOptionLinkAddr { buf };
        opt.set_link_addr(&[0, 0, 0, 0, 0, 0][..]);

        opt
    }

    #[inline]
    pub fn prefix_info(&mut self) -> NdpOptionPrefixInfo<&'a mut [u8]> {
        assert!(self.buf.len() > 32);

        self.buf[0] = PREFIX_INFO;
        self.buf[1] = 4;

        let (buf, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(32);
        self.buf = remaining;

        let mut opt = NdpOptionPrefixInfo { buf };
        (&mut opt.buf[2..]).fill(0);

        opt
    }

    #[inline]
    pub fn redirected_hdr(&mut self, opt_len: usize) -> NdpOptionRedirectedHdr<&'a mut [u8]> {
        assert!(self.buf.len() > opt_len && opt_len % 8 == 0 && opt_len >= 8 && opt_len <= 2040);

        self.buf[0] = REDIRECTED_HDR;
        self.buf[1] = (opt_len / 8) as u8;

        let (buf, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(8);
        self.buf = remaining;

        let mut opt = NdpOptionRedirectedHdr { buf };
        (&mut opt.buf[2..]).fill(0);

        opt
    }

    #[inline]
    pub fn mtu(&mut self, opt_len: usize) -> NdpOptionMtu<&'a mut [u8]> {
        assert!(self.buf.len() > 8);

        self.buf[0] = MTU;
        self.buf[1] = 1;

        let (buf, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(8);
        self.buf = remaining;

        let mut opt = NdpOptionMtu { buf };
        opt.set_mtu(0);

        opt
    }

    #[inline]
    pub fn from_option_bytes_mut(buf: &'a mut [u8]) -> Self {
        Self { buf }
    }

    #[inline]
    pub fn remaining_bytes(&self) -> usize {
        self.buf.len()
    }
}
