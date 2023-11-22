use bytes::Buf;

use crate::ipv4::IpProtocol;
use crate::PktMut;
use crate::{Cursor, CursorMut};

const PAD0: u8 = 0;
const PADN: u8 = 1;

pub enum Ipv6TlvOption<'a> {
    Pad0,
    PadN,
    Generic(GenericTlvOption<&'a [u8]>),
}

pub enum Ipv6TlvOptionMut<'a> {
    Pad0,
    PadN,
    Generic(GenericTlvOption<&'a mut [u8]>),
}

pub struct GenericTlvOption<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> GenericTlvOption<T> {
    #[inline]
    pub fn option_type(&self) -> u8 {
        self.buf.as_ref()[0]
    }

    #[inline]
    pub fn option_data_len(&self) -> u8 {
        self.buf.as_ref()[1]
    }

    #[inline]
    pub fn option_data(&self) -> &[u8] {
        let opt_len = usize::from(self.option_data_len()) + 2;
        &self.buf.as_ref()[2..opt_len]
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> GenericTlvOption<T> {
    #[inline]
    pub fn option_data_mut(&mut self) -> &mut [u8] {
        let opt_len = usize::from(self.option_data_len()) + 2;
        &mut self.buf.as_mut()[2..opt_len]
    }
}

pub struct Ipv6TlvOptionWriter<'a> {
    buf: &'a mut [u8],
}

impl<'a> Ipv6TlvOptionWriter<'a> {
    pub fn pad0(&mut self) {
        assert!(self.buf.len() > 0);

        self.buf[0] = PAD0;

        let (_, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(1);
        self.buf = remaining;
    }

    pub fn padn(&mut self, opt_len: usize) {
        assert!(opt_len >= 2 && opt_len <= 257 && self.buf.len() >= opt_len);

        self.buf[0] = PADN;
        self.buf[1] = (opt_len - 2) as u8;
        (&mut self.buf[2..opt_len]).fill(0);

        let (_, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(opt_len);
        self.buf = remaining;
    }

    pub fn generic(&mut self, opt_type: u8, opt_len: usize) -> GenericTlvOption<&'a mut [u8]> {
        assert!(opt_len >= 2 && opt_len <= 257 && self.buf.len() >= opt_len);

        self.buf[0] = opt_type;
        self.buf[1] = (opt_len - 2) as u8;
        (&mut self.buf[2..opt_len]).fill(0);

        let (buf, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(opt_len);
        self.buf = remaining;

        GenericTlvOption { buf }
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

pub struct Ipv6TlvOptionIter<'a> {
    buf: &'a [u8],
    valid: bool,
}

impl<'a> Ipv6TlvOptionIter<'a> {
    #[inline]
    pub fn from_option_bytes(buf: &'a [u8]) -> Ipv6TlvOptionIter<'a> {
        Self { buf, valid: true }
    }

    #[inline]
    pub fn check_option_bytes(buf: &'a [u8]) -> bool {
        let mut reader = Self::from_option_bytes(buf);
        while let Some(_) = (&mut reader).next() {}
        reader.valid
    }
}

impl<'a> Iterator for Ipv6TlvOptionIter<'a> {
    type Item = Ipv6TlvOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.valid || self.buf.len() == 0 {
            return None;
        }

        let opt_type = self.buf[0];
        match opt_type {
            PAD0 => {
                self.buf = &self.buf[1..];
                Some(Ipv6TlvOption::Pad0)
            }
            _ => {
                if self.buf.len() < 2 {
                    self.valid = false;
                    return None;
                }

                match opt_type {
                    PADN => {
                        let opt_len = usize::from(self.buf[1]) + 2;
                        if self.buf.len() < opt_len {
                            self.valid = false;
                            None
                        } else {
                            self.buf = &self.buf[opt_len..];
                            Some(Ipv6TlvOption::PadN)
                        }
                    }
                    _ => {
                        let opt_len = usize::from(self.buf[1]) + 2;
                        if self.buf.len() < opt_len {
                            self.valid = false;
                            None
                        } else {
                            let opt = GenericTlvOption {
                                buf: &self.buf[..opt_len],
                            };
                            self.buf = &self.buf[opt_len..];
                            Some(Ipv6TlvOption::Generic(opt))
                        }
                    }
                }
            }
        }
    }
}

pub struct Ipv6TlvOptionIterMut<'a> {
    buf: &'a mut [u8],
    valid: bool,
}

impl<'a> Ipv6TlvOptionIterMut<'a> {
    #[inline]
    pub fn from_option_bytes_mut(buf: &'a mut [u8]) -> Ipv6TlvOptionIterMut<'a> {
        Self { buf, valid: true }
    }
}

impl<'a> Iterator for Ipv6TlvOptionIterMut<'a> {
    type Item = Ipv6TlvOptionMut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.valid || self.buf.len() == 0 {
            return None;
        }

        let opt_type = self.buf[0];
        match opt_type {
            PAD0 => {
                let (_, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(1);
                self.buf = remaining;

                Some(Ipv6TlvOptionMut::Pad0)
            }
            _ => {
                if self.buf.len() < 2 {
                    self.valid = false;
                    return None;
                }

                match opt_type {
                    PADN => {
                        let opt_len = usize::from(self.buf[1]) + 2;
                        if self.buf.len() < opt_len {
                            self.valid = false;
                            None
                        } else {
                            let (_, remaining) =
                                std::mem::replace(&mut self.buf, &mut []).split_at_mut(opt_len);
                            self.buf = remaining;

                            Some(Ipv6TlvOptionMut::PadN)
                        }
                    }
                    _ => {
                        let opt_len = usize::from(self.buf[1]) + 2;
                        if self.buf.len() < opt_len {
                            self.valid = false;
                            None
                        } else {
                            let (buf, remaining) =
                                std::mem::replace(&mut self.buf, &mut []).split_at_mut(opt_len);
                            self.buf = remaining;

                            Some(Ipv6TlvOptionMut::Generic(GenericTlvOption { buf }))
                        }
                    }
                }
            }
        }
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct Ipv6OptionPacket<T> {
    buf: T,
}

impl<T: Buf> Ipv6OptionPacket<T> {
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
    pub fn next_header(&self) -> IpProtocol {
        self.buf.chunk()[0].into()
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        usize::from(self.buf.chunk()[1]) * 8 + 8
    }

    #[inline]
    pub fn option_bytes(&self) -> &[u8] {
        let header_len = usize::from(self.buf.chunk()[1]) * 8 + 8;
        &self.buf.chunk()[2..header_len]
    }

    #[inline]
    pub fn parse(buf: T) -> Result<Ipv6OptionPacket<T>, T> {
        if buf.chunk().len() >= 2 {
            let header_len = usize::from(buf.chunk()[1]) * 8 + 8;
            if buf.chunk().len() >= header_len {
                Ok(Self { buf })
            } else {
                Err(buf)
            }
        } else {
            Err(buf)
        }
    }

    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len();
        let mut buf = self.release();
        buf.advance(header_len);
        buf
    }
}

impl<T: PktMut> Ipv6OptionPacket<T> {
    #[inline]
    pub fn set_next_header(&mut self, value: IpProtocol) {
        self.buf.chunk_mut()[0] = value.into();
    }

    #[inline]
    pub fn set_header_len_unchecked(&mut self, value: usize) {
        assert!(value >= 8 && value <= 2048 && value % 8 == 0);
        self.buf.chunk_mut()[1] = ((value - 8) / 8) as u8;
    }

    #[inline]
    pub fn option_bytes_mut(&mut self) -> &mut [u8] {
        let header_len = usize::from(self.buf.chunk()[1]) * 8 + 8;
        &mut self.buf.chunk_mut()[2..header_len]
    }

    #[inline]
    pub fn prepend_header<HT: AsRef<[u8]>>(mut buf: T, header_len: usize) -> Ipv6OptionPacket<T> {
        assert!(header_len >= 8 && header_len <= 2048 && header_len % 8 == 0);

        assert!(buf.chunk_headroom() >= header_len);
        buf.move_back(header_len);

        let data = &mut buf.chunk_mut()[0..header_len];
        data[0] = IpProtocol::TCP.into();
        data[1] = ((header_len - 8) / 8) as u8;
        (&mut data[2..]).fill(0);

        Ipv6OptionPacket { buf }
    }
}

impl<'a> Ipv6OptionPacket<Cursor<'a>> {
    #[inline]
    pub fn cursor_option_bytes(&self) -> &'a [u8] {
        let header_len = self.header_len();
        &self.buf.chunk_shared_lifetime()[2..header_len]
    }

    #[inline]
    pub fn cursor_payload(&self) -> Cursor<'a> {
        let header_len = self.header_len();
        Cursor::new(&self.buf.chunk_shared_lifetime()[header_len..])
    }
}

impl<'a> Ipv6OptionPacket<CursorMut<'a>> {
    #[inline]
    pub fn split(self) -> (&'a mut [u8], CursorMut<'a>) {
        let header_len = self.header_len();
        let buf_mut = self.buf.chunk_mut_shared_lifetime();
        let (hdr, payload) = buf_mut.split_at_mut(header_len);
        (&mut hdr[2..], CursorMut::new(payload))
    }
}
