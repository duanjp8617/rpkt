use bytes::Buf;

use crate::ipv4::IpProtocol;
use crate::PktMut;
use crate::{Cursor, CursorMut};

const TYPE0: u8 = 0;
const TYPE2: u8 = 2;
const RPL: u8 = 3;

pub enum RoutingHeader<'a> {
    Type0(Generic<&'a [u8]>),
    Type2(Generic<&'a [u8]>),
    Rpl(Compressed<&'a [u8]>),
    Unknown,
}

impl<'a> RoutingHeader<'a> {
    #[inline]
    pub fn try_get<PT: Buf>(pkt: &'a Ipv6RoutingPacket<PT>) -> Option<Self> {
        let rt = pkt.routing_type();

        match rt {
            TYPE0 | TYPE2 => {
                let addr_buf_len = pkt.header_len() - 8;

                if addr_buf_len % 16 == 0 && pkt.segments_left() <= addr_buf_len / 16 {
                    Some(RoutingHeader::Type0(Generic {
                        buf: &pkt.buf.chunk()[..pkt.header_len()],
                    }))
                } else {
                    None
                }
            }
            RPL => {
                let addr_buf_len = pkt.header_len() - 8;
                let tmp_header = Compressed {
                    buf: pkt.buf.chunk(),
                };
                let addr_buf_len_without_padding = addr_buf_len.checked_sub(tmp_header.pad())?;
                let last_addr_len = (16 as usize).checked_sub(tmp_header.compr_e())?;
                let len_except_the_last =
                    addr_buf_len_without_padding.checked_sub(last_addr_len)?;
                let first_addr_len = (16 as usize).checked_sub(tmp_header.compr_i())?;

                if len_except_the_last % first_addr_len == 0
                    && tmp_header.segments_left() <= tmp_header.total_addrs()
                {
                    Some(RoutingHeader::Rpl(Compressed {
                        buf: &pkt.buf.chunk()[..pkt.header_len()],
                    }))
                } else {
                    None
                }
            }
            _ => Some(RoutingHeader::Unknown),
        }
    }
}

pub enum RoutingHeaderMut<'a> {
    Type0(Generic<&'a mut [u8]>),
    Type2(Generic<&'a mut [u8]>),
    Rpl(Compressed<&'a mut [u8]>),
    Unknown,
}

impl<'a> RoutingHeaderMut<'a> {
    #[inline]
    pub fn try_get<PT: PktMut>(pkt: &'a mut Ipv6RoutingPacket<PT>) -> Option<Self> {
        let rt = pkt.routing_type();

        match rt {
            TYPE0 | TYPE2 => {
                let addr_buf_len = pkt.header_len() - 8;

                if addr_buf_len % 16 == 0 && pkt.segments_left() <= addr_buf_len / 16 {
                    let header_len = pkt.header_len();
                    Some(RoutingHeaderMut::Type0(Generic {
                        buf: &mut pkt.buf.chunk_mut()[..header_len],
                    }))
                } else {
                    None
                }
            }
            RPL => {
                let addr_buf_len = pkt.header_len() - 8;
                let tmp_header = Compressed {
                    buf: pkt.buf.chunk(),
                };
                let addr_buf_len_without_padding = addr_buf_len.checked_sub(tmp_header.pad())?;
                let last_addr_len = (16 as usize).checked_sub(tmp_header.compr_e())?;
                let len_except_the_last =
                    addr_buf_len_without_padding.checked_sub(last_addr_len)?;
                let first_addr_len = (16 as usize).checked_sub(tmp_header.compr_i())?;

                if len_except_the_last % first_addr_len == 0
                    && tmp_header.segments_left() <= tmp_header.total_addrs()
                {
                    let header_len = pkt.header_len();
                    Some(RoutingHeaderMut::Rpl(Compressed {
                        buf: &mut pkt.buf.chunk_mut()[..header_len],
                    }))
                } else {
                    None
                }
            }
            _ => Some(RoutingHeaderMut::Unknown),
        }
    }
}

pub struct Generic<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> Generic<T> {
    #[inline]
    pub fn routing_type(&self) -> u8 {
        self.buf.as_ref()[2]
    }

    #[inline]
    pub fn segments_left(&self) -> usize {
        self.buf.as_ref()[3].into()
    }

    #[inline]
    pub fn total_addrs(&self) -> usize {
        let hdr_ext_len = usize::from(self.buf.as_ref()[1]);
        hdr_ext_len / 2
    }

    #[inline]
    pub fn next_to_read(&self) -> usize {
        self.total_addrs() - self.segments_left()
    }

    #[inline]
    pub fn addr(&self, idx: usize) -> &[u8] {
        assert!(idx < self.total_addrs());

        &self.buf.as_ref()[8 + 16 * idx..24 + 16 * idx]
    }

    #[inline]
    pub fn check_reserved(&self) -> bool {
        &self.buf.as_ref()[4..8] == &[0, 0, 0, 0][..]
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> Generic<T> {
    #[inline]
    pub fn set_segments_left(&mut self, value: usize) {
        assert!(value <= 255);
        self.buf.as_mut()[3] = value as u8;
    }

    #[inline]
    pub fn adjust_reserved(&mut self) {
        (&mut self.buf.as_mut()[4..8]).fill(0);
    }

    #[inline]
    pub fn addr_mut(&mut self, idx: usize) -> &mut [u8] {
        assert!(idx < self.total_addrs());

        &mut self.buf.as_mut()[8 + 16 * idx..24 + 16 * idx]
    }
}

pub struct Compressed<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> Compressed<T> {
    #[inline]
    pub fn routing_type(&self) -> u8 {
        self.buf.as_ref()[2]
    }

    #[inline]
    pub fn segments_left(&self) -> usize {
        self.buf.as_ref()[3].into()
    }

    #[inline]
    pub fn compr_i(&self) -> usize {
        usize::from(self.buf.as_ref()[4] >> 4)
    }

    #[inline]
    pub fn compr_e(&self) -> usize {
        usize::from(self.buf.as_ref()[4] & 0x0f)
    }

    #[inline]
    pub fn pad(&self) -> usize {
        usize::from(self.buf.as_ref()[5] >> 4)
    }

    #[inline]
    pub fn total_addrs(&self) -> usize {
        let addr_buf_len = usize::from(self.buf.as_ref()[1]) * 8;
        let len_except_the_last = addr_buf_len - self.pad() - (16 - self.compr_e());

        debug_assert!(len_except_the_last % (16 - self.compr_i()) == 0);
        len_except_the_last / (16 - self.compr_i()) + 1
    }

    #[inline]
    pub fn next_to_read(&self) -> usize {
        self.total_addrs() - self.segments_left()
    }

    #[inline]
    pub fn addr(&self, idx: usize) -> &[u8] {
        assert!(idx < self.total_addrs());

        if idx < self.total_addrs() - 1 {
            let addr_len = 16 - self.compr_i();
            &self.buf.as_ref()[8 + addr_len * idx..8 + addr_len * (idx + 1)]
        } else {
            let addr_len = 16 - self.compr_e();
            let len_before_last_addr = (16 - self.compr_i()) * (self.total_addrs() - 1);
            &self.buf.as_ref()[8 + len_before_last_addr..8 + len_before_last_addr + addr_len]
        }
    }

    #[inline]
    pub fn check_reserved(&self) -> bool {
        if (&self.buf.as_ref()[6..8] == &[0, 0][..]) && (self.buf.as_ref()[5] & 0x0f == 0) {
            true
        } else {
            false
        }
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> Compressed<T> {
    #[inline]
    pub fn set_segments_left(&mut self, value: usize) {
        assert!(value <= 255);
        self.buf.as_mut()[3] = value as u8;
    }

    #[inline]
    pub fn adjust_reserved(&mut self) {
        (&mut self.buf.as_mut()[6..8]).fill(0);
        self.buf.as_mut()[5] = self.buf.as_mut()[5] & 0xf0;
    }

    #[inline]
    pub fn addr_mut(&mut self, idx: usize) -> &mut [u8] {
        assert!(idx < self.total_addrs());

        if idx < self.total_addrs() - 1 {
            let addr_len = 16 - self.compr_i();
            &mut self.buf.as_mut()[8 + addr_len * idx..8 + addr_len * (idx + 1)]
        } else {
            let addr_len = 16 - self.compr_e();
            let len_before_last_addr = (16 - self.compr_i()) * (self.total_addrs() - 1);
            &mut self.buf.as_mut()[8 + len_before_last_addr..8 + len_before_last_addr + addr_len]
        }
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct Ipv6RoutingPacket<T> {
    buf: T,
}

impl<T: Buf> Ipv6RoutingPacket<T> {
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
    pub fn routing_type(&self) -> u8 {
        self.buf.chunk()[2]
    }

    #[inline]
    pub fn segments_left(&self) -> usize {
        self.buf.chunk()[3].into()
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        let header_len = usize::from(self.buf.chunk()[1]) * 8 + 8;
        &self.buf.chunk()[4..header_len]
    }

    #[inline]
    pub fn parse(buf: T) -> Result<Ipv6RoutingPacket<T>, T> {
        if buf.chunk().len() >= 2 {
            let pkt = Ipv6RoutingPacket::parse_unchecked(buf);
            if pkt.buf.chunk().len() >= pkt.header_len() {
                Ok(pkt)
            } else {
                Err(pkt.release())
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

impl<T: PktMut> Ipv6RoutingPacket<T> {
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
    pub fn set_routing_type(&mut self, value: u8) {
        self.buf.chunk_mut()[2] = value;
    }

    #[inline]
    pub fn set_segments_left(&mut self, value: usize) {
        assert!(value <= 255);
        self.buf.chunk_mut()[3] = value as u8;
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let header_len = usize::from(self.buf.chunk()[1]) * 8 + 8;
        &mut self.buf.chunk_mut()[4..header_len]
    }

    pub fn prepend_header(
        mut buf: T,
        num_addrs: usize,
        comp_i: u8,
        comp_e: u8,
    ) -> Ipv6RoutingPacket<T> {
        // argument value range check
        assert!(comp_i <= 15 && comp_e <= 15 && num_addrs > 0);

        let addr_buf_len =
            (num_addrs - 1) * (16 - usize::from(comp_i)) + (16 - usize::from(comp_e));
        let pad = if addr_buf_len % 8 == 0 {
            0
        } else {
            8 - (addr_buf_len % 8)
        };
        // make sure buffer size for storing addresses is not too large
        assert!(addr_buf_len + pad <= 2040);

        let header_len = 8 + addr_buf_len + pad;
        // we have enough head room to write the header
        assert!(buf.chunk_headroom() >= header_len);

        buf.move_back(header_len);
        let mut pkt = Ipv6RoutingPacket { buf };

        // create a correct header based on the input arguments
        pkt.set_next_header(IpProtocol::TCP);
        pkt.set_header_len_unchecked((header_len - 8) / 8);
        pkt.set_segments_left(0);
        if comp_i == 0 && comp_e == 0 {
            pkt.set_routing_type(TYPE0);
            (&mut pkt.buf.chunk_mut()[4..]).fill(0);
        } else {
            pkt.set_routing_type(RPL);
            pkt.buf.chunk_mut()[4] = (comp_i << 4) | comp_e;
            pkt.buf.chunk_mut()[5] = (pad as u8) << 4;
            (&mut pkt.buf.chunk_mut()[6..]).fill(0);
        }

        pkt
    }
}

impl<'a> Ipv6RoutingPacket<Cursor<'a>> {
    #[inline]
    pub fn cursor_header(&self) -> Ipv6RoutingPacket<&'a [u8]> {
        let header_len = self.header_len();
        Ipv6RoutingPacket {
            buf: &self.buf.chunk_shared_lifetime()[..header_len],
        }
    }

    #[inline]
    pub fn cursor_payload(&self) -> Cursor<'a> {
        let header_len = self.header_len();
        Cursor::new(&self.buf.chunk_shared_lifetime()[header_len..])
    }
}

impl<'a> Ipv6RoutingPacket<CursorMut<'a>> {
    #[inline]
    pub fn split(self) -> (Ipv6RoutingPacket<&'a mut [u8]>, CursorMut<'a>) {
        let header_len = self.header_len();
        let buf_mut = self.buf.chunk_mut_shared_lifetime();
        let (hdr, payload) = buf_mut.split_at_mut(header_len);
        (
            Ipv6RoutingPacket {
                buf: &mut hdr[..header_len],
            },
            CursorMut::new(payload),
        )
    }
}
