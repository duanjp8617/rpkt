use bytes::Buf;

use crate::ipv4::IpProtocol;
use crate::PktMut;
use crate::{Cursor, CursorMut};

/// RFC2460 - Sec. 4.3
#[derive(Clone, Copy, Debug)]
pub struct Ipv6DstExtHeader<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> Ipv6DstExtHeader<T> {
    #[inline]
    pub fn new(buf: T) -> Result<Self, T> {
        if buf.as_ref().len() >= 2 {
            let header_len = usize::from(buf.as_ref()[1]) * 8 + 8;
            if buf.as_ref().len() >= header_len {
                Ok(Self { buf })
            } else {
                Err(buf)
            }
        } else {
            Err(buf)
        }
    }

    #[inline]
    pub fn new_unchecked(buf: T) -> Self {
        Self { buf }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        let header_len = usize::from(self.buf.as_ref()[1]) * 8 + 8;
        &self.buf.as_ref()[0..header_len]
    }

    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        self.buf.as_ref()[0].into()
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        usize::from(self.buf.as_ref()[1]) * 8 + 8
    }

    #[inline]
    pub fn option_bytes(&self) -> &[u8] {
        &self.buf.as_ref()[2..self.header_len()]
    }
}

impl<T: AsMut<[u8]>> Ipv6DstExtHeader<T> {
    #[inline]
    pub fn set_next_header(&mut self, value: IpProtocol) {
        self.buf.as_mut()[0] = value.into();
    }

    #[inline]
    pub fn set_header_len(&mut self, value: usize) {
        assert!(value >= 8 && value <= 2048 && value % 8 == 0);
        self.buf.as_mut()[1] = ((value - 8) / 8) as u8;
    }

    #[inline]
    pub fn option_bytes_mut(&mut self) -> &mut [u8] {
        let header_len = usize::from(self.buf.as_mut()[1]) * 8 + 8;
        &mut self.buf.as_mut()[2..header_len]
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct Ipv6DstExtPacket<T> {
    buf: T,
}

impl<T: Buf> Ipv6DstExtPacket<T> {
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
    pub fn header(&self) -> Ipv6DstExtHeader<&[u8]> {
        let header_len = usize::from(self.buf.chunk()[1]) * 8 + 8;
        Ipv6DstExtHeader::new_unchecked(&self.buf.chunk()[..header_len])
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
    pub fn parse(buf: T) -> Result<Ipv6DstExtPacket<T>, T> {
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

impl<T: PktMut> Ipv6DstExtPacket<T> {
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
    pub fn prepend_header<HT: AsRef<[u8]>>(
        mut buf: T,
        header: &Ipv6DstExtHeader<HT>,
    ) -> Ipv6DstExtPacket<T> {
        let header_len = header.header_len();

        assert!(buf.chunk_headroom() >= header_len);
        buf.move_back(header_len);

        let data = &mut buf.chunk_mut()[0..header_len];
        data.copy_from_slice(header.as_bytes());

        Ipv6DstExtPacket { buf }
    }
}

impl<'a> Ipv6DstExtPacket<Cursor<'a>> {
    #[inline]
    pub fn cursor_header(&self) -> Ipv6DstExtHeader<&'a [u8]> {
        let header_len = self.header_len();
        let data = &self.buf.chunk_shared_lifetime()[..header_len];
        Ipv6DstExtHeader::new_unchecked(data)
    }

    #[inline]
    pub fn cursor_payload(&self) -> Cursor<'a> {
        let header_len = self.header_len();
        Cursor::new(&self.buf.chunk_shared_lifetime()[header_len..])
    }
}

impl<'a> Ipv6DstExtPacket<CursorMut<'a>> {
    #[inline]
    pub fn split(self) -> (Ipv6DstExtHeader<&'a mut [u8]>, CursorMut<'a>) {
        let header_len = self.header_len();
        let buf_mut = self.buf.chunk_mut_shared_lifetime();
        let (hdr, payload) = buf_mut.split_at_mut(header_len);
        (
            Ipv6DstExtHeader::new_unchecked(hdr),
            CursorMut::new(payload),
        )
    }
}
