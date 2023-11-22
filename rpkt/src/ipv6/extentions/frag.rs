use byteorder::{ByteOrder, NetworkEndian};
use bytes::Buf;

use crate::ipv4::IpProtocol;
use crate::PktMut;
use crate::{Cursor, CursorMut};

header_field_val_accessors! {
    (next_header, next_header_mut, 0)
}

header_field_range_accessors! {
    (frag_off, frag_off_mut, 2..4),
    (ident, ident_mut, 4..8)
}

pub const FRAG_HEADER_LEN: usize = 8;

/// RFC2460 - Sec. 4.5
#[derive(Clone, Copy, Debug)]
pub struct FragHeader<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> FragHeader<T> {
    #[inline]
    pub fn new(buf: T) -> Result<Self, T> {
        if buf.as_ref().len() >= FRAG_HEADER_LEN {
            Ok(Self { buf })
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
        &self.buf.as_ref()[0..FRAG_HEADER_LEN]
    }

    #[inline]
    pub fn to_owned(&self) -> FragHeader<[u8; FRAG_HEADER_LEN]> {
        let mut buf = [0; FRAG_HEADER_LEN];
        buf.copy_from_slice(self.as_bytes());
        FragHeader { buf }
    }

    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        let data = next_header(self.buf.as_ref());
        (*data).into()
    }

    #[inline]
    pub fn frag_off(&self) -> u16 {
        let data = frag_off(self.buf.as_ref());
        NetworkEndian::read_u16(data) >> 3
    }

    /// true: more frags
    /// false: last frag
    #[inline]
    pub fn m_flag(&self) -> bool {
        let data = frag_off(self.buf.as_ref());
        (NetworkEndian::read_u16(data) & 1) == 1
    }

    #[inline]
    pub fn ident(&self) -> u32 {
        let data = ident(self.buf.as_ref());
        NetworkEndian::read_u32(data)
    }
}

impl<T: AsMut<[u8]>> FragHeader<T> {
    #[inline]
    pub fn set_next_header(&mut self, value: IpProtocol) {
        let data = next_header_mut(self.buf.as_mut());
        *data = value.into();
    }

    #[inline]
    pub fn adjust_reserved(&mut self) {
        self.buf.as_mut()[1] = 0;

        let data = frag_off_mut(self.buf.as_mut());
        let raw = NetworkEndian::read_u16(data);
        NetworkEndian::write_u16(data, raw & 0xfff9);
    }

    #[inline]
    pub fn set_frag_off(&mut self, value: u16) {
        let data = frag_off_mut(self.buf.as_mut());
        let m_flag = NetworkEndian::read_u16(data) & 1;
        NetworkEndian::write_u16(data, value << 3 | m_flag);
    }

    #[inline]
    pub fn set_m_flag(&mut self, value: bool) {
        let data = frag_off_mut(self.buf.as_mut());
        let frag_off = NetworkEndian::read_u16(data) >> 3;
        if value {
            NetworkEndian::write_u16(data, frag_off << 3 | 1);
        } else {
            NetworkEndian::write_u16(data, frag_off << 3);
        }
    }

    #[inline]
    pub fn set_ident(&mut self, value: u32) {
        let data = ident_mut(self.buf.as_mut());
        NetworkEndian::write_u32(data, value);
    }
}

packet_base! {
    pub struct FragPacket: FragHeader {
        header_len: FRAG_HEADER_LEN,
        get_methods: [
            (next_header, IpProtocol),
            (frag_off, u16),
            (m_flag, bool),
            (ident, u32),
        ],
        set_methods: [
            (adjust_reserved),
            (set_next_header, value: IpProtocol),
            (set_frag_off, value: u16),
            (set_m_flag, value: bool),
            (set_ident, value: u32)
        ],
        unchecked_set_methods:[]
    }
}

impl<T: Buf> FragPacket<T> {
    #[inline]
    pub fn parse(buf: T) -> Result<FragPacket<T>, T> {
        if buf.chunk().len() >= FRAG_HEADER_LEN {
            Ok(FragPacket::parse_unchecked(buf))
        } else {
            Err(buf)
        }
    }

    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.release();
        buf.advance(FRAG_HEADER_LEN);
        buf
    }
}

impl<T: PktMut> FragPacket<T> {
    #[inline]
    pub fn prepend_header<HT: AsRef<[u8]>>(mut buf: T, header: &FragHeader<HT>) -> FragPacket<T> {
        assert!(buf.chunk_headroom() >= FRAG_HEADER_LEN);
        buf.move_back(FRAG_HEADER_LEN);

        let data = &mut buf.chunk_mut()[0..FRAG_HEADER_LEN];
        data.copy_from_slice(header.as_bytes());

        FragPacket { buf }
    }
}

impl<'a> FragPacket<Cursor<'a>> {
    #[inline]
    pub fn cursor_header(&self) -> FragHeader<&'a [u8]> {
        let data = &self.buf.chunk_shared_lifetime()[..FRAG_HEADER_LEN];
        FragHeader::new_unchecked(data)
    }

    #[inline]
    pub fn cursor_payload(&self) -> Cursor<'a> {
        Cursor::new(&self.buf.chunk_shared_lifetime()[FRAG_HEADER_LEN..])
    }
}

impl<'a> FragPacket<CursorMut<'a>> {
    #[inline]
    pub fn split(self) -> (FragHeader<&'a mut [u8]>, CursorMut<'a>) {
        let buf_mut = self.buf.chunk_mut_shared_lifetime();
        let (hdr, payload) = buf_mut.split_at_mut(FRAG_HEADER_LEN);
        (FragHeader::new_unchecked(hdr), CursorMut::new(payload))
    }
}
