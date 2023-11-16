use byteorder::{ByteOrder, NetworkEndian};
use bytes::Buf;

use crate::ipv4::IpProtocol;
use crate::PktMut;
use crate::{Cursor, CursorMut};

header_field_range_accessors! {
    (spi, spi_mut, 0..4),
    (seq, seq_mut, 4..8),
}
pub const IPSEC_ESP_HEADER_LEN: usize = 8;

/// RFC2460 - Sec. 4.5
#[derive(Clone, Copy, Debug)]
pub struct Ipv6EspHeader<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> Ipv6EspHeader<T> {
    #[inline]
    pub fn new(buf: T) -> Result<Self, T> {
        if buf.as_ref().len() >= IPSEC_ESP_HEADER_LEN {
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
        &self.buf.as_ref()[0..IPSEC_ESP_HEADER_LEN]
    }

    #[inline]
    pub fn to_owned(&self) -> Ipv6EspHeader<[u8; IPSEC_ESP_HEADER_LEN]> {
        let mut buf = [0; IPSEC_ESP_HEADER_LEN];
        buf.copy_from_slice(self.as_bytes());
        Ipv6EspHeader { buf }
    }

    #[inline]
    pub fn spi(&self) -> u32 {
        let data = spi(self.buf.as_ref());
        NetworkEndian::read_u32(data)
    }

    #[inline]
    pub fn seq_num(&self) -> u32 {
        let data = seq(self.buf.as_ref());
        NetworkEndian::read_u32(data)
    }
}

impl<T: AsMut<[u8]>> Ipv6EspHeader<T> {
    #[inline]
    pub fn set_spi(&mut self, value: u32) {
        let data = spi_mut(self.buf.as_mut());
        NetworkEndian::write_u32(data, value);
    }

    #[inline]
    pub fn set_seq_num(&mut self, value: u32) {
        let data = seq_mut(self.buf.as_mut());
        NetworkEndian::write_u32(data, value);
    }
}

packet_base! {
    pub struct IpsecEspPacket: Ipv6EspHeader {
        header_len: IPSEC_ESP_HEADER_LEN,
        get_methods: [
            (spi, u32),
            (seq_num, u32),
        ],
        set_methods: [
            (set_spi, val: u32),
            (set_seq_num, val: u32),
        ],
        unchecked_set_methods:[]
    }
}

impl<T: Buf> IpsecEspPacket<T> {
    #[inline]
    pub fn parse(buf: T) -> Result<IpsecEspPacket<T>, T> {
        if buf.chunk().len() >= IPSEC_ESP_HEADER_LEN {
            Ok(IpsecEspPacket::parse_unchecked(buf))
        } else {
            Err(buf)
        }
    }

    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.release();
        buf.advance(IPSEC_ESP_HEADER_LEN);
        buf
    }
}

impl<T: PktMut> IpsecEspPacket<T> {
    #[inline]
    pub fn prepend_header<HT: AsRef<[u8]>>(
        mut buf: T,
        header: &Ipv6EspHeader<HT>,
    ) -> IpsecEspPacket<T> {
        assert!(buf.chunk_headroom() >= IPSEC_ESP_HEADER_LEN);
        buf.move_back(IPSEC_ESP_HEADER_LEN);

        let data = &mut buf.chunk_mut()[0..IPSEC_ESP_HEADER_LEN];
        data.copy_from_slice(header.as_bytes());

        IpsecEspPacket { buf }
    }
}

impl<'a> IpsecEspPacket<Cursor<'a>> {
    #[inline]
    pub fn cursor_header(&self) -> Ipv6EspHeader<&'a [u8]> {
        let data = &self.buf.chunk_shared_lifetime()[..IPSEC_ESP_HEADER_LEN];
        Ipv6EspHeader::new_unchecked(data)
    }

    #[inline]
    pub fn cursor_payload(&self) -> Cursor<'a> {
        Cursor::new(&self.buf.chunk_shared_lifetime()[IPSEC_ESP_HEADER_LEN..])
    }
}

impl<'a> IpsecEspPacket<CursorMut<'a>> {
    #[inline]
    pub fn split(self) -> (Ipv6EspHeader<&'a mut [u8]>, CursorMut<'a>) {
        let buf_mut = self.buf.chunk_mut_shared_lifetime();
        let (hdr, payload) = buf_mut.split_at_mut(IPSEC_ESP_HEADER_LEN);
        (Ipv6EspHeader::new_unchecked(hdr), CursorMut::new(payload))
    }
}
