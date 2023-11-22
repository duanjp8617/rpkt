use byteorder::{ByteOrder, NetworkEndian};
use bytes::Buf;

use crate::ipv4::IpProtocol;
use crate::PktMut;
use crate::{Cursor, CursorMut};

header_field_val_accessors! {
    (next_header, next_header_mut, 0),
    (payload_len, payload_len_mut, 1),
}

header_field_range_accessors! {
    (spi, spi_mut, 4..8),
    (seq, seq_mut, 8..12),
}

pub const IPSEC_AUTH_HEADER_LEN: usize = 12;

// pub const UDP_HEADER_TEMPLATE: UdpHeader<[u8; 8]> = UdpHeader {
//     buf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
// };

#[derive(Clone, Copy, Debug)]
pub struct IpsecAuthHeader<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> IpsecAuthHeader<T> {
    #[inline]
    pub fn new(buf: T) -> Result<Self, T> {
        if buf.as_ref().len() >= IPSEC_AUTH_HEADER_LEN {
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
        &self.buf.as_ref()[0..IPSEC_AUTH_HEADER_LEN]
    }

    #[inline]
    pub fn to_owned(&self) -> IpsecAuthHeader<[u8; IPSEC_AUTH_HEADER_LEN]> {
        let mut buf = [0; IPSEC_AUTH_HEADER_LEN];
        buf.copy_from_slice(self.as_bytes());
        IpsecAuthHeader { buf }
    }

    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        let data = next_header(self.buf.as_ref());
        (*data).into()
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        let data = payload_len(self.buf.as_ref());
        (usize::from(*data) + 2) * 4
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

impl<T: AsMut<[u8]>> IpsecAuthHeader<T> {
    #[inline]
    pub fn set_next_header(&mut self, value: IpProtocol) {
        let data = next_header_mut(self.buf.as_mut());
        *data = value.into();
    }

    #[inline]
    pub fn set_header_len(&mut self, value: usize) {
        assert!(value >= 12 && value <= 1028 && value % 4 == 0);
        let data = payload_len_mut(self.buf.as_mut());
        *data = (value / 4 - 2) as u8;
    }

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
    pub struct IpsecAuthHdrPacket: IpsecAuthHeader {
        header_len: IPSEC_AUTH_HEADER_LEN,
        get_methods: [
            (next_header, IpProtocol),
            (header_len, usize),
            (spi, u32),
            (seq_num, u32),
        ],
        set_methods: [
            (set_next_header, val: IpProtocol),
            (set_spi, val: u32),
            (set_seq_num, val: u32),
        ],
        unchecked_set_methods:[
            (set_header_len_unchecked, set_header_len, value: usize)
        ]
    }
}

impl<T: Buf> IpsecAuthHdrPacket<T> {
    #[inline]
    pub fn parse(buf: T) -> Result<IpsecAuthHdrPacket<T>, T> {
        if buf.chunk().len() < IPSEC_AUTH_HEADER_LEN {
            return Err(buf);
        }

        let packet = IpsecAuthHdrPacket::parse_unchecked(buf);

        if packet.header_len() >= IPSEC_AUTH_HEADER_LEN
            && packet.header_len() <= packet.buf.chunk().len()
        {
            Ok(packet)
        } else {
            Err(packet.release())
        }
    }

    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len();

        let mut buf = self.release();
        buf.advance(header_len);

        buf
    }

    #[inline]
    pub fn icv_bytes(&self) -> &[u8] {
        let header_len = usize::from(self.header_len());
        &self.buf.chunk()[IPSEC_AUTH_HEADER_LEN..header_len]
    }
}

impl<T: PktMut> IpsecAuthHdrPacket<T> {
    #[inline]
    pub fn prepend_header<TH: AsRef<[u8]>>(
        mut buf: T,
        header: &IpsecAuthHeader<TH>,
    ) -> IpsecAuthHdrPacket<T> {
        let header_len = header.header_len();
        assert!(header_len >= IPSEC_AUTH_HEADER_LEN && buf.chunk_headroom() >= header_len);
        buf.move_back(header_len);

        let data = &mut buf.chunk_mut()[0..IPSEC_AUTH_HEADER_LEN];
        data.copy_from_slice(header.as_bytes());

        IpsecAuthHdrPacket::parse_unchecked(buf)
    }

    #[inline]
    pub fn icv_bytes_mut(&mut self) -> &mut [u8] {
        let header_len = usize::from(self.header_len());
        &mut self.buf.chunk_mut()[IPSEC_AUTH_HEADER_LEN..header_len]
    }
}

impl<'a> IpsecAuthHdrPacket<Cursor<'a>> {
    #[inline]
    pub fn cursor_header(&self) -> IpsecAuthHeader<&'a [u8]> {
        let data = &self.buf.chunk_shared_lifetime()[..IPSEC_AUTH_HEADER_LEN];
        IpsecAuthHeader::new_unchecked(data)
    }

    #[inline]
    pub fn cursor_icv_bytes(&self) -> &'a [u8] {
        &self.buf.chunk_shared_lifetime()[IPSEC_AUTH_HEADER_LEN..self.header_len()]
    }

    #[inline]
    pub fn cursor_payload(&self) -> Cursor<'a> {
        Cursor::new(&self.buf.chunk_shared_lifetime()[self.header_len()..])
    }
}

impl<'a> IpsecAuthHdrPacket<CursorMut<'a>> {
    #[inline]
    pub fn split(self) -> (IpsecAuthHeader<&'a mut [u8]>, &'a [u8], CursorMut<'a>) {
        let header_len = self.header_len();

        let (hdr, payload) = self
            .buf
            .chunk_mut_shared_lifetime()
            .split_at_mut(header_len);
        let (hdr, icv_bytes_mut) = hdr.split_at_mut(IPSEC_AUTH_HEADER_LEN);

        (
            IpsecAuthHeader::new_unchecked(hdr),
            icv_bytes_mut,
            CursorMut::new(payload),
        )
    }
}
