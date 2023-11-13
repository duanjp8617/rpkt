use bytes::Buf;

use crate::ipv4::IpProtocol;
use crate::{Cursor, CursorMut};
use crate::{PktBuf, PktMut};

use super::header::{Ipv6Header, IPV6_HEADER_LEN};
use super::Ipv6Addr;

packet_base! {
    pub struct Ipv6Packet: Ipv6Header {
        header_len: IPV6_HEADER_LEN,
        get_methods: [
            (check_version, bool),
            (traffic_class, u8),
            (flow_label, u32),
            (payload_len, u16),
            (next_header, IpProtocol),
            (hop_limit, u8),
            (source_ip, Ipv6Addr),
            (dest_ip, Ipv6Addr)
        ],
        set_methods: [
            (adjust_version),
            (set_traffic_class, value: u8),
            (set_flow_label, value: u32),
            (set_next_header, value: IpProtocol),
            (set_hop_limit, value: u8),
            (set_source_ip, value: &Ipv6Addr),
            (set_dest_ip, value: &Ipv6Addr),
        ],
        unchecked_set_methods:[
            (set_payload_len_unchecked, set_payload_len, value: u16)
        ]
    }
}

impl<T: Buf> Ipv6Packet<T> {
    #[inline]
    pub fn parse(buf: T) -> Result<Ipv6Packet<T>, T> {
        if buf.chunk().len() < IPV6_HEADER_LEN {
            return Err(buf);
        }

        let packet = Ipv6Packet::parse_unchecked(buf);
        if packet.buf.remaining() >= IPV6_HEADER_LEN + usize::from(packet.payload_len()) {
            Ok(packet)
        } else {
            Err(packet.release())
        }
    }
}

impl<T: PktBuf> Ipv6Packet<T> {
    #[inline]
    pub fn payload(self) -> T {
        assert!(IPV6_HEADER_LEN + usize::from(self.payload_len()) <= self.buf.remaining());
        let trim_size = self.buf.remaining() - (usize::from(self.payload_len()) + IPV6_HEADER_LEN);

        let mut buf = self.release();
        if trim_size > 0 {
            buf.trim_off(trim_size);
        }

        buf.advance(IPV6_HEADER_LEN);

        buf
    }
}

impl<T: PktMut> Ipv6Packet<T> {
    #[inline]
    pub fn prepend_header<HT: AsRef<[u8]>>(mut buf: T, header: &Ipv6Header<HT>) -> Ipv6Packet<T> {
        assert!(IPV6_HEADER_LEN <= buf.chunk_headroom());
        let payload_len = buf.remaining();
        buf.move_back(IPV6_HEADER_LEN);

        let data = &mut buf.chunk_mut()[0..IPV6_HEADER_LEN];
        data.copy_from_slice(header.as_bytes());

        let mut ippkt = Ipv6Packet::parse_unchecked(buf);
        ippkt.set_payload_len_unchecked(u16::try_from(payload_len).unwrap());
        ippkt
    }
}

impl<'a> Ipv6Packet<Cursor<'a>> {
    #[inline]
    pub fn cursor_header(&self) -> Ipv6Header<&'a [u8]> {
        let data = &self.buf.chunk_shared_lifetime()[..IPV6_HEADER_LEN];
        Ipv6Header::new_unchecked(data)
    }

    #[inline]
    pub fn cursor_payload(&self) -> Cursor<'a> {
        Cursor::new(
            &self.buf.chunk_shared_lifetime()
                [IPV6_HEADER_LEN..IPV6_HEADER_LEN + usize::from(self.payload_len())],
        )
    }
}

impl<'a> Ipv6Packet<CursorMut<'a>> {
    #[inline]
    pub fn split(self) -> (Ipv6Header<&'a mut [u8]>, CursorMut<'a>) {
        let packet_len = usize::from(self.payload_len()) + IPV6_HEADER_LEN;

        let (buf_mut, _) = self
            .buf
            .chunk_mut_shared_lifetime()
            .split_at_mut(packet_len);
        let (hdr, payload) = buf_mut.split_at_mut(IPV6_HEADER_LEN);

        (Ipv6Header::new_unchecked(hdr), CursorMut::new(payload))
    }
}
