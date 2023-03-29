use bytes::Buf;

use crate::checksum_utils;
use crate::ipv4::Ipv4Addr;
use crate::{PktBuf, PktMut};

use super::header::{Icmpv4Header, ICMPV4_HEADER_LEN};
use super::IcmpType;

packet_base! {
    pub struct Icmpv4Packet: Icmpv4Header {
        header_len: ICMPV4_HEADER_LEN,
        get_methods: [
            (icmp_type, IcmpType),
            (code, u8),
            (checksum, u16),
            (rest_of_header, [u8; 4]),
            (ipv4_addr, Ipv4Addr),
            (ident, u16),
            (seq_num, u16),
            (next_hop_mtu, u16),
        ],
        set_methods: [
            (set_icmp_type, value: IcmpType),
            (set_code, value: u8),
            (set_checksum, value: u16),
            (set_rest_of_header, value: &[u8]),
            (set_ipv4_addr, value: Ipv4Addr),
            (set_ident, value: u16),
            (set_seq_num, value: u16),
            (set_next_hop_mtu, value: u16),
        ],
        unchecked_set_methods: []
    }
}

impl<T: Buf> Icmpv4Packet<T> {
    #[inline]
    pub fn parse(buf: T) -> Result<Icmpv4Packet<T>, T> {
        if buf.chunk().len() >= ICMPV4_HEADER_LEN {
            return Ok(Icmpv4Packet { buf });
        } else {
            Err(buf)
        }
    }

    #[inline]
    pub fn data(self) -> T {
        let mut buf = self.release();
        buf.advance(ICMPV4_HEADER_LEN);

        buf
    }
}

impl<T: PktBuf> Icmpv4Packet<T> {
    #[inline]
    pub fn calc_checksum(&mut self) -> u16 {
        let total_len = self.buf().remaining();

        let result = checksum_utils::from_buf(&mut self.buf, total_len);
        self.buf.move_back(total_len);
        result
    }

    #[inline]
    pub fn verify_checksum(&mut self) -> bool {
        self.calc_checksum() == !0
    }
}

impl<T: PktMut> Icmpv4Packet<T> {
    #[inline]
    pub fn adjust_checksum(&mut self) {
        self.set_checksum(0);
        let cksum = !self.calc_checksum();
        self.set_checksum(cksum)
    }

    #[inline]
    pub fn prepend_header<HT: AsRef<[u8]>>(
        mut buf: T,
        header: &Icmpv4Header<HT>,
    ) -> Icmpv4Packet<T> {
        assert!(buf.chunk_headroom() >= ICMPV4_HEADER_LEN);
        buf.move_back(ICMPV4_HEADER_LEN);

        let data = &mut buf.chunk_mut()[0..ICMPV4_HEADER_LEN];
        data.copy_from_slice(header.as_bytes());

        Icmpv4Packet { buf }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ether::*;
    use crate::icmpv4::ICMPV4_HEADER_TEMPLATE;
    use crate::ipv4::*;
    use crate::{Cursor, CursorMut};

    static FRAME_BYTES: [u8; 114] = [
        0x00, 0x19, 0x06, 0xea, 0xb8, 0xc1, 0x00, 0x18, 0x73, 0xde, 0x57, 0xc1, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x64, 0x00, 0x05, 0x00, 0x00, 0xff, 0x01, 0x44, 0x3f, 0xc0, 0xa8, 0x7b, 0x02,
        0xc0, 0xa8, 0x7b, 0x01, 0x08, 0x00, 0x94, 0x9a, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x0c, 0xe9, 0xa2, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab,
        0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab,
        0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
    ];

    #[test]
    fn packet_parse() {
        let buf = Cursor::new(&FRAME_BYTES[..]);
        let eth = EtherPacket::parse(buf).unwrap();
        assert_eq!(eth.ethertype(), EtherType::IPV4);

        let ip = Ipv4Packet::parse(eth.payload()).unwrap();
        assert_eq!(ip.protocol(), IpProtocol::ICMP);
        assert_eq!(ip.verify_checksum(), true);

        let mut icmp = Icmpv4Packet::parse(ip.payload()).unwrap();
        assert_eq!(icmp.icmp_type(), IcmpType::ECHO_REQUEST);
        assert_eq!(icmp.code(), 0);
        assert_eq!(icmp.checksum(), 0x949a);
        assert_eq!(icmp.verify_checksum(), true);
        assert_eq!(icmp.ident(), 1);
        assert_eq!(icmp.seq_num(), 0);
        assert_eq!(icmp.buf().remaining() - ICMPV4_HEADER_LEN, 72);

        let data = icmp.data();
        assert_eq!(
            data.chunk(),
            &FRAME_BYTES[ETHER_HEADER_LEN + IPV4_HEADER_LEN + ICMPV4_HEADER_LEN..]
        );
    }

    #[test]
    fn packet_build() {
        let mut bytes = [0xff; 114];
        (&mut bytes[ETHER_HEADER_LEN + IPV4_HEADER_LEN + ICMPV4_HEADER_LEN..]).copy_from_slice(
            &FRAME_BYTES[ETHER_HEADER_LEN + IPV4_HEADER_LEN + ICMPV4_HEADER_LEN..],
        );

        let mut buf = CursorMut::new(&mut bytes[..]);
        buf.advance(ETHER_HEADER_LEN + IPV4_HEADER_LEN + ICMPV4_HEADER_LEN);

        let mut icmppkt = Icmpv4Packet::prepend_header(buf, &ICMPV4_HEADER_TEMPLATE);
        icmppkt.set_icmp_type(IcmpType::ECHO_REQUEST);
        icmppkt.set_code(0);
        icmppkt.set_checksum(0);
        icmppkt.set_ident(1);
        icmppkt.set_seq_num(0);
        icmppkt.adjust_checksum();

        let mut ippkt = Ipv4Packet::prepend_header(icmppkt.release(), &IPV4_HEADER_TEMPLATE);
        ippkt.adjust_version();
        ippkt.set_dscp(0);
        ippkt.set_ecn(0);
        ippkt.set_ident(0x0005);
        ippkt.clear_flags();
        ippkt.set_dont_frag(false);
        ippkt.set_more_frags(false);
        ippkt.set_frag_offset(0);
        ippkt.set_time_to_live(255);
        ippkt.set_protocol(IpProtocol::ICMP);
        ippkt.set_checksum(0);
        ippkt.set_source_ip(Ipv4Addr([192, 168, 123, 2]));
        ippkt.set_dest_ip(Ipv4Addr([192, 168, 123, 1]));
        ippkt.adjust_checksum();

        let mut header = ETHER_HEADER_TEMPLATE;
        header.set_dest_mac(MacAddr([0x00, 0x19, 0x06, 0xea, 0xb8, 0xc1]));
        header.set_source_mac(MacAddr([0x00, 0x18, 0x73, 0xde, 0x57, 0xc1]));
        header.set_ethertype(EtherType::IPV4);
        let ethpkt = EtherPacket::prepend_header(ippkt.release(), &header);

        assert_eq!(ethpkt.buf().chunk(), &FRAME_BYTES[..]);
    }
}
