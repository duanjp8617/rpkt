use bytes::Buf;

use crate::ether::MacAddr;
use crate::ipv4::Ipv4Addr;
use crate::PktMut;

use super::header::{ArpHeader, ARP_HEADER_LEN};

use super::Operation;

packet_base! {
    pub struct ArpPacket: ArpHeader {
        header_len: ARP_HEADER_LEN,
        get_methods: [
            (check_arp_format, bool),
            (operation, Operation),
            (source_mac_addr, MacAddr),
            (source_ipv4_addr, Ipv4Addr),
            (target_mac_addr, MacAddr),
            (target_ipv4_addr, Ipv4Addr),
        ],
        set_methods: [
            (adjust_arp_format),
            (set_operation, value: Operation),
            (set_source_mac_addr, value: MacAddr),
            (set_source_ipv4_addr, value: Ipv4Addr),
            (set_target_mac_addr, value: MacAddr),
            (set_target_ipv4_addr, value: Ipv4Addr),
        ],
        unchecked_set_methods: []
    }
}

impl<T: Buf> ArpPacket<T> {
    #[inline]
    pub fn parse(buf: T) -> Result<ArpPacket<T>, T> {
        if buf.chunk().len() >= ARP_HEADER_LEN {
            return Ok(ArpPacket { buf });
        } else {
            Err(buf)
        }
    }
}

impl<T: PktMut> ArpPacket<T> {
    #[inline]
    pub fn prepend_header<HT: AsRef<[u8]>>(mut buf: T, header: &ArpHeader<HT>) -> ArpPacket<T> {
        assert!(buf.chunk_headroom() >= ARP_HEADER_LEN);
        buf.move_back(ARP_HEADER_LEN);

        let data = &mut buf.chunk_mut()[0..ARP_HEADER_LEN];
        data.copy_from_slice(header.as_bytes());

        ArpPacket { buf }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::arp::ARP_HEADER_TEMPLATE;
    use crate::ether::*;
    use crate::PktMut;
    use crate::{Cursor, CursorMut};
    use bytes::BufMut;

    static FRAME_BYTES: [u8; 60] = [
        0xc4, 0x02, 0x32, 0x6b, 0x00, 0x00, 0xc4, 0x01, 0x32, 0x58, 0x00, 0x00, 0x08, 0x06, 0x00,
        0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xc4, 0x01, 0x32, 0x58, 0x00, 0x00, 0x0a, 0x00,
        0x00, 0x01, 0xc4, 0x02, 0x32, 0x6b, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn packet_parse() {
        let pres = EtherPacket::parse(Cursor::new(&FRAME_BYTES[..]));
        assert_eq!(pres.is_ok(), true);
        let ethpkt = pres.unwrap();

        let pres = ArpPacket::parse(ethpkt.payload());
        assert_eq!(pres.is_ok(), true);
        let arppkt = pres.unwrap();

        assert_eq!(arppkt.check_arp_format(), true);
        assert_eq!(arppkt.operation(), Operation::REQUEST);
        assert_eq!(
            arppkt.source_mac_addr(),
            MacAddr([0xc4, 0x01, 0x32, 0x58, 0x00, 0x00])
        );
        assert_eq!(arppkt.source_ipv4_addr(), Ipv4Addr([10, 0, 0, 1]),);
        assert_eq!(
            arppkt.target_mac_addr(),
            MacAddr([0xc4, 0x02, 0x32, 0x6b, 0x00, 0x00])
        );
        assert_eq!(arppkt.target_ipv4_addr(), Ipv4Addr([10, 0, 0, 2]),);
    }

    #[test]
    fn packet_build() {
        let mut bytes = [0xff; 60];
        (&mut bytes[(ETHER_HEADER_LEN + ARP_HEADER_LEN)..])
            .put_bytes(0, 60 - ETHER_HEADER_LEN - ARP_HEADER_LEN);
        let mut buf = CursorMut::new(&mut bytes[..]);
        buf.advance(ETHER_HEADER_LEN + ARP_HEADER_LEN);
        assert_eq!(buf.chunk_headroom(), ETHER_HEADER_LEN + ARP_HEADER_LEN);

        let mut arppkt = ArpPacket::prepend_header(buf, &ARP_HEADER_TEMPLATE);
        arppkt.set_operation(Operation::REQUEST);
        arppkt.set_source_mac_addr(MacAddr([0xc4, 0x01, 0x32, 0x58, 0x00, 0x00]));
        arppkt.set_source_ipv4_addr(Ipv4Addr([10, 0, 0, 1]));
        arppkt.set_target_mac_addr(MacAddr([0xc4, 0x02, 0x32, 0x6b, 0x00, 0x00]));
        arppkt.set_target_ipv4_addr(Ipv4Addr([10, 0, 0, 2]));

        let mut ethpkt = EtherPacket::prepend_header(arppkt.release(), &ETHER_HEADER_TEMPLATE);
        ethpkt.set_dest_mac(MacAddr([0xc4, 0x02, 0x32, 0x6b, 0x00, 0x00]));
        ethpkt.set_source_mac(MacAddr([0xc4, 0x01, 0x32, 0x58, 0x00, 0x00]));
        ethpkt.set_ethertype(EtherType::ARP);

        assert_eq!(ethpkt.buf().chunk(), &FRAME_BYTES[..]);
    }
}
