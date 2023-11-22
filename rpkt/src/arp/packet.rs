use bytes::Buf;

use crate::PktMut;

use super::{sha, spa, tha, tpa, ArpHeader, ARP_HEADER_LEN};

use super::Operation;

packet_base! {
    pub struct ArpPacket: ArpHeader {
        header_len: ARP_HEADER_LEN,
        get_methods: [
            (check_arp_format, bool),
            (operation, Operation),
        ],
        set_methods: [
            (adjust_arp_format),
            (set_operation, value: Operation),
            (set_sender_hardware_addr, value: &[u8]),
            (set_sender_protocol_addr, value: &[u8]),
            (set_target_hardware_addr, value: &[u8]),
            (set_target_protocol_addr, value: &[u8]),
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

    #[inline]
    pub fn sender_hardware_addr(&self) -> &[u8] {
        sha(self.buf.chunk())
    }

    #[inline]
    pub fn sender_protocol_addr(&self) -> &[u8] {
        spa(self.buf.chunk())
    }

    #[inline]
    pub fn target_hardware_addr(&self) -> &[u8] {
        tha(self.buf.chunk())
    }

    #[inline]
    pub fn target_protocol_addr(&self) -> &[u8] {
        tpa(self.buf.chunk())
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
mod tests {
    use super::*;
    use crate::arp::ARP_HEADER_TEMPLATE;
    use crate::ether::*;
    use crate::ipv4::*;
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
            MacAddr::from_bytes(arppkt.sender_hardware_addr()),
            MacAddr([0xc4, 0x01, 0x32, 0x58, 0x00, 0x00])
        );
        assert_eq!(
            Ipv4Addr::from_bytes(arppkt.sender_protocol_addr()),
            Ipv4Addr([10, 0, 0, 1]),
        );
        assert_eq!(
            MacAddr::from_bytes(arppkt.target_hardware_addr()),
            MacAddr([0xc4, 0x02, 0x32, 0x6b, 0x00, 0x00])
        );
        assert_eq!(
            Ipv4Addr::from_bytes(arppkt.target_protocol_addr()),
            Ipv4Addr([10, 0, 0, 2]),
        );
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
        arppkt.set_sender_hardware_addr(MacAddr([0xc4, 0x01, 0x32, 0x58, 0x00, 0x00]).as_bytes());
        arppkt.set_sender_protocol_addr(Ipv4Addr([10, 0, 0, 1]).as_bytes());
        arppkt.set_target_hardware_addr(MacAddr([0xc4, 0x02, 0x32, 0x6b, 0x00, 0x00]).as_bytes());
        arppkt.set_target_protocol_addr(Ipv4Addr([10, 0, 0, 2]).as_bytes());

        let mut ethpkt = EtherPacket::prepend_header(arppkt.release(), &ETHER_HEADER_TEMPLATE);
        ethpkt.set_dest_mac(MacAddr([0xc4, 0x02, 0x32, 0x6b, 0x00, 0x00]));
        ethpkt.set_source_mac(MacAddr([0xc4, 0x01, 0x32, 0x58, 0x00, 0x00]));
        ethpkt.set_ethertype(EtherType::ARP);

        assert_eq!(ethpkt.buf().chunk(), &FRAME_BYTES[..]);
    }
}
