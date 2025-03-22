mod common;
use common::file_to_packet;

use rpkt::arp::*;
use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::{Buf, PktBuf};
use rpkt::{Cursor, CursorMut};

#[test]
fn fuck() {
    // The test is executed under the crate root directory.
    let res = file_to_packet("ArpResponsePacket.dat");

    for c in res.iter() {
        print!("{:02x}", c);
    }
    println!();
}

#[test]
fn eth_and_arp_packet_parsing() {
    let packet = file_to_packet("ArpResponsePacket.dat");

    let pkt_buf = Cursor::new(&packet[..]);
    let eth_pkt = EtherPacket::parse(pkt_buf).unwrap();

    assert_eq!(
        eth_pkt.src_addr(),
        EtherAddr::from_bytes(&[0x30, 0x46, 0x9a, 0x23, 0xfb, 0xfa][..])
    );
    assert_eq!(
        eth_pkt.dst_addr(),
        EtherAddr::from_bytes(&[0x6c, 0xf0, 0x49, 0xb2, 0xde, 0x6e][..])
    );
    assert_eq!(eth_pkt.ethertype(), EtherType::ARP);

    let arp_pkt = ArpPacket::parse(eth_pkt.payload()).unwrap();
    assert_eq!(arp_pkt.hardware_type(), Hardware::ETHERNET);
    assert_eq!(arp_pkt.protocol_type(), EtherType::IPV4);
    assert_eq!(arp_pkt.hardware_addr_len(), 6);
    assert_eq!(arp_pkt.protocol_addr_len(), 4);
    assert_eq!(arp_pkt.operation(), Operation::REPLY);
    assert_eq!(arp_pkt.sender_ipv4_addr(), Ipv4Addr::new(10, 0, 0, 138));
    assert_eq!(
        arp_pkt.target_ether_addr(),
        EtherAddr::parse_from("6c:f0:49:b2:de:6e").unwrap()
    );
}

#[test]
fn arp_packet_creation() {
    let packet = file_to_packet("ArpRequestPacket.dat");
    let mut target = [0; ETHER_HEADER_LEN + ARP_HEADER_LEN];
    {
        let mut pkt = CursorMut::new(&mut target[..]);
        pkt.advance(ETHER_HEADER_LEN + ARP_HEADER_LEN);

        let mut arp_pkt = ArpPacket::prepend_header(pkt, &ARP_HEADER_TEMPLATE);
        assert_eq!(arp_pkt.hardware_type(), Hardware::ETHERNET);
        assert_eq!(arp_pkt.protocol_type(), EtherType::IPV4);
        assert_eq!(arp_pkt.hardware_addr_len(), 6);
        assert_eq!(arp_pkt.protocol_addr_len(), 4);
        assert_eq!(arp_pkt.operation(), Operation::REQUEST);

        arp_pkt.set_sender_ether_addr(EtherAddr::parse_from("6c:f0:49:b2:de:6e").unwrap());
        arp_pkt.set_target_ether_addr(EtherAddr::parse_from("00:00:00:00:00:00").unwrap());
        arp_pkt.set_sender_ipv4_addr(Ipv4Addr::new(10, 0, 0, 1));
        arp_pkt.set_target_ipv4_addr(Ipv4Addr::new(10, 0, 0, 138));

        let mut eth_pkt = EtherPacket::prepend_header(arp_pkt.release(), &ETHER_HEADER_TEMPLATE);
        assert_eq!(eth_pkt.ethertype(), EtherType::IPV4);

        eth_pkt.set_ethertype(EtherType::ARP);
        eth_pkt.set_src_addr(EtherAddr::parse_from("6c:f0:49:b2:de:6e").unwrap());
        eth_pkt.set_dst_addr(EtherAddr::parse_from("ff:ff:ff:ff:ff:ff").unwrap());

        assert_eq!(&target[..], &packet[..]);
    }
}
