mod common;
use core::panic;

use common::*;

use rpkt::arp::*;
use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::llc::*;
use rpkt::Buf;
use rpkt::{Cursor, CursorMut};

#[test]
fn eth_and_arp_packet_parsing() {
    let packet = file_to_packet("ArpResponsePacket.dat");

    let pkt_buf = Cursor::new(&packet[..]);
    let eth_pkt = match EtherGroup::group_parse(pkt_buf).unwrap() {
        EtherGroup::EtherFrame_(pkt) => pkt,
        _ => {
            assert!(false);
            panic!()
        }
    };

    assert_eq!(
        eth_pkt.src_addr(),
        EtherAddr::from_bytes(&[0x30, 0x46, 0x9a, 0x23, 0xfb, 0xfa][..])
    );
    assert_eq!(
        eth_pkt.dst_addr(),
        EtherAddr::from_bytes(&[0x6c, 0xf0, 0x49, 0xb2, 0xde, 0x6e][..])
    );
    assert_eq!(eth_pkt.ethertype(), EtherType::ARP);

    let arp_pkt = Arp::parse(eth_pkt.payload()).unwrap();
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
    {
        let packet = file_to_packet("ArpRequestPacket.dat");
        let mut target = [0; ETHERFRAME_HEADER_LEN + ARP_HEADER_LEN];

        let mut pkt = CursorMut::new(&mut target[..]);
        pkt.advance(ETHERFRAME_HEADER_LEN + ARP_HEADER_LEN);

        let mut arp_pkt = Arp::prepend_header(pkt, &ARP_HEADER_TEMPLATE);
        assert_eq!(arp_pkt.hardware_type(), Hardware::ETHERNET);
        assert_eq!(arp_pkt.protocol_type(), EtherType::IPV4);
        assert_eq!(arp_pkt.hardware_addr_len(), 6);
        assert_eq!(arp_pkt.protocol_addr_len(), 4);
        assert_eq!(arp_pkt.operation(), Operation::REQUEST);

        arp_pkt.set_sender_ether_addr(EtherAddr::parse_from("6c:f0:49:b2:de:6e").unwrap());
        arp_pkt.set_target_ether_addr(EtherAddr::parse_from("00:00:00:00:00:00").unwrap());
        arp_pkt.set_sender_ipv4_addr(Ipv4Addr::new(10, 0, 0, 1));
        arp_pkt.set_target_ipv4_addr(Ipv4Addr::new(10, 0, 0, 138));

        let mut eth_pkt =
            EtherFrame::prepend_header(arp_pkt.release(), &ETHERFRAME_HEADER_TEMPLATE);
        assert_eq!(eth_pkt.ethertype(), EtherType::IPV4);

        eth_pkt.set_ethertype(EtherType::ARP);
        eth_pkt.set_src_addr(EtherAddr::parse_from("6c:f0:49:b2:de:6e").unwrap());
        eth_pkt.set_dst_addr(EtherAddr::parse_from("ff:ff:ff:ff:ff:ff").unwrap());

        assert_eq!(&target[..], &packet[..]);
    }

    {
        let packet = file_to_packet("ArpResponsePacket.dat");
        let mut target = [0; ETHERFRAME_HEADER_LEN + ARP_HEADER_LEN];

        let mut pkt = CursorMut::new(&mut target[..]);
        pkt.advance(ETHERFRAME_HEADER_LEN + ARP_HEADER_LEN);

        let mut arp_pkt = Arp::prepend_header(pkt, &ARP_HEADER_TEMPLATE);
        assert_eq!(arp_pkt.hardware_type(), Hardware::ETHERNET);
        assert_eq!(arp_pkt.protocol_type(), EtherType::IPV4);
        assert_eq!(arp_pkt.hardware_addr_len(), 6);
        assert_eq!(arp_pkt.protocol_addr_len(), 4);
        assert_eq!(arp_pkt.operation(), Operation::REQUEST);

        arp_pkt.set_operation(Operation::REPLY);
        arp_pkt.set_sender_ether_addr(EtherAddr::parse_from("30:46:9a:23:fb:fa").unwrap());
        arp_pkt.set_target_ether_addr(EtherAddr::parse_from("6c:f0:49:b2:de:6e").unwrap());
        arp_pkt.set_sender_ipv4_addr(Ipv4Addr::new(10, 0, 0, 138));
        arp_pkt.set_target_ipv4_addr(Ipv4Addr::new(10, 0, 0, 1));

        let mut eth_pkt =
            EtherFrame::prepend_header(arp_pkt.release(), &ETHERFRAME_HEADER_TEMPLATE);
        assert_eq!(eth_pkt.ethertype(), EtherType::IPV4);

        eth_pkt.set_ethertype(EtherType::ARP);
        eth_pkt.set_src_addr(EtherAddr::parse_from("30:46:9a:23:fb:fa").unwrap());
        eth_pkt.set_dst_addr(EtherAddr::parse_from("6c:f0:49:b2:de:6e").unwrap());

        assert_eq!(&target[..], &packet[..target.len()]);
    }
}

#[test]
fn eth_dot3_layer_parsing_test() {
    let packet = file_to_packet("EthDot3.dat");

    let pkt = Cursor::new(&packet[..]);

    let ethdot3_pkt = match EtherGroup::group_parse(pkt).unwrap() {
        EtherGroup::EtherDot3Frame_(pkt) => pkt,
        _ => {
            assert!(false);
            panic!()
        }
    };
    assert_eq!(
        ethdot3_pkt.src_addr(),
        EtherAddr::parse_from("00:13:f7:11:5e:db").unwrap()
    );
    assert_eq!(
        ethdot3_pkt.dst_addr(),
        EtherAddr::parse_from("01:80:c2:00:00:00").unwrap()
    );
    assert_eq!(ethdot3_pkt.payload_len(), 38);

    let llc_pkt = Llc::parse(ethdot3_pkt.payload()).unwrap();
    assert_eq!(llc_pkt.dsap(), BPDU_CONST);
    assert_eq!(llc_pkt.ssap(), BPDU_CONST);
    assert_eq!(llc_pkt.control(), 0x03);

    assert_eq!(llc_pkt.payload().chunk().len(), 35);
}
