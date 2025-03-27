mod common;
use common::*;

use rpkt::arp::*;
use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::llc::*;
use rpkt::vlan::VlanPacket;
use rpkt::vlan::VLAN_HEADER_LEN;
use rpkt::vlan::VLAN_HEADER_TEMPLATE;
use rpkt::Buf;
use rpkt::{Cursor, CursorMut};

#[test]
fn vlan_parse_and_creation() {
    let packet = file_to_packet("ArpRequestWithVlan.dat");

    {
        let eth_pkt = EtherPacket::parse(Cursor::new(&packet[..])).unwrap();
        assert_eq!(eth_pkt.ethertype(), EtherType::VLAN);

        let vlan_pkt = VlanPacket::parse(eth_pkt.payload()).unwrap();
        assert_eq!(vlan_pkt.priority(), 5);
        assert_eq!(vlan_pkt.dei_flag(), true);
        assert_eq!(vlan_pkt.vlan_id(), 666);
        assert_eq!(vlan_pkt.ethertype(), EtherType::VLAN);

        let vlan_pkt = VlanPacket::parse(vlan_pkt.payload()).unwrap();
        assert_eq!(vlan_pkt.priority(), 2);
        assert_eq!(vlan_pkt.dei_flag(), false);
        assert_eq!(vlan_pkt.vlan_id(), 200);
        assert_eq!(vlan_pkt.ethertype(), EtherType::ARP);

        let arp_pkt = ArpPacket::parse(vlan_pkt.payload()).unwrap();
        assert_eq!(arp_pkt.hardware_type(), Hardware::ETHERNET);
        assert_eq!(arp_pkt.protocol_type(), EtherType::IPV4);
        assert_eq!(arp_pkt.hardware_addr_len(), 6);
        assert_eq!(arp_pkt.protocol_addr_len(), 4);
        assert_eq!(arp_pkt.operation(), Operation::REQUEST);
        assert_eq!(
            arp_pkt.sender_ether_addr(),
            EtherAddr::parse_from("ca:03:0d:b4:00:1c").unwrap()
        );
        assert_eq!(arp_pkt.sender_ipv4_addr(), Ipv4Addr::new(192, 168, 2, 200));
        assert_eq!(
            arp_pkt.target_ether_addr(),
            EtherAddr::parse_from("00:00:00:00:00:00").unwrap()
        );
        assert_eq!(arp_pkt.target_ipv4_addr(), Ipv4Addr::new(192, 168, 2, 254));
    }

    {
        let mut target = [0; ETHER_HEADER_LEN + 2 * VLAN_HEADER_LEN + ARP_HEADER_LEN];

        let mut pkt = CursorMut::new(&mut target[..]);
        pkt.advance(ETHER_HEADER_LEN + 2 * VLAN_HEADER_LEN + ARP_HEADER_LEN);

        let mut arp_pkt = ArpPacket::prepend_header(pkt, &ARP_HEADER_TEMPLATE);
        assert_eq!(arp_pkt.hardware_type(), Hardware::ETHERNET);
        assert_eq!(arp_pkt.protocol_type(), EtherType::IPV4);
        assert_eq!(arp_pkt.hardware_addr_len(), 6);
        assert_eq!(arp_pkt.protocol_addr_len(), 4);
        assert_eq!(arp_pkt.operation(), Operation::REQUEST);

        arp_pkt.set_sender_ether_addr(EtherAddr::parse_from("ca:03:0d:b4:00:1c").unwrap());
        arp_pkt.set_sender_ipv4_addr(Ipv4Addr::new(192, 168, 2, 200));
        arp_pkt.set_target_ether_addr(EtherAddr::parse_from("00:00:00:00:00:00").unwrap());
        arp_pkt.set_target_ipv4_addr(Ipv4Addr::new(192, 168, 2, 254));

        let mut vlan_pkt = VlanPacket::prepend_header(arp_pkt.release(), &VLAN_HEADER_TEMPLATE);
        vlan_pkt.set_priority(2);
        assert_eq!(vlan_pkt.dei_flag(), false);
        vlan_pkt.set_vlan_id(200);
        vlan_pkt.set_ethertype(EtherType::ARP);

        let mut vlan_pkt = VlanPacket::prepend_header(vlan_pkt.release(), &VLAN_HEADER_TEMPLATE);
        vlan_pkt.set_priority(5);
        vlan_pkt.set_dei_flag(true);
        vlan_pkt.set_vlan_id(666);
        vlan_pkt.set_ethertype(EtherType::VLAN);

        let mut eth_pkt = EtherPacket::prepend_header(vlan_pkt.release(), &ETHER_HEADER_TEMPLATE);
        assert_eq!(eth_pkt.ethertype(), EtherType::IPV4);

        eth_pkt.set_ethertype(EtherType::VLAN);
        eth_pkt.set_src_addr(EtherAddr::parse_from("ca:03:0d:b4:00:1c").unwrap());
        eth_pkt.set_dst_addr(EtherAddr::parse_from("ff:ff:ff:ff:ff:ff").unwrap());

        assert_eq!(&target[..], &packet[..]);
    }
}
