mod common;
use common::*;

use rpkt::arp::*;
use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::mpls::*;
use rpkt::udp::*;
use rpkt::vlan::*;
use rpkt::vxlan::*;
use rpkt::Buf;
use rpkt::{Cursor, CursorMut};

#[test]
fn vlan_parse_and_creation() {
    let packet = file_to_packet("ArpRequestWithVlan.dat");

    {
        let eth_pkt = EtherFrame::parse(Cursor::new(&packet[..])).unwrap();
        assert_eq!(eth_pkt.ethertype(), EtherType::VLAN);

        let vlan_pkt = VlanFrame::parse(eth_pkt.payload()).unwrap();
        assert_eq!(vlan_pkt.priority(), 5);
        assert_eq!(vlan_pkt.dei_flag(), true);
        assert_eq!(vlan_pkt.vlan_id(), 666);
        assert_eq!(vlan_pkt.ethertype(), EtherType::VLAN);

        let vlan_pkt = VlanFrame::parse(vlan_pkt.payload()).unwrap();
        assert_eq!(vlan_pkt.priority(), 2);
        assert_eq!(vlan_pkt.dei_flag(), false);
        assert_eq!(vlan_pkt.vlan_id(), 200);
        assert_eq!(vlan_pkt.ethertype(), EtherType::ARP);

        let arp_pkt = Arp::parse(vlan_pkt.payload()).unwrap();
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
        let mut target = [0; ETHERFRAME_HEADER_LEN + 2 * VLANFRAME_HEADER_LEN + ARP_HEADER_LEN];

        let mut pkt = CursorMut::new(&mut target[..]);
        pkt.advance(ETHERFRAME_HEADER_LEN + 2 * VLANFRAME_HEADER_LEN + ARP_HEADER_LEN);

        let mut arp_pkt = Arp::prepend_header(pkt, &ARP_HEADER_TEMPLATE);
        assert_eq!(arp_pkt.hardware_type(), Hardware::ETHERNET);
        assert_eq!(arp_pkt.protocol_type(), EtherType::IPV4);
        assert_eq!(arp_pkt.hardware_addr_len(), 6);
        assert_eq!(arp_pkt.protocol_addr_len(), 4);
        assert_eq!(arp_pkt.operation(), Operation::REQUEST);

        arp_pkt.set_sender_ether_addr(EtherAddr::parse_from("ca:03:0d:b4:00:1c").unwrap());
        arp_pkt.set_sender_ipv4_addr(Ipv4Addr::new(192, 168, 2, 200));
        arp_pkt.set_target_ether_addr(EtherAddr::parse_from("00:00:00:00:00:00").unwrap());
        arp_pkt.set_target_ipv4_addr(Ipv4Addr::new(192, 168, 2, 254));

        let mut vlan_pkt = VlanFrame::prepend_header(arp_pkt.release(), &VLANFRAME_HEADER_TEMPLATE);
        vlan_pkt.set_priority(2);
        assert_eq!(vlan_pkt.dei_flag(), false);
        vlan_pkt.set_vlan_id(200);
        vlan_pkt.set_ethertype(EtherType::ARP);

        let mut vlan_pkt =
            VlanFrame::prepend_header(vlan_pkt.release(), &VLANFRAME_HEADER_TEMPLATE);
        vlan_pkt.set_priority(5);
        vlan_pkt.set_dei_flag(true);
        vlan_pkt.set_vlan_id(666);
        vlan_pkt.set_ethertype(EtherType::VLAN);

        let mut eth_pkt =
            EtherFrame::prepend_header(vlan_pkt.release(), &ETHERFRAME_HEADER_TEMPLATE);
        assert_eq!(eth_pkt.ethertype(), EtherType::IPV4);

        eth_pkt.set_ethertype(EtherType::VLAN);
        eth_pkt.set_src_addr(EtherAddr::parse_from("ca:03:0d:b4:00:1c").unwrap());
        eth_pkt.set_dst_addr(EtherAddr::parse_from("ff:ff:ff:ff:ff:ff").unwrap());

        assert_eq!(&target[..], &packet[..]);
    }
}

#[test]
fn qinq802_1adparse() {
    let packet = file_to_packet("QinQ_802.1_AD.dat");

    let eth_pkt = EtherFrame::parse(Cursor::new(&packet[..])).unwrap();
    assert_eq!(eth_pkt.ethertype(), EtherType::QINQ);

    let qinq_pkt = VlanFrame::parse(eth_pkt.payload()).unwrap();
    assert_eq!(qinq_pkt.vlan_id(), 30);
    assert_eq!(qinq_pkt.ethertype(), EtherType::VLAN);

    let vlan_pkt = VlanFrame::parse(qinq_pkt.payload()).unwrap();
    assert_eq!(vlan_pkt.priority(), 0);
    assert_eq!(vlan_pkt.dei_flag(), false);
    assert_eq!(vlan_pkt.vlan_id(), 100);
    assert_eq!(vlan_pkt.ethertype(), EtherType::IPV4);

    let ipv4_pkt = Ipv4::parse(vlan_pkt.payload()).unwrap();
    assert_eq!(ipv4_pkt.version(), 4);
    assert_eq!(ipv4_pkt.header_len(), 20);
    assert_eq!(ipv4_pkt.dscp(), 0x00);
    assert_eq!(ipv4_pkt.packet_len(), 1474);
    assert_eq!(ipv4_pkt.ident(), 0x54b0);
    assert_eq!(ipv4_pkt.flag_reserved(), 0);
    assert_eq!(ipv4_pkt.dont_frag(), false);
    assert_eq!(ipv4_pkt.more_frag(), false);
    assert_eq!(ipv4_pkt.frag_offset(), 0);
    assert_eq!(ipv4_pkt.ttl(), 255);
    assert_eq!(ipv4_pkt.protocol().raw(), 253);
    assert_eq!(ipv4_pkt.checksum(), 0xddbf);
    assert_eq!(ipv4_pkt.src_addr(), Ipv4Addr::new(192, 85, 1, 22));
    assert_eq!(ipv4_pkt.dst_addr(), Ipv4Addr::new(192, 85, 1, 14));

    assert_eq!(ipv4_pkt.payload().chunk().len(), 1454);
}

#[test]
fn mpls_layer_test() {
    {
        let packet = file_to_packet("MplsPackets1.dat");

        let eth_pkt = EtherFrame::parse(Cursor::new(&packet[..])).unwrap();
        assert_eq!(eth_pkt.ethertype(), EtherType::VLAN);

        let vlan_pkt = VlanFrame::parse(eth_pkt.payload()).unwrap();
        assert_eq!(vlan_pkt.ethertype(), EtherType::VLAN);

        let vlan_pkt = VlanFrame::parse(vlan_pkt.payload()).unwrap();
        assert_eq!(vlan_pkt.ethertype(), EtherType::MPLS);

        let mpls_pkt = Mpls::parse(vlan_pkt.payload()).unwrap();
        assert_eq!(mpls_pkt.label(), 16000);
        assert_eq!(mpls_pkt.experimental_bits(), 0);
        assert_eq!(mpls_pkt.bottom_of_stack(), true);
        assert_eq!(mpls_pkt.ttl(), 126);

        let inner_payload = mpls_pkt.payload();
        assert_eq!(inner_payload.chunk()[0] >> 4, 4);
    }

    {
        let packet = file_to_packet("MplsPackets2.dat");
        let eth_pkt = EtherFrame::parse(Cursor::new(&packet[..])).unwrap();

        let mpls_pkt = Mpls::parse(eth_pkt.payload()).unwrap();
        assert_eq!(mpls_pkt.label(), 18);
        assert_eq!(mpls_pkt.experimental_bits(), 0);
        assert_eq!(mpls_pkt.bottom_of_stack(), false);
        assert_eq!(mpls_pkt.ttl(), 254);

        let mpls_pkt = Mpls::parse(mpls_pkt.payload()).unwrap();
        assert_eq!(mpls_pkt.label(), 16);
        assert_eq!(mpls_pkt.experimental_bits(), 0);
        assert_eq!(mpls_pkt.bottom_of_stack(), true);
        assert_eq!(mpls_pkt.ttl(), 255);

        let inner_payload = mpls_pkt.payload();
        assert_eq!(inner_payload.chunk()[0], 0);
        assert_eq!(inner_payload.chunk()[1], 0);
    }

    {
        let packet = file_to_packet("MplsPackets3.dat");
        let eth_pkt = EtherFrame::parse(Cursor::new(&packet[..])).unwrap();

        let mpls_pkt = Mpls::parse(eth_pkt.payload()).unwrap();
        assert_eq!(mpls_pkt.label(), 670543);
        assert_eq!(mpls_pkt.experimental_bits(), 6);
        assert_eq!(mpls_pkt.bottom_of_stack(), false);
        assert_eq!(mpls_pkt.ttl(), 5);

        let mpls_pkt = Mpls::parse(mpls_pkt.payload()).unwrap();
        assert_eq!(mpls_pkt.label(), 16);
        assert_eq!(mpls_pkt.experimental_bits(), 0);
        assert_eq!(mpls_pkt.bottom_of_stack(), true);
        assert_eq!(mpls_pkt.ttl(), 255);

        let inner_payload = mpls_pkt.payload();
        assert_eq!(inner_payload.chunk()[0], 0);
        assert_eq!(inner_payload.chunk()[1], 0);
    }

    {
        let packet = file_to_packet("MplsPackets3.dat");
        let mut buf = [0; 144];
        buf[22..].copy_from_slice(&packet[22..]);

        let mut pkt = CursorMut::new(&mut buf[..]);
        pkt.advance(22);

        let mut mpls_pkt = Mpls::prepend_header(pkt, &MPLS_HEADER_TEMPLATE);
        mpls_pkt.set_bottom_of_stack(true);
        mpls_pkt.set_experimental_bits(0);
        mpls_pkt.set_label(16);
        mpls_pkt.set_ttl(255);

        let mut mpls_pkt = Mpls::prepend_header(mpls_pkt.release(), &MPLS_HEADER_TEMPLATE);
        mpls_pkt.set_bottom_of_stack(false);
        mpls_pkt.set_experimental_bits(6);
        mpls_pkt.set_label(670543);
        mpls_pkt.set_ttl(5);

        assert_eq!(mpls_pkt.release().chunk(), &packet[14..])
    }
}

#[test]
fn vxlan_parsing_and_creation_test() {
    {
        let buf = file_to_packet("Vxlan1.dat");
        let pkt = Cursor::new(&buf[..]);

        let eth_pkt = EtherFrame::parse(pkt).unwrap();
        assert_eq!(eth_pkt.ethertype(), EtherType::IPV4);

        let ip_pkt = Ipv4::parse(eth_pkt.payload()).unwrap();
        assert_eq!(ip_pkt.protocol(), IpProtocol::UDP);

        let udp_pkt = Udp::parse(ip_pkt.payload()).unwrap();
        assert_eq!(udp_pkt.dst_port(), 4789);
        assert_eq!(udp_pkt.src_port(), 45149);

        let vxlan_pkt = Vxlan::parse(udp_pkt.payload()).unwrap();
        assert_eq!(vxlan_pkt.gbp_extention(), true);
        assert_eq!(vxlan_pkt.vni_present(), true);
        assert_eq!(vxlan_pkt.dont_learn(), true);
        assert_eq!(vxlan_pkt.policy_applied(), true);
        assert_eq!(vxlan_pkt.reserved_0(), 0);
        assert_eq!(vxlan_pkt.reserved_1(), 0);
        assert_eq!(vxlan_pkt.reserved_2(), 0);
        assert_eq!(vxlan_pkt.reserved_3(), 0);
        assert_eq!(vxlan_pkt.reserved_4(), 0);
        assert_eq!(vxlan_pkt.group_id(), 100);
        assert_eq!(vxlan_pkt.vni(), 3000001);

        let eth_pkt = EtherFrame::parse(vxlan_pkt.payload()).unwrap();
        assert_eq!(eth_pkt.ethertype(), EtherType::IPV4);
    }

    {
        let packet = file_to_packet("Vxlan2.dat");
        let total_header_len =
            ETHERFRAME_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + VXLAN_HEADER_LEN;
        let mut buf = [0; 148];
        buf[total_header_len..].copy_from_slice(&packet[total_header_len..]);

        let mut pkt = CursorMut::new(&mut buf);
        pkt.advance(total_header_len);

        let mut vxlan_pkt = Vxlan::prepend_header(pkt, &VXLAN_HEADER_TEMPLATE);
        assert_eq!(vxlan_pkt.gbp_extention(), false);
        assert_eq!(vxlan_pkt.vni_present(), false);
        assert_eq!(vxlan_pkt.dont_learn(), false);
        assert_eq!(vxlan_pkt.policy_applied(), false);
        vxlan_pkt.set_vni_present(true);
        vxlan_pkt.set_policy_applied(true);
        assert_eq!(vxlan_pkt.reserved_0(), 0);
        assert_eq!(vxlan_pkt.reserved_1(), 0);
        assert_eq!(vxlan_pkt.reserved_2(), 0);
        assert_eq!(vxlan_pkt.reserved_3(), 0);
        assert_eq!(vxlan_pkt.reserved_4(), 0);
        vxlan_pkt.set_group_id(32639);
        vxlan_pkt.set_vni(300);

        let mut udp_pkt = Udp::prepend_header(vxlan_pkt.release(), &UDP_HEADER_TEMPLATE);
        udp_pkt.set_src_port(45149);
        udp_pkt.set_dst_port(4789);
        assert_eq!(udp_pkt.packet_len(), 114);
        udp_pkt.set_checksum(0xad94);

        let mut ip_pkt = Ipv4::prepend_header(udp_pkt.release(), &IPV4_HEADER_TEMPLATE);
        assert_eq!(ip_pkt.version(), 4);
        assert_eq!(ip_pkt.header_len(), 20);
        ip_pkt.set_dscp(0);
        assert_eq!(ip_pkt.packet_len(), 134);
        ip_pkt.set_ident(0xd2c2);
        ip_pkt.set_dont_frag(true);
        assert_eq!(ip_pkt.more_frag(), false);
        assert_eq!(ip_pkt.flag_reserved(), 0);
        assert_eq!(ip_pkt.frag_offset(), 0);
        ip_pkt.set_ttl(64);
        ip_pkt.set_protocol(IpProtocol::UDP);
        ip_pkt.set_checksum(0x5150);
        ip_pkt.set_src_addr(Ipv4Addr::new(192, 168, 203, 1));
        ip_pkt.set_dst_addr(Ipv4Addr::new(192, 168, 202, 1));

        let mut eth_pkt = EtherFrame::prepend_header(ip_pkt.release(), &ETHERFRAME_HEADER_TEMPLATE);
        eth_pkt.set_dst_addr(EtherAddr([0x00, 0x16, 0x3e, 0x08, 0x71, 0xcf]));
        eth_pkt.set_src_addr(EtherAddr([0x36, 0xdc, 0x85, 0x1e, 0xb3, 0x40]));
        eth_pkt.set_ethertype(EtherType::IPV4);

        let pkt = eth_pkt.release();
        assert_eq!(pkt.cursor(), 0);
        assert_eq!(pkt.chunk(), &packet[..]);
    }
}
