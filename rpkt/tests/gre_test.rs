mod common;
use std::net::Ipv4Addr;

use common::*;

use rpkt::ether::*;
use rpkt::gre::*;
use rpkt::ipv4::IpProtocol;
use rpkt::ipv4::Ipv4;
use rpkt::ipv4::IPV4_HEADER_LEN;
use rpkt::ipv4::IPV4_HEADER_TEMPLATE;
use rpkt::ipv6::*;
use rpkt::udp::Udp;
use rpkt::vlan::VlanFrame;
use rpkt::Buf;
use rpkt::PktBufMut;
use rpkt::{Cursor, CursorMut};

#[test]
fn parse_grev0_1() {
    // to_hex_dump("GREv0_1.dat");
    let packet = file_to_packet("GREv0_1.dat");
    let pbuf = Cursor::new(&packet);

    let eth = EtherFrame::parse(pbuf).unwrap();
    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::GRE);

    let gre = match GreGroup::group_parse(ipv4.payload()).unwrap() {
        GreGroup::Gre_(pkt) => pkt,
        _ => panic!(),
    };

    assert_eq!(gre.header_len(), 8);
    assert_eq!(gre.checksum_present(), true);
    assert_eq!(gre.routing_present(), false);
    assert_eq!(gre.sequence_present(), false);
    assert_eq!(gre.recursion_control(), 0);
    assert_eq!(gre.flags(), 0);
    assert_eq!(gre.protocol_type(), EtherType::IPV4);
    assert_eq!(gre.checksum(), 30719);
    assert_eq!(gre.offset(), 0);

    let ipv4 = Ipv4::parse(gre.payload()).unwrap();
    assert_eq!(ipv4.ttl(), 64);
    assert_eq!(ipv4.ident(), 0x4c0f);
}

#[test]
fn parse_grev0_2() {
    // to_hex_dump("GREv0_2.dat");

    let packet = file_to_packet("GREv0_2.dat");
    let pbuf = Cursor::new(&packet);

    let eth = EtherFrame::parse(pbuf).unwrap();
    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::GRE);

    let gre = match GreGroup::group_parse(ipv4.payload()).unwrap() {
        GreGroup::Gre_(pkt) => pkt,
        _ => panic!(),
    };

    assert_eq!(gre.header_len(), 4);
    assert_eq!(gre.checksum_present(), false);
    assert_eq!(gre.routing_present(), false);
    assert_eq!(gre.sequence_present(), false);
    assert_eq!(gre.recursion_control(), 0);
    assert_eq!(gre.flags(), 0);
    assert_eq!(gre.protocol_type(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(gre.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::GRE);

    let gre = match GreGroup::group_parse(ipv4.payload()).unwrap() {
        GreGroup::Gre_(pkt) => pkt,
        _ => panic!(),
    };

    assert_eq!(gre.header_len(), 4);
    assert_eq!(gre.checksum_present(), false);
    assert_eq!(gre.routing_present(), false);
    assert_eq!(gre.sequence_present(), false);
    assert_eq!(gre.recursion_control(), 0);
    assert_eq!(gre.flags(), 0);
    assert_eq!(gre.protocol_type(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(gre.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::UDP);

    let udp = Udp::parse(ipv4.payload()).unwrap();
    assert_eq!(udp.src_port(), 520);
    assert_eq!(udp.dst_port(), 520);
    assert_eq!(udp.packet_len(), 32);
}

#[test]
fn parse_grev1_1() {
    // to_hex_dump("GREv1_1.dat");

    let packet = file_to_packet("GREv1_1.dat");
    let pbuf = Cursor::new(&packet);

    let eth = EtherFrame::parse(pbuf).unwrap();
    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::GRE);

    let gre = match GreGroup::group_parse(ipv4.payload()).unwrap() {
        GreGroup::GreForPPTP_(pkt) => pkt,
        _ => panic!(),
    };

    assert_eq!(gre.header_len(), 12);
    assert_eq!(gre.checksum_present(), false);
    assert_eq!(gre.routing_present(), false);
    assert_eq!(gre.key_present(), true);
    assert_eq!(gre.sequence_present(), false);
    assert_eq!(gre.recursion_control(), 0);
    assert_eq!(gre.strict_source_route(), false);
    assert_eq!(gre.recursion_control(), 0);
    assert_eq!(gre.ack_present(), true);
    assert_eq!(gre.flags(), 0);
    assert_eq!(gre.version(), 1);

    assert_eq!(gre.protocol_type(), EtherType::PPP);
    assert_eq!(gre.payload_len(), 0);
    assert_eq!(gre.key_call_id(), 6);

    assert_eq!(gre.ack(), 26);
}

#[test]
fn parse_grev1_2() {
    // to_hex_dump("GREv1_2.dat");

    let packet = file_to_packet("GREv1_2.dat");
    let pbuf = Cursor::new(&packet);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::VLAN);

    let vlan = VlanFrame::parse(eth.payload()).unwrap();
    assert_eq!(vlan.ethertype(), EtherType::IPV6);

    let ipv6 = Ipv6::parse(vlan.payload()).unwrap();
    assert_eq!(ipv6.next_header(), IpProtocol::IPIP);

    let ipv4 = Ipv4::parse(ipv6.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::GRE);

    let gre = match GreGroup::group_parse(ipv4.payload()).unwrap() {
        GreGroup::GreForPPTP_(pkt) => pkt,
        _ => panic!(),
    };

    assert_eq!(gre.header_len(), 12);
    assert_eq!(gre.checksum_present(), false);
    assert_eq!(gre.routing_present(), false);
    assert_eq!(gre.key_present(), true);
    assert_eq!(gre.sequence_present(), true);
    assert_eq!(gre.strict_source_route(), false);
    assert_eq!(gre.recursion_control(), 0);
    assert_eq!(gre.ack_present(), false);
    assert_eq!(gre.flags(), 0);
    assert_eq!(gre.version(), 1);

    assert_eq!(gre.protocol_type(), EtherType::PPP);
    assert_eq!(gre.payload_len(), 178);
    assert_eq!(gre.key_call_id(), 17);

    assert_eq!(gre.sequence(), 539320);

    let ppp = PPTP::parse(gre.payload()).unwrap();
    assert_eq!(ppp.address(), 0xff);
    assert_eq!(ppp.control(), 0x03);
    assert_eq!(ppp.protocol(), 0x0021);

    let ipv4 = Ipv4::parse(ppp.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::UDP);
}

#[test]
fn parse_grev0_4() {
    // to_hex_dump("GREv0_4.dat");
    let packet = file_to_packet("GREv0_4.dat");
    let pbuf = Cursor::new(&packet);

    let eth = EtherFrame::parse(pbuf).unwrap();
    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::GRE);

    let gre = match GreGroup::group_parse(ipv4.payload()).unwrap() {
        GreGroup::Gre_(pkt) => pkt,
        _ => panic!(),
    };

    assert_eq!(gre.header_len(), 8);
    assert_eq!(gre.checksum_present(), false);
    assert_eq!(gre.routing_present(), false);
    assert_eq!(gre.key_present(), true);
    assert_eq!(gre.sequence_present(), false);
    assert_eq!(gre.strict_source_route(), false);
    assert_eq!(gre.recursion_control(), 0);
    assert_eq!(gre.flags(), 0);
    assert_eq!(gre.version(), 0);

    assert_eq!(gre.protocol_type(), EtherType::TRANS_ETH_BRIDGE);
    assert_eq!(gre.key(), 0x0000fde8);
}

#[test]
fn create_grev1_3() {
    // to_hex_dump("GREv1_3.dat");
    let packet = file_to_packet("GREv1_3.dat");
    let mut big_buf = [0; 64];
    let mut pbuf = CursorMut::new(&mut big_buf);
    pbuf.advance(60);
    (pbuf.chunk_mut()).copy_from_slice(&packet[54..]);

    let mut ppp = PPTP::prepend_header(pbuf, &PPTP_HEADER_TEMPLATE);
    ppp.set_address(0xff);
    ppp.set_control(0x03);
    ppp.set_protocol(0x80fd);

    let mut gre_header = GRE_FOR_PPTP_HEADER_TEMPLATE.clone();
    {
        let mut gre_header = GreForPPTP::from_header_array_mut(&mut gre_header);
        gre_header.set_key_present(true);
        gre_header.set_sequence_present(true);
        gre_header.set_ack_present(true);
    }

    let mut gre = GreForPPTP::prepend_header(ppp.release(), &gre_header);
    gre.set_key_call_id(6);
    gre.set_sequence(34);
    gre.set_ack(17);

    let mut ipv4 = Ipv4::prepend_header(gre.release(), &IPV4_HEADER_TEMPLATE);
    ipv4.set_ident(0x067c);
    ipv4.set_ttl(128);
    ipv4.set_protocol(IpProtocol::GRE);
    ipv4.set_checksum(0xad97);
    ipv4.set_src_addr(Ipv4Addr::new(192, 168, 2, 65));
    ipv4.set_dst_addr(Ipv4Addr::new(192, 168, 2, 254));

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0x00, 0x0d, 0xed, 0x7b, 0x48, 0xf4]));
    eth.set_src_addr(EtherAddr([0x00, 0x90, 0x4b, 0x1f, 0xa4, 0xf7]));
    eth.set_ethertype(EtherType::IPV4);

    assert_eq!(eth.release().chunk(), &packet);
}

#[test]
fn create_grev0_4() {
    // to_hex_dump("GREv0_4.dat");
    let packet = file_to_packet("GREv0_4.dat");
    let mut big_buf = [0; 96];
    let mut pbuf = CursorMut::new(&mut big_buf);
    pbuf.advance(ETHER_FRAME_HEADER_LEN + IPV4_HEADER_LEN + 8);
    (pbuf.chunk_mut()).copy_from_slice(&packet[ETHER_FRAME_HEADER_LEN + IPV4_HEADER_LEN + 8..]);

    let mut gre_header = GRE_HEADER_TEMPLATE.clone();
    {
        let mut gre_header = Gre::from_header_array_mut(&mut gre_header);
        gre_header.set_key_present(true);
    }

    let mut gre = Gre::prepend_header(pbuf, &gre_header);
    gre.set_protocol_type(EtherType::TRANS_ETH_BRIDGE);
    gre.set_key(0x0000fde8);

    let mut ipv4 = Ipv4::prepend_header(gre.release(), &IPV4_HEADER_TEMPLATE);
    ipv4.set_ident(0x0001);
    ipv4.set_ttl(64);
    ipv4.set_protocol(IpProtocol::GRE);
    ipv4.set_checksum(0x7073);
    ipv4.set_src_addr(Ipv4Addr::new(1, 2, 3, 4));
    ipv4.set_dst_addr(Ipv4Addr::new(4, 3, 2, 1));

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0x00, 0xae, 0xf3, 0x52, 0xaa, 0xd1]));
    eth.set_src_addr(EtherAddr([0x00, 0x02, 0x15, 0x37, 0xa2, 0x44]));
    eth.set_ethertype(EtherType::IPV4);

    assert_eq!(eth.release().chunk(), &packet);
}
