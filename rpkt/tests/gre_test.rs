mod common;
use common::*;

use rpkt::ether::*;
use rpkt::gre::*;
use rpkt::ipv4::IpProtocol;
use rpkt::ipv4::Ipv4;
use rpkt::llc::*;
use rpkt::stp::*;
use rpkt::udp::Udp;
use rpkt::Buf;
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

    // let gre = match GreGroup::group_parse(ipv4.payload()).unwrap() {
    //     GreGroup::GreForPPTP_(pkt) => pkt,
    //     _ => panic!(),
    // };

    // assert_eq!(gre.header_len(), 8);
    // assert_eq!(gre.checksum_present(), false);
    // assert_eq!(gre.routing_present(), false);
    // assert_eq!(gre.key_present(), true);
    // assert_eq!(gre.sequence_present(), false);
    // assert_eq!(gre.recursion_control(), 0);
    // assert_eq!(gre.strict_source_route(), false);
    // assert_eq!(gre.recursion_control(), 0);
    // assert_eq!(gre.ack_present(), true);
    // assert_eq!(gre.flags(), 0);
    // assert_eq!(gre.version(), 1);
}
