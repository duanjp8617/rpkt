mod common;
use std::net::Ipv4Addr;

use common::*;

use rpkt::ether::*;
use rpkt::gre::*;
use rpkt::gtpv1::gtpv1_information_elements::{Gtpv1IEGroup, Gtpv1IEGroupIter};
use rpkt::gtpv1::*;
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
fn gtp_c1_parse() {
    let pkt = file_to_packet("gtp-c1.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::UDP);

    let udp = Udp::parse(ipv4.payload()).unwrap();
    assert_eq!(udp.src_port(), 2123);
    assert_eq!(udp.dst_port(), 2123);

    let gtp = Gtpv1::parse(udp.payload()).unwrap();
    assert_eq!(gtp.version(), 1);
    assert_eq!(gtp.protocol_type(), 1);
    assert_eq!(gtp.extention_header_present(), false);
    assert_eq!(gtp.sequence_present(), true);
    assert_eq!(gtp.npdu_present(), false);
    assert_eq!(gtp.message_type(), Gtpv1MsgType::SGSN_CONTEXT_RESPONSE);
    assert_eq!(gtp.packet_len() as usize, 44 + GTPV1_HEADER_LEN);
    assert_eq!(gtp.teid(), 0x09fe4b60);
    assert_eq!(gtp.sequence(), 0x850e);

    // let payload = gtp.payload();
    // let mut iter = GtpuIEGroupIter::from_slice(payload.chunk());

    // println!("{}, {}", gtp.header_len(), gtp.packet_len());
}
