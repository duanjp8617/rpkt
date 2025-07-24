mod common;
use std::net::Ipv4Addr;
use std::str::FromStr;

use common::*;

use rpkt::ether::*;
use rpkt::gtpv1::gtpv1_extentions::*;
use rpkt::gtpv1::gtpv1_information_elements::*;
use rpkt::gtpv1::nr_up::*;
use rpkt::gtpv1::pdu_session_up::*;
use rpkt::gtpv1::*;
use rpkt::ipv4::*;
use rpkt::network_rw::*;
use rpkt::udp::*;
use rpkt::Buf;
use rpkt::PktBuf;
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

    let payload = gtp.payload();
    let mut iter = Gtpv1IEGroupIter::from_slice(payload.chunk());

    let ie = match iter.next().unwrap() {
        Gtpv1IEGroup::CauseIE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ie.cause_value(), 128);

    let ie = match iter.next().unwrap() {
        Gtpv1IEGroup::TunnelEndpointIdentData1IE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ie.endpoint_ident_data(), 0xd8fde1aa);

    let ie = match iter.next().unwrap() {
        Gtpv1IEGroup::TunnelEndpointIdentControlPlaneIE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ie.endpoint_ident_control_plane(), 0x3aeb040a);

    let ie = match iter.next().unwrap() {
        Gtpv1IEGroup::GtpuPeerAddrIE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ie.var_header_slice().len(), 4);
    assert_eq!(
        Ipv4Addr::new(
            ie.var_header_slice()[0],
            ie.var_header_slice()[1],
            ie.var_header_slice()[2],
            ie.var_header_slice()[3]
        ),
        Ipv4Addr::from_str("192.168.168.245").unwrap()
    );

    let ie = match iter.next().unwrap() {
        Gtpv1IEGroup::GtpuPeerAddrIE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ie.var_header_slice().len(), 4);
    assert_eq!(
        Ipv4Addr::new(
            ie.var_header_slice()[0],
            ie.var_header_slice()[1],
            ie.var_header_slice()[2],
            ie.var_header_slice()[3]
        ),
        Ipv4Addr::from_str("192.168.168.245").unwrap()
    );

    let ie = match iter.next().unwrap() {
        Gtpv1IEGroup::PrivateExtentionIE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ie.extention_ident(), 34501);
    assert_eq!(
        ie.var_header_slice().len(),
        ie.header_len() as usize - PRIVATE_EXTENTION_IE_HEADER_LEN
    );
    assert_eq!(
        ie.var_header_slice(),
        &[0x03, 0x00, 0x20, 0x06, 0x01, 0x03, 0x07, 0x01, 0x80][..]
    );

    assert_eq!(matches!(iter.next(), None), true);
    assert_eq!(iter.buf().len(), 0);
}

#[test]
fn gtp_c1_build() {
    let pkt = file_to_packet("gtp-c1.dat");
    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    pbuf.move_back(9);
    let mut ie = PrivateExtentionIE::prepend_header(pbuf, &PRIVATE_EXTENTION_IE_HEADER_TEMPLATE);
    ie.set_header_len(14);
    ie.set_extention_ident(34501);
    ie.var_header_slice_mut()
        .copy_from_slice(&[0x03, 0x00, 0x20, 0x06, 0x01, 0x03, 0x07, 0x01, 0x80][..]);

    let mut pbuf = ie.release();
    pbuf.move_back(4);
    let mut ie = GtpuPeerAddrIE::prepend_header(pbuf, &GTPU_PEER_ADDR_IE_HEADER_TEMPLATE);
    ie.set_header_len(7);
    ie.var_header_slice_mut().copy_from_slice(
        Ipv4Addr::from_str("192.168.168.245")
            .unwrap()
            .octets()
            .as_slice(),
    );

    let mut pbuf = ie.release();
    pbuf.move_back(4);
    let mut ie = GtpuPeerAddrIE::prepend_header(pbuf, &GTPU_PEER_ADDR_IE_HEADER_TEMPLATE);
    ie.set_header_len(7);
    ie.var_header_slice_mut().copy_from_slice(
        Ipv4Addr::from_str("192.168.168.245")
            .unwrap()
            .octets()
            .as_slice(),
    );

    let mut ie = TunnelEndpointIdentControlPlaneIE::prepend_header(
        ie.release(),
        &TUNNEL_ENDPOINT_IDENT_CONTROL_PLANE_IE_HEADER_TEMPLATE,
    );
    ie.set_endpoint_ident_control_plane(0x3aeb040a);

    let mut ie = TunnelEndpointIdentData1IE::prepend_header(
        ie.release(),
        &TUNNEL_ENDPOINT_IDENT_DATA1_IE_HEADER_TEMPLATE,
    );
    ie.set_endpoint_ident_data(0xd8fde1aa);

    let mut ie = CauseIE::prepend_header(ie.release(), &CAUSE_IE_HEADER_TEMPLATE);
    ie.set_cause_value(128);

    let mut gtpv1_header = GTPV1_HEADER_TEMPLATE.clone();
    let mut header_mod = Gtpv1::from_header_array_mut(&mut gtpv1_header);
    header_mod.set_sequence_present(true);
    let mut gtpv1_pkt = Gtpv1::prepend_header(ie.release(), &gtpv1_header);
    assert_eq!(gtpv1_pkt.header_len(), 12);
    gtpv1_pkt.set_sequence(34062);
    gtpv1_pkt.set_teid(0x09fe4b60);
    gtpv1_pkt.set_message_type(Gtpv1MsgType::SGSN_CONTEXT_RESPONSE);

    let mut udp = Udp::prepend_header(gtpv1_pkt.release(), &UDP_HEADER_TEMPLATE);
    udp.set_checksum(0xa9d9);
    udp.set_dst_port(2123);
    udp.set_src_port(2123);

    let mut ipv4 = Ipv4::prepend_header(udp.release(), &IPV4_HEADER_TEMPLATE);
    ipv4.set_ident(0x9566);
    ipv4.set_ttl(64);
    ipv4.set_protocol(IpProtocol::UDP);
    ipv4.set_checksum(0x1202);
    ipv4.set_src_addr(Ipv4Addr::new(192, 168, 168, 245));
    ipv4.set_dst_addr(Ipv4Addr::new(192, 168, 168, 238));

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0x94, 0xde, 0x80, 0x1b, 0xa0, 0x0e]));
    eth.set_src_addr(EtherAddr([0x08, 0x00, 0x27, 0x26, 0x2f, 0xe7]));
    eth.set_ethertype(EtherType::IPV4);

    let eth_release = eth.release();
    assert_eq!(eth_release.chunk(), &pkt);
}

#[test]
fn gtp_u1_ext_parse() {
    // to_hex_dump("gtp-u-1ext.dat");
    let pkt = file_to_packet("gtp-u-1ext.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::UDP);

    let udp = Udp::parse(ipv4.payload()).unwrap();
    assert_eq!(udp.src_port(), 2152);
    assert_eq!(udp.dst_port(), 2152);

    let gtp = Gtpv1::parse(udp.payload()).unwrap();
    assert_eq!(gtp.extention_header_present(), true);
    assert_eq!(gtp.sequence_present(), true);
    assert_eq!(gtp.npdu_present(), false);
    assert_eq!(gtp.message_type(), Gtpv1MsgType::G_PDU);
    assert_eq!(gtp.packet_len() as usize, 92 + GTPV1_HEADER_LEN);
    assert_eq!(gtp.teid(), 1);
    assert_eq!(gtp.sequence(), 10461);
    assert_eq!(gtp.next_extention_header(), Gtpv1NextExtention::PDU_NUMBER);

    let ext = ExtPduNumber::parse(gtp.payload()).unwrap();
    assert_eq!(ext.pdcp_number(), 2308);
    assert_eq!(
        ext.next_extention_header(),
        Gtpv1NextExtention::NO_EXTENTION
    );

    let ipv4 = Ipv4::parse(ext.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::ICMP);
}

#[test]
fn gtp_u1_ext_build() {
    let pkt = file_to_packet("gtp-u-1ext.dat");
    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    pbuf.move_back(84);
    pbuf.chunk_mut().copy_from_slice(&pkt[pkt.len() - 84..]);

    let mut ext = ExtPduNumber::prepend_header(pbuf, &EXT_PDU_NUMBER_HEADER_TEMPLATE);
    ext.set_pdcp_number(2308);
    ext.set_next_extention_header(Gtpv1NextExtention::NO_EXTENTION);

    let mut gtpv1_header = GTPV1_HEADER_TEMPLATE.clone();
    let mut gtpv1_hdr_mut = Gtpv1::from_header_array_mut(&mut gtpv1_header);
    gtpv1_hdr_mut.set_extention_header_present(true);
    gtpv1_hdr_mut.set_sequence_present(true);
    gtpv1_hdr_mut.set_message_type(Gtpv1MsgType::G_PDU);
    gtpv1_hdr_mut.set_teid(1);

    let mut gtpv1 = Gtpv1::prepend_header(ext.release(), &gtpv1_header);
    gtpv1.set_sequence(10461);
    gtpv1.set_next_extention_header(Gtpv1NextExtention::PDU_NUMBER);

    let mut udp = Udp::prepend_header(gtpv1.release(), &UDP_HEADER_TEMPLATE);
    udp.set_checksum(0xb58d);
    udp.set_dst_port(2152);
    udp.set_src_port(2152);

    let mut ipv4 = Ipv4::prepend_header(udp.release(), &IPV4_HEADER_TEMPLATE);
    ipv4.set_ident(0);
    ipv4.set_ttl(64);
    ipv4.set_dont_frag(true);
    ipv4.set_protocol(IpProtocol::UDP);
    ipv4.set_checksum(0x67b7);
    ipv4.set_src_addr(Ipv4Addr::new(192, 168, 40, 179));
    ipv4.set_dst_addr(Ipv4Addr::new(192, 168, 40, 178));

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0x00, 0x0c, 0x29, 0xda, 0xd1, 0xde]));
    eth.set_src_addr(EtherAddr([0x00, 0x0c, 0x29, 0xe3, 0xc6, 0x4d]));
    eth.set_ethertype(EtherType::IPV4);

    let eth_release = eth.release();
    assert_eq!(eth_release.chunk(), &pkt);
}

#[test]
fn gtp_u2_ext_parse() {
    // to_hex_dump("gtp-u-2ext.dat");
    let pkt = file_to_packet("gtp-u-2ext.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::UDP);

    let udp = Udp::parse(ipv4.payload()).unwrap();
    assert_eq!(udp.src_port(), 2152);
    assert_eq!(udp.dst_port(), 2152);

    let gtp = Gtpv1::parse(udp.payload()).unwrap();
    assert_eq!(gtp.extention_header_present(), true);
    assert_eq!(gtp.sequence_present(), true);
    assert_eq!(gtp.npdu_present(), false);
    assert_eq!(gtp.message_type(), Gtpv1MsgType::G_PDU);
    assert_eq!(gtp.packet_len() as usize, 96 + GTPV1_HEADER_LEN);
    assert_eq!(gtp.teid(), 1);
    assert_eq!(gtp.sequence(), 10461);
    assert_eq!(gtp.next_extention_header(), Gtpv1NextExtention::PDU_NUMBER);

    let ext = ExtPduNumber::parse(gtp.payload()).unwrap();
    assert_eq!(ext.pdcp_number(), 2308);
    assert_eq!(ext.next_extention_header(), Gtpv1NextExtention::UDP_PORT);

    let ext = ExtUdpPort::parse(ext.payload()).unwrap();
    assert_eq!(ext.udp_port(), 1308);
    assert_eq!(
        ext.next_extention_header(),
        Gtpv1NextExtention::NO_EXTENTION
    );

    let ipv4 = Ipv4::parse(ext.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::ICMP);
}

#[test]
fn gtp_u2_ext_build() {
    let pkt = file_to_packet("gtp-u-2ext.dat");
    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    pbuf.move_back(84);
    pbuf.chunk_mut().copy_from_slice(&pkt[pkt.len() - 84..]);

    let mut ext = ExtUdpPort::prepend_header(pbuf, &EXT_UDP_PORT_HEADER_TEMPLATE);
    ext.set_udp_port(1308);
    ext.set_next_extention_header(Gtpv1NextExtention::NO_EXTENTION);

    let mut ext = ExtPduNumber::prepend_header(ext.release(), &EXT_PDU_NUMBER_HEADER_TEMPLATE);
    ext.set_pdcp_number(2308);
    ext.set_next_extention_header(Gtpv1NextExtention::UDP_PORT);

    let mut gtpv1_header = GTPV1_HEADER_TEMPLATE.clone();
    let mut gtpv1_hdr_mut = Gtpv1::from_header_array_mut(&mut gtpv1_header);
    gtpv1_hdr_mut.set_extention_header_present(true);
    gtpv1_hdr_mut.set_sequence_present(true);
    gtpv1_hdr_mut.set_message_type(Gtpv1MsgType::G_PDU);
    gtpv1_hdr_mut.set_teid(1);

    let mut gtpv1 = Gtpv1::prepend_header(ext.release(), &gtpv1_header);
    gtpv1.set_sequence(10461);
    gtpv1.set_next_extention_header(Gtpv1NextExtention::PDU_NUMBER);

    let mut udp = Udp::prepend_header(gtpv1.release(), &UDP_HEADER_TEMPLATE);
    udp.set_checksum(0x983c);
    udp.set_dst_port(2152);
    udp.set_src_port(2152);

    let mut ipv4 = Ipv4::prepend_header(udp.release(), &IPV4_HEADER_TEMPLATE);
    ipv4.set_ident(0);
    ipv4.set_ttl(64);
    ipv4.set_dont_frag(true);
    ipv4.set_protocol(IpProtocol::UDP);
    ipv4.set_checksum(0x67b3);
    ipv4.set_src_addr(Ipv4Addr::new(192, 168, 40, 179));
    ipv4.set_dst_addr(Ipv4Addr::new(192, 168, 40, 178));

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0x00, 0x0c, 0x29, 0xda, 0xd1, 0xde]));
    eth.set_src_addr(EtherAddr([0x00, 0x0c, 0x29, 0xe3, 0xc6, 0x4d]));
    eth.set_ethertype(EtherType::IPV4);

    let eth_release = eth.release();
    assert_eq!(eth_release.chunk(), &pkt);
}

#[test]
fn gtp_nr_container_parse() {
    let pkt = file_to_packet("gtp_nr_container.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::UDP);

    let udp = Udp::parse(ipv4.payload()).unwrap();
    assert_eq!(udp.src_port(), 2152);
    assert_eq!(udp.dst_port(), 2152);

    let gtp = Gtpv1::parse(udp.payload()).unwrap();
    assert_eq!(gtp.extention_header_present(), true);
    assert_eq!(gtp.sequence_present(), false);
    assert_eq!(gtp.npdu_present(), false);
    assert_eq!(gtp.message_type(), Gtpv1MsgType::G_PDU);
    assert_eq!(gtp.packet_len() as usize, 16 + GTPV1_HEADER_LEN);
    assert_eq!(gtp.teid(), 1);
    assert_eq!(
        gtp.next_extention_header(),
        Gtpv1NextExtention::NR_RAN_CONTAINER
    );

    let pkt = match NrUp::group_parse(gtp.payload()).unwrap() {
        NrUp::DlDataDeliveryStatus_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(pkt.highest_trans_nr_pdcp_sn_ind(), 1);
    assert_eq!(pkt.buf_size_for_data_radio_bearer(), 0);
    assert_eq!(read_3_bytes(&pkt.variable_content()[..3]), 2);
    assert_eq!(
        pkt.next_extention_header(),
        Gtpv1NextExtention::NO_EXTENTION
    );

    assert_eq!(pkt.payload().chunk().len(), 0);
}

#[test]
fn gtp_nr_container_build() {
    let pkt = file_to_packet("gtp_nr_container.dat");
    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    let mut hdr = DL_DATA_DELIVERY_STATUS_HEADER_TEMPLATE.clone();
    let mut hdr_mut = DlDataDeliveryStatus::from_header_array_mut(&mut hdr);
    hdr_mut.set_header_len(12);

    let mut nrpkt = DlDataDeliveryStatus::prepend_header(pbuf, &hdr);
    nrpkt.set_next_extention_header(Gtpv1NextExtention::NO_EXTENTION);
    write_3_bytes(&mut nrpkt.variable_content_mut()[..3], 2);
    nrpkt.set_highest_trans_nr_pdcp_sn_ind(1);

    let mut gtpv1_header = GTPV1_HEADER_TEMPLATE.clone();
    let mut gtpv1_hdr_mut = Gtpv1::from_header_array_mut(&mut gtpv1_header);
    gtpv1_hdr_mut.set_extention_header_present(true);
    gtpv1_hdr_mut.set_sequence_present(false);
    gtpv1_hdr_mut.set_message_type(Gtpv1MsgType::G_PDU);
    gtpv1_hdr_mut.set_teid(1);

    let mut gtpv1 = Gtpv1::prepend_header(nrpkt.release(), &gtpv1_header);
    gtpv1.set_next_extention_header(Gtpv1NextExtention::NR_RAN_CONTAINER);

    let mut udp = Udp::prepend_header(gtpv1.release(), &UDP_HEADER_TEMPLATE);
    udp.set_checksum(0x9fd9);
    udp.set_dst_port(2152);
    udp.set_src_port(2152);

    let mut ipv4 = Ipv4::prepend_header(udp.release(), &IPV4_HEADER_TEMPLATE);
    ipv4.set_ident(0xfc2e);
    ipv4.set_ttl(64);
    ipv4.set_dont_frag(true);
    ipv4.set_protocol(IpProtocol::UDP);
    ipv4.set_checksum(0x2834);
    ipv4.set_src_addr(Ipv4Addr::new(10, 10, 1, 38));
    ipv4.set_dst_addr(Ipv4Addr::new(10, 10, 1, 29));

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0x00, 0x0c, 0x29, 0xda, 0xd1, 0xde]));
    eth.set_src_addr(EtherAddr([0x00, 0x0c, 0x29, 0xe3, 0xc6, 0x4d]));
    eth.set_ethertype(EtherType::IPV4);

    let eth_release = eth.release();
    assert_eq!(eth_release.chunk(), &pkt);
}

#[test]
fn gtp_pdu_session_container_parse() {
    let pkt = file_to_packet("gtp_pdu_session_container.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::UDP);

    let udp = Udp::parse(ipv4.payload()).unwrap();
    assert_eq!(udp.src_port(), 2152);
    assert_eq!(udp.dst_port(), 2152);

    let gtp = Gtpv1::parse(udp.payload()).unwrap();
    assert_eq!(gtp.extention_header_present(), true);
    assert_eq!(gtp.sequence_present(), false);
    assert_eq!(gtp.npdu_present(), false);
    assert_eq!(gtp.message_type(), Gtpv1MsgType::G_PDU);
    assert_eq!(gtp.packet_len() as usize, 159 + GTPV1_HEADER_LEN);
    assert_eq!(gtp.teid(), 14872);
    assert_eq!(
        gtp.next_extention_header(),
        Gtpv1NextExtention::PDU_SESSION_CONTAINER
    );

    let pkt = match PduSessionUp::group_parse(gtp.payload()).unwrap() {
        PduSessionUp::UlPduSessionInfo_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(pkt.qos_flow_identifier(), 1);
    assert_eq!(
        pkt.next_extention_header(),
        Gtpv1NextExtention::NO_EXTENTION
    );
    assert_eq!(pkt.header_len(), 4);

    let ipv4 = Ipv4::parse(pkt.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::TCP);

    println!("{}", ipv4.buf().chunk().len());
}

#[test]
fn gtp_pdu_session_container_build() {
    let pkt = file_to_packet("gtp_pdu_session_container.dat");
    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    pbuf.move_back(151);
    pbuf.chunk_mut().copy_from_slice(&pkt[pkt.len() - 151..]);

    let mut pdupkt = UlPduSessionInfo::prepend_header(pbuf, &UL_PDU_SESSION_INFO_HEADER_TEMPLATE);
    pdupkt.set_next_extention_header(Gtpv1NextExtention::NO_EXTENTION);
    pdupkt.set_qos_flow_identifier(1);

    let mut gtpv1_header = GTPV1_HEADER_TEMPLATE.clone();
    let mut gtpv1_hdr_mut = Gtpv1::from_header_array_mut(&mut gtpv1_header);
    gtpv1_hdr_mut.set_extention_header_present(true);
    gtpv1_hdr_mut.set_sequence_present(false);
    gtpv1_hdr_mut.set_message_type(Gtpv1MsgType::G_PDU);
    gtpv1_hdr_mut.set_teid(14872);

    let mut gtpv1 = Gtpv1::prepend_header(pdupkt.release(), &gtpv1_header);
    gtpv1.set_next_extention_header(Gtpv1NextExtention::PDU_SESSION_CONTAINER);

    let mut udp = Udp::prepend_header(gtpv1.release(), &UDP_HEADER_TEMPLATE);
    udp.set_checksum(0x1714);
    udp.set_dst_port(2152);
    udp.set_src_port(2152);

    let mut ipv4 = Ipv4::prepend_header(udp.release(), &IPV4_HEADER_TEMPLATE);
    ipv4.set_ident(0xa79b);
    ipv4.set_ttl(64);
    ipv4.set_dont_frag(true);
    ipv4.set_protocol(IpProtocol::UDP);
    ipv4.set_checksum(0x7c3b);
    ipv4.set_src_addr(Ipv4Addr::new(10, 10, 1, 39));
    ipv4.set_dst_addr(Ipv4Addr::new(10, 10, 1, 25));

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0x00, 0x0c, 0x29, 0xda, 0xd1, 0xde]));
    eth.set_src_addr(EtherAddr([0x00, 0x0c, 0x29, 0xe3, 0xc6, 0x4d]));
    eth.set_ethertype(EtherType::IPV4);

    let eth_release = eth.release();
    assert_eq!(eth_release.chunk(), &pkt);
}

#[test]
fn p() {
    to_hex_dump("gtpv2-with-piggyback.dat");
}