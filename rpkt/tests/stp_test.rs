mod common;
use common::*;

use rpkt::ether::*;
use rpkt::llc::*;
use rpkt::stp::*;
use rpkt::vlan::*;
use rpkt::Buf;
use rpkt::PktBufMut;
use rpkt::{Cursor, CursorMut};

#[test]
fn stp_configuration_parsing_tests() {
    {
        let packet = file_to_packet("StpConf.dat");

        let pkt = Cursor::new(&packet[..]);
        assert_eq!(store_ieee_dot3_frame(pkt.chunk()), true);
        assert_eq!(store_ether_frame(pkt.chunk()), false);
        let ethdot3_pkt = EthDot3Packet::parse(pkt).unwrap();

        assert_eq!(ethdot3_pkt.payload_len(), 38);

        let llc_pkt = LlcPacket::parse(ethdot3_pkt.payload()).unwrap();
        assert_eq!(llc_pkt.buf().chunk().len(), 38);
        assert_eq!(llc_pkt.dsap(), BPDU_CONST);
        assert_eq!(llc_pkt.ssap(), BPDU_CONST);
        assert_eq!(llc_pkt.control(), 0x03);

        let payload = llc_pkt.payload();
        let res = StpMessageGroup::group_parse(payload.chunk()).unwrap();
        match res {
            StpMessageGroup::StpConf(msg) => {
                assert_eq!(msg.proto_id(), 0);
                assert_eq!(msg.version(), StpVersion::STP);
                assert_eq!(msg.type_(), StpType::STP_CONF);

                assert_eq!(msg.flag(), 0);
                let root_id = msg.root_id();
                assert_eq!(root_id, 0x8064001c0e877800);
                assert_eq!(msg.root_priority(), 32768);
                assert_eq!(msg.root_sys_id_ext(), 100);
                assert_eq!(
                    msg.root_mac_addr(),
                    EtherAddr::parse_from("00:1c:0e:87:78:00").unwrap()
                );

                assert_eq!(msg.path_cost(), 0x4);

                let bridge_id = msg.bridge_id();
                assert_eq!(bridge_id, 0x8064001c0e878500);
                assert_eq!(msg.bridge_priority(), 32768);
                assert_eq!(msg.bridge_sys_id_ext(), 100);
                assert_eq!(
                    msg.bridge_mac_addr(),
                    EtherAddr::parse_from("00:1c:0e:87:85:00").unwrap()
                );
                assert_eq!(msg.port_id(), 0x8004);
                assert_eq!(msg.msg_age(), 1);
                assert_eq!(msg.max_age(), 20);
                assert_eq!(msg.hello_time(), 2);
                assert_eq!(msg.forward_delay(), 15);
            }
            _ => panic!(),
        }
    }
}

#[test]
fn stp_configuration_creation_tests() {
    let mut buf: [u8; 64] = [0; 64];

    let mut pkt_buf = CursorMut::new(
        &mut buf[..ETHER_HEADER_LEN + LLC_HEADER_LEN + STPCONFBPDU_HEADER_ARRAY.len()],
    );
    pkt_buf.advance(ETHER_HEADER_LEN + LLC_HEADER_LEN);

    let mut stp_conf_msg = StpConfBpduMessage::build_message(pkt_buf.chunk_mut());
    stp_conf_msg.set_root_id(0x8064001c0e877800);
    stp_conf_msg.set_path_cost(4);
    stp_conf_msg.set_bridge_id(0x8064001c0e878500);
    stp_conf_msg.set_port_id(0x8004);
    stp_conf_msg.set_msg_age(1);
    stp_conf_msg.set_max_age(20);
    stp_conf_msg.set_hello_time(2);
    stp_conf_msg.set_forward_delay(15);

    let llc_pkt = LlcPacket::prepend_header(pkt_buf, &LLC_HEADER_TEMPLATE);
    let mut eth_pkt = EthDot3Packet::prepend_header(llc_pkt.release(), &ETHDOT3_HEADER_TEMPLATE);
    eth_pkt.set_dst_addr(EtherAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]));
    eth_pkt.set_src_addr(EtherAddr([0x00, 0x1c, 0x0e, 0x87, 0x85, 0x04]));

    let target = file_to_packet("StpConf.dat");
    assert_eq!(
        eth_pkt.release().chunk(),
        &target[..ETHER_HEADER_LEN + LLC_HEADER_LEN + STPCONFBPDU_HEADER_ARRAY.len()]
    );
}

#[test]
fn stp_configuration_edit_tests() {
    let mut edited_packet = file_to_packet("StpConf.dat");

    let pkt = CursorMut::new(&mut edited_packet[..]);
    assert_eq!(store_ieee_dot3_frame(pkt.chunk()), true);
    assert_eq!(store_ether_frame(pkt.chunk()), false);
    let ethdot3_pkt = EthDot3Packet::parse(pkt).unwrap();

    assert_eq!(ethdot3_pkt.payload_len(), 38);

    let llc_pkt = LlcPacket::parse(ethdot3_pkt.payload()).unwrap();
    assert_eq!(llc_pkt.buf().chunk().len(), 38);
    assert_eq!(llc_pkt.dsap(), BPDU_CONST);
    assert_eq!(llc_pkt.ssap(), BPDU_CONST);
    assert_eq!(llc_pkt.control(), 0x03);

    let mut payload = llc_pkt.payload();
    let res = StpMessageGroup::group_parse(payload.chunk_mut()).unwrap();
    let edited_stp_conf = match res {
        StpMessageGroup::StpConf(mut msg) => {
            msg.set_flag(0x13);
            msg.set_root_priority(4096);
            msg.set_root_sys_id_ext(290);
            msg.set_root_mac_addr(EtherAddr::parse_from("33:44:55:66:77:88").unwrap());
            msg.set_path_cost(7);
            msg.set_bridge_priority(40960);
            msg.set_bridge_sys_id_ext(2834);
            msg.set_bridge_mac_addr(EtherAddr::parse_from("34:87:65:99:88:77").unwrap());
            msg.set_port_id(0x1111);
            msg.set_msg_age(7);
            msg.set_max_age(12);
            msg.set_hello_time(3);
            msg.set_forward_delay(9);
            msg.release()
        }
        _ => panic!(),
    };

    let packet = file_to_packet("StpConfEdit1.dat");

    let pkt = Cursor::new(&packet[..]);
    assert_eq!(store_ieee_dot3_frame(pkt.chunk()), true);
    assert_eq!(store_ether_frame(pkt.chunk()), false);
    let ethdot3_pkt = EthDot3Packet::parse(pkt).unwrap();

    assert_eq!(ethdot3_pkt.payload_len(), 38);

    let llc_pkt = LlcPacket::parse(ethdot3_pkt.payload()).unwrap();
    assert_eq!(llc_pkt.buf().chunk().len(), 38);
    assert_eq!(llc_pkt.dsap(), BPDU_CONST);
    assert_eq!(llc_pkt.ssap(), BPDU_CONST);
    assert_eq!(llc_pkt.control(), 0x03);

    let payload = llc_pkt.payload();

    assert_eq!(payload.chunk(), edited_stp_conf);
}

#[test]
fn stp_topology_change_parsing_tests() {
    let packet = file_to_packet("StpTcn.dat");

    let pkt = Cursor::new(&packet[..]);
    assert_eq!(store_ieee_dot3_frame(pkt.chunk()), true);
    assert_eq!(store_ether_frame(pkt.chunk()), false);
    let ethdot3_pkt = EthDot3Packet::parse(pkt).unwrap();

    assert_eq!(ethdot3_pkt.payload_len(), 7);

    let llc_pkt = LlcPacket::parse(ethdot3_pkt.payload()).unwrap();
    assert_eq!(llc_pkt.buf().chunk().len(), 7);
    assert_eq!(llc_pkt.dsap(), BPDU_CONST);
    assert_eq!(llc_pkt.ssap(), BPDU_CONST);
    assert_eq!(llc_pkt.control(), 0x03);

    let payload = llc_pkt.payload();
    let res = StpMessageGroup::group_parse(payload.chunk()).unwrap();
    match res {
        StpMessageGroup::StpTcn(msg) => {
            assert_eq!(msg.proto_id(), 0);
            assert_eq!(msg.version(), StpVersion::STP);
            assert_eq!(msg.type_(), StpType::STP_TCN);
        }
        _ => panic!(),
    }
}

#[test]
fn stp_topology_change_creation_tests() {
    let mut buf: [u8; 64] = [0; 64];

    let mut pkt_buf = CursorMut::new(
        &mut buf[..ETHER_HEADER_LEN + LLC_HEADER_LEN + STPTCNBPDU_HEADER_ARRAY.len()],
    );
    pkt_buf.advance(ETHER_HEADER_LEN + LLC_HEADER_LEN);

    let _ = StpTcnBpduMessage::build_message(pkt_buf.chunk_mut());

    let llc_pkt = LlcPacket::prepend_header(pkt_buf, &LLC_HEADER_TEMPLATE);
    let mut eth_pkt = EthDot3Packet::prepend_header(llc_pkt.release(), &ETHDOT3_HEADER_TEMPLATE);
    eth_pkt.set_dst_addr(EtherAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]));
    eth_pkt.set_src_addr(EtherAddr([0xaa, 0xbb, 0xcc, 0x00, 0x02, 0x00]));

    let target = file_to_packet("StpTcn.dat");
    assert_eq!(
        eth_pkt.release().chunk(),
        &target[..ETHER_HEADER_LEN + LLC_HEADER_LEN + STPTCNBPDU_HEADER_ARRAY.len()]
    );
}

#[test]
fn rapid_stp_parsing_tests() {
    {
        let packet = file_to_packet("StpRapid.dat");

        let pkt = Cursor::new(&packet[..]);
        assert_eq!(store_ieee_dot3_frame(pkt.chunk()), true);
        assert_eq!(store_ether_frame(pkt.chunk()), false);
        let ethdot3_pkt = EthDot3Packet::parse(pkt).unwrap();

        assert_eq!(ethdot3_pkt.payload_len(), 39);

        let llc_pkt = LlcPacket::parse(ethdot3_pkt.payload()).unwrap();
        assert_eq!(llc_pkt.buf().chunk().len(), 39);
        assert_eq!(llc_pkt.dsap(), BPDU_CONST);
        assert_eq!(llc_pkt.ssap(), BPDU_CONST);
        assert_eq!(llc_pkt.control(), 0x03);

        let payload = llc_pkt.payload();
        let res = StpMessageGroup::group_parse(payload.chunk()).unwrap();
        match res {
            StpMessageGroup::RstpConf(msg) => {
                assert_eq!(msg.proto_id(), 0);
                assert_eq!(msg.version(), StpVersion::RSTP);
                assert_eq!(msg.type_(), StpType::RSTP_OR_MSTP);

                assert_eq!(msg.flag(), 0x3d);
                let root_id = msg.root_id();
                assert_eq!(root_id, 0x6001000d65adf600);
                assert_eq!(msg.root_priority(), 24576);
                assert_eq!(msg.root_sys_id_ext(), 1);
                assert_eq!(
                    msg.root_mac_addr(),
                    EtherAddr::parse_from("00:0d:65:ad:f6:00").unwrap()
                );

                assert_eq!(msg.path_cost(), 0x0a);

                let bridge_id = msg.bridge_id();
                assert_eq!(bridge_id, 0x8001000bfd860f00);
                assert_eq!(msg.bridge_priority(), 32768);
                assert_eq!(msg.bridge_sys_id_ext(), 1);
                assert_eq!(
                    msg.bridge_mac_addr(),
                    EtherAddr::parse_from("00:0b:fd:86:0f:00").unwrap()
                );
                assert_eq!(msg.port_id(), 0x8001);
                assert_eq!(msg.msg_age(), 1);
                assert_eq!(msg.max_age(), 20);
                assert_eq!(msg.hello_time(), 2);
                assert_eq!(msg.forward_delay(), 15);
                assert_eq!(msg.version1_len(), 0);
            }
            _ => panic!(),
        }
    }
}

#[test]
fn rapid_stp_creation_tests() {
    let mut buf: [u8; 64] = [0; 64];

    let mut pkt_buf = CursorMut::new(
        &mut buf[..ETHER_HEADER_LEN + LLC_HEADER_LEN + RSTPCONFBPDU_HEADER_ARRAY.len()],
    );
    pkt_buf.advance(ETHER_HEADER_LEN + LLC_HEADER_LEN);

    let mut rstp_conf_msg = RstpConfBpduMessage::build_message(pkt_buf.chunk_mut());
    rstp_conf_msg.set_flag(0x3d);
    rstp_conf_msg.set_root_id(0x6001000d65adf600);
    rstp_conf_msg.set_path_cost(0x0a);
    rstp_conf_msg.set_bridge_id(0x8001000bfd860f00);
    rstp_conf_msg.set_port_id(0x8001);
    rstp_conf_msg.set_msg_age(1);
    rstp_conf_msg.set_max_age(20);
    rstp_conf_msg.set_hello_time(2);
    rstp_conf_msg.set_forward_delay(15);
    rstp_conf_msg.set_version1_len(0);

    let llc_pkt = LlcPacket::prepend_header(pkt_buf, &LLC_HEADER_TEMPLATE);
    let mut eth_pkt = EthDot3Packet::prepend_header(llc_pkt.release(), &ETHDOT3_HEADER_TEMPLATE);
    eth_pkt.set_dst_addr(EtherAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]));
    eth_pkt.set_src_addr(EtherAddr([0x00, 0x01, 0x01, 0x00, 0x00, 0x01]));

    let target = file_to_packet("StpRapid.dat");
    assert_eq!(
        eth_pkt.release().chunk(),
        &target[..ETHER_HEADER_LEN + LLC_HEADER_LEN + RSTPCONFBPDU_HEADER_ARRAY.len()]
    );
}
