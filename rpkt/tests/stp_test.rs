mod common;
use common::*;

use rpkt::ether::*;
use rpkt::llc::*;
use rpkt::stp::*;
use rpkt::Buf;
use rpkt::{Cursor, CursorMut};

#[test]
fn stp_configuration_parsing_tests() {
    {
        let packet = file_to_packet("StpConf.dat");

        let pkt = Cursor::new(&packet[..]);
        let ethdot3_pkt = match EtherGroup::group_parse(pkt).unwrap() {
            EtherGroup::EtherDot3Frame_(f) => f,
            _ => panic!(),
        };

        assert_eq!(ethdot3_pkt.payload_len(), 38);

        let llc_pkt = Llc::parse(ethdot3_pkt.payload()).unwrap();
        assert_eq!(llc_pkt.buf().chunk().len(), 38);
        assert_eq!(llc_pkt.dsap(), BPDU_CONST);
        assert_eq!(llc_pkt.ssap(), BPDU_CONST);
        assert_eq!(llc_pkt.control(), 0x03);

        let payload = llc_pkt.payload();
        let res = StpGroup::group_parse(payload.chunk()).unwrap();
        match res {
            StpGroup::StpConfBpdu_(msg) => {
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
        &mut buf[..ETHER_FRAME_HEADER_LEN + LLC_HEADER_LEN + STP_CONF_BPDU_HEADER_LEN],
    );
    pkt_buf.advance(ETHER_FRAME_HEADER_LEN + LLC_HEADER_LEN + STP_CONF_BPDU_HEADER_LEN);

    let mut stp_conf_msg = StpConfBpdu::prepend_header(pkt_buf, &STP_CONF_BPDU_HEADER_TEMPLATE);
    stp_conf_msg.set_root_id(0x8064001c0e877800);
    stp_conf_msg.set_path_cost(4);
    stp_conf_msg.set_bridge_id(0x8064001c0e878500);
    stp_conf_msg.set_port_id(0x8004);
    stp_conf_msg.set_msg_age(1);
    stp_conf_msg.set_max_age(20);
    stp_conf_msg.set_hello_time(2);
    stp_conf_msg.set_forward_delay(15);

    let llc_pkt = Llc::prepend_header(stp_conf_msg.release(), &LLC_HEADER_TEMPLATE);
    let mut eth_pkt =
        EtherDot3Frame::prepend_header(llc_pkt.release(), &ETHER_DOT3_FRAME_HEADER_TEMPLATE);
    eth_pkt.set_dst_addr(EtherAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]));
    eth_pkt.set_src_addr(EtherAddr([0x00, 0x1c, 0x0e, 0x87, 0x85, 0x04]));

    let target = file_to_packet("StpConf.dat");
    assert_eq!(
        eth_pkt.release().chunk(),
        &target[..ETHER_FRAME_HEADER_LEN + LLC_HEADER_LEN + STP_CONF_BPDU_HEADER_LEN]
    );
}

#[test]
fn stp_configuration_edit_tests() {
    let mut edited_packet = file_to_packet("StpConf.dat");

    let pkt = CursorMut::new(&mut edited_packet[..]);
    let ethdot3_pkt = match EtherGroup::group_parse(pkt).unwrap() {
        EtherGroup::EtherDot3Frame_(f) => f,
        _ => panic!(),
    };

    assert_eq!(ethdot3_pkt.payload_len(), 38);

    let llc_pkt = Llc::parse(ethdot3_pkt.payload()).unwrap();
    assert_eq!(llc_pkt.buf().chunk().len(), 38);
    assert_eq!(llc_pkt.dsap(), BPDU_CONST);
    assert_eq!(llc_pkt.ssap(), BPDU_CONST);
    assert_eq!(llc_pkt.control(), 0x03);

    let payload = llc_pkt.payload();
    let res = StpGroup::group_parse(payload).unwrap();
    let edited_stp_conf = match res {
        StpGroup::StpConfBpdu_(mut msg) => {
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
    let ethdot3_pkt = match EtherGroup::group_parse(pkt).unwrap() {
        EtherGroup::EtherDot3Frame_(f) => f,
        _ => panic!(),
    };

    assert_eq!(ethdot3_pkt.payload_len(), 38);

    let llc_pkt = Llc::parse(ethdot3_pkt.payload()).unwrap();
    assert_eq!(llc_pkt.buf().chunk().len(), 38);
    assert_eq!(llc_pkt.dsap(), BPDU_CONST);
    assert_eq!(llc_pkt.ssap(), BPDU_CONST);
    assert_eq!(llc_pkt.control(), 0x03);

    let payload = llc_pkt.payload();

    assert_eq!(payload.chunk(), edited_stp_conf.chunk());
}

#[test]
fn stp_topology_change_parsing_tests() {
    let packet = file_to_packet("StpTcn.dat");

    let pkt = Cursor::new(&packet[..]);
    let ethdot3_pkt = match EtherGroup::group_parse(pkt).unwrap() {
        EtherGroup::EtherDot3Frame_(f) => f,
        _ => panic!(),
    };

    assert_eq!(ethdot3_pkt.payload_len(), 7);

    let llc_pkt = Llc::parse(ethdot3_pkt.payload()).unwrap();
    assert_eq!(llc_pkt.buf().chunk().len(), 7);
    assert_eq!(llc_pkt.dsap(), BPDU_CONST);
    assert_eq!(llc_pkt.ssap(), BPDU_CONST);
    assert_eq!(llc_pkt.control(), 0x03);

    let payload = llc_pkt.payload();
    let res = StpGroup::group_parse(payload.chunk()).unwrap();
    match res {
        StpGroup::StpTcnBpdu_(msg) => {
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
        &mut buf[..ETHER_FRAME_HEADER_LEN + LLC_HEADER_LEN + STP_TCN_BPDU_HEADER_LEN],
    );
    pkt_buf.advance(ETHER_FRAME_HEADER_LEN + LLC_HEADER_LEN + STP_TCN_BPDU_HEADER_LEN);

    let stptcnbdpu_msg = StpTcnBpdu::prepend_header(pkt_buf, &STP_TCN_BPDU_HEADER_TEMPLATE);

    let llc_pkt = Llc::prepend_header(stptcnbdpu_msg.release(), &LLC_HEADER_TEMPLATE);
    let mut eth_pkt =
        EtherDot3Frame::prepend_header(llc_pkt.release(), &ETHER_DOT3_FRAME_HEADER_TEMPLATE);
    eth_pkt.set_dst_addr(EtherAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]));
    eth_pkt.set_src_addr(EtherAddr([0xaa, 0xbb, 0xcc, 0x00, 0x02, 0x00]));

    let target = file_to_packet("StpTcn.dat");
    assert_eq!(
        eth_pkt.release().chunk(),
        &target[..ETHER_DOT3_FRAME_HEADER_LEN + LLC_HEADER_LEN + STP_TCN_BPDU_HEADER_LEN]
    );
}

#[test]
fn rapid_stp_parsing_tests() {
    {
        let packet = file_to_packet("StpRapid.dat");

        let pkt = Cursor::new(&packet[..]);
        let ethdot3_pkt = match EtherGroup::group_parse(pkt).unwrap() {
            EtherGroup::EtherDot3Frame_(f) => f,
            _ => panic!(),
        };

        assert_eq!(ethdot3_pkt.payload_len(), 39);

        let llc_pkt = Llc::parse(ethdot3_pkt.payload()).unwrap();
        assert_eq!(llc_pkt.buf().chunk().len(), 39);
        assert_eq!(llc_pkt.dsap(), BPDU_CONST);
        assert_eq!(llc_pkt.ssap(), BPDU_CONST);
        assert_eq!(llc_pkt.control(), 0x03);

        let payload = llc_pkt.payload();
        let res = StpGroup::group_parse(payload.chunk()).unwrap();
        match res {
            StpGroup::RstpConfBpdu_(msg) => {
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
    let mut buf: [u8; 256] = [0; 256];

    let mut pkt_buf = CursorMut::new(
        &mut buf[..ETHER_FRAME_HEADER_LEN + LLC_HEADER_LEN + RSTP_CONF_BPDU_HEADER_LEN],
    );
    pkt_buf.advance(ETHER_FRAME_HEADER_LEN + LLC_HEADER_LEN + RSTP_CONF_BPDU_HEADER_LEN);

    let mut rstp_conf_msg = RstpConfBpdu::prepend_header(pkt_buf, &RSTP_CONF_BPDU_HEADER_TEMPLATE);
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

    let llc_pkt = Llc::prepend_header(rstp_conf_msg.release(), &LLC_HEADER_TEMPLATE);
    let mut eth_pkt =
        EtherDot3Frame::prepend_header(llc_pkt.release(), &ETHER_DOT3_FRAME_HEADER_TEMPLATE);
    eth_pkt.set_dst_addr(EtherAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]));
    eth_pkt.set_src_addr(EtherAddr([0x00, 0x01, 0x01, 0x00, 0x00, 0x01]));

    let target = file_to_packet("StpRapid.dat");
    assert_eq!(
        eth_pkt.release().chunk(),
        &target[..ETHER_DOT3_FRAME_HEADER_LEN + LLC_HEADER_LEN + RSTP_CONF_BPDU_HEADER_LEN]
    );
}

#[test]
fn multiple_stp_parsing_tests() {
    {
        let packet = file_to_packet("StpMultiple.dat");

        let pkt = Cursor::new(&packet[..]);
        let ethdot3_pkt = match EtherGroup::group_parse(pkt).unwrap() {
            EtherGroup::EtherDot3Frame_(f) => f,
            _ => panic!(),
        };

        assert_eq!(ethdot3_pkt.payload_len(), 121);

        let llc_pkt = Llc::parse(ethdot3_pkt.payload()).unwrap();
        assert_eq!(llc_pkt.buf().chunk().len(), 121);
        assert_eq!(llc_pkt.dsap(), BPDU_CONST);
        assert_eq!(llc_pkt.ssap(), BPDU_CONST);
        assert_eq!(llc_pkt.control(), 0x03);

        let payload = llc_pkt.payload();
        let res = StpGroup::group_parse(payload.chunk()).unwrap();
        match res {
            StpGroup::MstpConfBpdu_(msg) => {
                assert_eq!(msg.proto_id(), 0);
                assert_eq!(msg.version(), StpVersion::MSTP);
                assert_eq!(msg.type_(), StpType::RSTP_OR_MSTP);

                assert_eq!(msg.flag(), 0x7c);
                let root_id = msg.root_id();
                assert_eq!(root_id, 0x8000000c305dd100);
                assert_eq!(msg.root_priority(), 32768);
                assert_eq!(msg.root_sys_id_ext(), 0);
                assert_eq!(
                    msg.root_mac_addr(),
                    EtherAddr::parse_from("00:0c:30:5d:d1:00").unwrap()
                );

                assert_eq!(msg.path_cost(), 0x0);

                let bridge_id = msg.bridge_id();
                assert_eq!(bridge_id, 0x8000000c305dd100);
                assert_eq!(msg.bridge_priority(), 32768);
                assert_eq!(msg.bridge_sys_id_ext(), 0);
                assert_eq!(
                    msg.bridge_mac_addr(),
                    EtherAddr::parse_from("00:0c:30:5d:d1:00").unwrap()
                );
                assert_eq!(msg.port_id(), 0x8005);
                assert_eq!(msg.msg_age(), 0);
                assert_eq!(msg.max_age(), 20);
                assert_eq!(msg.hello_time(), 2);
                assert_eq!(msg.forward_delay(), 15);
                assert_eq!(msg.version1_len(), 0);
                assert_eq!(msg.version3_len(), 80);

                assert_eq!(
                    msg.header_len() as usize,
                    MSTP_CONF_BPDU_HEADER_LEN + MSTI_CONF_HEADER_LEN
                );

                assert_eq!(msg.mst_config_format_selector(), 0x0);
                assert_eq!(msg.mst_config_name(), &[0; 256 / 8][..]);
                assert_eq!(msg.mst_config_revision(), 0);
                assert_eq!(
                    msg.mst_config_digest(),
                    &[
                        0x55, 0xbf, 0x4e, 0x8a, 0x44, 0xb2, 0x5d, 0x44, 0x28, 0x68, 0x54, 0x9c,
                        0x1b, 0xf7, 0x72, 0x0f
                    ][..]
                );
                assert_eq!(msg.irpc(), 200000);
                assert_eq!(msg.cist_bridge_id(), 0x8000001aa197d180);
                assert_eq!(msg.cist_bridge_priority(), 32768);
                assert_eq!(msg.cist_bridge_sys_id_ext(), 0);
                assert_eq!(
                    msg.cist_bridge_mac_addr(),
                    EtherAddr::parse_from("00:1a:a1:97:d1:80").unwrap()
                );
                assert_eq!(msg.remain_id(), 19);

                assert_eq!(msg.num_of_msti_msg(), Some(1));

                let msti_msg = msg.msti_conf(0);
                assert_eq!(msti_msg.flags(), 0x7c);
                assert_eq!(msti_msg.regional_root_id(), 0x8005000c305dd100);
                assert_eq!(msti_msg.regional_root_priority(), 8 * 4096);
                assert_eq!(msti_msg.regional_root_sys_id_ext(), 5);
                assert_eq!(
                    msti_msg.regional_root_mac_addr(),
                    EtherAddr::parse_from("00:0c:30:5d:d1:00").unwrap()
                );
                assert_eq!(msti_msg.path_cost(), 200000);
                assert_eq!(msti_msg.bridge_priority(), 8 << 4);
                assert_eq!(msti_msg.port_priority(), 8 << 4);
                assert_eq!(msti_msg.remaining_hops(), 19);
            }
            _ => panic!(),
        }
    }
}

#[test]
fn multiple_stp_creation_tests() {
    let mut buf: [u8; 256] = [0; 256];

    let mut pkt_buf = CursorMut::new(
        &mut buf[..ETHER_DOT3_FRAME_HEADER_LEN
            + LLC_HEADER_LEN
            + MSTP_CONF_BPDU_HEADER_LEN
            + MSTI_CONF_HEADER_LEN],
    );
    pkt_buf.advance(
        ETHER_DOT3_FRAME_HEADER_LEN
            + LLC_HEADER_LEN
            + MSTP_CONF_BPDU_HEADER_LEN
            + MSTI_CONF_HEADER_LEN,
    );

    let mut mstp_conf_bpdu_header = MSTP_CONF_BPDU_HEADER_TEMPLATE.clone();
    MstpConfBpdu::from_header_array_mut(&mut mstp_conf_bpdu_header)
        .set_header_len((MSTP_CONF_BPDU_HEADER_LEN + MSTI_CONF_HEADER_LEN) as u32);
    let mut msg = MstpConfBpdu::prepend_header(pkt_buf, &mstp_conf_bpdu_header);
    assert_eq!(
        msg.buf().chunk().len(),
        MSTP_CONF_BPDU_HEADER_LEN + MSTI_CONF_HEADER_LEN
    );

    msg.set_flag(0x7c);
    msg.set_root_id(0x8000000c305dd100);
    msg.set_path_cost(0x0);
    msg.set_bridge_id(0x8000000c305dd100);
    msg.set_port_id(0x8005);
    msg.set_msg_age(0);
    msg.set_max_age(20);
    msg.set_hello_time(2);
    msg.set_forward_delay(15);
    msg.set_version1_len(0);
    assert_eq!(msg.version3_len(), 80);

    msg.set_mst_config_format_selector(0x0);
    msg.set_mst_config_name(&[0; 256 / 8][..]);
    msg.set_mst_config_revision(0);
    msg.set_mst_config_digest(
        &[
            0x55, 0xbf, 0x4e, 0x8a, 0x44, 0xb2, 0x5d, 0x44, 0x28, 0x68, 0x54, 0x9c, 0x1b, 0xf7,
            0x72, 0x0f,
        ][..],
    );
    msg.set_irpc(200000);
    msg.set_cist_bridge_id(0x8000001aa197d180);
    msg.set_remain_id(19);

    assert_eq!(msg.num_of_msti_msg(), Some(1));

    let mut msti_msg = msg.msti_conf_message_mut(0);
    msti_msg.set_flags(0x7c);
    msti_msg.set_regional_root_id(0x8005000c305dd100);
    msti_msg.set_path_cost(200000);
    msti_msg.set_bridge_priority(8 << 4);
    msti_msg.set_port_priority(8 << 4);
    msti_msg.set_remaining_hops(19);

    let llc_pkt = Llc::prepend_header(msg.release(), &LLC_HEADER_TEMPLATE);
    let mut eth_pkt =
        EtherDot3Frame::prepend_header(llc_pkt.release(), &ETHER_DOT3_FRAME_HEADER_TEMPLATE);
    eth_pkt.set_dst_addr(EtherAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]));
    eth_pkt.set_src_addr(EtherAddr([0x00, 0x1a, 0xa1, 0x97, 0xd1, 0x85]));

    let target = file_to_packet("StpMultiple.dat");
    assert_eq!(
        eth_pkt.release().chunk(),
        &target[..ETHER_DOT3_FRAME_HEADER_LEN
            + LLC_HEADER_LEN
            + MSTP_CONF_BPDU_HEADER_LEN
            + MSTI_CONF_HEADER_LEN]
    );
}
