mod common;
use common::*;

use rpkt::ether::*;
use rpkt::llc::*;
use rpkt::stp::*;
use rpkt::vlan::*;
use rpkt::Buf;
use rpkt::{Cursor, CursorMut};

#[test]
fn llc_parsing_test() {
    {
        let packet = file_to_packet("StpConf.dat");

        let pkt = Cursor::new(&packet[..]);

        let ethdot3_pkt = match EtherGroup::group_parse(pkt).unwrap() {
            EtherGroup::EtherDot3Frame_(pkt) => pkt,
            _ => {
                assert!(false);
                panic!()
            }
        };

        assert_eq!(ethdot3_pkt.payload_len(), 38);

        let llc_pkt = Llc::parse(ethdot3_pkt.payload()).unwrap();
        assert_eq!(llc_pkt.buf().chunk().len(), 38);
        assert_eq!(llc_pkt.dsap(), BPDU_CONST);
        assert_eq!(llc_pkt.ssap(), BPDU_CONST);
        assert_eq!(llc_pkt.control(), 0x03);

        let payload = llc_pkt.payload();
        let res = StpGroup::group_parse(payload.chunk()).unwrap();
        assert_eq!(matches!(res, StpGroup::StpConfBpdu_(_)), true);
    }

    {
        let pkt = file_to_packet("llc_vlan.dat");
        let pkt = Cursor::new(&pkt[..]);

        let eth_pkt = EtherFrame::parse(pkt).unwrap();
        assert_eq!(eth_pkt.ethertype(), EtherType::VLAN);

        let eth_payload = eth_pkt.payload();
        let vlan_dot3 = match VlanGroup::group_parse(eth_payload).unwrap() {
            VlanGroup::VlanDot3Frame_(pkt) => pkt,
            _ => {
                assert!(false);
                panic!()
            }
        };

        assert_eq!(vlan_dot3.payload_len(), 357);

        let llc_pkt = Llc::parse(vlan_dot3.payload()).unwrap();
        assert_eq!(llc_pkt.ssap(), 0xaa);
        assert_eq!(llc_pkt.dsap(), 0xaa);
        assert_eq!(llc_pkt.control(), 0x03);
    }
}

#[test]
fn llc_creation_test() {
    let mut buf: [u8; 64] = [0; 64];

    let mut pkt_buf =
        CursorMut::new(&mut buf[..ETHERFRAME_HEADER_LEN + LLC_HEADER_LEN + STPCONFBPDU_HEADER_LEN]);
    pkt_buf.advance(ETHERFRAME_HEADER_LEN + LLC_HEADER_LEN + STPCONFBPDU_HEADER_LEN);

    let mut stp_conf_msg = StpConfBpdu::prepend_header(pkt_buf, &STPCONFBPDU_HEADER_TEMPLATE);
    stp_conf_msg.set_root_priority(32768);
    stp_conf_msg.set_root_sys_id_ext(100);
    stp_conf_msg.set_root_mac_addr(EtherAddr([0x00, 0x1c, 0x0e, 0x87, 0x78, 0x00]));
    stp_conf_msg.set_path_cost(4);
    stp_conf_msg.set_bridge_priority(32768);
    stp_conf_msg.set_bridge_sys_id_ext(100);
    stp_conf_msg.set_bridge_mac_addr(EtherAddr([0x00, 0x1c, 0x0e, 0x87, 0x85, 0x00]));
    stp_conf_msg.set_port_id(0x8004);
    stp_conf_msg.set_msg_age(1);
    stp_conf_msg.set_max_age(20);
    stp_conf_msg.set_hello_time(2);
    stp_conf_msg.set_forward_delay(15);

    let llc_pkt = Llc::prepend_header(stp_conf_msg.release(), &LLC_HEADER_TEMPLATE);
    let mut eth_pkt =
        EtherDot3Frame::prepend_header(llc_pkt.release(), &ETHERDOT3FRAME_HEADER_TEMPLATE);
    eth_pkt.set_dst_addr(EtherAddr([0x01, 0x80, 0xc2, 0x00, 0x00, 0x00]));
    eth_pkt.set_src_addr(EtherAddr([0x00, 0x1c, 0x0e, 0x87, 0x85, 0x04]));

    let target = file_to_packet("StpConf.dat");
    assert_eq!(
        eth_pkt.release().chunk(),
        &target[..ETHERDOT3FRAME_HEADER_LEN + LLC_HEADER_LEN + STPCONFBPDU_HEADER_LEN]
    );
}
