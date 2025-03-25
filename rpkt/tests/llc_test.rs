mod common;
use common::*;

use rpkt::arp::*;
use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::llc::*;
use rpkt::stp::*;
use rpkt::vlan::*;
use rpkt::Buf;
use rpkt::PktBufMut;
use rpkt::{Cursor, CursorMut};

#[test]
fn llc_parsing_test() {
    {
        let packet = file_to_packet("StpConf.dat");
        to_hex_dump("StpConf.dat");

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
        assert_eq!(matches!(res, StpMessageGroup::StpConf(_)), true);
    }

    {
        let pkt = file_to_packet("llc_vlan.dat");
        let pkt = Cursor::new(&pkt[..]);

        let eth_pkt = EtherPacket::parse(pkt).unwrap();
        assert_eq!(eth_pkt.ethertype(), EtherType::VLAN);

        let eth_payload = eth_pkt.payload();
        assert_eq!(vlan_tag_for_dot3_frame(eth_payload.chunk()), true);
        assert_eq!(vlan_tag_for_ether_frame(eth_payload.chunk()), false);

        let vlan_dot3 = VlanDot3Packet::parse(eth_payload).unwrap();
        assert_eq!(vlan_dot3.payload_len(), 357);

        let llc_pkt = LlcPacket::parse(vlan_dot3.payload()).unwrap();
        assert_eq!(llc_pkt.ssap(), 0xaa);
        assert_eq!(llc_pkt.dsap(), 0xaa);
        assert_eq!(llc_pkt.control(), 0x03);
    }
}

#[test]
fn llc_creation_test() {
    let mut buf: [u8; 64] = [0; 64];

    let mut pkt_buf = CursorMut::new(
        &mut buf[..ETHER_HEADER_LEN + LLC_HEADER_LEN + STPCONFBPDU_HEADER_ARRAY.len()],
    );
    pkt_buf.advance(ETHER_HEADER_LEN + LLC_HEADER_LEN);

    let mut stp_conf_msg = StpConfBpduMessage::build_message(pkt_buf.chunk_mut());
    let buf = [0x80, 0x64, 0x00, 0x1c, 0x0e, 0x87, 0x78, 0x00];
    let bridge_id = BridgeId::from_bytes(&buf[..]);
    assert_eq!(bridge_id.priority(), 32768);
    assert_eq!(bridge_id.sys_id_ext(), 100);
    assert_eq!(
        bridge_id.mac_addr(),
        EtherAddr([0x00, 0x1c, 0x0e, 0x87, 0x78, 0x00])
    );
    stp_conf_msg.set_root_id(bridge_id);
    stp_conf_msg.set_path_cost(4);
    let buf = [0x80, 0x64, 0x00, 0x1c, 0x0e, 0x87, 0x85, 0x00];
    let bridge_id = BridgeId::from_bytes(&buf[..]);
    stp_conf_msg.set_bridge_id(bridge_id);
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
