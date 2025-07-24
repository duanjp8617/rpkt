mod common;
use std::net::Ipv4Addr;
use std::str::FromStr;

use common::*;

use rpkt::ether::*;
use rpkt::gtpv2::gtpv2_information_elements::*;
use rpkt::gtpv2::*;
use rpkt::ipv4::*;
use rpkt::udp::*;
use rpkt::Buf;
use rpkt::{Cursor, CursorMut};

#[test]
fn gtpv2_with_teid_parse() {
    let pkt = file_to_packet("gtpv2-with-teid.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::UDP);

    let udp = Udp::parse(ipv4.payload()).unwrap();
    assert_eq!(udp.src_port(), 2123);

    let gtp = Gtpv2::parse(udp.payload()).unwrap();
    assert_eq!(gtp.version(), 2);
    assert_eq!(gtp.piggybacking_flag(), false);
    assert_eq!(gtp.teid_present(), true);
    assert_eq!(gtp.message_priority_present(), false);
    assert_eq!(gtp.message_type(), 34);
    assert_eq!(gtp.packet_len() as usize, GTPV2_HEADER_LEN + 107);
    assert_eq!(gtp.teid(), 0xd37d1590);
    assert_eq!(gtp.seq_number(), 0x1a4a43);

    let ie = match Gtpv2IEGroup::group_parse(gtp.payload()).unwrap() {
        Gtpv2IEGroup::UserLocationInfoIE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ie.type_(), 86);
    assert_eq!(ie.ecgi(), true);
    assert_eq!(ie.tai(), true);
    assert_eq!(
        ie.var_header_slice().len(),
        ie.header_len() as usize - USER_LOCATION_INFO_IE_HEADER_LEN
    );
    assert_eq!(
        ie.var_header_slice(),
        &[0x64, 0xf6, 0x29, 0x2e, 0x18, 0x64, 0xf6, 0x29, 0x01, 0xce, 0x66, 0x21,][..]
    );

    let ie = match Gtpv2IEGroup::group_parse(ie.payload()).unwrap() {
        Gtpv2IEGroup::ServingNetworkIE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ie.len(), 3);
    assert_eq!(ie.mcc_digit1(), 4);
    assert_eq!(ie.mcc_digit2(), 6);
    assert_eq!(ie.mcc_digit3(), 6);
    assert_eq!(ie.mnc_digit1(), 9);
    assert_eq!(ie.mnc_digit2(), 2);
    assert_eq!(ie.mnc_digit3(), 0xf);

    let ie = match Gtpv2IEGroup::group_parse(ie.payload()).unwrap() {
        Gtpv2IEGroup::RatTypeIE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ie.rat_type(), 6);
    assert_eq!(ie.len(), 1);

    let ie = match Gtpv2IEGroup::group_parse(ie.payload()).unwrap() {
        Gtpv2IEGroup::FullyQualifiedTeidIE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ie.v4(), true);
    assert_eq!(ie.interface_type(), 6);
    assert_eq!(ie.teid_gre_key(), 0xa43ed030);
    assert_eq!(
        Ipv4Addr::new(
            ie.var_header_slice()[0],
            ie.var_header_slice()[1],
            ie.var_header_slice()[2],
            ie.var_header_slice()[3]
        ),
        Ipv4Addr::from_str("111.71.236.49").unwrap()
    );

    let ie = match Gtpv2IEGroup::group_parse(ie.payload()).unwrap() {
        Gtpv2IEGroup::AggregateMaxBitRateIE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ie.apn_ambr_for_uplink(), 2048);
    assert_eq!(ie.apn_ambr_for_downlink(), 2048);
    assert_eq!(ie.len(), 8);

    let ie = match Gtpv2IEGroup::group_parse(ie.payload()).unwrap() {
        Gtpv2IEGroup::MobileEquipmentIdIE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ie.var_header_slice().len(), 8);
    assert_eq!(
        ie.var_header_slice(),
        &[0x53, 0x02, 0x89, 0x70, 0x72, 0x61, 0x23, 0x60][..]
    );

    let ie = match Gtpv2IEGroup::group_parse(ie.payload()).unwrap() {
        Gtpv2IEGroup::UeTimeZoneIE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ie.time_zone(), 0x23);
    assert_eq!(ie.daylight_saving_time(), 0);
    assert_eq!(ie.len(), 2);

    let ie = match Gtpv2IEGroup::group_parse(ie.payload()).unwrap() {
        Gtpv2IEGroup::BearerContextIE_(pkt) => pkt,
        _ => panic!(),
    };
    {
        let subpbuf = Cursor::new(ie.var_header_slice());
        let sub_ie = match Gtpv2IEGroup::group_parse(subpbuf).unwrap() {
            Gtpv2IEGroup::EpsBearerIdIE_(pkt) => pkt,
            _ => panic!(),
        };
        assert_eq!(sub_ie.eps_bearer_id(), 5);
        assert_eq!(sub_ie.len(), 1);

        let sub_ie = match Gtpv2IEGroup::group_parse(sub_ie.payload()).unwrap() {
            Gtpv2IEGroup::FullyQualifiedTeidIE_(pkt) => pkt,
            _ => panic!(),
        };
        assert_eq!(sub_ie.v4(), true);
        assert_eq!(sub_ie.interface_type(), 4);
        assert_eq!(sub_ie.teid_gre_key(), 0xa430f3e2);
        assert_eq!(
            Ipv4Addr::new(
                sub_ie.var_header_slice()[0],
                sub_ie.var_header_slice()[1],
                sub_ie.var_header_slice()[2],
                sub_ie.var_header_slice()[3]
            ),
            Ipv4Addr::from_str("111.71.236.67").unwrap()
        );
        assert_eq!(sub_ie.payload().chunk().len(), 0);
    }

    let ie = match Gtpv2IEGroup::group_parse(ie.payload()).unwrap() {
        Gtpv2IEGroup::RecoveryIE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ie.var_header_slice()[0], 18);
}

#[test]
fn gtpv2_with_teid_build() {
    let pkt = file_to_packet("gtpv2-with-teid.dat");
    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    let mut id_hdr = RecoveryIE::default_header();
    RecoveryIE::from_header_array_mut(&mut id_hdr).set_header_len(1 + 4);

    let mut ie = RecoveryIE::prepend_header(pbuf, &id_hdr);
    ie.var_header_slice_mut()[0] = 18;

    let mut id_hdr = BearerContextIE::default_header();
    BearerContextIE::from_header_array_mut(&mut id_hdr).set_header_len(18 + 4);

    let mut ie = BearerContextIE::prepend_header(ie.release(), &id_hdr);
    {
        let mut pbuf = CursorMut::new(ie.var_header_slice_mut());
        pbuf.advance(18);

        let mut id_hdr = FullyQualifiedTeidIE::default_header();
        FullyQualifiedTeidIE::from_header_array_mut(&mut id_hdr).set_header_len(9 + 4);

        let mut ie = FullyQualifiedTeidIE::prepend_header(pbuf, &id_hdr);
        ie.set_v4(true);
        ie.set_interface_type(4);
        ie.set_teid_gre_key(0xa430f3e2);
        ie.var_header_slice_mut().copy_from_slice(
            Ipv4Addr::from_str("111.71.236.67")
                .unwrap()
                .octets()
                .as_slice(),
        );
        ie.set_instance(1);

        let mut ie = EpsBearerIdIE::prepend_header(ie.release(), &EPS_BEARER_ID_IE_HEADER_TEMPLATE);
        ie.set_eps_bearer_id(5);
    }

    let mut ie = UeTimeZoneIE::prepend_header(ie.release(), &UE_TIME_ZONE_IE_HEADER_TEMPLATE);
    ie.set_time_zone(0x23);
    ie.set_daylight_saving_time(0);

    let mut id_hdr = MobileEquipmentIdIE::default_header();
    MobileEquipmentIdIE::from_header_array_mut(&mut id_hdr).set_header_len(8 + 4);

    let mut ie = MobileEquipmentIdIE::prepend_header(ie.release(), &id_hdr);
    ie.var_header_slice_mut()
        .copy_from_slice(&[0x53, 0x02, 0x89, 0x70, 0x72, 0x61, 0x23, 0x60][..]);

    let mut ie = AggregateMaxBitRateIE::prepend_header(
        ie.release(),
        &AGGREGATE_MAX_BIT_RATE_IE_HEADER_TEMPLATE,
    );
    ie.set_apn_ambr_for_downlink(2048);
    ie.set_apn_ambr_for_uplink(2048);

    let mut id_hdr = FullyQualifiedTeidIE::default_header();
    FullyQualifiedTeidIE::from_header_array_mut(&mut id_hdr)
        .set_header_len(4 + FULLY_QUALIFIED_TEID_IE_HEADER_LEN as u32);
    let mut ie = FullyQualifiedTeidIE::prepend_header(ie.release(), &id_hdr);
    ie.set_v4(true);
    ie.set_interface_type(6);
    ie.set_teid_gre_key(0xa43ed030);
    ie.var_header_slice_mut().copy_from_slice(
        Ipv4Addr::from_str("111.71.236.49")
            .unwrap()
            .octets()
            .as_slice(),
    );

    let mut ie = RatTypeIE::prepend_header(ie.release(), &RAT_TYPE_IE_HEADER_TEMPLATE);
    ie.set_rat_type(6);

    let mut ie =
        ServingNetworkIE::prepend_header(ie.release(), &SERVING_NETWORK_IE_HEADER_TEMPLATE);
    ie.set_mcc_digit1(4);
    ie.set_mcc_digit2(6);
    ie.set_mcc_digit3(6);
    ie.set_mnc_digit1(9);
    ie.set_mnc_digit2(2);
    ie.set_mnc_digit3(0xf);

    let mut id_hdr = UserLocationInfoIE::default_header();
    UserLocationInfoIE::from_header_array_mut(&mut id_hdr).set_header_len(4 + 13);
    let mut ie = UserLocationInfoIE::prepend_header(ie.release(), &id_hdr);
    ie.set_ecgi(true);
    ie.set_tai(true);
    ie.var_header_slice_mut().copy_from_slice(
        &[
            0x64, 0xf6, 0x29, 0x2e, 0x18, 0x64, 0xf6, 0x29, 0x01, 0xce, 0x66, 0x21,
        ][..],
    );

    let mut id_hdr = Gtpv2::default_header();
    Gtpv2::from_header_array_mut(&mut id_hdr).set_teid_present(true);
    let mut gtp = Gtpv2::prepend_header(ie.release(), &id_hdr);
    gtp.set_message_type(34);
    gtp.set_teid(0xd37d1590);
    gtp.set_seq_number(1722947);

    let mut udp = Udp::prepend_header(gtp.release(), &UDP_HEADER_TEMPLATE);
    udp.set_src_port(2123);
    udp.set_dst_port(2123);
    udp.set_checksum(0);

    let mut ipv4 = Ipv4::prepend_header(udp.release(), &IPV4_HEADER_TEMPLATE);
    ipv4.set_dscp(26);
    ipv4.set_ecn(0);
    ipv4.set_ident(52414);
    ipv4.set_ttl(61);
    ipv4.set_protocol(IpProtocol::UDP);
    ipv4.set_checksum(0x7afb);
    ipv4.set_src_addr(Ipv4Addr::from_str("111.71.236.49").unwrap());
    ipv4.set_dst_addr(Ipv4Addr::from_str("221.177.252.21").unwrap());

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0x40, 0xb4, 0xf0, 0xd8, 0xd9, 0x3c]));
    eth.set_src_addr(EtherAddr([0x28, 0x8a, 0x1c, 0xcb, 0x07, 0xd9]));
    eth.set_ethertype(EtherType::IPV4);

    assert_eq!(eth.release().chunk(), &pkt);
}
