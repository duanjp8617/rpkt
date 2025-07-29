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

    let uli_var_header = uli::UliVarHeader::try_from(&ie).unwrap();
    assert_eq!(uli_var_header.extended_macro_enodeb_id.is_none(), true);
    assert_eq!(uli_var_header.macro_enodeb_id.is_none(), true);
    assert_eq!(uli_var_header.lai.is_none(), true);
    assert_eq!(uli_var_header.rai.is_none(), true);
    assert_eq!(uli_var_header.sai.is_none(), true);
    assert_eq!(uli_var_header.cgi.is_none(), true);

    let tai = uli_var_header.tai.unwrap();
    assert_eq!(tai.tracking_area_code(), 0x2e18);
    assert_eq!(tai.mcc1(), 4);
    assert_eq!(tai.mcc2(), 6);
    assert_eq!(tai.mcc3(), 6);
    assert_eq!(tai.mnc1(), 9);
    assert_eq!(tai.mnc2(), 2);
    assert_eq!(tai.mnc3(), 0xf);

    let ecgi = uli_var_header.ecgi.unwrap();
    assert_eq!(ecgi.e_utran_cell_identifier(), 30303777);
    assert_eq!(ecgi.mcc1(), 4);
    assert_eq!(ecgi.mcc2(), 6);
    assert_eq!(ecgi.mcc3(), 6);
    assert_eq!(ecgi.mnc1(), 9);
    assert_eq!(ecgi.mnc2(), 2);
    assert_eq!(ecgi.mnc3(), 0xf);

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

    let uli_var_header = uli::UliVarHeaderMut::try_from(&mut ie).unwrap();
    assert_eq!(uli_var_header.extended_macro_enodeb_id.is_none(), true);
    assert_eq!(uli_var_header.macro_enodeb_id.is_none(), true);
    assert_eq!(uli_var_header.lai.is_none(), true);
    assert_eq!(uli_var_header.rai.is_none(), true);
    assert_eq!(uli_var_header.sai.is_none(), true);
    assert_eq!(uli_var_header.cgi.is_none(), true);

    let mut tai = uli_var_header.tai.unwrap();
    tai.set_tracking_area_code(0x2e18);
    tai.set_mcc1(4);
    tai.set_mcc2(6);
    tai.set_mcc3(6);
    tai.set_mnc1(9);
    tai.set_mnc2(2);
    tai.set_mnc3(0xf);

    let mut ecgi = uli_var_header.ecgi.unwrap();
    ecgi.set_e_utran_cell_identifier(30303777);
    ecgi.set_mcc1(4);
    ecgi.set_mcc2(6);
    ecgi.set_mcc3(6);
    ecgi.set_mnc1(9);
    ecgi.set_mnc2(2);
    ecgi.set_mnc3(0xf);

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

#[test]
fn gtpv2_with_piggyback_parse() {
    let pkt = file_to_packet("gtpv2-with-piggyback.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::UDP);

    let udp = Udp::parse(ipv4.payload()).unwrap();
    assert_eq!(udp.src_port(), 2123);

    let gtp = Gtpv2::parse(udp.payload()).unwrap();
    assert_eq!(gtp.version(), 2);
    assert_eq!(gtp.piggybacking_flag(), true);
    assert_eq!(gtp.teid_present(), false);
    assert_eq!(gtp.message_priority_present(), false);
    assert_eq!(gtp.message_type(), 1);
    assert_eq!(gtp.packet_len() as usize, GTPV2_HEADER_LEN + 9);
    assert_eq!(gtp.seq_number(), 12345);
    assert_eq!(gtp.spare_last(), 0);

    {
        let ie = match Gtpv2IEGroup::group_parse(gtp.payload()).unwrap() {
            Gtpv2IEGroup::RecoveryIE_(pkt) => pkt,
            _ => panic!(),
        };
        assert_eq!(ie.var_header_slice()[0], 17);
    }

    let mut after_current_msg = *gtp.buf();
    after_current_msg.advance(gtp.packet_len() as usize);

    let gtp = Gtpv2::parse(after_current_msg).unwrap();
    assert_eq!(gtp.version(), 2);
    assert_eq!(gtp.piggybacking_flag(), false);
    assert_eq!(gtp.teid_present(), true);
    assert_eq!(gtp.message_priority_present(), true);
    assert_eq!(gtp.message_type(), 33);
    assert_eq!(gtp.packet_len() as usize, GTPV2_HEADER_LEN + 20);
    assert_eq!(gtp.teid(), 87654);
    assert_eq!(gtp.seq_number(), 67890);
    assert_eq!(gtp.message_priority(), 0x9);
    assert_eq!(gtp.spare_last(), 0);

    let ie = match Gtpv2IEGroup::group_parse(gtp.payload()).unwrap() {
        Gtpv2IEGroup::InternationalMobileSubscriberIdIE_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(
        ie.var_header_slice(),
        &[0x33, 0x87, 0x93, 0x34, 0x49, 0x51, 0x83, 0xf6]
    );
    assert_eq!(ie.payload().chunk().len(), 0);
}

#[test]
fn gtpv2_with_piggyback_build() {
    let pkt = file_to_packet("gtpv2-with-piggyback.dat");
    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    let mut hdr = InternationalMobileSubscriberIdIE::default_header();
    InternationalMobileSubscriberIdIE::from_header_array_mut(&mut hdr)
        .set_header_len((INTERNATIONAL_MOBILE_SUBSCRIBER_ID_IE_HEADER_LEN + 8) as u32);
    let mut ie = InternationalMobileSubscriberIdIE::prepend_header(pbuf, &hdr);
    ie.var_header_slice_mut()
        .copy_from_slice(&[0x33, 0x87, 0x93, 0x34, 0x49, 0x51, 0x83, 0xf6]);

    let mut hdr = Gtpv2::default_header();
    Gtpv2::from_header_array_mut(&mut hdr).set_piggybacking_flag(false);
    Gtpv2::from_header_array_mut(&mut hdr).set_teid_present(true);
    Gtpv2::from_header_array_mut(&mut hdr).set_message_priority_present(true);
    let mut gtp_pkt = Gtpv2::prepend_header(ie.release(), &hdr);
    gtp_pkt.set_message_type(33);
    gtp_pkt.set_teid(87654);
    gtp_pkt.set_seq_number(67890);
    gtp_pkt.set_message_priority(0x9);

    let cursor = gtp_pkt.release().cursor();
    let mut pbuf = CursorMut::new(&mut buf[..cursor]);
    pbuf.advance(cursor);

    let mut hdr = RecoveryIE::default_header();
    RecoveryIE::from_header_array_mut(&mut hdr).set_header_len((RECOVERY_IE_HEADER_LEN + 1) as u32);
    let mut ie = RecoveryIE::prepend_header(pbuf, &hdr);
    ie.var_header_slice_mut()[0] = 17;

    let mut hdr = Gtpv2::default_header();
    Gtpv2::from_header_array_mut(&mut hdr).set_piggybacking_flag(true);
    Gtpv2::from_header_array_mut(&mut hdr).set_teid_present(false);
    Gtpv2::from_header_array_mut(&mut hdr).set_message_priority_present(false);
    let mut gtp_pkt = Gtpv2::prepend_header(ie.release(), &hdr);
    gtp_pkt.set_message_type(1);
    gtp_pkt.set_seq_number(12345);
    gtp_pkt.set_spare_last(0);

    let first_msg_len = gtp_pkt.release().chunk().len();
    let payload_len = buf.len() - cursor + first_msg_len;
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600 - payload_len);

    let mut udp = Udp::prepend_header(pbuf, &UDP_HEADER_TEMPLATE);
    udp.set_src_port(2123);
    udp.set_dst_port(2123);
    udp.set_checksum(0x92d3);

    let mut ipv4 = Ipv4::prepend_header(udp.release(), &IPV4_HEADER_TEMPLATE);
    ipv4.set_dscp(0);
    ipv4.set_ecn(0);
    ipv4.set_ident(1);
    ipv4.set_ttl(64);
    ipv4.set_protocol(IpProtocol::UDP);
    ipv4.set_checksum(0xf62e);
    ipv4.set_src_addr(Ipv4Addr::from_str("192.168.1.100").unwrap());
    ipv4.set_dst_addr(Ipv4Addr::from_str("192.168.1.200").unwrap());

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0x08, 0xb4, 0xb1, 0x1a, 0x46, 0xad]));
    eth.set_src_addr(EtherAddr([0x10, 0x5b, 0xad, 0xb0, 0xf5, 0x07]));
    eth.set_ethertype(EtherType::IPV4);

    assert_eq!(eth.release().chunk(), &pkt);
}
