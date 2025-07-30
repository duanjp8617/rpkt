mod common;
use std::net::Ipv4Addr;
use std::str::FromStr;

use common::*;

use rpkt::ether::*;
use rpkt::ipv4::options::*;
use rpkt::ipv4::*;
use rpkt::network_rw::*;
use rpkt::Buf;
use rpkt::PktBuf;
use rpkt::PktBufMut;
use rpkt::{Cursor, CursorMut};

#[test]
fn ipv4_option1_parse() {
    let pkt = file_to_packet("IPv4Option1.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.header_len(), 44);
    assert_eq!(ipv4.dscp(), 0);
    assert_eq!(ipv4.ecn(), 0);
    assert_eq!(ipv4.ident(), 30775);
    assert_eq!(ipv4.packet_len(), 108);
    assert_eq!(ipv4.dont_frag(), false);
    assert_eq!(ipv4.more_frag(), false);
    assert_eq!(ipv4.ttl(), 64);
    assert_eq!(ipv4.protocol(), IpProtocol::ICMP);
    assert_eq!(ipv4.checksum(), 0x752d);
    assert_eq!(ipv4.src_addr(), Ipv4Addr::from_str("127.0.0.1").unwrap());
    assert_eq!(ipv4.dst_addr(), Ipv4Addr::from_str("127.0.0.1").unwrap());

    let mut option_iter = Ipv4OptionsIter::from_slice(ipv4.var_header_slice());

    let op1 = match option_iter.next().unwrap() {
        Ipv4Options::CommercialSecurity_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(op1.header_len(), 22);
    assert_eq!(op1.doi(), 2);
    let tag = CommercialSecurityTag::parse(op1.var_header_slice()).unwrap();
    assert_eq!(tag.header_len(), 16);
    assert_eq!(tag.tag_type(), 2);
    assert_eq!(tag.sensitivity_level(), 2);
    assert_eq!(
        tag.var_header_slice(),
        &[0, 0, 0, 2, 0, 4, 0, 5, 0, 6, 0, 0xef][..]
    );

    let op2 = match option_iter.next().unwrap() {
        Ipv4Options::Eol_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(op2.type_(), 0);

    let payload = ipv4.payload();

    assert_eq!(&pkt[payload.cursor()..], payload.chunk());
}

#[test]
fn ipv4_option1_build() {
    let pkt = file_to_packet("IPv4Option1.dat");
    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    pbuf.move_back(64);
    pbuf.chunk_mut().copy_from_slice(&pkt[pkt.len() - 64..]);

    let mut hdr = Ipv4::default_header();
    Ipv4::from_header_array_mut(&mut hdr).set_header_len(20 + 2 + 22);
    let mut ipv4 = Ipv4::prepend_header(pbuf, &hdr);
    ipv4.set_ttl(64);
    ipv4.set_ident(30775);
    ipv4.set_protocol(IpProtocol::ICMP);
    ipv4.set_checksum(0x752d);
    ipv4.set_src_addr(Ipv4Addr::from_str("127.0.0.1").unwrap());
    ipv4.set_dst_addr(Ipv4Addr::from_str("127.0.0.1").unwrap());

    {
        let option_pbuf = CursorMut::new(ipv4.var_header_slice_mut());

        let mut cs = CommercialSecurity::parse_unchecked(option_pbuf);
        cs.set_header_len(22);
        cs.set_type_(134);
        cs.set_doi(2);

        let mut tag =
            CommercialSecurityTag::parse_unchecked(CursorMut::new(cs.var_header_slice_mut()));
        tag.set_tag_type(2);
        tag.set_header_len(16);
        tag.set_sensitivity_level(2);
        tag.set_alignment_octet(0);
        tag.var_header_slice_mut()
            .copy_from_slice(&[0, 0, 0, 2, 0, 4, 0, 5, 0, 6, 0, 0xef][..]);

        let mut payload = cs.payload();
        payload.chunk_mut()[..2].copy_from_slice(&[0, 0]);
    }

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_ethertype(EtherType::IPV4);

    assert_eq!(eth.release().chunk(), pkt);
}

#[test]
fn ipv4_option2_parse() {
    // to_hex_dump("IPv4Option2.dat");
    let pkt = file_to_packet("IPv4Option2.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.header_len(), 60);
    assert_eq!(ipv4.dscp(), 0);
    assert_eq!(ipv4.ecn(), 0);
    assert_eq!(ipv4.packet_len(), 124);
    assert_eq!(ipv4.ident(), 33505);
    assert_eq!(ipv4.dont_frag(), true);
    assert_eq!(ipv4.more_frag(), false);
    assert_eq!(ipv4.ttl(), 64);
    assert_eq!(ipv4.protocol(), IpProtocol::ICMP);
    assert_eq!(ipv4.checksum(), 0x0d44);
    assert_eq!(ipv4.src_addr(), Ipv4Addr::from_str("10.0.0.6").unwrap());
    assert_eq!(ipv4.dst_addr(), Ipv4Addr::from_str("10.0.0.138").unwrap());

    let mut option_iter = Ipv4OptionsIter::from_slice(ipv4.var_header_slice());

    let op1 = match option_iter.next().unwrap() {
        Ipv4Options::Timestamp_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(op1.header_len(), 40);
    assert_eq!(op1.pointer(), 9);
    assert_eq!(op1.oflw(), 0);
    assert_eq!(op1.flg(), 0);
    for i in 0..9 {
        let val = read_4_bytes(&op1.var_header_slice()[4 * i..4 * i + 4]);
        if i == 0 {
            assert_eq!(val, 82524601);
        } else {
            assert_eq!(val, 0);
        }
    }

    let payload = ipv4.payload();

    assert_eq!(&pkt[payload.cursor()..], payload.chunk());
}

#[test]
fn ipv4_option2_build() {
    let pkt = file_to_packet("IPv4Option2.dat");
    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    pbuf.move_back(64);
    pbuf.chunk_mut().copy_from_slice(&pkt[pkt.len() - 64..]);

    let mut hdr = Ipv4::default_header();
    Ipv4::from_header_array_mut(&mut hdr).set_header_len(60);
    let mut ipv4 = Ipv4::prepend_header(pbuf, &hdr);
    ipv4.set_dscp(0);
    ipv4.set_ecn(0);
    ipv4.set_ident(33505);
    ipv4.set_dont_frag(true);
    ipv4.set_more_frag(false);
    ipv4.set_ttl(64);
    ipv4.set_protocol(IpProtocol::ICMP);
    ipv4.set_checksum(0x0d44);
    ipv4.set_src_addr(Ipv4Addr::from_str("10.0.0.6").unwrap());
    ipv4.set_dst_addr(Ipv4Addr::from_str("10.0.0.138").unwrap());

    {
        let option_pbuf = CursorMut::new(ipv4.var_header_slice_mut());

        let mut ts = Timestamp::parse_unchecked(option_pbuf);
        ts.set_header_len(40);
        ts.set_type_(68);
        ts.set_pointer(9);
        ts.set_oflw(0);
        ts.set_flg(0);

        for i in 0..9 {
            if i == 0 {
                write_4_bytes(&mut ts.var_header_slice_mut()[4 * i..4 * i + 4], 82524601);
            } else {
                write_4_bytes(&mut ts.var_header_slice_mut()[4 * i..4 * i + 4], 0);
            }
        }
    }

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0xc4, 0x12, 0xf5, 0xff, 0x72, 0xe8]));
    eth.set_src_addr(EtherAddr([0x08, 0x00, 0x27, 0x19, 0x1c, 0x78]));
    eth.set_ethertype(EtherType::IPV4);

    assert_eq!(eth.release().chunk(), pkt);
}

#[test]
fn ipv4_option3_parse() {
    // to_hex_dump("IPv4Option2.dat");
    let pkt = file_to_packet("IPv4Option3.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.header_len(), 24);
    assert_eq!(ipv4.dscp(), 0);
    assert_eq!(ipv4.ecn(), 0);
    assert_eq!(ipv4.packet_len(), 36);
    assert_eq!(ipv4.ident(), 0);
    assert_eq!(ipv4.dont_frag(), true);
    assert_eq!(ipv4.more_frag(), false);
    assert_eq!(ipv4.ttl(), 1);
    assert_eq!(ipv4.protocol(), IpProtocol::IGMP);
    assert_eq!(ipv4.checksum(), 0xfa48);
    assert_eq!(ipv4.src_addr(), Ipv4Addr::from_str("10.0.0.138").unwrap());
    assert_eq!(ipv4.dst_addr(), Ipv4Addr::from_str("224.0.0.1").unwrap());

    let mut option_iter = Ipv4OptionsIter::from_slice(ipv4.var_header_slice());

    let op1 = match option_iter.next().unwrap() {
        Ipv4Options::RouteAlert_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(op1.header_len(), 4);
    assert_eq!(op1.data(), 0);

    let payload = ipv4.payload();

    assert_eq!(
        &pkt[payload.cursor()..(payload.cursor() + 12)],
        payload.chunk()
    );
}

#[test]
fn ipv4_option3_build() {
    let pkt = file_to_packet("IPv4Option3.dat");
    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    pbuf.move_back(12);
    pbuf.chunk_mut()
        .copy_from_slice(&pkt[pkt.len() - 22..pkt.len() - 10]);

    let mut hdr = Ipv4::default_header();
    Ipv4::from_header_array_mut(&mut hdr).set_header_len(24);
    let mut ipv4 = Ipv4::prepend_header(pbuf, &hdr);
    ipv4.set_dscp(0);
    ipv4.set_ecn(0);
    ipv4.set_ident(0);
    ipv4.set_dont_frag(true);
    ipv4.set_more_frag(false);
    ipv4.set_ttl(1);
    ipv4.set_protocol(IpProtocol::IGMP);
    ipv4.set_checksum(0xfa48);
    ipv4.set_src_addr(Ipv4Addr::from_str("10.0.0.138").unwrap());
    ipv4.set_dst_addr(Ipv4Addr::from_str("224.0.0.1").unwrap());

    {
        let mut option_pbuf = CursorMut::new(ipv4.var_header_slice_mut());
        option_pbuf.advance(4);

        let mut ra = RouteAlert::prepend_header(option_pbuf, &ROUTE_ALERT_HEADER_TEMPLATE);
        ra.set_data(0);
    }

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]));
    eth.set_src_addr(EtherAddr([0xc4, 0x12, 0xf5, 0xff, 0x72, 0xe8]));
    eth.set_ethertype(EtherType::IPV4);

    let built = eth.release();
    assert_eq!(built.chunk(), &pkt[..built.chunk().len()]);
}

#[test]
fn ipv4_option4_parse() {
    // to_hex_dump("IPv4Option2.dat");
    let pkt = file_to_packet("IPv4Option4.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.header_len(), 60);
    assert_eq!(ipv4.dscp(), 0);
    assert_eq!(ipv4.ecn(), 0);
    assert_eq!(ipv4.packet_len(), 80);
    assert_eq!(ipv4.ident(), 0);
    assert_eq!(ipv4.dont_frag(), true);
    assert_eq!(ipv4.more_frag(), false);
    assert_eq!(ipv4.ttl(), 64);
    assert_eq!(ipv4.protocol(), IpProtocol::TCP);
    assert_eq!(ipv4.checksum(), 0xead8);
    assert_eq!(ipv4.src_addr(), Ipv4Addr::from_str("10.0.0.138").unwrap());
    assert_eq!(ipv4.dst_addr(), Ipv4Addr::from_str("10.0.0.6").unwrap());

    let mut option_iter = Ipv4OptionsIter::from_slice(ipv4.var_header_slice());

    let op1 = match option_iter.next().unwrap() {
        Ipv4Options::RecordRoute_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(op1.header_len(), 39);
    assert_eq!(op1.pointer(), 16);

    {
        assert_eq!(
            u32::from_be_bytes(op1.var_header_slice()[0..4].try_into().unwrap()),
            Ipv4Addr::new(1, 2, 3, 4).to_bits()
        );

        assert_eq!(
            u32::from_be_bytes(op1.var_header_slice()[4..8].try_into().unwrap()),
            Ipv4Addr::new(10, 0, 0, 138).to_bits()
        );

        assert_eq!(
            u32::from_be_bytes(op1.var_header_slice()[8..12].try_into().unwrap()),
            Ipv4Addr::new(10, 0, 0, 138).to_bits()
        );

        for i in 3..9 {
            assert_eq!(
                u32::from_be_bytes(op1.var_header_slice()[4 * i..4 * i + 4].try_into().unwrap()),
                Ipv4Addr::new(0, 0, 0, 0).to_bits()
            );
        }
    }

    let _ = match option_iter.next().unwrap() {
        Ipv4Options::Eol_(pkt) => pkt,
        _ => panic!(),
    };

    let payload = ipv4.payload();

    assert_eq!(&pkt[payload.cursor()..], payload.chunk());
}

#[test]
fn ipv4_option4_build() {
    let pkt = file_to_packet("IPv4Option4.dat");
    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    pbuf.move_back(20);
    pbuf.chunk_mut().copy_from_slice(&pkt[pkt.len() - 20..]);

    let mut hdr = Ipv4::default_header();
    Ipv4::from_header_array_mut(&mut hdr).set_header_len(60);
    let mut ipv4 = Ipv4::prepend_header(pbuf, &hdr);
    ipv4.set_dscp(0);
    ipv4.set_ecn(0);
    ipv4.set_ident(0);
    ipv4.set_dont_frag(true);
    ipv4.set_more_frag(false);
    ipv4.set_ttl(64);
    ipv4.set_protocol(IpProtocol::TCP);
    ipv4.set_checksum(0xead8);
    ipv4.set_src_addr(Ipv4Addr::from_str("10.0.0.138").unwrap());
    ipv4.set_dst_addr(Ipv4Addr::from_str("10.0.0.6").unwrap());

    {
        let mut option_pbuf = CursorMut::new(ipv4.var_header_slice_mut());
        *option_pbuf.chunk_mut().last_mut().unwrap() = 0;

        let mut rr = RecordRoute::parse_unchecked(option_pbuf);
        rr.set_header_len(39);
        rr.set_type_(7);
        rr.set_pointer(16);

        {
            rr.var_header_slice_mut()[0..4]
                .copy_from_slice(Ipv4Addr::new(1, 2, 3, 4).octets().as_slice());

            rr.var_header_slice_mut()[4..8]
                .copy_from_slice(Ipv4Addr::new(10, 0, 0, 138).octets().as_slice());

            rr.var_header_slice_mut()[8..12]
                .copy_from_slice(Ipv4Addr::new(10, 0, 0, 138).octets().as_slice());

            for i in 3..9 {
                rr.var_header_slice_mut()[4 * i..4 * i + 4]
                    .copy_from_slice(Ipv4Addr::new(0, 0, 0, 0).octets().as_slice());
            }
        }
    }

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0x08, 0x00, 0x27, 0x19, 0x1c, 0x78]));
    eth.set_src_addr(EtherAddr([0xc4, 0x12, 0xf5, 0xff, 0x72, 0xe8]));    
    eth.set_ethertype(EtherType::IPV4);

    assert_eq!(eth.release().chunk(), pkt);
}
