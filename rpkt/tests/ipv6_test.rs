mod common;

use common::*;

use std::net::Ipv6Addr;
use std::str::FromStr;

use rpkt::ether::*;
use rpkt::ipv4::IpProtocol;
use rpkt::ipv6::extentions::*;
use rpkt::ipv6::options::*;
use rpkt::ipv6::*;
use rpkt::udp::*;
use rpkt::Buf;
use rpkt::PktBuf;
use rpkt::PktBufMut;
use rpkt::{Cursor, CursorMut};

#[test]
fn ipv6_options_destination_parse() {
    let pkt = file_to_packet("ipv6_options_destination.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV6);

    let ipv6 = Ipv6::parse(eth.payload()).unwrap();
    assert_eq!(ipv6.version(), 6);
    assert_eq!(ipv6.traffic_class(), 0);
    assert_eq!(ipv6.flow_label(), 0);
    assert_eq!(ipv6.payload_len(), 26);
    assert_eq!(ipv6.next_header(), IpProtocol::IPV6_OPTS);
    assert_eq!(ipv6.hop_limit(), 64);
    assert_eq!(
        ipv6.src_addr(),
        Ipv6Addr::from_str("2a01:e35:8bd9:8bb0:a0a7:ea9c:74e8:d397").unwrap()
    );
    assert_eq!(
        ipv6.dst_addr(),
        Ipv6Addr::from_str("2001:4b98:dc0:41:216:3eff:fece:1902").unwrap()
    );

    let dest_opts = DestOptions::parse(ipv6.payload()).unwrap();
    assert_eq!(dest_opts.next_header(), IpProtocol::UDP);
    assert_eq!(dest_opts.header_len(), 8);

    let mut option_iter = Ipv6OptionsIter::from_slice(dest_opts.var_header_slice());

    let first_option = option_iter.next().unwrap();
    match first_option {
        Ipv6Options::Generic_(opt) => {
            assert_eq!(opt.type_(), 11);
            assert_eq!(opt.header_len(), 3);
            assert_eq!(opt.var_header_slice()[0], 09);
        }
        _ => panic!("Expected Generic option with type 11"),
    }

    let second_option = option_iter.next().unwrap();
    match second_option {
        Ipv6Options::Padn_(opt) => {
            assert_eq!(opt.type_(), 1);
            assert_eq!(opt.header_len(), 3);
            assert_eq!(opt.var_header_slice()[0], 00);
        }
        _ => panic!("Expected PadN option"),
    }

    assert!(option_iter.next().is_none());

    let udp_pkt = Udp::parse(dest_opts.payload()).unwrap();
    assert_eq!(udp_pkt.packet_len(), 18);

    let payload = udp_pkt.payload();
    assert_eq!(payload.chunk().len(), 10);
}

#[test]
fn ipv6_options_destination_build() {
    let pkt = file_to_packet("ipv6_options_destination.dat");
    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    pbuf.move_back(10);
    pbuf.chunk_mut().copy_from_slice(&pkt[pkt.len() - 10..]);

    let mut udp = Udp::prepend_header(pbuf, &UDP_HEADER_TEMPLATE);
    udp.set_src_port(42513);
    udp.set_dst_port(42);    
    udp.set_checksum(0x6889);

    let mut hdr = DestOptions::default_header();
    DestOptions::from_header_array_mut(&mut hdr).set_header_len(8);
    let mut dest_opts = DestOptions::prepend_header(udp.release(), &hdr);
    dest_opts.set_next_header(IpProtocol::UDP);

    let mut option_pbuf = CursorMut::new(dest_opts.var_header_slice_mut());
    option_pbuf.advance(6);

    let mut padn_hdr = Padn::default_header();
    Padn::from_header_array_mut(&mut padn_hdr).set_header_len(3);
    let mut padn_opt = Padn::prepend_header(option_pbuf, &padn_hdr);
    padn_opt.var_header_slice_mut()[0] = 0x00;

    let mut generic_hdr = Generic::default_header();
    Generic::from_header_array_mut(&mut generic_hdr).set_header_len(3);
    let mut generic_opt = Generic::prepend_header(padn_opt.release(), &generic_hdr);
    generic_opt.set_type_(11);
    generic_opt.var_header_slice_mut()[0] = 0x09;

    let mut ipv6 = Ipv6::prepend_header(dest_opts.release(), &IPV6_HEADER_TEMPLATE);
    ipv6.set_version(6);
    ipv6.set_traffic_class(0);
    ipv6.set_flow_label(0);    
    ipv6.set_next_header(IpProtocol::IPV6_OPTS);
    ipv6.set_hop_limit(64);
    ipv6.set_src_addr(Ipv6Addr::from_str("2a01:e35:8bd9:8bb0:a0a7:ea9c:74e8:d397").unwrap());
    ipv6.set_dst_addr(Ipv6Addr::from_str("2001:4b98:dc0:41:216:3eff:fece:1902").unwrap());

    let mut eth = EtherFrame::prepend_header(ipv6.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0xf4, 0xca, 0xe5, 0x4d, 0x1f, 0x41]));
    eth.set_src_addr(EtherAddr([0x00, 0x1e, 0x8c, 0x76, 0x29, 0xb6]));
    eth.set_ethertype(EtherType::IPV6);

    assert_eq!(eth.release().chunk(), &pkt);
}
