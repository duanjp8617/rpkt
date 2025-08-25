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
