mod common;
use std::net::Ipv4Addr;
use std::str::FromStr;

use common::*;

use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::tcp::options::*;
use rpkt::tcp::*;
use rpkt::Buf;
use rpkt::PktBuf;
use rpkt::PktBufMut;
use rpkt::{Cursor, CursorMut};

#[test]
fn tcp_packet_with_options_parse() {
    let pkt = file_to_packet("TcpPacketWithOptions.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::TCP);

    let tcp = Tcp::parse(ipv4.payload()).unwrap();
    assert_eq!(tcp.src_port(), 44147);
    assert_eq!(tcp.dst_port(), 80);
    assert_eq!(tcp.seq_num(), 777047406);
    assert_eq!(tcp.ack_num(), 3761117865);
    assert_eq!(tcp.header_len() - 20, 12);
    assert_eq!(tcp.cwr(), false);
    assert_eq!(tcp.ece(), false);
    assert_eq!(tcp.urg(), false);
    assert_eq!(tcp.ack(), true);
    assert_eq!(tcp.psh(), true);
    assert_eq!(tcp.rst(), false);
    assert_eq!(tcp.syn(), false);
    assert_eq!(tcp.fin(), false);
    assert_eq!(tcp.window_size(), 913);
    assert_eq!(tcp.checksum(), 0xac20);
    assert_eq!(tcp.urgent_pointer(), 0);

    let mut tcp_opts = TcpOptionsIter::from_slice(tcp.var_header_slice());

    let _nop = match tcp_opts.next().unwrap() {
        TcpOptions::Nop_(pkt) => pkt,
        _ => panic!(),
    };

    let _nop = match tcp_opts.next().unwrap() {
        TcpOptions::Nop_(pkt) => pkt,
        _ => panic!(),
    };

    let ts = match tcp_opts.next().unwrap() {
        TcpOptions::Timestamp_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ts.ts(), 195102);
    assert_eq!(ts.ts_echo(), 3555729271);

    let payload = tcp.payload();
    assert_eq!(payload.chunk(), &pkt[pkt.len() - payload.chunk().len()..]);
}

#[test]
fn tcp_packet_with_options_build() {
    let pkt = file_to_packet("TcpPacketWithOptions.dat");
    
    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    pbuf.move_back(803);
    pbuf.chunk_mut().copy_from_slice(&pkt[pkt.len() - 803..]);

    let mut hdr = Tcp::default_header();
    Tcp::from_header_array_mut(&mut hdr).set_header_len(20 + 12);
    let mut tcp = Tcp::prepend_header(pbuf, &hdr);
    tcp.set_src_port(44147);
    tcp.set_dst_port(80);
    tcp.set_seq_num(777047406);
    tcp.set_ack_num(3761117865);
    tcp.set_cwr(false);
    tcp.set_ece(false);
    tcp.set_urg(false);
    tcp.set_ack(true);
    tcp.set_psh(true);
    tcp.set_rst(false);
    tcp.set_syn(false);
    tcp.set_fin(false);
    tcp.set_window_size(913);
    tcp.set_checksum(0xac20);
    tcp.set_urgent_pointer(0);

    let mut option_pbuf = CursorMut::new(tcp.var_header_slice_mut());
    option_pbuf.advance(12);

    let mut ts_opt = Timestamp::prepend_header(option_pbuf, &TIMESTAMP_HEADER_TEMPLATE);
    ts_opt.set_ts(195102);
    ts_opt.set_ts_echo(3555729271);

    let nop = Nop::prepend_header(ts_opt.release(), &NOP_HEADER_TEMPLATE);
    let _nop = Nop::prepend_header(nop.release(), &NOP_HEADER_TEMPLATE);

    let mut ipv4 = Ipv4::prepend_header(tcp.release(), &IPV4_HEADER_TEMPLATE);
    ipv4.set_ident(0x3776);
    ipv4.set_dont_frag(true);
    ipv4.set_ttl(64);
    ipv4.set_protocol(IpProtocol::TCP);
    ipv4.set_checksum(0x5754);
    ipv4.set_src_addr(Ipv4Addr::from_str("10.0.0.6").unwrap());
    ipv4.set_dst_addr(Ipv4Addr::from_str("212.199.202.9").unwrap());

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0x30, 0x46, 0x9a, 0x23, 0xfb, 0xfa]));
    eth.set_src_addr(EtherAddr([0x08, 0x00, 0x27, 0x19, 0x1c, 0x78]));
    eth.set_ethertype(EtherType::IPV4);

    assert_eq!(eth.release().chunk(), &pkt);
}
