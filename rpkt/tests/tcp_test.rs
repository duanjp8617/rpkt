mod common;
use std::net::Ipv4Addr;
use std::str::FromStr;

use common::*;

use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::network_rw::*;
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

#[test]
fn tcp_packet_with_options2_parse() {
    let pkt = file_to_packet("TcpPacketWithOptions2.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::TCP);

    let tcp = Tcp::parse(ipv4.payload()).unwrap();
    assert_eq!(tcp.src_port(), 80);
    assert_eq!(tcp.dst_port(), 44160);
    assert_eq!(tcp.seq_num(), 3089746840);
    assert_eq!(tcp.ack_num(), 3916895622);
    assert_eq!(tcp.header_len() - 20, 16);
    assert_eq!(tcp.cwr(), false);
    assert_eq!(tcp.ece(), false);
    assert_eq!(tcp.urg(), false);
    assert_eq!(tcp.ack(), true);
    assert_eq!(tcp.psh(), true);
    assert_eq!(tcp.rst(), false);
    assert_eq!(tcp.syn(), false);
    assert_eq!(tcp.fin(), false);
    assert_eq!(tcp.window_size(), 20178);
    assert_eq!(tcp.checksum(), 0xdea1);
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
    assert_eq!(ts.ts(), 3555735960);
    assert_eq!(ts.ts_echo(), 196757);

    let _nop = match tcp_opts.next().unwrap() {
        TcpOptions::Nop_(pkt) => pkt,
        _ => panic!(),
    };

    let ws = match tcp_opts.next().unwrap() {
        TcpOptions::WindowScale_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(ws.shift_count(), 2);

    let payload = tcp.payload();
    assert_eq!(payload.chunk(), &pkt[pkt.len() - payload.chunk().len()..]);
}

#[test]
fn tcp_packet_with_options2_build() {
    let pkt = file_to_packet("TcpPacketWithOptions2.dat");

    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    pbuf.move_back(9);
    pbuf.chunk_mut().copy_from_slice(&pkt[pkt.len() - 9..]);

    let mut hdr = Tcp::default_header();
    Tcp::from_header_array_mut(&mut hdr).set_header_len(20 + 16);
    let mut tcp = Tcp::prepend_header(pbuf, &hdr);
    tcp.set_src_port(80);
    tcp.set_dst_port(44160);
    tcp.set_seq_num(3089746840);
    tcp.set_ack_num(3916895622);
    tcp.set_cwr(false);
    tcp.set_ece(false);
    tcp.set_urg(false);
    tcp.set_ack(true);
    tcp.set_psh(true);
    tcp.set_rst(false);
    tcp.set_syn(false);
    tcp.set_fin(false);
    tcp.set_window_size(20178);
    tcp.set_checksum(0xdea1);
    tcp.set_urgent_pointer(0);

    let mut option_pbuf = CursorMut::new(tcp.var_header_slice_mut());
    option_pbuf.advance(16);

    let mut ws_opt = WindowScale::prepend_header(option_pbuf, &WINDOW_SCALE_HEADER_TEMPLATE);
    ws_opt.set_shift_count(2);

    let nop = Nop::prepend_header(ws_opt.release(), &NOP_HEADER_TEMPLATE);

    let mut ts_opt = Timestamp::prepend_header(nop.release(), &TIMESTAMP_HEADER_TEMPLATE);
    ts_opt.set_ts(3555735960);
    ts_opt.set_ts_echo(196757);

    let nop = Nop::prepend_header(ts_opt.release(), &NOP_HEADER_TEMPLATE);
    let _nop = Nop::prepend_header(nop.release(), &NOP_HEADER_TEMPLATE);

    let mut ipv4 = Ipv4::prepend_header(tcp.release(), &IPV4_HEADER_TEMPLATE);
    ipv4.set_ident(20300);
    ipv4.set_dont_frag(true);
    ipv4.set_ttl(59);
    ipv4.set_protocol(IpProtocol::TCP);
    ipv4.set_checksum(0x4794);
    ipv4.set_src_addr(Ipv4Addr::from_str("212.199.202.9").unwrap());
    ipv4.set_dst_addr(Ipv4Addr::from_str("10.0.0.6").unwrap());

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0x08, 0x00, 0x27, 0x19, 0x1c, 0x78]));
    eth.set_src_addr(EtherAddr([0x30, 0x46, 0x9a, 0x23, 0xfb, 0xfa]));
    eth.set_ethertype(EtherType::IPV4);

    assert_eq!(eth.release().chunk(), &pkt);
}

#[test]
fn tcp_packet_with_mss_sackperm_parse() {
    let pkt = file_to_packet("TcpPacketWithMssSackperm.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::TCP);

    let tcp = Tcp::parse(ipv4.payload()).unwrap();
    assert_eq!(tcp.src_port(), 2000);
    assert_eq!(tcp.dst_port(), 6712);
    assert_eq!(tcp.seq_num(), 191135221);
    assert_eq!(tcp.ack_num(), 4211666100);
    assert_eq!(tcp.header_len() - 20, 8);
    assert_eq!(tcp.cwr(), false);
    assert_eq!(tcp.ece(), false);
    assert_eq!(tcp.urg(), false);
    assert_eq!(tcp.ack(), true);
    assert_eq!(tcp.psh(), false);
    assert_eq!(tcp.rst(), false);
    assert_eq!(tcp.syn(), true);
    assert_eq!(tcp.fin(), false);
    assert_eq!(tcp.window_size(), 64240);
    assert_eq!(tcp.checksum(), 0xe310);
    assert_eq!(tcp.urgent_pointer(), 0);

    let mut tcp_opts = TcpOptionsIter::from_slice(tcp.var_header_slice());

    let mss = match tcp_opts.next().unwrap() {
        TcpOptions::Mss_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(mss.mss(), 1460);

    let _nop = match tcp_opts.next().unwrap() {
        TcpOptions::Nop_(pkt) => pkt,
        _ => panic!(),
    };

    let _nop = match tcp_opts.next().unwrap() {
        TcpOptions::Nop_(pkt) => pkt,
        _ => panic!(),
    };

    let _ = match tcp_opts.next().unwrap() {
        TcpOptions::SackPermitted_(pkt) => pkt,
        _ => panic!(),
    };

    assert_eq!(tcp_opts.next().is_none(), true);

    let payload = tcp.payload();
    assert_eq!(payload.chunk(), &pkt[pkt.len() - payload.chunk().len()..]);
}

#[test]
fn tcp_packet_with_mss_sackperm_build() {
    let pkt = file_to_packet("TcpPacketWithMssSackperm.dat");

    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    let mut hdr = Tcp::default_header();
    Tcp::from_header_array_mut(&mut hdr).set_header_len(20 + 8);
    let mut tcp = Tcp::prepend_header(pbuf, &hdr);
    tcp.set_src_port(2000);
    tcp.set_dst_port(6712);
    tcp.set_seq_num(191135221);
    tcp.set_ack_num(4211666100);
    tcp.set_cwr(false);
    tcp.set_ece(false);
    tcp.set_urg(false);
    tcp.set_ack(true);
    tcp.set_psh(false);
    tcp.set_rst(false);
    tcp.set_syn(true);
    tcp.set_fin(false);
    tcp.set_window_size(64240);
    tcp.set_checksum(0xe310);
    tcp.set_urgent_pointer(0);

    let mut option_pbuf = CursorMut::new(tcp.var_header_slice_mut());
    option_pbuf.advance(8);

    let sack_permitted =
        SackPermitted::prepend_header(option_pbuf, &SACK_PERMITTED_HEADER_TEMPLATE);
    let nop1 = Nop::prepend_header(sack_permitted.release(), &NOP_HEADER_TEMPLATE);
    let nop2 = Nop::prepend_header(nop1.release(), &NOP_HEADER_TEMPLATE);
    let mut mss = Mss::prepend_header(nop2.release(), &MSS_HEADER_TEMPLATE);
    mss.set_mss(1460);

    let mut ipv4 = Ipv4::prepend_header(tcp.release(), &IPV4_HEADER_TEMPLATE);
    ipv4.set_ident(0);
    ipv4.set_dont_frag(true);
    ipv4.set_ttl(64);
    ipv4.set_protocol(IpProtocol::TCP);
    ipv4.set_checksum(0x28da);
    ipv4.set_src_addr(Ipv4Addr::from_str("192.168.200.21").unwrap());
    ipv4.set_dst_addr(Ipv4Addr::from_str("192.168.200.135").unwrap());

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_dst_addr(EtherAddr([0xec, 0xf4, 0xbb, 0xd9, 0x3e, 0x7d]));
    eth.set_src_addr(EtherAddr([0x00, 0x0c, 0x29, 0x1c, 0xe3, 0x19]));
    eth.set_ethertype(EtherType::IPV4);

    assert_eq!(eth.release().chunk(), &pkt);
}

#[test]
fn tcp_packet_with_sack_parse() {
    let pkt = file_to_packet("TcpPacketWithSack.dat");
    let pbuf = Cursor::new(&pkt);

    let eth = EtherFrame::parse(pbuf).unwrap();
    assert_eq!(eth.ethertype(), EtherType::IPV4);

    let ipv4 = Ipv4::parse(eth.payload()).unwrap();
    assert_eq!(ipv4.protocol(), IpProtocol::TCP);

    let tcp = Tcp::parse(ipv4.payload()).unwrap();
    assert_eq!(tcp.src_port(), 54436);
    assert_eq!(tcp.dst_port(), 80);
    assert_eq!(tcp.seq_num(), 3714426508);
    assert_eq!(tcp.ack_num(), 2530491013);
    assert_eq!(tcp.header_len() - 20, 12);
    assert_eq!(tcp.cwr(), false);
    assert_eq!(tcp.ece(), false);
    assert_eq!(tcp.urg(), false);
    assert_eq!(tcp.ack(), true);
    assert_eq!(tcp.psh(), false);
    assert_eq!(tcp.rst(), false);
    assert_eq!(tcp.syn(), false);
    assert_eq!(tcp.fin(), false);
    assert_eq!(tcp.window_size(), 4380);
    assert_eq!(tcp.checksum(), 0x8497);
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

    let sack = match tcp_opts.next().unwrap() {
        TcpOptions::Sack_(pkt) => pkt,
        _ => panic!(),
    };
    assert_eq!(
        u32::from_be_bytes(sack.var_header_slice()[..4].try_into().unwrap()) - tcp.ack_num() + 1,
        13141
    );
    assert_eq!(
        u32::from_be_bytes(sack.var_header_slice()[4..8].try_into().unwrap()) - tcp.ack_num() + 1,
        14601
    );

    assert_eq!(tcp_opts.next().is_none(), true);

    let payload = tcp.payload();
    assert_eq!(payload.chunk(), &pkt[pkt.len() - payload.chunk().len()..]);
}

#[test]
fn tcp_packet_with_sack_build() {
    let pkt = file_to_packet("TcpPacketWithSack.dat");

    let mut buf = [0; 1600];
    let mut pbuf = CursorMut::new(&mut buf);
    pbuf.advance(1600);

    let mut hdr = Tcp::default_header();
    Tcp::from_header_array_mut(&mut hdr).set_header_len(20 + 12);
    let mut tcp = Tcp::prepend_header(pbuf, &hdr);
    tcp.set_src_port(54436);
    tcp.set_dst_port(80);
    tcp.set_seq_num(3714426508);
    tcp.set_ack_num(2530491013);
    tcp.set_cwr(false);
    tcp.set_ece(false);
    tcp.set_urg(false);
    tcp.set_ack(true);
    tcp.set_psh(false);
    tcp.set_rst(false);
    tcp.set_syn(false);
    tcp.set_fin(false);
    tcp.set_window_size(4380);
    tcp.set_checksum(0x8497);
    tcp.set_urgent_pointer(0);
    let ack_num = tcp.ack_num();

    let mut option_pbuf = CursorMut::new(tcp.var_header_slice_mut());
    option_pbuf.advance(12);

    let mut sack_hdr = SACK_HEADER_TEMPLATE.clone();
    Sack::from_header_array_mut(&mut sack_hdr).set_header_len(10);
    let mut sack = Sack::prepend_header(option_pbuf, &sack_hdr);
    sack.var_header_slice_mut()[..4]
        .copy_from_slice((ack_num + 13141 - 1).to_be_bytes().as_slice());
    sack.var_header_slice_mut()[4..8]
        .copy_from_slice((ack_num + 14601 - 1).to_be_bytes().as_slice());

    let nop1 = Nop::prepend_header(sack.release(), &NOP_HEADER_TEMPLATE);
    let _nop2 = Nop::prepend_header(nop1.release(), &NOP_HEADER_TEMPLATE);

    let mut ipv4 = Ipv4::prepend_header(tcp.release(), &IPV4_HEADER_TEMPLATE);
    ipv4.set_ident(0x50f5);
    ipv4.set_dont_frag(true);
    ipv4.set_ttl(128);
    ipv4.set_protocol(IpProtocol::TCP);
    ipv4.set_checksum(0xff15);
    ipv4.set_src_addr(Ipv4Addr::from_str("10.0.0.145").unwrap());
    ipv4.set_dst_addr(Ipv4Addr::from_str("186.15.230.24").unwrap());

    let mut eth = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);

    eth.set_dst_addr(EtherAddr([0xc0, 0xc1, 0xc0, 0xdc, 0x39, 0xed]));
    eth.set_src_addr(EtherAddr([0x88, 0x53, 0x2e, 0x84, 0x7c, 0x5e]));
    eth.set_ethertype(EtherType::IPV4);

    assert_eq!(eth.release().chunk(), &pkt);
}
