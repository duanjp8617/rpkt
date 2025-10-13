use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pnet::{packet::*, util::MacAddr};

use std::net::Ipv4Addr;

fn pnet_build(buf: &mut [u8], payload_len: usize) {
    let mut frame = ethernet::MutableEthernetPacket::new(buf).unwrap();
    frame.set_source(MacAddr(0x00, 0x50, 0x56, 0xae, 0x76, 0xf5));
    frame.set_destination(MacAddr(0x00, 0x0b, 0x86, 0x64, 0x8b, 0xa0));
    frame.set_ethertype(ethernet::EtherTypes::Ipv4);

    let mut ipv4_pkt = ipv4::MutableIpv4Packet::new(frame.payload_mut()).unwrap();
    ipv4_pkt.set_version(4);
    ipv4_pkt.set_header_length(20);
    ipv4_pkt.set_dscp(0);
    ipv4_pkt.set_ecn(0);
    ipv4_pkt.set_total_length((28 + payload_len) as u16);
    ipv4_pkt.set_identification(0x5c65);    
    ipv4_pkt.set_flags(0);
    ipv4_pkt.set_fragment_offset(0);
    ipv4_pkt.set_ttl(128);
    ipv4_pkt.set_next_level_protocol(ip::IpNextHeaderProtocols::Udp);
    ipv4_pkt.set_source(Ipv4Addr::new(192, 168, 29, 58));
    ipv4_pkt.set_destination(Ipv4Addr::new(192, 168, 29, 160));
    ipv4_pkt.set_checksum(0);

    let mut udp_pkt = udp::MutableUdpPacket::new(ipv4_pkt.payload_mut()).unwrap();
    udp_pkt.set_source(60376);
    udp_pkt.set_destination(161);
    udp_pkt.set_length((8 + payload_len) as u16);
    udp_pkt.set_checksum(0xbc86);
}

pub fn b(c: &mut Criterion) {
    c.bench_function("pnet_build", |b| {
        let mut buf = [0; 200];
        b.iter(|| {
            pnet_build(black_box(&mut buf[..]), black_box(66));
        })
    });
}

criterion_group!(benches, b);
criterion_main!(benches);
