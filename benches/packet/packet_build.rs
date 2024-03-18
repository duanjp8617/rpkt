use bytes::Buf;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::udp::*;
use rpkt::CursorMut;

fn packet_build(buf: &mut [u8], payload_len: usize) {
    let mut pkt = CursorMut::new(&mut buf[0..42 + payload_len]);
    pkt.advance(42);

    let mut udppkt = UdpPacket::prepend_header(pkt, &UDP_HEADER_TEMPLATE);
    udppkt.set_source_port(60376);
    udppkt.set_dest_port(161);
    udppkt.set_checksum(0xbc86);

    let mut ippkt = Ipv4Packet::prepend_header(udppkt.release(), &IPV4_HEADER_TEMPLATE);
    ippkt.set_ident(0x5c65);
    ippkt.clear_flags();
    ippkt.set_time_to_live(128);
    ippkt.set_source_ip(Ipv4Addr([192, 168, 29, 58]));
    ippkt.set_dest_ip(Ipv4Addr([192, 168, 29, 160]));

    let mut ethpkt = EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
    ethpkt.set_dest_mac(MacAddr([0x00, 0x0b, 0x86, 0x64, 0x8b, 0xa0]));
    ethpkt.set_source_mac(MacAddr([0x00, 0x50, 0x56, 0xae, 0x76, 0xf5]));
    ethpkt.set_ethertype(EtherType::IPV4);
}

pub fn b(c: &mut Criterion) {
    c.bench_function("packet_build", |b| {
        let mut buf = [0; 200];
        b.iter(|| {
            packet_build(black_box(&mut buf[..]), black_box(66));
        })
    });
}

criterion_group!(benches, b);
criterion_main!(benches);
