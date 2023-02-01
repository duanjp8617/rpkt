use criterion::{black_box, criterion_group, criterion_main, Criterion};
use smoltcp::wire;

fn smol_build(buf: &mut [u8], payload_len: usize) {
    let mut frame = wire::EthernetFrame::new_unchecked(&mut buf[0..42 + payload_len]);
    frame.set_src_addr(wire::EthernetAddress([0x00, 0x50, 0x56, 0xae, 0x76, 0xf5]));
    frame.set_dst_addr(wire::EthernetAddress([0x00, 0x0b, 0x86, 0x64, 0x8b, 0xa0]));
    frame.set_ethertype(wire::EthernetProtocol::Ipv4);

    let mut ipv4_pkt = wire::Ipv4Packet::new_unchecked(frame.payload_mut());
    ipv4_pkt.set_version(4);
    ipv4_pkt.set_header_len(20);
    ipv4_pkt.set_dscp(0);
    ipv4_pkt.set_ecn(0);
    ipv4_pkt.set_total_len((28 + payload_len) as u16);
    ipv4_pkt.set_ident(0x5c65);
    ipv4_pkt.clear_flags();
    ipv4_pkt.set_frag_offset(0);
    ipv4_pkt.set_hop_limit(128);
    ipv4_pkt.set_protocol(wire::IpProtocol::Udp);
    ipv4_pkt.set_src_addr(wire::Ipv4Address([192, 168, 29, 58]));
    ipv4_pkt.set_dst_addr(wire::Ipv4Address([192, 168, 29, 160]));
    ipv4_pkt.set_checksum(0);

    let mut udp_pkt = wire::UdpPacket::new_unchecked(ipv4_pkt.payload_mut());
    udp_pkt.set_src_port(60376);
    udp_pkt.set_dst_port(161);
    udp_pkt.set_len((8 + payload_len) as u16);
    udp_pkt.set_checksum(0xbc86);
}

pub fn b(c: &mut Criterion) {
    c.bench_function("smol_build", |b| {
        let mut buf = [0; 200];
        b.iter(|| {
            smol_build(black_box(&mut buf[..]), black_box(66));
        })
    });
}

criterion_group!(benches, b);
criterion_main!(benches);
