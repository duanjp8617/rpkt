use arrayvec::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use run_dpdk::*;
use run_packet::ether::*;
use run_packet::ipv4::*;
use run_packet::udp::*;
use run_packet::Buf;

fn batched_build(batch: &mut ArrayVec<Mbuf, 32>, payload_len: usize) {
    for mut mbuf in batch.drain(..) {
        unsafe { mbuf.extend(42 + payload_len) };
        let mut pkt = Pbuf::new(&mut mbuf);
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
        ippkt.set_protocol(IpProtocol::UDP);

        let mut ethpkt = EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
        ethpkt.set_dest_mac(MacAddr([0x00, 0x0b, 0x86, 0x64, 0x8b, 0xa0]));
        ethpkt.set_source_mac(MacAddr([0x00, 0x50, 0x56, 0xae, 0x76, 0xf5]));
        ethpkt.set_ethertype(EtherType::IPV4);
    }
}

pub fn b(c: &mut Criterion) {
    DpdkOption::new().init().unwrap();
    let mut config = MempoolConf::default();
    config.nb_mbufs = 128;
    config.dataroom = 2048;
    {
        let mp = service().mempool_create("wtf", &config).unwrap();
        // let mut mbuf = mp.try_alloc().unwrap();
        let mut batch: ArrayVec<_, 32> = ArrayVec::new();
        c.bench_function("pbuf_build", |b| {
            b.iter(|| {
                mp.fill_batch(&mut batch);
                batched_build(black_box(&mut batch), black_box(1024));
            })
        });
    }
    service().mempool_free("wtf").unwrap();
}

criterion_group!(benches, b);
criterion_main!(benches);
