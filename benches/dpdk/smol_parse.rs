use arrayvec::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rpkt_dpdk::*;
use smoltcp::wire;

static FRAME_BYTES: [u8; 110] = [
    0x00, 0x0b, 0x86, 0x64, 0x8b, 0xa0, 0x00, 0x50, 0x56, 0xae, 0x76, 0xf5, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x5e, 0x5c, 0x65, 0x00, 0x00, 0x80, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x1d, 0x3a, 0xc0, 0xa8,
    0x1d, 0xa0, 0xeb, 0xd8, 0x00, 0xa1, 0x00, 0x4a, 0xbc, 0x86, 0x30, 0x40, 0x02, 0x01, 0x03, 0x30,
    0x0f, 0x02, 0x03, 0x00, 0x91, 0xc8, 0x02, 0x02, 0x05, 0xdc, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03,
    0x04, 0x15, 0x30, 0x13, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x05, 0x61, 0x64,
    0x6d, 0x69, 0x6e, 0x04, 0x00, 0x04, 0x00, 0x30, 0x13, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0d, 0x02,
    0x03, 0x00, 0x91, 0xc8, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00, 0x00, 0x00,
];

fn batched_l3(batch: &mut ArrayVec<Mbuf, 32>) {
    for mbuf in batch.iter_mut() {
        let ethpkt = wire::EthernetFrame::new_checked(mbuf.data()).unwrap();
        assert_eq!(ethpkt.ethertype(), wire::EthernetProtocol::Ipv4);

        let ippkt = wire::Ipv4Packet::new_checked(ethpkt.payload()).unwrap();
        assert_eq!(ippkt.next_header(), wire::IpProtocol::Udp);
        assert_eq!(ippkt.src_addr(), wire::Ipv4Address([192, 168, 29, 58]));
        assert_eq!(ippkt.dst_addr(), wire::Ipv4Address([192, 168, 29, 160]));
        assert_eq!(ippkt.checksum(), 0x0000);
        assert_eq!(ippkt.ident(), 0x5c65);
    }
}

fn batched_l4(batch: &mut ArrayVec<Mbuf, 32>) {
    for mbuf in batch.iter_mut() {
        let ethpkt = wire::EthernetFrame::new_checked(mbuf.data()).unwrap();
        assert_eq!(ethpkt.ethertype(), wire::EthernetProtocol::Ipv4);

        let ippkt = wire::Ipv4Packet::new_checked(ethpkt.payload()).unwrap();
        assert_eq!(ippkt.next_header(), wire::IpProtocol::Udp);

        let udppkt = wire::UdpPacket::new_checked(ippkt.payload()).unwrap();
        assert_eq!(udppkt.src_port(), 60376);
        assert_eq!(udppkt.dst_port(), 161);
        assert_eq!(udppkt.len(), 74);
        assert_eq!(udppkt.checksum(), 0xbc86);
    }
}

fn batched_app(batch: &mut ArrayVec<Mbuf, 32>) {
    for mbuf in batch.iter_mut() {
        let ethpkt = wire::EthernetFrame::new_checked(mbuf.data()).unwrap();
        assert_eq!(ethpkt.ethertype(), wire::EthernetProtocol::Ipv4);

        let ippkt = wire::Ipv4Packet::new_checked(ethpkt.payload()).unwrap();
        assert_eq!(ippkt.next_header(), wire::IpProtocol::Udp);

        let udppkt = wire::UdpPacket::new_checked(ippkt.payload()).unwrap();
        assert_eq!(udppkt.src_port(), 60376);
        assert_eq!(udppkt.dst_port(), 161);
        assert_eq!(udppkt.len(), 74);

        let payload = udppkt.payload();

        let mut b = [0; 66];
        (&mut b[..]).copy_from_slice(payload);
        assert_eq!(b[0..66], FRAME_BYTES[42..108]);
    }
}

pub fn b1(c: &mut Criterion) {
    DpdkOption::new().init().unwrap();
    let mut config = MempoolConf::default();
    config.nb_mbufs = 128;
    config.dataroom = 2048;
    {
        let mp = service().mempool_create("wtf", &config).unwrap();
        let mut batch: ArrayVec<_, 32> = ArrayVec::new();
        mp.fill_batch(&mut batch);
        for mbuf in batch.iter_mut() {
            mbuf.extend_from_slice(&FRAME_BYTES[..]);
        }

        c.bench_function("smol_l3", |b| {
            b.iter(|| {
                batched_l3(black_box(&mut batch));
            })
        });
    }
    service().mempool_free("wtf").unwrap();
}

pub fn b2(c: &mut Criterion) {
    DpdkOption::new().init().unwrap();
    let mut config = MempoolConf::default();
    config.nb_mbufs = 128;
    config.dataroom = 2048;
    {
        let mp = service().mempool_create("wtf", &config).unwrap();
        let mut batch: ArrayVec<_, 32> = ArrayVec::new();
        mp.fill_batch(&mut batch);
        for mbuf in batch.iter_mut() {
            mbuf.extend_from_slice(&FRAME_BYTES[..]);
        }

        c.bench_function("smol_l4", |b| {
            b.iter(|| {
                batched_l4(black_box(&mut batch));
            })
        });
    }
    service().mempool_free("wtf").unwrap();
}

pub fn b3(c: &mut Criterion) {
    DpdkOption::new().init().unwrap();
    let mut config = MempoolConf::default();
    config.nb_mbufs = 128;
    config.dataroom = 2048;
    {
        let mp = service().mempool_create("wtf", &config).unwrap();
        let mut batch: ArrayVec<_, 32> = ArrayVec::new();
        mp.fill_batch(&mut batch);
        for mbuf in batch.iter_mut() {
            mbuf.extend_from_slice(&FRAME_BYTES[..]);
        }

        c.bench_function("smol_app", |b| {
            b.iter(|| {
                batched_app(black_box(&mut batch));
            })
        });
    }
    service().mempool_free("wtf").unwrap();
}

criterion_group!(benches, b1, b2, b3);
criterion_main!(benches);
