use bytes::BufMut;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
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

fn smol_l2(buf: &[u8]) {
    let ethpkt = wire::EthernetFrame::new_checked(buf).unwrap();
    assert!(ethpkt.ethertype() == wire::EthernetProtocol::Ipv4);
    assert!(
        ethpkt.dst_addr()
            == wire::EthernetAddress([
                FRAME_BYTES[0],
                FRAME_BYTES[1],
                FRAME_BYTES[2],
                FRAME_BYTES[3],
                FRAME_BYTES[4],
                FRAME_BYTES[5]
            ])
    );
    assert!(
        ethpkt.src_addr()
            == wire::EthernetAddress([
                FRAME_BYTES[6],
                FRAME_BYTES[7],
                FRAME_BYTES[8],
                FRAME_BYTES[9],
                FRAME_BYTES[10],
                FRAME_BYTES[11]
            ])
    );
}

fn smol_l3(buf: &[u8]) {
    let ethpkt = wire::EthernetFrame::new_checked(buf).unwrap();
    assert!(ethpkt.ethertype() == wire::EthernetProtocol::Ipv4);

    let ippkt = wire::Ipv4Packet::new_checked(ethpkt.payload()).unwrap();
    assert!(ippkt.protocol() == wire::IpProtocol::Udp);
    assert!(ippkt.src_addr() == wire::Ipv4Address([192, 168, 29, 58]));
    assert!(ippkt.dst_addr() == wire::Ipv4Address([192, 168, 29, 160]));
    assert!(ippkt.checksum() == 0x0000);
    assert!(ippkt.ident() == 0x5c65);
}

fn smol_l4(buf: &[u8]) {
    let ethpkt = wire::EthernetFrame::new_checked(buf).unwrap();
    assert!(ethpkt.ethertype() == wire::EthernetProtocol::Ipv4);

    let ippkt = wire::Ipv4Packet::new_checked(ethpkt.payload()).unwrap();
    assert!(ippkt.protocol() == wire::IpProtocol::Udp);

    let udppkt = wire::UdpPacket::new_checked(ippkt.payload()).unwrap();
    assert!(udppkt.src_port() == 60376);
    assert!(udppkt.dst_port() == 161);
    assert!(udppkt.len() == 74);
    assert!(udppkt.checksum() == 0xbc86);
}

fn smol_app(buf: &[u8]) {
    let ethpkt = wire::EthernetFrame::new_checked(buf).unwrap();
    assert!(ethpkt.ethertype() == wire::EthernetProtocol::Ipv4);

    let ippkt = wire::Ipv4Packet::new_checked(ethpkt.payload()).unwrap();
    assert!(ippkt.protocol() == wire::IpProtocol::Udp);

    let udppkt = wire::UdpPacket::new_checked(ippkt.payload()).unwrap();
    assert!(udppkt.src_port() == 60376);
    assert!(udppkt.dst_port() == 161);
    assert!(udppkt.len() == 74);

    let payload = udppkt.payload();

    let mut b = [0; 66];
    (&mut b[..]).put(payload);
    assert!(b[0..66] == FRAME_BYTES[42..108]);
}

pub fn b1(c: &mut Criterion) {
    c.bench_function("smol_l2", |b| {
        b.iter(|| {
            smol_l2(black_box(&FRAME_BYTES[..]));
        })
    });
}

pub fn b2(c: &mut Criterion) {
    c.bench_function("smol_l3", |b| {
        b.iter(|| {
            smol_l3(black_box(&FRAME_BYTES[..]));
        })
    });
}

pub fn b3(c: &mut Criterion) {
    c.bench_function("smol_l4", |b| {
        b.iter(|| {
            smol_l4(black_box(&FRAME_BYTES[..]));
        })
    });
}

pub fn b4(c: &mut Criterion) {
    c.bench_function("smol_app", |b| {
        b.iter(|| {
            smol_app(black_box(&FRAME_BYTES[..]));
        })
    });
}

criterion_group!(benches, b1, b2, b3, b4);
criterion_main!(benches);
