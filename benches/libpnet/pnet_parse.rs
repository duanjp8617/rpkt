use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pnet::{packet::*, util::MacAddr};

use std::net::Ipv4Addr;




static FRAME_BYTES: [u8; 110] = [
    0x00, 0x0b, 0x86, 0x64, 0x8b, 0xa0, 0x00, 0x50, 0x56, 0xae, 0x76, 0xf5, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x5e, 0x5c, 0x65, 0x00, 0x00, 0x80, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x1d, 0x3a, 0xc0, 0xa8,
    0x1d, 0xa0, 0xeb, 0xd8, 0x00, 0xa1, 0x00, 0x4a, 0xbc, 0x86, 0x30, 0x40, 0x02, 0x01, 0x03, 0x30,
    0x0f, 0x02, 0x03, 0x00, 0x91, 0xc8, 0x02, 0x02, 0x05, 0xdc, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03,
    0x04, 0x15, 0x30, 0x13, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x05, 0x61, 0x64,
    0x6d, 0x69, 0x6e, 0x04, 0x00, 0x04, 0x00, 0x30, 0x13, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0d, 0x02,
    0x03, 0x00, 0x91, 0xc8, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00, 0x00, 0x00,
];

fn pnet_l2(buf: &[u8]) {
    let ethpkt = ethernet::EthernetPacket::new(buf).unwrap();
    assert!(ethpkt.get_ethertype() == ethernet::EtherTypes::Ipv4);
    assert!(
        ethpkt.get_destination()
            == MacAddr(
                FRAME_BYTES[0],
                FRAME_BYTES[1],
                FRAME_BYTES[2],
                FRAME_BYTES[3],
                FRAME_BYTES[4],
                FRAME_BYTES[5]
            )
    );
    assert!(
        ethpkt.get_source()
            == MacAddr(
                FRAME_BYTES[6],
                FRAME_BYTES[7],
                FRAME_BYTES[8],
                FRAME_BYTES[9],
                FRAME_BYTES[10],
                FRAME_BYTES[11]
            )
    );
}

fn pnet_l3(buf: &[u8]) {
    let ethpkt = ethernet::EthernetPacket::new(buf).unwrap();
    assert!(ethpkt.get_ethertype() == ethernet::EtherTypes::Ipv4);

    let ippkt = ipv4::Ipv4Packet::new(ethpkt.payload()).unwrap();
    assert!(ippkt.get_next_level_protocol() == ip::IpNextHeaderProtocols::Udp);
    assert!(ippkt.get_source() == Ipv4Addr::new(192, 168, 29, 58));
    assert!(ippkt.get_destination() == Ipv4Addr::new(192, 168, 29, 160));
    assert!(ippkt.get_checksum() == 0x0000);
    assert!(ippkt.get_identification() == 0x5c65);
}

fn pnet_l4(buf: &[u8]) {
    let ethpkt = ethernet::EthernetPacket::new(buf).unwrap();
    assert!(ethpkt.get_ethertype() == ethernet::EtherTypes::Ipv4);

    let ippkt = ipv4::Ipv4Packet::new(ethpkt.payload()).unwrap();
    assert!(ippkt.get_next_level_protocol() == ip::IpNextHeaderProtocols::Udp);
    assert!(ippkt.get_source() == Ipv4Addr::new(192, 168, 29, 58));
    assert!(ippkt.get_destination() == Ipv4Addr::new(192, 168, 29, 160));
    assert!(ippkt.get_checksum() == 0x0000);
    assert!(ippkt.get_identification() == 0x5c65);

    let udppkt = udp::UdpPacket::new(ippkt.payload()).unwrap();
    assert!(udppkt.get_source() == 60376);
    assert!(udppkt.get_destination() == 161);
    assert!(udppkt.get_length() == 74);
    assert!(udppkt.get_checksum() == 0xbc86);
}

fn pnet_app(buf: &[u8]) {
    let ethpkt = ethernet::EthernetPacket::new(buf).unwrap();
    assert!(ethpkt.get_ethertype() == ethernet::EtherTypes::Ipv4);

    let ippkt = ipv4::Ipv4Packet::new(ethpkt.payload()).unwrap();
    assert!(ippkt.get_next_level_protocol() == ip::IpNextHeaderProtocols::Udp);
    assert!(ippkt.get_source() == Ipv4Addr::new(192, 168, 29, 58));
    assert!(ippkt.get_destination() == Ipv4Addr::new(192, 168, 29, 160));
    assert!(ippkt.get_checksum() == 0x0000);
    assert!(ippkt.get_identification() == 0x5c65);

    let udppkt = udp::UdpPacket::new(ippkt.payload()).unwrap();
    assert!(udppkt.get_source() == 60376);
    assert!(udppkt.get_destination() == 161);
    assert!(udppkt.get_length() == 74);
    assert!(udppkt.get_checksum() == 0xbc86);

    let payload = udppkt.payload();
    let mut b = [0; 66];
    (&mut b[..]).copy_from_slice(payload);

    assert!(b[0..66] == FRAME_BYTES[42..108]);
}

pub fn b1(c: &mut Criterion) {
    c.bench_function("pnet_l2", |b| {
        b.iter(|| {
            pnet_l2(black_box(&FRAME_BYTES[..]));
        })
    });
}

pub fn b2(c: &mut Criterion) {
    c.bench_function("pnet_l3", |b| {
        b.iter(|| {
            pnet_l3(black_box(&FRAME_BYTES[..]));
        })
    });
}

pub fn b3(c: &mut Criterion) {
    c.bench_function("pnet_l4", |b| {
        b.iter(|| {
            pnet_l4(black_box(&FRAME_BYTES[..]));
        })
    });
}

pub fn b4(c: &mut Criterion) {
    c.bench_function("pnet_app", |b| {
        b.iter(|| {
            pnet_app(black_box(&FRAME_BYTES[..]));
        })
    });
}

criterion_group!(benches, b1, b2, b3, b4);
criterion_main!(benches);
