use arrayvec::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rpkt_dpdk::*;
use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::udp::*;
use rpkt::CursorMut;

static FRAME_BYTES: [u8; 110] = [
    0x00, 0x0b, 0x86, 0x64, 0x8b, 0xa0, 0x00, 0x50, 0x56, 0xae, 0x76, 0xf5, 0x08, 0x00, 0x45, 0x00,
    0x00, 0x5e, 0x5c, 0x65, 0x00, 0x00, 0x80, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x1d, 0x3a, 0xc0, 0xa8,
    0x1d, 0xa0, 0xeb, 0xd8, 0x00, 0xa1, 0x00, 0x4a, 0xbc, 0x86, 0x30, 0x40, 0x02, 0x01, 0x03, 0x30,
    0x0f, 0x02, 0x03, 0x00, 0x91, 0xc8, 0x02, 0x02, 0x05, 0xdc, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03,
    0x04, 0x15, 0x30, 0x13, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x05, 0x61, 0x64,
    0x6d, 0x69, 0x6e, 0x04, 0x00, 0x04, 0x00, 0x30, 0x13, 0x04, 0x00, 0x04, 0x00, 0xa0, 0x0d, 0x02,
    0x03, 0x00, 0x91, 0xc8, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00, 0x00, 0x00,
];

const BATCHSIZE: usize = 32;

const DMAC: MacAddr = MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]);
const DIP: Ipv4Addr = Ipv4Addr([192, 168, 22, 2]);
const DPORT: u16 = 1024;

fn cursor_fwd_l3(
    mp: &Mempool,
    ibatch: &mut ArrayVec<Mbuf, BATCHSIZE>,
    obatch: &mut ArrayVec<Mbuf, BATCHSIZE>,
) {
    mp.fill_batch(ibatch);

    for mut mbuf in ibatch.drain(..) {
        let pkt = CursorMut::new(mbuf.data_mut());
        match EtherPacket::parse(pkt) {
            Ok(ethpkt) => {
                match ethpkt.ethertype() {
                    EtherType::IPV4 => {
                        let (mut ethhdr, payload) = ethpkt.split();
                        match Ipv4Packet::parse(payload) {
                            Ok(mut ippkt) => {
                                ippkt.set_dest_ip(DIP);
                                ippkt.set_time_to_live(ippkt.time_to_live() - 1);
                                ethhdr.set_dest_mac(DMAC);
                                // omit manual ip address adjustment
                                // ippkt.adjust_checksum()
                                obatch.push(mbuf);
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    Mempool::free_batch(obatch);
}

fn cursor_fwd_l4(
    mp: &Mempool,
    ibatch: &mut ArrayVec<Mbuf, BATCHSIZE>,
    obatch: &mut ArrayVec<Mbuf, BATCHSIZE>,
) {
    mp.fill_batch(ibatch);

    for mut mbuf in ibatch.drain(..) {
        let pkt = CursorMut::new(mbuf.data_mut());
        match EtherPacket::parse(pkt) {
            Ok(ethpkt) => match ethpkt.ethertype() {
                EtherType::IPV4 => {
                    let (mut ethhdr, payload) = ethpkt.split();
                    match Ipv4Packet::parse(payload) {
                        Ok(ippkt) => match ippkt.protocol() {
                            IpProtocol::UDP => {
                                let (mut iphdr, _, payload) = ippkt.split();
                                match UdpPacket::parse(payload) {
                                    Ok(mut udppkt) => {
                                        ethhdr.set_dest_mac(DMAC);
                                        iphdr.set_dest_ip(DIP);
                                        iphdr.set_time_to_live(iphdr.time_to_live() - 1);
                                        udppkt.set_dest_port(DPORT);
                                        obatch.push(mbuf);
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    Mempool::free_batch(obatch);
}

pub fn b3(c: &mut Criterion) {
    DpdkOption::new().init().unwrap();
    {
        let mut config = MempoolConf::default();
        config.nb_mbufs = 4096;
        config.dataroom = 2048;

        let mp = service().mempool_create("wtf", &config).unwrap();

        let mut v = Vec::new();
        while let Some(mut mbuf) = mp.try_alloc() {
            mbuf.extend_from_slice(&FRAME_BYTES[..]);
            v.push(mbuf);
        }
        drop(v);

        let mut ibatch: ArrayVec<_, BATCHSIZE> = ArrayVec::new();
        let mut obatch: ArrayVec<_, BATCHSIZE> = ArrayVec::new();

        c.bench_function("cursor_fwd_l3", |b| {
            b.iter(|| {
                cursor_fwd_l3(
                    black_box(&mp),
                    black_box(&mut ibatch),
                    black_box(&mut obatch),
                );
            })
        });
    }
    service().mempool_free("wtf").unwrap();
}

pub fn b4(c: &mut Criterion) {
    DpdkOption::new().init().unwrap();
    {
        let mut config = MempoolConf::default();
        config.nb_mbufs = 4096;
        config.dataroom = 2048;

        let mp = service().mempool_create("wtf", &config).unwrap();

        let mut v = Vec::new();
        while let Some(mut mbuf) = mp.try_alloc() {
            mbuf.extend_from_slice(&FRAME_BYTES[..]);
            v.push(mbuf);
        }
        drop(v);

        let mut ibatch: ArrayVec<_, BATCHSIZE> = ArrayVec::new();
        let mut obatch: ArrayVec<_, BATCHSIZE> = ArrayVec::new();

        c.bench_function("cursor_fwd_l4", |b| {
            b.iter(|| {
                cursor_fwd_l4(
                    black_box(&mp),
                    black_box(&mut ibatch),
                    black_box(&mut obatch),
                );
            })
        });
    }
    service().mempool_free("wtf").unwrap();
}

criterion_group!(benches, b3, b4);
criterion_main!(benches);
