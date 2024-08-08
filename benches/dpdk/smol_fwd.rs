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

const BATCHSIZE: usize = 32;

const DMAC: wire::EthernetAddress = wire::EthernetAddress([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]);
const DIP: wire::Ipv4Address = wire::Ipv4Address([192, 168, 22, 2]);
const DPORT: u16 = 1024;

fn smol_fwd_l3(
    mp: &Mempool,
    ibatch: &mut ArrayVec<Mbuf, BATCHSIZE>,
    obatch: &mut ArrayVec<Mbuf, BATCHSIZE>,
) {
    mp.fill_batch(ibatch);

    for mut mbuf in ibatch.drain(..) {
        let pkt = mbuf.data_mut();

        match wire::EthernetFrame::new_checked(pkt) {
            Ok(mut ethpkt) => {
                if ethpkt.ethertype() == wire::EthernetProtocol::Ipv4 {
                    match wire::Ipv4Packet::new_checked(ethpkt.payload_mut()) {
                        Ok(mut ippkt) => {
                            ippkt.set_dst_addr(DIP);
                            ippkt.set_hop_limit(ippkt.hop_limit() - 1);
                            ethpkt.set_dst_addr(DMAC);
                            // omit manual ip address adjustment
                            // ippkt.adjust_checksum()
                            obatch.push(mbuf);
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => {}
        }
    }

    Mempool::free_batch(obatch);
}

fn smol_fwd_l4(
    mp: &Mempool,
    ibatch: &mut ArrayVec<Mbuf, BATCHSIZE>,
    obatch: &mut ArrayVec<Mbuf, BATCHSIZE>,
) {
    mp.fill_batch(ibatch);

    for mut mbuf in ibatch.drain(..) {
        let pkt = mbuf.data_mut();

        match wire::EthernetFrame::new_checked(pkt) {
            Ok(mut ethpkt) => {
                if ethpkt.ethertype() == wire::EthernetProtocol::Ipv4 {
                    match wire::Ipv4Packet::new_checked(ethpkt.payload_mut()) {
                        Ok(mut ippkt) => {
                            if ippkt.next_header() == wire::IpProtocol::Udp {
                                match wire::UdpPacket::new_checked(ippkt.payload_mut()) {
                                    Ok(mut udppkt) => {
                                        udppkt.set_dst_port(DPORT);
                                        ippkt.set_dst_addr(DIP);
                                        ippkt.set_hop_limit(ippkt.hop_limit() - 1);
                                        ethpkt.set_dst_addr(DMAC);
                                        // omit manual ip address adjustment
                                        // ippkt.adjust_checksum()
                                        obatch.push(mbuf);
                                    }
                                    Err(_) => {}
                                }
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(_) => {}
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

        c.bench_function("smol_fwd_l3", |b| {
            b.iter(|| {
                smol_fwd_l3(
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

        c.bench_function("smol_fwd_l4", |b| {
            b.iter(|| {
                black_box(smol_fwd_l4(
                    black_box(&mp),
                    black_box(&mut ibatch),
                    black_box(&mut obatch),
                ));
            })
        });
    }
    service().mempool_free("wtf").unwrap();
}

criterion_group!(benches, b3, b4);
criterion_main!(benches);
