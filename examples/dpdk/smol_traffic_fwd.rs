use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;
use rpkt_dpdk::*;
use smoltcp::wire;

const BATCHSIZE: usize = 32;

// 14.01

fn init_port(
    port_id: u16,
    nb_qs: u32,
    mp_name: &'static str,
    mpconf: &mut MempoolConf,
    rxq_conf: &mut RxQueueConf,
    txq_conf: &mut TxQueueConf,
) {
    let port_infos = service().port_infos().unwrap();
    let port_info = &port_infos[port_id as usize];
    let socket_id = port_info.socket_id;

    mpconf.socket_id = socket_id;
    service().mempool_create(mp_name, mpconf).unwrap();

    let pconf = PortConf::from_port_info(port_info).unwrap();

    rxq_conf.mp_name = mp_name.to_string();
    rxq_conf.socket_id = socket_id;
    txq_conf.socket_id = socket_id;
    let mut rxq_confs = Vec::new();
    let mut txq_confs = Vec::new();
    for _ in 0..nb_qs {
        rxq_confs.push(rxq_conf.clone());
        txq_confs.push(txq_conf.clone());
    }

    service()
        .port_configure(port_id, &pconf, &rxq_confs, &txq_confs)
        .unwrap();

    println!("finish configuring p{}", port_id);
}

fn main() {
    DpdkOption::new().init().unwrap();

    let dmac = wire::EthernetAddress([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]);
    let dip = wire::Ipv4Address([192, 168, 22, 2]);
    let dport = 1024;

    let nb_qs = 1;
    let mut mpconf = MempoolConf::default();
    mpconf.nb_mbufs = 8192 * 5;
    mpconf.per_core_caches = 256;
    let mut rxq_conf = RxQueueConf::default();
    rxq_conf.nb_rx_desc = 1024;
    let mut txq_conf = TxQueueConf::default();
    txq_conf.nb_tx_desc = 1024;

    let iport_id = 0;
    let iport_mp = "iport_mp";
    init_port(
        iport_id,
        nb_qs,
        iport_mp,
        &mut mpconf,
        &mut rxq_conf,
        &mut txq_conf,
    );

    let oport_id = 3;
    let oport_mp = "oport_mp";
    init_port(
        oport_id,
        nb_qs,
        oport_mp,
        &mut mpconf,
        &mut rxq_conf,
        &mut txq_conf,
    );

    let start_core = 1;
    let iport_socket_id = service().port_infos().unwrap()[iport_id as usize].socket_id;
    let oport_socket_id = service().port_infos().unwrap()[oport_id as usize].socket_id;
    service()
        .lcores()
        .iter()
        .find(|lcore| lcore.lcore_id >= start_core && lcore.lcore_id < start_core + nb_qs)
        .map(|lcore| {
            assert!(
                lcore.socket_id == iport_socket_id,
                "core with invalid socket id"
            );
            assert!(
                lcore.socket_id == oport_socket_id,
                "core with invalid socket id"
            );
        });

    let run = Arc::new(AtomicBool::new(true));
    let run_clone = run.clone();
    ctrlc::set_handler(move || {
        run_clone.store(false, Ordering::Release);
    })
    .unwrap();

    let mut jhs = Vec::new();

    // launch forwarding
    for qid in 0..nb_qs {
        let run = run.clone();
        let jh = std::thread::spawn(move || {
            service().lcore_bind(start_core + qid).unwrap();

            let mut txq = service().tx_queue(oport_id, qid as u16).unwrap();
            let mut rxq = service().rx_queue(iport_id, qid as u16).unwrap();

            let mut ibatch = ArrayVec::<_, BATCHSIZE>::new();
            let mut obatch = ArrayVec::<_, BATCHSIZE>::new();
            while run.load(Ordering::Acquire) {
                rxq.rx(&mut ibatch);
                for mut mbuf in ibatch.drain(..) {
                    let pkt = mbuf.data_mut();

                    let mut ethpkt = wire::EthernetFrame::new_unchecked(pkt);
                    match ethpkt.ethertype() {
                        wire::EthernetProtocol::Ipv4 => {
                            match wire::Ipv4Packet::new_checked(ethpkt.payload_mut()) {
                                Ok(mut ippkt) => {
                                    if ippkt.hop_limit() > 0
                                        && ippkt.protocol() == wire::IpProtocol::Udp
                                    {
                                        match wire::UdpPacket::new_checked(ippkt.payload_mut()) {
                                            Ok(mut udppkt) => {
                                                udppkt.set_dst_port(dport);
                                                ippkt.set_dst_addr(dip);
                                                ippkt.set_hop_limit(ippkt.hop_limit() - 1);
                                                ethpkt.set_dst_addr(dmac);
                                                // omit manual ip address adjustment
                                                // ippkt.adjust_checksum()
                                                obatch.push(mbuf);
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                }
                txq.tx(&mut obatch);
                Mempool::free_batch(&mut obatch);
            }
        });
        jhs.push(jh);
    }

    let mut old_stats = service().port_stats(oport_id).unwrap();
    while run.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let curr_stats = service().port_stats(oport_id).unwrap();
        println!(
            "forwarded pkts: {} pps, {} Gbps, {} errors/s",
            curr_stats.opackets() - old_stats.opackets(),
            (curr_stats.obytes() - old_stats.obytes()) as f64 * 8.0 / 1000000000.0,
            curr_stats.oerrors() - old_stats.oerrors(),
        );

        old_stats = curr_stats;
    }

    for jh in jhs {
        jh.join().unwrap();
    }

    service().port_close(iport_id).unwrap();
    service().port_close(oport_id).unwrap();
    println!("port closed");

    service().mempool_free(iport_mp).unwrap();
    service().mempool_free(oport_mp).unwrap();
    println!("mempool freed");

    service().service_close().unwrap();
    println!("dpdk service shutdown gracefully");
}
