use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;
use rpkt_dpdk::*;
use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::udp::*;
use rpkt::Buf;
use rpkt::CursorMut;

const BATCHSIZE: usize = 64;

fn init_port(
    port_id: u16,
    nb_qs: u32,
    start_core: u32,
    mp_name: &'static str,
    mpconf: &mut MempoolConf,
    rxq_conf: &mut RxQueueConf,
    txq_conf: &mut TxQueueConf,
) {
    let port_infos = service().port_infos().unwrap();
    let port_info = &port_infos[port_id as usize];
    let socket_id = port_info.socket_id;

    service()
        .lcores()
        .iter()
        .find(|lcore| lcore.lcore_id >= start_core && lcore.lcore_id < start_core + nb_qs)
        .map(|lcore| {
            assert!(lcore.socket_id == socket_id, "core with invalid socket id");
        });

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

    // ethernet frame size: 64 - 1514, where 4 bytes are check sum
    let total_header_len = ETHER_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN; // 42
    let payload_len = 18; // min size: 60-4-total_header_len, max_size: 1514-4-total_header_len

    let p0_id = 0;
    let p0_nb_qs = 14;
    let p0_start_core = 1;
    let mut p0_mpconf = MempoolConf::default();
    p0_mpconf.nb_mbufs = 8192 * 10;
    p0_mpconf.per_core_caches = 256;
    p0_mpconf.dataroom = MempoolConf::DATAROOM;
    let mut p0_rxq_conf = RxQueueConf::default();
    p0_rxq_conf.nb_rx_desc = 1024;
    let mut p0_txq_conf = TxQueueConf::default();
    p0_txq_conf.nb_tx_desc = 1024;

    init_port(
        p0_id,
        p0_nb_qs,
        p0_start_core,
        "p0_mp",
        &mut p0_mpconf,
        &mut p0_rxq_conf,
        &mut p0_txq_conf,
    );

    let p1_id = 1;
    let p1_nb_qs = 4;
    let p1_start_core = p0_start_core + p0_nb_qs;
    let mut p1_mpconf = MempoolConf::default();
    p1_mpconf.nb_mbufs = 8192 * 10;
    p1_mpconf.per_core_caches = 256;
    p1_mpconf.dataroom = MempoolConf::DATAROOM;
    let mut p1_rxq_conf = RxQueueConf::default();
    p1_rxq_conf.nb_rx_desc = 1024;
    let mut p1_txq_conf = TxQueueConf::default();
    p1_txq_conf.nb_tx_desc = 1024;

    init_port(
        p1_id,
        p1_nb_qs,
        p1_start_core,
        "p1_mp",
        &mut p1_mpconf,
        &mut p1_rxq_conf,
        &mut p1_txq_conf,
    );

    let run = Arc::new(AtomicBool::new(true));
    let run_clone = run.clone();
    ctrlc::set_handler(move || {
        run_clone.store(false, Ordering::Release);
    })
    .unwrap();

    let mut jhs = Vec::new();

    // launch p0 threads
    for qid in 0..p0_nb_qs {
        let run = run.clone();
        let jh = std::thread::spawn(move || {
            service().lcore_bind(p0_start_core + qid).unwrap();

            let mut txq = service().tx_queue(p0_id, qid as u16).unwrap();
            let mp = service().mempool("p0_mp").unwrap();

            let mut batch = ArrayVec::<_, BATCHSIZE>::new();
            while run.load(Ordering::Acquire) {
                mp.fill_batch(&mut batch);
                for mbuf in batch.iter_mut() {
                    unsafe { mbuf.extend(total_header_len + payload_len) };

                    let mut pkt = CursorMut::new(mbuf.data_mut());
                    pkt.advance(total_header_len);

                    let mut udppkt = UdpPacket::prepend_header(pkt, &UDP_HEADER_TEMPLATE);
                    udppkt.set_source_port(60376);
                    udppkt.set_dest_port(161);

                    let mut ippkt =
                        Ipv4Packet::prepend_header(udppkt.release(), &IPV4_HEADER_TEMPLATE);
                    ippkt.set_ident(0x5c65);
                    ippkt.clear_flags();
                    ippkt.set_time_to_live(128);
                    ippkt.set_source_ip(Ipv4Addr([192, 168, 29, 58]));
                    ippkt.set_dest_ip(Ipv4Addr([192, 168, 12, 2]));
                    ippkt.set_protocol(IpProtocol::UDP);

                    let mut ethpkt =
                        EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
                    ethpkt.set_dest_mac(MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]));
                    ethpkt.set_source_mac(MacAddr([0x00, 0x50, 0x56, 0xae, 0x76, 0xf5]));
                    ethpkt.set_ethertype(EtherType::IPV4);
                }

                while batch.len() > 0 {
                    let _sent = txq.tx(&mut batch);
                }
            }
        });
        jhs.push(jh);
    }

    // launch p1 threads
    for qid in 0..p1_nb_qs {
        let run = run.clone();
        let jh = std::thread::spawn(move || {
            service().lcore_bind(p1_start_core + qid).unwrap();

            let mut rxq = service().rx_queue(p1_id, qid as u16).unwrap();

            let mut batch = ArrayVec::<_, BATCHSIZE>::new();
            while run.load(Ordering::Acquire) {
                rxq.rx(&mut batch);
                batch.drain(..);
            }
        });
        jhs.push(jh);
    }

    let mut p0_old_stats = service().port_stats(p0_id).unwrap();
    let mut p1_old_stats = service().port_stats(p1_id).unwrap();
    while run.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_secs(1));

        let p0_curr_stats = service().port_stats(p0_id).unwrap();
        let p1_curr_stats = service().port_stats(p1_id).unwrap();

        println!(
            "tx: {} pps, {} Gbps; rx: {} pps, {} Gps; rx_missed: {} pps",
            p0_curr_stats.opackets() - p0_old_stats.opackets(),
            (p0_curr_stats.obytes() - p0_old_stats.obytes()) as f64 * 8.0 / 1000000000.0,
            p1_curr_stats.ipackets() - p1_old_stats.ipackets(),
            (p1_curr_stats.ibytes() - p1_old_stats.ibytes()) as f64 * 8.0 / 1000000000.0,
            p1_curr_stats.imissed() - p1_old_stats.imissed()
        );

        p0_old_stats = p0_curr_stats;
        p1_old_stats = p1_curr_stats;
    }

    for jh in jhs {
        jh.join().unwrap();
    }

    service().port_close(0).unwrap();
    service().port_close(1).unwrap();
    println!("port 0/1 closed");

    service().mempool_free("p0_mp").unwrap();
    service().mempool_free("p1_mp").unwrap();
    println!("mempool p0/p1 freed");

    service().service_close().unwrap();
    println!("dpdk service shutdown gracefully");
}
