use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;
use rpkt_dpdk::*;
use smoltcp::wire;

fn main() {
    DpdkOption::new().init().unwrap();
    let nb_qs = 14;

    let mut mpconf = MempoolConf::default();
    mpconf.nb_mbufs = 8192 * 4;
    mpconf.per_core_caches = 256;
    service().mempool_create("wtf", &mpconf).unwrap();

    let pconf = PortConf::default();
    let mut rxq_confs = Vec::new();
    let mut txq_confs = Vec::new();
    for _ in 0..nb_qs {
        let mut rx_queue = RxQueueConf::new();
        rx_queue.set_nb_rx_desc(1024);
        rx_queue.set_socket_id(0);
        rx_queue.set_mp_name("wtf");
        rxq_confs.push(rx_queue);
        let mut tx_queue = TxQueueConf::new();
        tx_queue.set_nb_tx_desc(1024);
        tx_queue.set_socket_id(0);
        txq_confs.push(tx_queue);
    }

    service()
        .port_configure(0, &pconf, &rxq_confs, &txq_confs)
        .unwrap();

    let run = Arc::new(AtomicBool::new(true));
    let run_curr = run.clone();
    let run_clone = run.clone();
    ctrlc::set_handler(move || {
        run_clone.store(false, Ordering::Release);
    })
    .unwrap();

    let total_header_len = 42;
    let payload_len = 18;

    let mut jhs = Vec::new();
    for i in 0..nb_qs {
        let run = run.clone();
        let jh = std::thread::spawn(move || {
            service().lcore_bind(i+1).unwrap();
            let mut txq = service().tx_queue(0, i as u16).unwrap();
            let mp = service().mempool("wtf").unwrap();
            let mut batch = ArrayVec::<_, 64>::new();

            while run.load(Ordering::Acquire) {
                mp.fill_batch(&mut batch);
                for mbuf in batch.iter_mut() {
                    unsafe { mbuf.extend(total_header_len + payload_len) };

                    let mut frame = wire::EthernetFrame::new_unchecked(mbuf.data_mut());
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

                while batch.len() > 0 {
                    let _sent = txq.tx(&mut batch);
                    // batch.drain(..);
                }
            }
        });
        jhs.push(jh);
    }

    let mut old_stats = service().stats_query(0).unwrap().query();
    while run_curr.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let curr_stats = service().stats_query(0).unwrap().query();
        println!(
            "pkts per sec: {}, bytes per sec: {}, errors per sec: {}",
            curr_stats.opackets() - old_stats.opackets(),
            (curr_stats.obytes() - old_stats.obytes()) as f64 * 8.0 / 1000000000.0,
            curr_stats.oerrors() - old_stats.oerrors(),
        );

        old_stats = curr_stats;
    }

    for jh in jhs {
        jh.join().unwrap();
    }

    service().port_close(0).unwrap();
    println!("port 0 closed");

    service().mempool_free("wtf").unwrap();
    println!("mempool wtf freed");

    service().service_close().unwrap();
    println!("dpdk service shutdown gracefully");
}
