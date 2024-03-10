// use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use rpkt::ether::MacAddr;
use rpkt_dpdk::*;
// use ctrlc;

fn main() {
    DpdkOption::new().init().unwrap();

    for lcore in service().lcores().iter() {
        println!("lcore {} on socket {}", lcore.lcore_id, lcore.socket_id);
    }

    let port_infos = service().port_infos().unwrap();
    for port_info in port_infos {
        println!(
            "port {} with driver {} on socket {} with mac addr {}, started {}",
            port_info.port_id,
            port_info.driver_name,
            port_info.socket_id,
            MacAddr(port_info.eth_addr),
            port_info.started
        );
        println!(
            "port {}: tx desc {}, {}, {}",
            port_info.port_id,
            port_info.tx_desc_lim().nb_min(),
            port_info.tx_desc_lim().nb_max(),
            port_info.tx_desc_lim().nb_align()
        );
        println!(
            "port {}: rx desc {}, {}, {}",
            port_info.port_id,
            port_info.rx_desc_lim().nb_min(),
            port_info.rx_desc_lim().nb_max(),
            port_info.rx_desc_lim().nb_align()
        );
        println!(
            "port {}, rx q {}, tx q {}",
            port_info.port_id,
            port_info.max_rx_queues(),
            port_info.max_tx_queues()
        );
        println!(
            "port {}, min mtu {}, max mtu {}",
            port_info.port_id,
            port_info.min_mtu(),
            port_info.max_mtu()
        );
        println!(
            "port {}, lro info: {}, {}, {}",
            port_info.port_id,
            port_info.min_rx_bufsize(),
            port_info.max_lro_pkt_size(),
            port_info.max_rx_pktlen()
        );
        println!(
            "port {}, rss info: {}, {}",
            port_info.port_id,
            port_info.reta_size(),
            port_info.hash_key_size()
        );
    }

    let mut mpconf = MempoolConf::default();
    mpconf.socket_id = 1;
    service().mempool_create("wtf", &mpconf).unwrap();
    println!("mempool wtf created");

    let pconf = PortConf::default();
    let mut rxq_confs = Vec::new();
    let mut txq_confs = Vec::new();
    for _ in 0..4 {
        rxq_confs.push(RxQueueConf::new(128, 0, "wtf"));
        txq_confs.push(TxQueueConf::new(128, 0));
    }
    println!("create confs");

    service()
        .port_configure(0, &pconf, &rxq_confs, &txq_confs)
        .unwrap();
    println!("port 0 created");

    let mut jhs = Vec::new();
    for i in 0..4 {
        let jh = std::thread::spawn(move || {
            service().lcore_bind(u32::from(i) + 1).unwrap();
            let mut rxq = service().rx_queue(0, i).unwrap();
            let mut txq = service().tx_queue(0, i).unwrap();

            let mut batch = ArrayVec::<_, 32>::new();
            let nb = rxq.rx(&mut batch);
            println!("lcore {}: recieving {} packets", i + 1, nb);

            let tnb = txq.tx(&mut batch);
            println!("lcore {}: sending {} packets", i + 1, tnb);
        });
        jhs.push(jh);
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
