use std::sync::{atomic::AtomicBool, atomic::AtomicUsize, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;
use run_dpdk::*;
use run_time::*;

// test pmd test command:
// sudo ./dpdk-testpmd -l 0-16 -n 4 -- -i  --portlist=0 --forward-mode=rxonly --txq=16 --rxq=16 --nb-cores=16

// nbcore      1         2        4        8         12      16
// run         17.35     31.68    46.04    55.66     60.33   59.36
// testpmd     16.75      30.66    43.51    48.70     53.06   55.40

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

    let port_id = 3;
    let nb_qs = 4;
    let mp_name = "mp";
    let mut mpconf = MempoolConf::default();
    mpconf.nb_mbufs = 8192 * 4;
    mpconf.per_core_caches = 256;
    let mut rxq_conf = RxQueueConf::default();
    rxq_conf.nb_rx_desc = 1024;
    let mut txq_conf = TxQueueConf::default();
    txq_conf.nb_tx_desc = 1024;
    init_port(
        port_id,
        nb_qs,
        mp_name,
        &mut mpconf,
        &mut rxq_conf,
        &mut txq_conf,
    );

    let start_core = 1;
    let socket_id = service().port_infos().unwrap()[port_id as usize].socket_id;
    service()
        .lcores()
        .iter()
        .find(|lcore| lcore.lcore_id >= start_core && lcore.lcore_id < start_core + nb_qs)
        .map(|lcore| {
            assert!(lcore.socket_id == socket_id, "core with invalid socket id");
        });

    let run = Arc::new(AtomicBool::new(true));
    let run_clone = run.clone();
    ctrlc::set_handler(move || {
        run_clone.store(false, Ordering::Release);
    })
    .unwrap();

    let mut jhs = Vec::new();
    let mut pps_stats = Vec::new();
    let mut bps_stats = Vec::new();
    for i in 0..nb_qs {
        let run = run.clone();
        let per_q_pps = Arc::new(AtomicUsize::new(0));
        pps_stats.push(per_q_pps.clone());
        let per_q_bps = Arc::new(AtomicUsize::new(0));
        bps_stats.push(per_q_bps.clone());

        let jh = std::thread::spawn(move || {
            service().lcore_bind(i + 1).unwrap();
            let mut rxq = service().rx_queue(port_id as u16, i as u16).unwrap();
            let mut batch = ArrayVec::<_, 32>::new();

            let mut total_pkts = 0;
            let mut total_bytes = 0;
            let mut prev_pkts = 0;
            let mut prev_bytes = 0;

            let mut next_ddl = Instant::now().raw() + cycles_per_sec();

            while run.load(Ordering::Acquire) {
                rxq.rx(&mut batch);

                total_pkts += batch.len();
                for mbuf in batch.iter() {
                    total_bytes += mbuf.len();
                }

                Mempool::free_batch(&mut batch);

                if Instant::now().raw() >= next_ddl {
                    per_q_pps.store(total_pkts - prev_pkts, Ordering::SeqCst);
                    per_q_bps.store(total_bytes - prev_bytes, Ordering::SeqCst);

                    prev_pkts = total_pkts;
                    prev_bytes = total_bytes;
                    next_ddl = Instant::now().raw() + cycles_per_sec();
                }
            }
        });
        jhs.push(jh);
    }

    let mut old_stats = service().port_stats(port_id).unwrap();
    while run.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let curr_stats = service().port_stats(port_id).unwrap();

        println!(
            "total rx: {} pps, {} bps, {} misses/s",
            curr_stats.ipackets() - old_stats.ipackets(),
            (curr_stats.ibytes() - old_stats.ibytes()) as f64 * 8.0 / 1000000000.0,
            curr_stats.imissed() - old_stats.imissed()
        );

        print!("per q rx: ");
        for qid in 0..nb_qs as usize {
            print!(
                "q{} {} pps {} bps, ",
                qid,
                pps_stats[qid].load(Ordering::SeqCst),
                bps_stats[qid].load(Ordering::SeqCst) as f64 * 8.0 / 1000000000.0,
            );
        }
        println!("");

        old_stats = curr_stats;
    }

    for jh in jhs {
        jh.join().unwrap();
    }

    service().port_close(port_id).unwrap();
    println!("port closed");

    service().mempool_free(mp_name).unwrap();
    println!("mempool freed");

    service().service_close().unwrap();
    println!("dpdk service shutdown gracefully");
}
