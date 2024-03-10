use std::collections::HashSet;
use std::sync::{atomic::AtomicBool, atomic::AtomicUsize, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;

use rpkt_dpdk::*;
use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::Cursor;
use rpkt_time::*;

// The socket to work on
const WORKING_SOCKET: u32 = 1;
const THREAD_NUM: u32 = 3;
const START_CORE: usize = 33;

// dpdk batch size
const BATCH_SIZE: usize = 64;

// Basic configuration of the mempool
const MBUF_CACHE: u32 = 256;
const MBUF_NUM: u32 = MBUF_CACHE * 32 * THREAD_NUM;
const MP_NAME: &str = "wtf";

// Basic configuration of the port
const PORT_ID: u16 = 0;
const TXQ_DESC_NUM: u16 = 1024;
const RXQ_DESC_NUM: u16 = 1024;

fn entry_func() {
    // make sure that the rx and tx threads are on the correct cores
    let res = service()
        .lcores()
        .iter()
        .filter(|lcore| {
            lcore.lcore_id >= START_CORE as u32
                && lcore.lcore_id < START_CORE as u32 + THREAD_NUM
        })
        .all(|lcore| lcore.socket_id == WORKING_SOCKET);
    assert_eq!(res, true);

    let run = Arc::new(AtomicBool::new(true));
    let run_clone = run.clone();
    ctrlc::set_handler(move || {
        run_clone.store(false, Ordering::Release);
    })
    .unwrap();

    let mut jhs = Vec::new();

    let mut pps_stats = Vec::new();
    let mut bps_stats = Vec::new();
    let mut flow_nums = Vec::new();

    for i in 0..THREAD_NUM as usize {
        let run_clone = run.clone();

        let per_q_pps = Arc::new(AtomicUsize::new(0));
        pps_stats.push(per_q_pps.clone());
        let per_q_bps = Arc::new(AtomicUsize::new(0));
        bps_stats.push(per_q_bps.clone());
        let flow_num = Arc::new(AtomicUsize::new(0));
        flow_nums.push(flow_num.clone());

        let jh = std::thread::spawn(move || {
            service().lcore_bind(i as u32 + START_CORE as u32).unwrap();

            let mut rxq = service().rx_queue(PORT_ID, i as u16).unwrap();
            let mut batch = ArrayVec::<_, BATCH_SIZE>::new();

            let mut total_pkts = 0;
            let mut total_bytes = 0;
            let mut prev_pkts = 0;
            let mut prev_bytes = 0;

            let mut next_ddl = Instant::now().raw() + cycles_per_sec();

            let mut hs = HashSet::new();

            while run_clone.load(Ordering::Acquire) {
                rxq.rx(&mut batch);

                total_pkts += batch.len();
                for mbuf in batch.iter() {
                    total_bytes += mbuf.len();

                    let buf = Cursor::new(mbuf.data());
                    let _ = EtherPacket::parse(buf)
                        .and_then(|eth| {
                            if eth.ethertype() != EtherType::IPV4 {
                                Err(eth.release())
                            } else {
                                Ipv4Packet::parse(eth.payload())
                            }
                        })
                        .and_then(|ipv4| {
                            let addr = u32::from_le_bytes(ipv4.source_ip().0);

                            if let None = hs.get(&addr) {
                                hs.insert(addr);
                            }

                            Ok(())
                        });
                }

                Mempool::free_batch(&mut batch);

                if Instant::now().raw() >= next_ddl {
                    per_q_pps.store(total_pkts - prev_pkts, Ordering::SeqCst);
                    per_q_bps.store(total_bytes - prev_bytes, Ordering::SeqCst);
                    flow_num.store(hs.len(), Ordering::SeqCst);

                    prev_pkts = total_pkts;
                    prev_bytes = total_bytes;
                    hs.clear();
                    next_ddl = Instant::now().raw() + cycles_per_sec();
                }
            }
        });
        jhs.push(jh);
    }

    let mut stats_query = service().stats_query(PORT_ID).unwrap();
    let mut old_stats = stats_query.query();
    let mut curr_stats = stats_query.query();
    while run.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        stats_query.update(&mut curr_stats);
        println!(
            "rx: {} Mpps, {} Gbps",
            (curr_stats.ipackets() - old_stats.ipackets()) as f64 / 1_000_000.0,
            (curr_stats.ibytes() - old_stats.ibytes()) as f64 * 8.0 / 1_000_000_000.0,
        );

        old_stats = curr_stats;

        let mut sum_pps = 0.0;
        let mut sum_bps = 0.0;
        for qid in 0..THREAD_NUM as usize {
            print!("rxq {}: ", qid);
            println!(
                "{} Mpps, {} Gbps, {} flows",
                pps_stats[qid].load(Ordering::SeqCst) as f64 / 1_000_000.0,
                bps_stats[qid].load(Ordering::SeqCst) as f64 * 8.0 / 1_000_000_000.0,
                flow_nums[qid].load(Ordering::SeqCst)
            );
            sum_pps += pps_stats[qid].load(Ordering::SeqCst) as f64 / 1_000_000.0;
            sum_bps += bps_stats[qid].load(Ordering::SeqCst) as f64 * 8.0 / 1_000_000_000.0;
        }
        println!("total {} Mpps, {} Gbps", sum_pps, sum_bps);
    }

    for jh in jhs {
        jh.join().unwrap();
    }
}

fn main() {
    DpdkOption::new().init().unwrap();

    // create mempool
    utils::init_mempool(MP_NAME, MBUF_NUM, MBUF_CACHE, WORKING_SOCKET).unwrap();

    // create the port
    utils::init_port(
        PORT_ID,
        THREAD_NUM as u16,
        THREAD_NUM as u16,
        RXQ_DESC_NUM,
        MP_NAME,
        TXQ_DESC_NUM,
        WORKING_SOCKET,
    )
    .unwrap();

    entry_func();

    // shutdown the port
    service().port_close(PORT_ID).unwrap();

    // free the mempool
    service().mempool_free(MP_NAME).unwrap();

    // shutdown the DPDK service
    service().service_close().unwrap();

    println!("dpdk service shutdown gracefully");
}
