use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;

use smoltcp::wire;

use run_dpdk::offload::MbufTxOffload;
use run_dpdk::*;

// the following result is acuiqred without setting ip checksum value
// nbcore      1         2        3        4          14       18
// run         17.02   28.94    30.94     31
// smoltcp     13.52   25.92    30.89     31


// The socket to work on
const WORKING_SOCKET: u32 = 1;

// Basic configuration of the mempool
const MBUF_CACHE: u32 = 256;
const MBUF_NUM: u32 = MBUF_CACHE * 32 * 10;
const MP_NAME: &str = "wtf";

// Basic configuration of the port
const PORT_ID: u16 = 3;

// Basic configuration of tx queues
const TXQ_NUM: u16 = 1;
const TXQ_DESC_NUM: u16 = 1024;

// Basic configuration of rx queues
const RXQ_NUM: u16 = TXQ_NUM;
const RXQ_DESC_NUM: u16 = 1024;

// rx threads
const START_CORE: usize = 33;

// dpdk batch size
const BATCH_SIZE: usize = 64;

fn entry_func() {
    // make sure that the rx and tx threads are on the correct cores
    let res = service()
        .lcores()
        .iter()
        .filter(|lcore| {
            lcore.lcore_id >= START_CORE as u32
                && lcore.lcore_id < START_CORE as u32 + RXQ_NUM as u32
        })
        .all(|lcore| lcore.socket_id == WORKING_SOCKET);
    assert!(res == true);

    let run = Arc::new(AtomicBool::new(true));
    let run_clone = run.clone();
    ctrlc::set_handler(move || {
        run_clone.store(false, Ordering::Release);
    })
    .unwrap();

    let mut jhs = Vec::new();

    for i in 0..TXQ_NUM as usize {
        let run_clone = run.clone();

        let jh = std::thread::spawn(move || {
            service().lcore_bind(i as u32 + START_CORE as u32).unwrap();

            let mut rxq = service().rx_queue(PORT_ID, i as u16).unwrap();
            let mut txq = service().tx_queue(PORT_ID, i as u16).unwrap();
            let mut batch = ArrayVec::<_, BATCH_SIZE>::new();

            let mut tx_of_flag = MbufTxOffload::ALL_DISABLED;
            tx_of_flag.enable_ip_cksum();
            tx_of_flag.enable_udp_cksum();

            while run_clone.load(Ordering::Acquire) {
                rxq.rx(&mut batch);

                for mbuf in batch.iter_mut() {
                    if let Ok(mut ethpkt) = wire::EthernetFrame::new_checked(mbuf.data_mut()) {
                        if ethpkt.ethertype() == wire::EthernetProtocol::Ipv4 {
                            if let Ok(mut ippkt) =
                                wire::Ipv4Packet::new_checked(ethpkt.payload_mut())
                            {
                                if ippkt.protocol() == wire::IpProtocol::Udp {
                                    if let Ok(mut udppkt) =
                                        wire::UdpPacket::new_checked(ippkt.payload_mut())
                                    {
                                        let old = udppkt.src_port();
                                        udppkt.set_src_port(udppkt.dst_port());
                                        udppkt.set_dst_port(old);

                                        let old = ippkt.src_addr();
                                        ippkt.set_src_addr(ippkt.dst_addr());
                                        ippkt.set_dst_addr(old);
                                        let ip_hdr_len = ippkt.header_len();

                                        let old = ethpkt.src_addr();
                                        ethpkt.set_src_addr(ethpkt.dst_addr());
                                        ethpkt.set_dst_addr(old);

                                        mbuf.set_tx_offload(tx_of_flag);
                                        mbuf.set_l2_len(14 as u64);
                                        mbuf.set_l3_len(ip_hdr_len as u64);
                                    }
                                }
                            }
                        }
                    }
                }

                txq.tx(&mut batch);
                Mempool::free_batch(&mut batch);
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
            "rx: {} Mpps, {} Gbps || tx: {} Mpps, {} Gbps",
            (curr_stats.ipackets() - old_stats.ipackets()) as f64 / 1_000_000.0,
            (curr_stats.ibytes() - old_stats.ibytes()) as f64 * 8.0 / 1_000_000_000.0,
            (curr_stats.opackets() - old_stats.opackets()) as f64 / 1_000_000.0,
            (curr_stats.obytes() - old_stats.obytes()) as f64 * 8.0 / 1_000_000_000.0,
        );

        old_stats = curr_stats;
    }

    for jh in jhs {
        jh.join().unwrap();
    }
}

fn main() {
    assert!(RXQ_NUM == TXQ_NUM);

    DpdkOption::new().init().unwrap();

    // create mempool
    utils::init_mempool(MP_NAME, MBUF_NUM, MBUF_CACHE, WORKING_SOCKET).unwrap();

    // create the port
    utils::init_port(
        PORT_ID,
        RXQ_NUM,
        TXQ_NUM,
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
