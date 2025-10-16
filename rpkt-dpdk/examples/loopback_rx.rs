use std::net::Ipv4Addr;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;
use once_cell::sync::OnceCell;

use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::udp::*;
use rpkt::CursorMut;
use rpkt_dpdk::*;

// The socket to work on
const WORKING_SOCKET: u32 = 1;
const THREAD_NUM: u32 = 2;
const START_CORE: usize = 64;

// dpdk batch size
const BATCH_SIZE: usize = 64;

// Basic configuration of the mempool
const MBUF_CACHE: u32 = 256;
const MBUF_NUM: u32 = MBUF_CACHE * 32 * THREAD_NUM;
const MP_NAME: &str = "wtf";

// Basic configuration of the port
const PORT_ID: u16 = 0;
const MTU: u32 = 1512;
const Q_DESC_NUM: u16 = 1024;
const PTHRESH: u8 = 8;

// header info
const DMAC: [u8; 6] = [0x40, 0xa6, 0xb7, 0x60, 0xa2, 0xb1];
const SMAC: [u8; 6] = [0x40, 0xa6, 0xb7, 0x60, 0xa5, 0xf8];
const DIP: [u8; 4] = [192, 168, 22, 2];
const SPORT: u16 = 60376;
const DPORT: u16 = 161;
const NUM_FLOWS: usize = 8192;

static IP_ADDRS: OnceCell<Vec<[u8; 4]>> = OnceCell::new();

// range 2-251
// Generate at mot 62500 different IP addresses.
fn gen_ip_addrs(fst: u8, snd: u8, size: usize) -> Vec<[u8; 4]> {
    assert!(size <= 250 * 250);

    let mut v = Vec::new();

    for i in 0..size / 250 {
        for j in 2..252 {
            v.push([fst, snd, 2 + i as u8, j]);
        }
    }

    for j in 0..size % 250 {
        v.push([fst, snd, 2 + (size / 250) as u8, 2 + j as u8]);
    }

    v
}

fn entry_func() {
    IP_ADDRS.get_or_init(|| gen_ip_addrs(192, 168, NUM_FLOWS));

    // make sure that the rx and tx threads are on the correct cores
    let res = service()
        .available_lcores()
        .iter()
        .filter(|lcore| {
            lcore.lcore_id >= START_CORE as u32 && lcore.lcore_id < START_CORE as u32 + THREAD_NUM
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

    for i in 0..THREAD_NUM as usize {
        let run_clone = run.clone();

        let jh = std::thread::spawn(move || {
            service()
                .thread_bind_to(i as u32 + START_CORE as u32)
                .unwrap();

            let mut rxq = service().rx_queue(PORT_ID, i as u16).unwrap();
            let mut txq = service().tx_queue(PORT_ID, i as u16).unwrap();
            let mut batch = ArrayVec::<_, BATCH_SIZE>::new();

            // let mut tx_of_flag = MbufTxOffload::ALL_DISABLED;
            // tx_of_flag.enable_ip_cksum();
            // tx_of_flag.enable_udp_cksum();

            let ip_addrs = IP_ADDRS.get().unwrap();
            let mut adder: usize = 0;

            while run_clone.load(Ordering::Acquire) {
                rxq.rx(&mut batch);

                for mbuf in batch.iter_mut() {
                    let buf = CursorMut::new(mbuf.data_mut());
                    if let Ok(mut ethpkt) = EtherFrame::parse_from_cursor_mut(buf) {
                        if ethpkt.ethertype() == EtherType::IPV4 {
                            if let Ok(mut ippkt) =
                                Ipv4::parse_from_cursor_mut(ethpkt.payload_as_cursor_mut())
                            {
                                if ippkt.protocol() == IpProtocol::UDP {
                                    if let Ok(mut udppkt) =
                                        Udp::parse_from_cursor_mut(ippkt.payload_as_cursor_mut())
                                    {
                                        udppkt.set_dst_port(DPORT);
                                        udppkt.set_src_port(SPORT);

                                        ippkt.set_dst_addr(Ipv4Addr::new(
                                            DIP[0], DIP[1], DIP[2], DIP[3],
                                        ));
                                        let src_ip = &ip_addrs[adder % NUM_FLOWS];
                                        ippkt.set_src_addr(Ipv4Addr::new(
                                            src_ip[0], src_ip[1], src_ip[2], src_ip[3],
                                        ));
                                        let ip_hdr_len = ippkt.header_len();
                                        adder += 1;

                                        ethpkt.set_dst_addr(EtherAddr(DMAC));
                                        ethpkt.set_src_addr(EtherAddr(SMAC));

                                        // mbuf.set_tx_offload(tx_of_flag);
                                        // mbuf.set_l2_len(ETHER_HEADER_LEN as u64);
                                        // mbuf.set_l3_len(ip_hdr_len as u64);
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

fn config_port() {
    let dev_info = service().dev_info(PORT_ID).unwrap();

    // create the eth conf
    let mut eth_conf = EthConf::new();
    eth_conf.mtu = MTU;
    eth_conf.lpbk_mode = 0;
    eth_conf.max_lro_pkt_size = 0;

    // enable ipv4/udp/tcp checksum and rss hash rx offload
    assert!(
        dev_info.rx_offload_capa() & (1 << 1 | 1 << 2 | 1 << 3 | 1 << 19)
            == 1 << 1 | 1 << 2 | 1 << 3 | 1 << 19,
        "NIC does not support rx offload"
    );
    eth_conf.rx_offloads = 1 << 1 | 1 << 2 | 1 << 3 | 1 << 19;

    // enable ipv4/udp/tcp checksum tx offload
    assert!(
        dev_info.tx_offload_capa() & (1 << 1 | 1 << 2 | 1 << 3) == 1 << 1 | 1 << 2 | 1 << 3,
        "NIC does not support tx offload"
    );
    eth_conf.tx_offloads = 1 << 1 | 1 << 2 | 1 << 3;

    // set up ip/udp, ip/tcp rss hash function
    assert!(
        dev_info.flow_type_rss_offloads() & (1 << 4 | 1 << 5 | 1 << 10 | 1 << 11)
            == 1 << 4 | 1 << 5 | 1 << 10 | 1 << 11,
        "NIC does not support rss hash function"
    );
    eth_conf.rss_hf = 1 << 4 | 1 << 5 | 1 << 10 | 1 << 11;

    if dev_info.hash_key_size() == 40 {
        eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_40B.into();
    } else if dev_info.hash_key_size() == 52 {
        eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_52B.into();
    } else {
        panic!("unsupported hash key size: {}", dev_info.hash_key_size())
    };
    eth_conf.enable_promiscuous = true;

    // create rxq conf and txq conf
    let rxq_conf = RxqConf::new(Q_DESC_NUM, PTHRESH, WORKING_SOCKET, MP_NAME);
    let txq_conf = TxqConf::new(Q_DESC_NUM, PTHRESH, WORKING_SOCKET);
    let rxq_confs: Vec<RxqConf> = std::iter::repeat_with(|| rxq_conf.clone())
        .take(THREAD_NUM as usize)
        .collect();
    let txq_confs: Vec<TxqConf> = std::iter::repeat_with(|| txq_conf.clone())
        .take(THREAD_NUM as usize)
        .collect();

    // initialize the port
    service()
        .dev_configure_and_start(PORT_ID, &eth_conf, &rxq_confs, &txq_confs)
        .unwrap();
}

fn main() {
    DpdkOption::new().args("-n 6".split(" ")).init().unwrap();

    let dev_info = service().dev_info(PORT_ID).unwrap();
    assert!(
        dev_info.socket_id == WORKING_SOCKET,
        "WORKING_SOCKET does not match nic socket"
    );

    // create mempool
    service()
        .mempool_alloc(
            MP_NAME,
            MBUF_NUM,
            MBUF_CACHE,
            constant::MBUF_DATAROOM_SIZE + constant::MBUF_HEADROOM_SIZE,
            WORKING_SOCKET as i32,
        )
        .unwrap();

    config_port();

    entry_func();

    service().graceful_cleanup().unwrap();
    println!("dpdk service shutdown gracefully");
}
