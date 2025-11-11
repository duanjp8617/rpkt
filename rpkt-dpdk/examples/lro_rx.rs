use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;

use rpkt::Buf;
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

fn entry_func_rpkt() {
    use rpkt::ether::*;
    use rpkt::ipv4::*;
    use rpkt::tcp::*;

    service().thread_bind_to(0).unwrap();

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
            service().register_as_rte_thread().unwrap();

            let mut rxq = service().rx_queue(PORT_ID, i as u16).unwrap();
            let mut ibatch = ArrayVec::<_, BATCH_SIZE>::new();

            while run_clone.load(Ordering::Acquire) {
                rxq.rx(&mut ibatch);

                for mut mbuf in ibatch.drain(..) {
                    let rx_offload = mbuf.rx_offload();

                    if let Ok(ethpkt) = EtherFrame::parse(Pbuf::new(&mut mbuf)) {
                        // found a ethernet packet
                        if ethpkt.ethertype() == EtherType::IPV4 {
                            // the inner of the ethernet packet is ipv4
                            if let Ok(ipv4) = Ipv4::parse(ethpkt.payload()) {
                                if rx_offload & (1 << 7) != 0 {
                                    if ipv4.protocol() == IpProtocol::TCP {
                                        if let Ok(tcp) = Tcp::parse(ipv4.payload()) {
                                            if rx_offload & (1 << 8) != 0 {
                                                let sport = tcp.src_port();
                                                let dport = tcp.dst_port();
                                                let seq_num = tcp.seq_num();
                                                let ack_num = tcp.ack_num();
                                                let ack = tcp.ack();
                                                let psh = tcp.psh();
                                                let windows_size = tcp.window_size();
                                                let payload_len = tcp.buf().remaining()
                                                    - tcp.header_len() as usize;
                                                println!("");
                                                println!("receiving a tcp segment with:");
                                                println!("sport {sport}, dport:{dport}");
                                                println!(
                                                    "seq_num 0x{:x}, ack_num 0x{:X}",
                                                    seq_num, ack_num
                                                );
                                                println!("ack enabled {ack}, psh enabled {psh}");
                                                println!("window_size {windows_size}, payload_len {payload_len}");
                                                println!("tcp checksum 0x{:x}", tcp.checksum());

                                                println!("details of the mbuf:");
                                                println!(
                                                    "pkt_len {}, num_segs {}",
                                                    mbuf.pkt_len(),
                                                    mbuf.num_segs()
                                                );
                                                for (idx, seg) in mbuf.seg_iter().enumerate() {
                                                    println!(
                                                        "{}-th seg length: {}",
                                                        idx + 1,
                                                        seg.len()
                                                    );
                                                }
                                                println!("");
                                            } else {
                                                println!("invalid tcp checksum")
                                            }
                                        } else {
                                            println!("packet has invalid tcp packet format");
                                        }
                                    } else {
                                        println!("L4 protocol is not tcp")
                                    }
                                } else {
                                    println!("invalid ipv4 checksum")
                                }
                            } else {
                                println!("packet has invalid ipv4 format");
                            }
                        } else {
                            println!("L3 protocol is not ipv4")
                        }
                    } else {
                        println!("packet has invalid ethernet frame format");
                    }
                }
            }
        });
        jhs.push(jh);
    }

    while run.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    for jh in jhs {
        jh.join().unwrap();
    }
}

fn config_port() {
    let dev_info = service().dev_info(PORT_ID).unwrap();
    assert!(
        dev_info.socket_id == WORKING_SOCKET,
        "WORKING_SOCKET does not match nic socket"
    );
    println!(
        "the port mac is: {}",
        rpkt::ether::EtherAddr(dev_info.mac_addr)
    );

    // create the eth conf
    let mut eth_conf = EthConf::new();
    eth_conf.mtu = MTU;
    eth_conf.lpbk_mode = 0;
    eth_conf.max_lro_pkt_size = 0;

    // enable ipv4/udp/tcp checksum and rss hash rx offload
    // also enable lro and receive scatter
    assert!(
        dev_info.rx_offload_capa() & (1 << 1 | 1 << 2 | 1 << 3 | 1 << 19 | 1 << 4 | 1 << 13)
            == 1 << 1 | 1 << 2 | 1 << 3 | 1 << 19 | 1 << 4 | 1 << 13,
        "NIC does not support rx offload"
    );
    eth_conf.rx_offloads = 1 << 1 | 1 << 2 | 1 << 3 | 1 << 19 | 1 << 4 | 1 << 13;

    // enable ipv4/udp/tcp checksum tx offload
    // also enable tso and tx multi-seg
    assert!(
        dev_info.tx_offload_capa() & (1 << 1 | 1 << 2 | 1 << 3 | 1 << 5 | 1 << 15)
            == 1 << 1 | 1 << 2 | 1 << 3 | 1 << 5 | 1 << 15,
        "NIC does not support tx offload"
    );
    eth_conf.tx_offloads = 1 << 1 | 1 << 2 | 1 << 3 | 1 << 5 | 1 << 15;

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

    entry_func_rpkt();

    service().graceful_cleanup().unwrap();
    println!("dpdk service shutdown gracefully");
}
