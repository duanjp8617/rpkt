use std::sync::atomic::AtomicU64;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;

use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::tcp::{Tcp, TCP_HEADER_LEN, TCP_HEADER_TEMPLATE};
use rpkt::Buf;
use rpkt_dpdk::time::TscClockSource;
use rpkt_dpdk::*;

// The socket to work on
const WORKING_SOCKET: u32 = 1;
const THREAD_NUM: u32 = 1;
const START_CORE: usize = 64;

// dpdk batch size
const BATCH_SIZE: usize = 32;

// Basic configuration of the mempool
const MBUF_CACHE: u32 = 256;
const MBUF_NUM: u32 = MBUF_CACHE * 32 * THREAD_NUM;

const TX_MP: &str = "tx";
const RX_MP: &str = "rx";

// Basic configuration of the port
const PORT_ID: u16 = 0;
const MTU: u32 = 1512;
const Q_DESC_NUM: u16 = 1024;

// header info
const DMAC: [u8; 6] = [0xac, 0xdc, 0xca, 0x79, 0xe5, 0xc6];
const SMAC: [u8; 6] = [0xac, 0xdc, 0xca, 0x79, 0xca, 0x86];
const DIP: [u8; 4] = [192, 168, 23, 2];
const SIP: [u8; 4] = [172, 0, 10, 17];
const DPORT: u16 = 161;
const SPORT: u16 = 60376;

// payload info
const PAYLOAD_BYTE: u8 = 0xae;
const PAYLOAD_LEN: usize = 4000;

fn build_tcp_packet(mp: &Mempool) -> Mbuf {
    let mut data = vec![];
    data.extend(std::iter::repeat_with(|| PAYLOAD_BYTE).take(PAYLOAD_LEN));

    let mut mbuf = Mbuf::from_slice(&data[..], mp).unwrap();

    unsafe { mbuf.extend_front(ETHER_FRAME_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN) };
    let mut pbuf = Pbuf::new(&mut mbuf);
    pbuf.advance(ETHER_FRAME_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN);

    let mut tcp = Tcp::prepend_header(pbuf, &TCP_HEADER_TEMPLATE);
    tcp.set_src_port(SPORT);
    tcp.set_dst_port(DPORT);
    tcp.set_seq_num(0x8e501902);
    tcp.set_ack_num(0xc7529d89);
    tcp.set_ack(true);
    tcp.set_psh(true);
    tcp.set_window_size(46);

    let mut ipv4 = Ipv4::prepend_header(tcp.release(), &IPV4_HEADER_TEMPLATE);
    ipv4.set_src_addr(Ipv4Addr::new(SIP[0], SIP[1], SIP[2], SIP[3]));
    ipv4.set_dst_addr(Ipv4Addr::new(DIP[0], DIP[1], DIP[2], DIP[3]));
    ipv4.set_protocol(IpProtocol::TCP);
    ipv4.set_ttl(128);

    let mut eth_pkt = EtherFrame::prepend_header(ipv4.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth_pkt.set_src_addr(EtherAddr(SMAC));
    eth_pkt.set_dst_addr(EtherAddr(DMAC));
    eth_pkt.set_ethertype(EtherType::IPV4);

    mbuf
}

fn entry_func() {
    // make sure that the rx and tx threads are on the correct cores
    let res = service()
        .available_lcores()
        .iter()
        .filter(|lcore| {
            lcore.lcore_id >= START_CORE as u32 && lcore.lcore_id < START_CORE as u32 + THREAD_NUM
        })
        .all(|lcore| lcore.socket_id == WORKING_SOCKET);
    assert_eq!(res, true);

    let ip_checksum_error = Arc::new(AtomicU64::new(0));
    let l4_checksum_error = Arc::new(AtomicU64::new(0));

    let run = Arc::new(AtomicBool::new(true));
    let run_clone = run.clone();
    ctrlc::set_handler(move || {
        run_clone.store(false, Ordering::Release);
    })
    .unwrap();

    let mut jhs = Vec::new();

    for i in 0..THREAD_NUM as usize {
        let run_clone = run.clone();
        let ip_cksum_error = ip_checksum_error.clone();
        let l4_cksum_error = l4_checksum_error.clone();

        let jh = std::thread::spawn(move || {
            service()
                .thread_bind_to(i as u32 + START_CORE as u32)
                .unwrap();
            service().register_as_rte_thread().unwrap();

            let clock_source = TscClockSource::create().unwrap();
            let mut txq = service().tx_queue(PORT_ID, i as u16).unwrap();
            let tx_mp = service().mempool(TX_MP).unwrap();
            let mut tx_batch = ArrayVec::<_, BATCH_SIZE>::new();

            let mut rxq = service().rx_queue(PORT_ID, i as u16).unwrap();
            let mut rx_batch = ArrayVec::<_, BATCH_SIZE>::new();
            let mut old_tic = clock_source.get_tsc();
            let one_sec = clock_source.freq().sec_to_cycles(1.0);

            while run_clone.load(Ordering::Acquire) {
                let curr_tic = clock_source.get_tsc();
                if old_tic + one_sec < curr_tic {
                    // for each second
                    let mut mbuf = build_tcp_packet(&tx_mp);
                    mbuf.set_tx_offload(1 << 54 | 1 << 55 | 1 << 52 | 1 << 50);
                    mbuf.set_l2_len(ETHER_FRAME_HEADER_LEN as u64);
                    mbuf.set_l3_len(IPV4_HEADER_LEN as u64);
                    mbuf.set_l4_len(TCP_HEADER_LEN as u64);
                    mbuf.set_tso_segsz(1024);


                    tx_batch.push(mbuf);
                    let _ = txq.tx(&mut tx_batch);
                    Mempool::free_batch(&mut tx_batch);

                    old_tic = curr_tic;
                }

                rxq.rx(&mut rx_batch);
                for mbuf in rx_batch.iter() {
                    if mbuf.rx_offload() & (1 << 7) == 0 {
                        ip_cksum_error.fetch_add(1, Ordering::SeqCst);
                    }
                    if mbuf.rx_offload() & (1 << 8) == 0 {
                        l4_cksum_error.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Mempool::free_batch(&mut rx_batch);
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
            "tx: {} Mpps, {} Gbps || rx: {} Mpps, {} Gbps",
            (curr_stats.opackets() - old_stats.opackets()) as f64 / 1_000_000.0,
            (curr_stats.obytes() - old_stats.obytes()) as f64 * 8.0 / 1_000_000_000.0,
            (curr_stats.ipackets() - old_stats.ipackets()) as f64 / 1_000_000.0,
            (curr_stats.ibytes() - old_stats.ibytes()) as f64 * 8.0 / 1_000_000_000.0,
        );
        println!(
            "ip cksum errors: {}, l4 cksum errors: {}",
            ip_checksum_error.load(Ordering::SeqCst),
            l4_checksum_error.load(Ordering::SeqCst),
        );

        old_stats = curr_stats;
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
    println!("the port mac is: {}", EtherAddr(dev_info.mac_addr));

    // create the eth conf
    let mut eth_conf = EthConf::new();
    eth_conf.mtu = MTU;
    eth_conf.lpbk_mode = 0;
    eth_conf.max_lro_pkt_size = 65535;

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
    let rxq_conf = RxqConf::new(Q_DESC_NUM, WORKING_SOCKET, RX_MP);
    let txq_conf = TxqConf::new(Q_DESC_NUM, WORKING_SOCKET);
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
    DpdkOption::new().init().unwrap();
    println!("using batchsize {BATCH_SIZE}!!!!");

    // create mempool
    service()
        .mempool_alloc(
            TX_MP,
            MBUF_NUM,
            MBUF_CACHE,
            constant::MBUF_DATAROOM_SIZE + constant::MBUF_HEADROOM_SIZE,
            WORKING_SOCKET as i32,
        )
        .unwrap();

    service()
        .mempool_alloc(
            RX_MP,
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
