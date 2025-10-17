use std::net::Ipv4Addr;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;

use rpkt::ipv4::*;
use rpkt::udp::*;
use rpkt::Buf;
use rpkt::CursorMut;
use rpkt::{ether::*, Cursor};
use rpkt_dpdk::rdtsc::*;
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
const MP_NAME: &str = "wtf";
const TX_MP: &str = "tx";

// Basic configuration of the port
const PORT_ID: u16 = 0;
const MTU: u32 = 1512;
const Q_DESC_NUM: u16 = 1024;
const PTHRESH: u8 = 8;

// header info
const DMAC: [u8; 6] = [0xac, 0xdc, 0xca, 0x79, 0xe5, 0xc6];
const SMAC: [u8; 6] = [0xac, 0xdc, 0xca, 0x79, 0xca, 0x86];
const DIP: Ipv4Addr = Ipv4Addr::new(192, 168, 23, 2);
const SIP: Ipv4Addr = Ipv4Addr::new(174, 55, 11, 2);
const SPORT: u16 = 60376;
const DPORT: u16 = 161;

// payload info
const PAYLOAD_BYTE: u8 = 0xae;
const PACKET_LEN: usize = 1500;

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

    let run = Arc::new(AtomicBool::new(true));
    let run_clone = run.clone();
    ctrlc::set_handler(move || {
        run_clone.store(false, Ordering::Release);
    })
    .unwrap();

    let mut jhs = Vec::new();
    let base_freq = BaseFreq::new();

    for i in 0..THREAD_NUM as usize {
        let run_clone = run.clone();

        let jh = std::thread::spawn(move || {
            service()
                .thread_bind_to(i as u32 + START_CORE as u32)
                .unwrap();
            service().register_as_rte_thread().unwrap();

            let mut txq = service().tx_queue(PORT_ID, i as u16).unwrap();
            let tx_mp = service().mempool(TX_MP).unwrap();
            let mut tx_batch = ArrayVec::<_, BATCH_SIZE>::new();

            let mut rxq = service().rx_queue(PORT_ID, i as u16).unwrap();
            let mut rx_batch = ArrayVec::<_, BATCH_SIZE>::new();
            let mut response_received = 0;
            let mut response_received_1s_ago = 0;

            let mut cycle_marker = rdtsc();

            send_trigger_packet(&mut txq, &tx_mp);
            while run_clone.load(Ordering::Acquire) {
                // run the rx loop, we send a data packet upon receiving a reply
                assert!(tx_batch.len() == 0);
                rxq.rx(&mut rx_batch);
                for mbuf in rx_batch.drain(..) {
                    let rx_offload = mbuf.rx_offload();
                    let pkt = Cursor::new(mbuf.data());
                    if let Ok(ethpkt) = EtherFrame::parse(pkt) {
                        if ethpkt.ethertype() == EtherType::IPV4 && (rx_offload & (1 << 7) != 0) {
                            if let Ok(ippkt) = Ipv4::parse(ethpkt.payload()) {
                                if ippkt.protocol() == IpProtocol::UDP
                                    && (rx_offload & (1 << 8) != 0)
                                {
                                    if let Ok(udppkt) = Udp::parse(ippkt.payload()) {
                                        let payload = udppkt.payload();
                                        if payload.chunk() == &[0xae; 8][..] {
                                            // we get a valid response
                                            response_received += 1;

                                            let mut mbuf = tx_mp.try_alloc().unwrap();
                                            unsafe {
                                                mbuf.set_data_len(
                                                    PACKET_LEN
                                                        - (ETHER_FRAME_HEADER_LEN
                                                            + IPV4_HEADER_LEN
                                                            + UDP_HEADER_LEN),
                                                );
                                            }
                                            mbuf.data_mut().fill(PAYLOAD_BYTE);
                                            format_mbuf_header(&mut mbuf);
                                            tx_batch.push(mbuf);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // when we get here, we have already filled tx_batch with packets for sending
                while tx_batch.len() > 0 {
                    txq.tx(&mut tx_batch);
                }

                let curr_rdtsc = rdtsc();
                if curr_rdtsc - cycle_marker > base_freq.sec_to_cycles(1.0) {
                    // 1 second has elapsed
                    if response_received_1s_ago == response_received {
                        // we have not received any responses for 1s, it could be
                        // that the packet that we sent as a trigger are all lost.
                        // resend those packets
                        println!("sending trigger batch");
                        send_trigger_packet(&mut txq, &tx_mp);
                    } else {
                        // we have made some progresses
                        response_received_1s_ago = response_received;
                    }

                    cycle_marker = curr_rdtsc;
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
            "tx: {} Mpps, {} Gbps || rx: {} Mpps, {} Gbps",
            (curr_stats.opackets() - old_stats.opackets()) as f64 / 1_000_000.0,
            (curr_stats.obytes() - old_stats.obytes()) as f64 * 8.0 / 1_000_000_000.0,
            (curr_stats.ipackets() - old_stats.ipackets()) as f64 / 1_000_000.0,
            (curr_stats.ibytes() - old_stats.ibytes()) as f64 * 8.0 / 1_000_000_000.0,
        );
        old_stats = curr_stats;
    }

    for jh in jhs {
        jh.join().unwrap();
    }
}

fn send_trigger_packet(txq: &mut TxQueue, mp: &Mempool) {
    const TRIGGER_BATCH: usize = 64;
    let mut obatch = ArrayVec::<_, TRIGGER_BATCH>::new();

    for _ in 0..TRIGGER_BATCH {
        let mut mbuf = mp.try_alloc().unwrap();
        unsafe {
            mbuf.set_data_len(
                PACKET_LEN - (ETHER_FRAME_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN),
            );
        }
        mbuf.data_mut().fill(PAYLOAD_BYTE);
        format_mbuf_header(&mut mbuf);
        obatch.push(mbuf);
    }

    while obatch.len() > 0 {
        txq.tx(&mut obatch);
    }
}

fn format_mbuf_header(mbuf: &mut Mbuf) {
    unsafe {
        mbuf.increase_len_at_front(ETHER_FRAME_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN);
    }

    let mut pbuf = CursorMut::new(mbuf.data_mut());
    pbuf.advance(ETHER_FRAME_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN);

    let mut udp_pkt = Udp::prepend_header(pbuf, &UDP_HEADER_TEMPLATE);
    udp_pkt.set_src_port(SPORT);
    udp_pkt.set_dst_port(DPORT);
    udp_pkt.set_checksum(0);

    let mut ipv4_pkt = Ipv4::prepend_header(udp_pkt.release(), &IPV4_HEADER_TEMPLATE);
    ipv4_pkt.set_src_addr(SIP);
    ipv4_pkt.set_dst_addr(DIP);
    ipv4_pkt.set_protocol(IpProtocol::UDP);
    ipv4_pkt.set_ttl(128);
    ipv4_pkt.set_checksum(0);

    let mut eth_pkt = EtherFrame::prepend_header(ipv4_pkt.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth_pkt.set_src_addr(EtherAddr(SMAC));
    eth_pkt.set_dst_addr(EtherAddr(DMAC));
    eth_pkt.set_ethertype(EtherType::IPV4);

    mbuf.set_tx_offload(1 << 54 | 1 << 55 | 3 << 52);
    mbuf.set_l2_len(ETHER_FRAME_HEADER_LEN as u64);
    mbuf.set_l3_len(IPV4_HEADER_LEN as u64);
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
    DpdkOption::new().args("-n 8".split(" ")).init().unwrap();

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
    service()
        .mempool_alloc(
            TX_MP,
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
