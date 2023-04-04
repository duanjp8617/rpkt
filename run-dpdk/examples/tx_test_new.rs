use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;
use run_dpdk::offload::MbufTxOffload;
use run_dpdk::*;
use run_packet::ether::*;
use run_packet::ipv4::*;
use run_packet::udp::*;
use run_packet::Buf;
use run_packet::CursorMut;

// The socket to work on
const WORKING_SOCKET: u32 = 1;

// Basic configuration of the mempool
const MBUF_CACHE: u32 = 256;
const MBUF_NUM: u32 = MBUF_CACHE * 32 * 10;
const MP_NAME: &str = "wtf";

// Basic configuration of the port
const PORT_ID: u16 = 0;

// Basic configuration of rx queues
const RXQ_NUM: u16 = 10;
const RXQ_DESC_NUM: u16 = 1024;

// Basic configuration of tx queues
const TXQ_NUM: u16 = 10;
const TXQ_DESC_NUM: u16 = 1024;

// Basic configuration for traffic generation
const SMAC: [u8; 6] = [0x00, 0x50, 0x56, 0xae, 0x76, 0xf5];
const DMAC: [u8; 6] = [0x08, 0x68, 0x8d, 0x61, 0x69, 0x28];
const SIP: [u8; 4] = [192, 168, 57, 10];
const DIP: [u8; 4] = [192, 168, 23, 2];
const SPORT: u16 = 60376;
const DPORT: u16 = 161;
const PAYLOAD_LEN: usize = 18;
const PAYLOAD_BYTE: u8 = 0xae;

// rx threads
const RX_START: usize = 32;

const BATCH_SIZE: usize = 64;

fn fill_packet_template() {
    let packet_len = ETHER_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + PAYLOAD_LEN;
    let mut v = vec![PAYLOAD_BYTE; packet_len];

    let mut pbuf = CursorMut::new(&mut v[..]);
    pbuf.advance(ETHER_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN);

    let mut udp_pkt = UdpPacket::prepend_header(pbuf, &UDP_HEADER_TEMPLATE);
    udp_pkt.set_source_port(SPORT);
    udp_pkt.set_dest_port(DPORT);

    let mut ipv4_pkt = Ipv4Packet::prepend_header(udp_pkt.release(), &IPV4_HEADER_TEMPLATE);
    ipv4_pkt.set_source_ip(Ipv4Addr(SIP));
    ipv4_pkt.set_dest_ip(Ipv4Addr(DIP));
    ipv4_pkt.set_protocol(IpProtocol::UDP);
    ipv4_pkt.set_time_to_live(128);

    let mut eth_pkt = EtherPacket::prepend_header(ipv4_pkt.release(), &ETHER_HEADER_TEMPLATE);
    eth_pkt.set_source_mac(MacAddr(SMAC));
    eth_pkt.set_dest_mac(MacAddr(DMAC));
    eth_pkt.set_ethertype(EtherType::IPV4);

    utils::fill_mempool(MP_NAME, &v[..]).unwrap();
}

fn entry_func() {
    fill_packet_template();

    // make sure that the rx and tx threads are on the correct cores
    let res = service()
        .lcores()
        .iter()
        .filter(|lcore| {
            lcore.lcore_id >= RX_START as u32
                && lcore.lcore_id < RX_START as u32 + RXQ_NUM as u32 + TXQ_NUM as u32
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

    for i in RX_START..(RX_START + RXQ_NUM as usize) {
        let run_clone = run.clone();
        let jh = std::thread::spawn(move || {
            service().lcore_bind(i as u32).unwrap();

            let mut rxq = service().rx_queue(PORT_ID, (i - RX_START) as u16).unwrap();
            let mut batch = ArrayVec::<_, BATCH_SIZE>::new();

            while run_clone.load(Ordering::Acquire) {
                rxq.rx(&mut batch);
                Mempool::free_batch(&mut batch);
            }
        });
        jhs.push(jh);
    }

    for i in (RX_START + RXQ_NUM as usize)..(RX_START + RXQ_NUM as usize + TXQ_NUM as usize) {
        let run_clone = run.clone();
        let jh = std::thread::spawn(move || {
            service().lcore_bind(i as u32).unwrap();

            let mut txq = service()
                .tx_queue(PORT_ID, (i - RX_START - RXQ_NUM as usize) as u16)
                .unwrap();
            let mp = service().mempool(MP_NAME).unwrap();
            let mut batch = ArrayVec::<_, BATCH_SIZE>::new();

            let mut tx_of_flag = MbufTxOffload::ALL_DISABLED;
            tx_of_flag.enable_ip_cksum();
            tx_of_flag.enable_udp_cksum();

            while run_clone.load(Ordering::Acquire) {
                mp.fill_batch(&mut batch);

                for mbuf in batch.iter_mut() {
                    unsafe {
                        mbuf.extend(
                            ETHER_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + PAYLOAD_LEN,
                        )
                    };

                    mbuf.set_tx_offload(tx_of_flag);
                    mbuf.set_l2_len(ETHER_HEADER_LEN as u64);
                    mbuf.set_l3_len(UDP_HEADER_LEN as u64);
                }

                while batch.len() > 0 {
                    let _ = txq.tx(&mut batch);
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
}

fn main() {
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