use std::env;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;

use rpkt_dpdk::error::{Error, Result};
use rpkt_dpdk::offload::MbufTxOffload;
use rpkt_dpdk::*;
use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::tcp::*;
use rpkt::udp::*;
use rpkt::Buf;

// The socket to work on
const WORKING_SOCKET: u32 = 0;
const THREAD_NUM: u32 = 1;
const START_CORE: usize = 1;

// dpdk batch size
const BATCH_SIZE: usize = 64;

// Basic configuration of the mempool
const MBUF_CACHE: u32 = 256;
const MBUF_NUM: u32 = MBUF_CACHE * 32 * THREAD_NUM;

const MP: &str = "wtf";

// Basic configuration of the port
const PORT_ID: u16 = 0;
const TXQ_DESC_NUM: u16 = 1024;
const RXQ_DESC_NUM: u16 = 1024;

// header info
const DMAC: [u8; 6] = [0x08, 0x68, 0x8d, 0x61, 0x69, 0x28];
const SMAC: [u8; 6] = [0x00, 0x50, 0x56, 0xae, 0x76, 0xf5];
const DIP: [u8; 4] = [192, 168, 23, 2];
const SIP: [u8; 4] = [192, 168, 57, 10];
const SPORT: u16 = 60376;
const DPORT: u16 = 161;

// payload info
const PAYLOAD_BYTE: u8 = 0xae;
const PACKET_LEN: usize = 8000;

static FRAME_BYTES: [u8; 200] = [
    0x00, 0x26, 0x62, 0x2f, 0x47, 0x87, 0x00, 0x1d, 0x60, 0xb3, 0x01, 0x84, 0x08, 0x00, 0x45, 0x00,
    0x00, 0xba, 0xcb, 0x5d, 0x40, 0x00, 0x40, 0x06, 0x28, 0x64, 0xc0, 0xa8, 0x01, 0x8c, 0xae, 0x8f,
    0xd5, 0xb8, 0xe1, 0x4e, 0x00, 0x50, 0x8e, 0x50, 0x19, 0x02, 0xc7, 0x52, 0x9d, 0x89, 0x80, 0x18,
    0x00, 0x2e, 0x47, 0x29, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x00, 0x21, 0xd2, 0x5f, 0x31, 0xc7,
    0xba, 0x48, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x73, 0x2f, 0x6c, 0x61,
    0x79, 0x6f, 0x75, 0x74, 0x2f, 0x6c, 0x6f, 0x67, 0x6f, 0x2e, 0x70, 0x6e, 0x67, 0x20, 0x48, 0x54,
    0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65,
    0x6e, 0x74, 0x3a, 0x20, 0x57, 0x67, 0x65, 0x74, 0x2f, 0x31, 0x2e, 0x31, 0x32, 0x20, 0x28, 0x6c,
    0x69, 0x6e, 0x75, 0x78, 0x2d, 0x67, 0x6e, 0x75, 0x29, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70,
    0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x70, 0x61,
    0x63, 0x6b, 0x65, 0x74, 0x6c, 0x69, 0x66, 0x65, 0x2e, 0x6e, 0x65, 0x74, 0x0d, 0x0a, 0x43, 0x6f,
    0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x4b, 0x65, 0x65, 0x70, 0x2d, 0x41,
    0x6c, 0x69, 0x76, 0x65, 0x0d, 0x0a, 0x0d, 0x0a,
];

fn build_udp_manual(mp: &Mempool) -> Mbuf {
    let v = vec![PAYLOAD_BYTE; PACKET_LEN];
    let mut mbuf = Mbuf::from_slice(&v[..], mp).unwrap();

    let total_header_len = ETHER_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN;
    let mut pkt = Pbuf::new(&mut mbuf);
    pkt.advance(total_header_len);

    let mut udppkt = UdpPacket::prepend_header(pkt, &UDP_HEADER_TEMPLATE);
    udppkt.set_source_port(SPORT);
    udppkt.set_dest_port(DPORT);
    // For UDP, both 0 and correctly calculated checksum are correct for mlx5 NIC.
    // udppkt.set_checksum(0);
    udppkt.adjust_ipv4_checksum(Ipv4Addr(SIP), Ipv4Addr(DIP));
    // however, mlx5 nic reports invalid udp checksum for arbitrary set udp checksum
    // udppkt.set_checksum(512);

    let mut ippkt = Ipv4Packet::prepend_header(udppkt.release(), &IPV4_HEADER_TEMPLATE);
    ippkt.set_ident(0x5c65);
    ippkt.clear_flags();
    ippkt.set_time_to_live(128);
    ippkt.set_source_ip(Ipv4Addr(SIP));
    ippkt.set_dest_ip(Ipv4Addr(DIP));
    ippkt.set_protocol(IpProtocol::UDP);
    ippkt.adjust_checksum();

    let mut ethpkt = EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
    ethpkt.set_source_mac(MacAddr(SMAC));
    ethpkt.set_dest_mac(MacAddr(DMAC));
    ethpkt.set_ethertype(EtherType::IPV4);

    mbuf
}

fn build_udp_offload(mp: &Mempool) -> Mbuf {
    let v = vec![PAYLOAD_BYTE; PACKET_LEN];
    let mut mbuf = Mbuf::from_slice(&v[..], mp).unwrap();

    let total_header_len = ETHER_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN;
    let mut pkt = Pbuf::new(&mut mbuf);
    pkt.advance(total_header_len);

    let mut udppkt = UdpPacket::prepend_header(pkt, &UDP_HEADER_TEMPLATE);
    udppkt.set_source_port(SPORT);
    udppkt.set_dest_port(DPORT);
    udppkt.set_checksum(155);

    let mut ippkt = Ipv4Packet::prepend_header(udppkt.release(), &IPV4_HEADER_TEMPLATE);
    ippkt.set_ident(0x5c65);
    ippkt.clear_flags();
    ippkt.set_time_to_live(128);
    ippkt.set_source_ip(Ipv4Addr(SIP));
    ippkt.set_dest_ip(Ipv4Addr(DIP));
    ippkt.set_protocol(IpProtocol::UDP);
    ippkt.set_checksum(0);

    let mut ethpkt = EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
    ethpkt.set_dest_mac(MacAddr(DMAC));
    ethpkt.set_source_mac(MacAddr(SMAC));
    ethpkt.set_ethertype(EtherType::IPV4);

    let mut of_flag = MbufTxOffload::ALL_DISABLED;
    of_flag.enable_ip_cksum();
    of_flag.enable_udp_cksum();
    mbuf.set_l2_len(ETHER_HEADER_LEN as u64);
    mbuf.set_l3_len(IPV4_HEADER_LEN as u64);
    mbuf.set_tx_offload(of_flag);

    mbuf
}

fn build_tcp_manual(mp: &Mempool) -> Mbuf {
    let v = vec![PAYLOAD_BYTE; PACKET_LEN];
    let mut mbuf = Mbuf::from_slice(&v[..], mp).unwrap();

    let total_header_len = ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + 12;
    let mut pkt = Pbuf::new(&mut mbuf);
    pkt.advance(total_header_len);

    let mut tcpheader = TCP_HEADER_TEMPLATE;
    tcpheader.set_header_len((TCP_HEADER_LEN + 12) as u8);
    let mut tcppkt = TcpPacket::prepend_header(pkt, &tcpheader);
    tcppkt.set_src_port(SPORT);
    tcppkt.set_dst_port(DPORT);
    tcppkt.set_seq_number(0x8e501902);
    tcppkt.set_ack_number(0xc7529d89);
    tcppkt.adjust_reserved();
    tcppkt.set_ns(false);
    tcppkt.set_cwr(false);
    tcppkt.set_ece(false);
    tcppkt.set_urg(false);
    tcppkt.set_ack(true);
    tcppkt.set_psh(true);
    tcppkt.set_rst(false);
    tcppkt.set_syn(false);
    tcppkt.set_fin(false);
    tcppkt.set_window_size(46);
    tcppkt.set_urgent_ptr(0);
    tcppkt.set_option_bytes(
        &FRAME_BYTES[ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN
            ..(ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + 12)],
    );
    // tcppkt.set_checksum(0);
    tcppkt.adjust_ipv4_checksum(Ipv4Addr(SIP), Ipv4Addr(DIP));

    let mut ippkt = Ipv4Packet::prepend_header(tcppkt.release(), &IPV4_HEADER_TEMPLATE);
    ippkt.set_ident(0x5c65);
    ippkt.clear_flags();
    ippkt.set_time_to_live(128);
    ippkt.set_source_ip(Ipv4Addr(SIP));
    ippkt.set_dest_ip(Ipv4Addr(DIP));
    ippkt.set_protocol(IpProtocol::TCP);
    ippkt.adjust_checksum();

    let mut ethpkt = EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
    ethpkt.set_dest_mac(MacAddr(DMAC));
    ethpkt.set_source_mac(MacAddr(SMAC));
    ethpkt.set_ethertype(EtherType::IPV4);

    mbuf
}

fn build_tcp_offload(mp: &Mempool) -> Mbuf {
    let v = vec![PAYLOAD_BYTE; PACKET_LEN];
    let mut mbuf = Mbuf::from_slice(&v[..], mp).unwrap();

    let total_header_len = ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + 12;
    let mut pkt = Pbuf::new(&mut mbuf);
    pkt.advance(total_header_len);

    let mut tcpheader = TCP_HEADER_TEMPLATE;
    tcpheader.set_header_len((TCP_HEADER_LEN + 12) as u8);
    let mut tcppkt = TcpPacket::prepend_header(pkt, &tcpheader);
    tcppkt.set_src_port(SPORT);
    tcppkt.set_dst_port(DPORT);
    tcppkt.set_seq_number(0x8e501902);
    tcppkt.set_ack_number(0xc7529d89);
    tcppkt.adjust_reserved();
    tcppkt.set_ns(false);
    tcppkt.set_cwr(false);
    tcppkt.set_ece(false);
    tcppkt.set_urg(false);
    tcppkt.set_ack(true);
    tcppkt.set_psh(true);
    tcppkt.set_rst(false);
    tcppkt.set_syn(false);
    tcppkt.set_fin(false);
    tcppkt.set_window_size(46);
    tcppkt.set_urgent_ptr(0);
    tcppkt.set_option_bytes(
        &FRAME_BYTES[ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN
            ..(ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + 12)],
    );
    tcppkt.set_checksum(0);

    let mut ippkt = Ipv4Packet::prepend_header(tcppkt.release(), &IPV4_HEADER_TEMPLATE);
    ippkt.set_ident(0x5c65);
    ippkt.clear_flags();
    ippkt.set_time_to_live(128);
    ippkt.set_source_ip(Ipv4Addr(SIP));
    ippkt.set_dest_ip(Ipv4Addr(DIP));
    ippkt.set_protocol(IpProtocol::TCP);
    ippkt.set_checksum(0);

    let mut ethpkt = EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
    ethpkt.set_dest_mac(MacAddr(DMAC));
    ethpkt.set_source_mac(MacAddr(SMAC));
    ethpkt.set_ethertype(EtherType::IPV4);

    let mut of_flag = MbufTxOffload::ALL_DISABLED;
    of_flag.enable_ip_cksum();
    of_flag.enable_tcp_cksum();
    mbuf.set_l2_len(ETHER_HEADER_LEN as u64);
    mbuf.set_l3_len(IPV4_HEADER_LEN as u64);
    mbuf.set_tx_offload(of_flag);

    mbuf
}

fn entry_func(val: u64) {
    // make sure that the rx and tx threads are on the correct cores
    let res = service()
        .lcores()
        .iter()
        .filter(|lcore| {
            lcore.lcore_id >= START_CORE as u32
                && lcore.lcore_id < START_CORE as u32 + THREAD_NUM as u32
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

    for i in 0..THREAD_NUM as usize {
        let run_clone = run.clone();
        let jh = std::thread::spawn(move || {
            service().lcore_bind(i as u32 + START_CORE as u32).unwrap();

            let mut txq = service().tx_queue(PORT_ID, i as u16).unwrap();
            let mp = service().mempool(MP).unwrap();
            let mut batch = ArrayVec::<_, BATCH_SIZE>::new();

            while run_clone.load(Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_secs(1));

                let mbuf = match val {
                    0 => build_udp_manual(&mp),
                    1 => build_udp_offload(&mp),
                    2 => build_tcp_manual(&mp),
                    3 => build_tcp_offload(&mp),
                    _ => panic!("impossible"),
                };

                batch.push(mbuf);
                while batch.len() > 0 {
                    let _sent = txq.tx(&mut batch);
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

fn init_port(
    port_id: u16,
    nb_rx_queue: u16,
    nb_tx_queue: u16,
    nb_rx_desc: u16,
    mp_name: &str,
    nb_tx_desc: u16,
    socket_id: u32,
) -> Result<()> {
    // make sure that the port is on the correct socket
    let port_info = service().port_info(port_id)?;
    if port_info.socket_id != socket_id {
        return Err(Error::service_err("invalid socket id"));
    }

    // get the default port conf
    let mut port_conf = PortConf::from_port_info(&port_info)?;
    port_conf.mtu = 9000;
    port_conf.rx_offloads.enable_scatter();
    port_conf.tx_offloads.enable_multi_segs();

    // configure rxq
    let mut rxq_conf = RxQueueConf::default();
    rxq_conf.set_nb_rx_desc(nb_rx_desc);
    rxq_conf.set_socket_id(socket_id);
    rxq_conf.set_mp_name(mp_name);
    let rxq_confs: Vec<RxQueueConf> = (0..nb_rx_queue as usize)
        .map(|_| rxq_conf.clone())
        .collect();

    // configure txq
    let mut txq_conf = TxQueueConf::default();
    txq_conf.set_nb_tx_desc(nb_tx_desc);
    txq_conf.set_socket_id(socket_id);
    let txq_confs: Vec<TxQueueConf> = (0..nb_tx_queue as usize)
        .map(|_| txq_conf.clone())
        .collect();

    // create the port
    service().port_configure(port_id, &port_conf, &rxq_confs, &txq_confs)?;

    Ok(())
}

fn main() {
    let mut args = env::args();
    if args.len() != 2 {
        println!(
            "Invalid number of arguments. Given {}, required 1.",
            args.len() - 1
        );
        return;
    }

    args.next();
    let arg = args.next().unwrap();

    // 0: UDP with manual checksum computation
    // 1: UDP with checksum offloading
    // 2: TCP with manual checksum computation
    // 3: TCP with checksum offloading
    let val = match arg.parse::<u64>() {
        Err(_) => {
            println!("Invalid argument: {}. The argument should be 0-3", arg);
            return;
        }
        Ok(val) => {
            if val > 3 {
                println!("Invalid argument: {}. The argument should be 0-3", val);
                return;
            }
            val
        }
    };

    DpdkOption::new().init().unwrap();

    // create mempool
    utils::init_mempool(MP, MBUF_NUM, MBUF_CACHE, WORKING_SOCKET).unwrap();

    // create the port
    init_port(
        PORT_ID,
        THREAD_NUM as u16,
        THREAD_NUM as u16,
        RXQ_DESC_NUM,
        MP,
        TXQ_DESC_NUM,
        WORKING_SOCKET,
    )
    .unwrap();

    entry_func(val);

    // shutdown the port
    service().port_close(PORT_ID).unwrap();

    // free the mempool
    service().mempool_free(MP).unwrap();

    // shutdown the DPDK service
    service().service_close().unwrap();

    println!("dpdk service shutdown gracefully");
}
