use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;
use rpkt_dpdk::offload::*;
use rpkt_dpdk::*;
use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::tcp::*;
use rpkt::udp::*;
use rpkt::Buf;
use rpkt::CursorMut;

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

#[allow(dead_code)]
fn build_udp_manual(mbuf: &mut Mbuf, payload_len: usize) {
    let total_header_len = ETHER_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN;
    unsafe { mbuf.extend(total_header_len + payload_len) };

    let mut pkt = CursorMut::new(mbuf.data_mut());
    pkt.advance(total_header_len);

    let mut udppkt = UdpPacket::prepend_header(pkt, &UDP_HEADER_TEMPLATE);
    udppkt.set_source_port(60376);
    udppkt.set_dest_port(161);
    // For UDP, both 0 and correctly calculated checksum are correct for mlx5 NIC.
    udppkt.set_checksum(0);
    // udppkt.adjust_ipv4_checksum(
    //     Ipv4Addr([192, 168, 57, 10]),
    //     Ipv4Addr([192, 168, 23, 2]),
    // );
    // however, mlx5 nic reports invalid udp checksum for arbitrary set udp checksum
    // udppkt.set_checksum(512);

    let mut ippkt = Ipv4Packet::prepend_header(udppkt.release(), &IPV4_HEADER_TEMPLATE);
    ippkt.set_ident(0x5c65);
    ippkt.clear_flags();
    ippkt.set_time_to_live(128);
    ippkt.set_source_ip(Ipv4Addr([192, 168, 57, 10]));
    ippkt.set_dest_ip(Ipv4Addr([192, 168, 23, 2]));
    ippkt.set_protocol(IpProtocol::UDP);
    ippkt.adjust_checksum();

    let mut ethpkt = EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
    ethpkt.set_dest_mac(MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]));
    ethpkt.set_source_mac(MacAddr([0x00, 0x50, 0x56, 0xae, 0x76, 0xf5]));
    ethpkt.set_ethertype(EtherType::IPV4);
}

#[allow(dead_code)]
fn build_udp_offload(mbuf: &mut Mbuf, payload_len: usize) {
    let total_header_len = ETHER_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN;
    unsafe { mbuf.extend(total_header_len + payload_len) };

    let mut pkt = CursorMut::new(mbuf.data_mut());
    pkt.advance(total_header_len);

    let mut udppkt = UdpPacket::prepend_header(pkt, &UDP_HEADER_TEMPLATE);
    udppkt.set_source_port(60376);
    udppkt.set_dest_port(161);
    udppkt.set_checksum(155);

    let mut ippkt = Ipv4Packet::prepend_header(udppkt.release(), &IPV4_HEADER_TEMPLATE);
    ippkt.set_ident(0x5c65);
    ippkt.clear_flags();
    ippkt.set_time_to_live(128);
    ippkt.set_source_ip(Ipv4Addr([192, 168, 57, 10]));
    ippkt.set_dest_ip(Ipv4Addr([192, 168, 23, 2]));
    ippkt.set_protocol(IpProtocol::UDP);
    ippkt.set_checksum(0);

    let mut ethpkt = EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
    ethpkt.set_dest_mac(MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]));
    ethpkt.set_source_mac(MacAddr([0x00, 0x50, 0x56, 0xae, 0x76, 0xf5]));
    ethpkt.set_ethertype(EtherType::IPV4);

    let mut of_flag = MbufTxOffload::ALL_DISABLED;
    of_flag.enable_ip_cksum();
    of_flag.enable_udp_cksum();
    mbuf.set_l2_len(ETHER_HEADER_LEN as u64);
    mbuf.set_l3_len(IPV4_HEADER_LEN as u64);
    mbuf.set_tx_offload(of_flag);
}

#[allow(dead_code)]
fn build_tcp_manual<'a>(mbuf: &mut Mbuf, payload_len: usize) {
    let total_header_len = ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + 12;
    unsafe { mbuf.extend(total_header_len + payload_len) };

    let mut pkt = CursorMut::new(mbuf.data_mut());
    pkt.advance(total_header_len);

    let mut tcpheader = TCP_HEADER_TEMPLATE;
    tcpheader.set_header_len((TCP_HEADER_LEN + 12) as u8);
    let mut tcppkt = TcpPacket::prepend_header(pkt, &tcpheader);
    tcppkt.set_src_port(57678);
    tcppkt.set_dst_port(80);
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
    // tcppkt.adjust_ipv4_checksum(Ipv4Addr([192, 168, 57, 10]), Ipv4Addr([192, 168, 23, 2]));

    let mut ippkt = Ipv4Packet::prepend_header(tcppkt.release(), &IPV4_HEADER_TEMPLATE);
    ippkt.set_ident(0x5c65);
    ippkt.clear_flags();
    ippkt.set_time_to_live(128);
    ippkt.set_source_ip(Ipv4Addr([192, 168, 57, 10]));
    ippkt.set_dest_ip(Ipv4Addr([192, 168, 23, 2]));
    ippkt.set_protocol(IpProtocol::TCP);
    ippkt.adjust_checksum();

    let mut ethpkt = EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
    ethpkt.set_dest_mac(MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]));
    ethpkt.set_source_mac(MacAddr([0x00, 0x50, 0x56, 0xae, 0x76, 0xf5]));
    ethpkt.set_ethertype(EtherType::IPV4);
}

#[allow(dead_code)]
fn build_tcp_offload<'a>(mbuf: &mut Mbuf, payload_len: usize) {
    let total_header_len = ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + 12;
    unsafe { mbuf.extend(total_header_len + payload_len) };

    let mut pkt = CursorMut::new(mbuf.data_mut());
    pkt.advance(total_header_len);

    let mut tcpheader = TCP_HEADER_TEMPLATE;
    tcpheader.set_header_len((TCP_HEADER_LEN + 12) as u8);
    let mut tcppkt = TcpPacket::prepend_header(pkt, &tcpheader);
    tcppkt.set_src_port(57678);
    tcppkt.set_dst_port(80);
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
    // tcppkt.adjust_ipv4_checksum(Ipv4Addr([192, 168, 57, 10]), Ipv4Addr([192, 168, 23, 2]));

    let mut ippkt = Ipv4Packet::prepend_header(tcppkt.release(), &IPV4_HEADER_TEMPLATE);
    ippkt.set_ident(0x5c65);
    ippkt.clear_flags();
    ippkt.set_time_to_live(128);
    ippkt.set_source_ip(Ipv4Addr([192, 168, 57, 10]));
    ippkt.set_dest_ip(Ipv4Addr([192, 168, 23, 2]));
    ippkt.set_protocol(IpProtocol::TCP);
    ippkt.set_checksum(0);

    let mut ethpkt = EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
    ethpkt.set_dest_mac(MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]));
    ethpkt.set_source_mac(MacAddr([0x00, 0x50, 0x56, 0xae, 0x76, 0xf5]));
    ethpkt.set_ethertype(EtherType::IPV4);

    let mut of_flag = MbufTxOffload::ALL_DISABLED;
    of_flag.enable_ip_cksum();
    of_flag.enable_udp_cksum();
    mbuf.set_l2_len(ETHER_HEADER_LEN as u64);
    mbuf.set_l3_len(IPV4_HEADER_LEN as u64);
    mbuf.set_tx_offload(of_flag);
}

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
    // pconf.mtu = 9000;

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

    let port_id = 0;
    let nb_qs = 1;
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
    let run_curr = run.clone();
    let run_clone = run.clone();
    ctrlc::set_handler(move || {
        run_clone.store(false, Ordering::Release);
    })
    .unwrap();

    let payload_len = 1800;

    let mut jhs = Vec::new();
    for i in 0..nb_qs {
        let run = run.clone();
        let jh = std::thread::spawn(move || {
            service().lcore_bind(i + 1).unwrap();
            let mut txq = service().tx_queue(port_id, i as u16).unwrap();
            let mp = service().mempool(mp_name).unwrap();
            let mut batch = ArrayVec::<_, 64>::new();

            while run.load(Ordering::Acquire) {
                std::thread::sleep(std::time::Duration::from_secs(1));

                let mut mbuf = mp.try_alloc().unwrap();
                build_udp_offload(&mut mbuf, payload_len);

                batch.push(mbuf);
                while batch.len() > 0 {
                    let _sent = txq.tx(&mut batch);
                }
            }
        });
        jhs.push(jh);
    }

    let mut old_stats = service().port_stats(port_id).unwrap();
    while run_curr.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let curr_stats = service().port_stats(port_id).unwrap();
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

    service().port_close(port_id).unwrap();
    println!("port closed");

    service().mempool_free(mp_name).unwrap();
    println!("mempool freed");

    service().service_close().unwrap();
    println!("dpdk service shutdown gracefully");
}
