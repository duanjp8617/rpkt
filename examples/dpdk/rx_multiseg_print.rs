use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;
use rpkt_dpdk::*;
use rpkt::ether::*;
use rpkt::ipv4::*;
use rpkt::tcp::*;
use rpkt::udp::*;
use rpkt::Buf;

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

    let mut pconf = PortConf::from_port_info(port_info).unwrap();
    pconf.mtu = 9000;
    pconf.rx_offloads.enable_scatter();
    pconf.tx_offloads.enable_multi_segs();

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
    let run_clone = run.clone();
    ctrlc::set_handler(move || {
        run_clone.store(false, Ordering::Release);
    })
    .unwrap();

    let mut jhs = Vec::new();
    for i in 0..nb_qs {
        let run = run.clone();

        let jh = std::thread::spawn(move || {
            service().lcore_bind(i + 1).unwrap();
            let mut rxq = service().rx_queue(port_id as u16, i as u16).unwrap();
            let mut batch = ArrayVec::<_, 32>::new();

            while run.load(Ordering::Acquire) {
                rxq.rx(&mut batch);

                for mut mbuf in batch.drain(..) {
                    let ol_flag = mbuf.rx_offload();
                    if ol_flag.ip_cksum_good() {
                        println!("ip correct");
                    }
                    if ol_flag.l4_cksum_good() {
                        println!("l4 correct");
                    }
                    if ol_flag.rss_hash() {
                        println!("rss value {}", mbuf.rss());
                    }
                    println!("mbuf has {} segments", mbuf.num_segs());

                    let buf = Pbuf::new(&mut mbuf);

                    let ethpkt = match EtherPacket::parse(buf) {
                        Err(_) => continue,
                        Ok(ethpkt) => ethpkt,
                    };

                    let ippkt = match Ipv4Packet::parse(ethpkt.payload()) {
                        Err(_) => continue,
                        Ok(ippkt) => ippkt,
                    };
                    let src_ip = ippkt.source_ip();
                    let dst_ip = ippkt.dest_ip();

                    println!(
                        "receive ippkt with checksum: {}, correct? {}",
                        ippkt.checksum(),
                        ippkt.verify_checksum()
                    );

                    match ippkt.protocol() {
                        IpProtocol::TCP => {
                            let mut tcppkt = match TcpPacket::parse(ippkt.payload()) {
                                Err(_) => continue,
                                Ok(tcppkt) => tcppkt,
                            };

                            println!(
                                "receive tcp pkt with payload {}, checksum correct? {}",
                                tcppkt.buf().remaining() - tcppkt.header_len() as usize,
                                tcppkt.verify_ipv4_checksum(src_ip, dst_ip)
                            );
                        }
                        IpProtocol::UDP => {
                            let mut udppkt = match UdpPacket::parse(ippkt.payload()) {
                                Err(_) => continue,
                                Ok(udppkt) => udppkt,
                            };

                            println!(
                                "receive udp pkt with payload {}, checksum correct? {}",
                                udppkt.packet_len() as usize - UDP_HEADER_LEN,
                                udppkt.verify_ipv4_checksum(src_ip, dst_ip)
                            );
                        }
                        _ => {}
                    }
                }
            }
        });
        jhs.push(jh);
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
