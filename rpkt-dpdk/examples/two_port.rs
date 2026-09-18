//! Bounded single-worker two-link traffic generator/forwarder. See README.
use arrayvec::ArrayVec;
use rpkt::{
    checksum,
    ether::{EtherAddr, EtherFrame, EtherType},
    ipv4::{IpProtocol, Ipv4, Ipv4Addr},
    template::{UdpIpv4Flow, UdpIpv4Template},
    udp::Udp,
    Cursor,
};
use rpkt_dpdk::{service, DpdkOption, EthConf, Mbuf, Mempool, RxqConf, TxqConf};
use std::time::{Duration, Instant};

struct Config {
    generate: bool,
    core: u32,
    rx: u16,
    tx: u16,
    seconds: u64,
    size: usize,
    offload: bool,
}

fn checked(data: &[u8]) -> Option<usize> {
    let eth = EtherFrame::parse(Cursor::new(data)).ok()?;
    if eth.ethertype() != EtherType::IPV4 {
        return None;
    }
    let ip = Ipv4::parse(eth.payload()).ok()?;
    if ip.version() != 4
        || ip.header_len() != 20
        || ip.more_frag()
        || ip.frag_offset() != 0
        || ip.protocol() != IpProtocol::UDP
    {
        return None;
    }
    let ip_len = ip.packet_len() as usize;
    let udp = Udp::parse(ip.payload()).ok()?;
    if udp.packet_len() as usize != ip_len - 20 || udp.packet_len() < 28 {
        return None;
    }
    if &data[42..46] != b"RPKT" {
        return None;
    }
    Some(udp.packet_len() as usize)
}

fn pseudo(data: &[u8], udp_len: usize) -> u16 {
    checksum::combine(&[checksum::from_slice(&data[26..34]), 17, udp_len as u16])
}

fn tx_offload(mbuf: &mut Mbuf, enabled: bool, udp_len: usize) {
    if enabled {
        let data = mbuf.data_mut();
        let seed = pseudo(data, udp_len);
        data[24..26].fill(0);
        data[40..42].copy_from_slice(&seed.to_be_bytes());
        mbuf.set_l2_len(14);
        mbuf.set_l3_len(20);
        mbuf.set_l4_len(8);
        mbuf.set_tx_offload((1 << 54) | (1 << 55) | (3 << 52));
    } else {
        mbuf.set_tx_offload(0);
    }
}

fn run<const N: usize>(config: &Config) {
    let mut rxq = service().rx_queue(config.rx, 0).unwrap();
    let mut txq = service().tx_queue(config.tx, 0).unwrap();
    let pool = service()
        .mempool(&format!("two_port_{}", config.tx))
        .unwrap();
    let mut rx = ArrayVec::<Mbuf, N>::new();
    let mut tx = ArrayVec::<Mbuf, N>::new();
    let mut rx_stats = service().stats_query(config.rx).unwrap();
    let mut tx_stats = service().stats_query(config.tx).unwrap();
    let before_rx = rx_stats.query();
    let before_tx = tx_stats.query();
    let info = service().dev_info(config.tx).unwrap();
    let template = UdpIpv4Template::new(UdpIpv4Flow {
        src_mac: EtherAddr(info.mac_addr),
        dst_mac: EtherAddr([255; 6]),
        src_ip: Ipv4Addr::new(10, 77, 0, 1),
        dst_ip: Ipv4Addr::new(10, 77, 0, 2),
        src_port: 1234,
        dst_port: 4321,
        ttl: 64,
    });
    let mut payload = vec![0xa5; config.size - 42];
    payload[..4].copy_from_slice(b"RPKT");
    let mut prepared = vec![0; config.size];
    template.write(&mut prepared, &payload, 0).unwrap();
    let header: [u8; 42] = prepared[..42].try_into().unwrap();
    let ip_checksum = u16::from_be_bytes([header[24], header[25]]);
    let start = Instant::now();
    let duration = Duration::from_secs(config.seconds);
    let stop = duration
        + if config.generate {
            Duration::from_millis(200)
        } else {
            Duration::ZERO
        };
    let mut sent = 0u64;
    let mut received = 0u64;
    let mut invalid = 0u64;
    let mut checksum_errors = 0u64;
    let mut partial_tx = 0u64;
    let mut unsent = 0u64;
    let mut alloc_empty = 0u64;
    let mut sequence = 0u64;
    let mut samples = Vec::with_capacity(65536);
    while start.elapsed() < stop {
        if config.generate && start.elapsed() < duration {
            pool.fill_up_batch(&mut tx);
            if tx.is_empty() {
                alloc_empty += 1;
            }
            let timestamp = start.elapsed().as_nanos() as u64;
            for mbuf in &mut tx {
                payload[4..12].copy_from_slice(&sequence.to_be_bytes());
                payload[12..20].copy_from_slice(&timestamp.to_be_bytes());
                // SAFETY: pool capacity was chosen for this frame. The template
                // writes every exposed byte before any read or NIC transfer.
                unsafe {
                    mbuf.extend(config.size);
                }
                let data = mbuf.data_mut();
                data[..42].copy_from_slice(&header);
                data[42..].copy_from_slice(&payload);
                data[18..20].copy_from_slice(&(sequence as u16).to_be_bytes());
                if !config.offload {
                    data[24..26].copy_from_slice(
                        &checksum::replace_word(ip_checksum, 0, sequence as u16).to_be_bytes(),
                    );
                    data[40..42].fill(0);
                    let sum = !checksum::combine(&[
                        pseudo(data, config.size - 34),
                        checksum::from_slice(&data[34..]),
                    ]);
                    data[40..42]
                        .copy_from_slice(&if sum == 0 { 0xffff } else { sum }.to_be_bytes());
                }
                tx_offload(mbuf, config.offload, config.size - 34);
                sequence += 1;
            }
        }
        rxq.rx(&mut rx);
        for mut mbuf in rx.drain(..) {
            let Some(udp_len) = checked(mbuf.data()) else {
                invalid += 1;
                continue;
            };
            received += 1;
            if checksum::from_slice(&mbuf.data()[14..34]) != 0xffff {
                checksum_errors += 1;
                continue;
            }
            if config.generate {
                let data = mbuf.data();
                if checksum::combine(&[
                    pseudo(data, udp_len),
                    checksum::from_slice(&data[34..34 + udp_len]),
                ]) != 0xffff
                {
                    checksum_errors += 1;
                }
                let seq = u64::from_be_bytes(data[46..54].try_into().unwrap());
                if seq % 1024 == 0 && samples.len() < samples.capacity() {
                    let timestamp = u64::from_be_bytes(data[54..62].try_into().unwrap());
                    if let Some(latency) =
                        (start.elapsed().as_nanos() as u64).checked_sub(timestamp)
                    {
                        samples.push(latency);
                    }
                }
            } else {
                let data = mbuf.data_mut();
                if data[22] <= 1 {
                    invalid += 1;
                    continue;
                }
                let old = u16::from_be_bytes([data[22], data[23]]);
                let hc = u16::from_be_bytes([data[24], data[25]]);
                data[22] -= 1;
                let new = u16::from_be_bytes([data[22], data[23]]);
                data[24..26].copy_from_slice(&checksum::replace_word(hc, old, new).to_be_bytes());
                tx_offload(&mut mbuf, config.offload, udp_len);
                tx.push(mbuf);
            }
        }
        if !tx.is_empty() {
            let offered = tx.len();
            let accepted = txq.tx(&mut tx);
            sent += accepted as u64;
            if accepted < offered {
                partial_tx += 1;
                unsent += tx.len() as u64;
            }
            // Never wait indefinitely for a full burst or a congested TX queue.
            Mempool::free_batch(&mut tx);
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let after_rx = rx_stats.query();
    let after_tx = tx_stats.query();
    samples.sort_unstable();
    let percentile = |percent: usize| {
        samples
            .get((samples.len().saturating_sub(1) * percent) / 100)
            .copied()
            .unwrap_or(0)
    };
    println!("{{\"role\":\"{}\",\"core\":{},\"burst\":{},\"frame_bytes\":{},\"tx_offload\":{},\"elapsed_s\":{:.6},\"tx\":{},\"rx\":{},\"tx_pps\":{:.3},\"rx_pps\":{:.3},\"unreturned\":{},\"invalid\":{},\"checksum_errors\":{},\"partial_tx_bursts\":{},\"unsent\":{},\"allocation_empty\":{},\"hw_rx\":{},\"hw_tx\":{},\"rx_missed\":{},\"rx_no_mbuf\":{},\"tx_errors\":{},\"latency_samples\":{},\"rtt_p50_ns\":{},\"rtt_p95_ns\":{},\"rtt_p99_ns\":{}}}",
        if config.generate {"gen"} else {"fwd"}, config.core, N, config.size, config.offload, elapsed,
        sent, received, sent as f64 / config.seconds as f64, received as f64 / config.seconds as f64,
        if config.generate {sent.saturating_sub(received)} else {0}, invalid, checksum_errors, partial_tx, unsent, alloc_empty,
        after_rx.ipackets().saturating_sub(before_rx.ipackets()), after_tx.opackets().saturating_sub(before_tx.opackets()),
        after_rx.imissed().saturating_sub(before_rx.imissed()), after_rx.rx_nombuf().saturating_sub(before_rx.rx_nombuf()),
        after_tx.oerrors().saturating_sub(before_tx.oerrors()), samples.len(), percentile(50), percentile(95), percentile(99));
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "two_port <gen|fwd> CORE RX_PORT TX_PORT SECONDS FRAME_BYTES BURST <software|offload> -- EAL_ARGS";
    let separator = args.iter().position(|s| s == "--").expect(usage);
    assert_eq!(separator, 8, "{usage}");
    assert!(matches!(args[0].as_str(), "gen" | "fwd"), "{usage}");
    assert!(
        matches!(args[7].as_str(), "software" | "offload"),
        "{usage}"
    );
    let mut config = Config {
        generate: args[0] == "gen",
        core: args[1].parse().unwrap(),
        rx: args[2].parse().unwrap(),
        tx: args[3].parse().unwrap(),
        seconds: args[4].parse().unwrap(),
        size: args[5].parse().unwrap(),
        offload: args[7] == "offload",
    };
    let burst: usize = args[6].parse().unwrap();
    assert!(
        matches!(burst, 1 | 4 | 8 | 16 | 32 | 64),
        "unsupported burst size"
    );
    assert!((1..=60).contains(&config.seconds) && (64..=9014).contains(&config.size));
    assert_ne!(config.rx, config.tx, "use two distinct ports");
    DpdkOption::new()
        .args(&args[separator + 1..])
        .init()
        .unwrap();
    service().thread_bind_to(config.core).unwrap();
    service().register_as_rte_thread().unwrap();
    let worker = service().current_lcore().unwrap();
    let required_tx = u64::from(rpkt_dpdk::ffi::RPKT_TX_CHECKSUM_OFFLOADS);
    let tx_info = service().dev_info(config.tx).unwrap();
    if config.offload && tx_info.tx_offload_capa() & required_tx != required_tx {
        eprintln!("Requested checksum offload unavailable; using software");
        config.offload = false;
    }
    for port in [config.rx, config.tx] {
        let info = service().dev_info(port).unwrap();
        assert!(
            burst >= 4 || !info.driver_name().contains("mlx5")
                || args[separator + 1..].iter().any(|arg| arg.contains("rx_vec_en=0")),
            "mlx5 vector RX cannot receive a burst of 1; pass rx_vec_en=0 for BOTH allowlisted ports"
        );
        assert_eq!(
            worker.socket_id, info.socket_id,
            "worker must be local to both NICs"
        );
        let pool = format!("two_port_{port}");
        service()
            .mempool_alloc(
                &pool,
                8191,
                256,
                (config.size.max(2048) + 128) as u16,
                info.socket_id as i32,
            )
            .unwrap();
        let mut conf = EthConf::default();
        conf.mtu = (config.size - 14).max(1500) as u32;
        conf.rx_offloads =
            info.rx_offload_capa() & u64::from(rpkt_dpdk::ffi::RPKT_RX_CHECKSUM_OFFLOADS);
        conf.tx_offloads = if port == config.tx && config.offload {
            required_tx
        } else {
            0
        };
        service()
            .dev_configure_and_start(
                port,
                &conf,
                &vec![RxqConf::new(1024, info.socket_id, &pool)],
                &vec![TxqConf::new(1024, info.socket_id)],
            )
            .unwrap();
        eprintln!(
            "port={port} mac={:?} socket={} core={} driver={}",
            info.mac_addr,
            info.socket_id,
            config.core,
            info.driver_name()
        );
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    for port in [config.rx, config.tx] {
        loop {
            // SAFETY: port is configured. The C wrapper hides DPDK's
            // version-dependent bitfield/anonymous-union layout.
            let status = unsafe { rpkt_dpdk::ffi::rte_eth_link_up_(port) };
            assert!(status >= 0, "could not query port {port} link: {status}");
            if status == 1 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "port {port} link did not come up"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    eprintln!("READY: both links up");
    match burst {
        1 => run::<1>(&config),
        4 => run::<4>(&config),
        8 => run::<8>(&config),
        16 => run::<16>(&config),
        32 => run::<32>(&config),
        64 => run::<64>(&config),
        _ => unreachable!(),
    }
    service().graceful_cleanup().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> [u8; 64] {
        let template = UdpIpv4Template::new(UdpIpv4Flow {
            src_mac: EtherAddr([1; 6]),
            dst_mac: EtherAddr([2; 6]),
            src_ip: Ipv4Addr::new(10, 0, 0, 1),
            dst_ip: Ipv4Addr::new(10, 0, 0, 2),
            src_port: 1234,
            dst_port: 4321,
            ttl: 64,
        });
        let mut payload = [0; 22];
        payload[..4].copy_from_slice(b"RPKT");
        let mut frame = [0; 64];
        template.write(&mut frame, &payload, 7).unwrap();
        frame
    }

    #[test]
    fn checked_rejects_all_truncations_and_unsupported_layouts() {
        let frame = frame();
        assert_eq!(checked(&frame), Some(30));
        for len in 0..frame.len() {
            assert_eq!(checked(&frame[..len]), None, "length {len}");
        }
        for (offset, value) in [
            (12, 0x81),
            (14, 0x65),
            (20, 0x20),
            (21, 1),
            (23, 6),
            (38, 0xff),
            (42, 0),
        ] {
            let mut bad = frame;
            bad[offset] = value;
            assert_eq!(checked(&bad), None, "offset {offset}");
        }
    }

    #[test]
    fn pseudo_seed_and_incremental_forwarding_match_full_checksums() {
        let mut frame = frame();
        assert_eq!(
            checksum::combine(&[pseudo(&frame, 30), checksum::from_slice(&frame[34..])]),
            0xffff
        );
        let old = u16::from_be_bytes([frame[24], frame[25]]);
        frame[22] -= 1;
        frame[24..26].copy_from_slice(&checksum::replace_word(old, 0x4011, 0x3f11).to_be_bytes());
        assert_eq!(checksum::from_slice(&frame[14..34]), 0xffff);
    }
}
