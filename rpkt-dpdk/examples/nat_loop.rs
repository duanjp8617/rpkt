//! Established-flow NAT loopback: separate generator, forwarding worker and sink.
//! See README for lab wiring, bounded runs and checksum/measurement contracts.
use arrayvec::ArrayVec;
use rpkt_dpdk::{service, DpdkOption, EthConf, Mbuf, Mempool, RxqConf, TxqConf};
use std::sync::Barrier;
use std::time::{Duration, Instant};
#[path = "common/mod.rs"]
mod common;
#[path = "../../benches/nat_support/mod.rs"]
#[allow(dead_code)]
mod nat;

// Apply the same inlining policy to every adapter. The investigation also
// tested outlined kernels; those were not retained as a throughput optimization.
mod kernels {
    use super::nat;
    macro_rules! kernel {
        ($name:ident) => {
            #[inline(always)]
            pub fn $name(data: &mut [u8], table: &nat::Table) -> bool {
                nat::$name(data, table)
            }
        };
    }
    kernel!(rpkt);
    kernel!(rpkt_cursor);
    kernel!(pnet);
    kernel!(smoltcp);

    /// Diagnostic I/O ceiling, not a NAT implementation or a competitor.
    #[inline(always)]
    pub fn io(data: &mut [u8], _: &nat::Table) -> bool {
        if data.len() < 14 {
            return false;
        }
        data[..6].copy_from_slice(&nat::DST_MAC);
        data[6..12].copy_from_slice(&nat::SRC_MAC);
        true
    }
}

struct Config {
    mode: String,
    core: u32,
    rx: u16,
    tx: u16,
    seconds: u64,
    size: usize,
    flows: usize,
    pattern: String,
    workers: u16,
    io_only: bool,
    dut_queues: u16,
}
fn packet(c: &Config, id: usize) -> Vec<u8> {
    let tcp = match c.pattern.as_str() {
        "udp" => false,
        "mixed" => id % 2 != 0,
        _ => true,
    };
    let b = nat::input(c.size, id as u32, tcp, c.pattern == "tcpopts");
    assert_eq!(b.len(), c.size, "frame too short for selected options");
    b
}
#[inline(never)]
fn run<const ROLE: u8, F: Fn(&mut [u8], &nat::Table) -> bool>(
    c: &Config,
    f: F,
    qid: u16,
    barrier: &Barrier,
) {
    if qid != 0 {
        service().thread_bind_to(c.core + u32::from(qid)).unwrap();
        service().register_as_rte_thread().unwrap();
        assert_eq!(
            service().current_lcore().unwrap().socket_id,
            service().dev_info(c.rx).unwrap().socket_id
        );
    }
    let table = nat::table(c.flows);
    let originals: Vec<_> = (0..c.flows).map(|id| packet(c, id)).collect();
    let expected: Vec<_> = originals
        .iter()
        .map(|b| {
            let mut p = b.clone();
            if c.io_only {
                assert!(kernels::io(&mut p, &table));
            } else {
                assert!(nat::reference(&mut p, &table));
            }
            p
        })
        .collect();
    // Several hardware queues can still be serviced by exactly one DUT thread.
    let queue_ids = if ROLE == 2 {
        0..c.dut_queues
    } else {
        qid..qid + 1
    };
    let mut queues: ArrayVec<_, 4> = queue_ids
        .map(|id| {
            (
                service().rx_queue(c.rx, id).unwrap(),
                service().tx_queue(c.tx, id).unwrap(),
            )
        })
        .collect();
    let queue_count = queues.len();
    let mut queue_index = 0;
    let mut queue_rx = [0u64; 4];
    let pool = service().mempool(&format!("nat_{}", c.tx)).unwrap();
    let mut rx = ArrayVec::<Mbuf, 64>::new();
    let mut tx = ArrayVec::<Mbuf, 64>::new();
    let mut recycled = ArrayVec::<Mbuf, 64>::new();
    let mut rs = if qid == 0 {
        Some(service().stats_query(c.rx).unwrap())
    } else {
        None
    };
    let mut ts = if qid == 0 && c.rx != c.tx {
        Some(service().stats_query(c.tx).unwrap())
    } else {
        None
    };
    let rb = rs.as_mut().map(|q| q.query()).unwrap_or_default();
    let tx_errors_before = ts
        .as_mut()
        .map(|q| q.query().oerrors())
        .unwrap_or(rb.oerrors());
    let mut received = 0u64;
    let mut sent = 0u64;
    let mut rejected = 0u64;
    let mut bad_checksum = 0u64;
    let mut fallback = 0u64;
    let mut samples = 0u64;
    let mut bad_output = 0u64;
    let mut unsent = 0u64;
    let mut partial = 0u64;
    let mut first = None;
    let mut last = Duration::ZERO;
    let mut bins = [0u64; 64];
    let mut seq = usize::from(qid);
    barrier.wait();
    eprintln!(
        "READY mode={} core={} worker={qid}",
        c.mode,
        c.core + u32::from(qid)
    );
    let mut clock = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock points to initialized, writable timespec storage.
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) },
        0
    );
    let mono_origin = clock.tv_sec as f64 + clock.tv_nsec as f64 * 1e-9;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(c.seconds) {
        let active_queue = queue_index;
        let (rxq, txq) = &mut queues[queue_index];
        queue_index += 1;
        if queue_index == queue_count {
            queue_index = 0;
        }
        // Receiver/DUT wall-time is a safety bound. Finish one second after
        // traffic stops, allowing staggered SSH startup without truncating TX.
        if ROLE != 0 && first.is_some() && start.elapsed() - last > Duration::from_secs(1) {
            break;
        }
        if ROLE == 0 {
            pool.fill_up_batch(&mut tx);
            for m in &mut tx {
                let bytes = &originals[seq % c.flows];
                seq += usize::from(c.workers);
                // SAFETY: pool data room >= frame size; every exposed byte is
                // initialized immediately, before reads or transmission.
                unsafe {
                    m.extend(bytes.len());
                }
                m.data_mut().copy_from_slice(bytes);
                m.set_tx_offload(0);
            }
        } else {
            rxq.rx(&mut rx);
            queue_rx[active_queue] += rx.len() as u64;
            // The same header-prefetch pass for all adapters. Only the first
            // cache line is needed for ordinary Ethernet/IPv4/UDP/TCP headers.
            #[cfg(target_arch = "x86_64")]
            for m in &rx {
                // SAFETY: x86_64 guarantees SSE; this is a non-dereferencing
                // prefetch hint into a live packet allocation.
                unsafe {
                    core::arch::x86_64::_mm_prefetch(
                        m.data().as_ptr().cast(),
                        core::arch::x86_64::_MM_HINT_T0,
                    );
                }
            }
            let mut accepted = 0;
            for mut m in rx.drain(..) {
                if m.pkt_len() != m.data().len() {
                    rejected += 1;
                    continue;
                }
                let flags = m.rx_offload();
                if flags & ((1 << 4) | (1 << 3)) != 0 {
                    bad_checksum += 1;
                    continue;
                }
                if ROLE == 1 {
                    let b = m.data();
                    if b.len() != c.size || b[..6] != nat::DST_MAC || b[6..12] != nat::SRC_MAC {
                        rejected += 1;
                        continue;
                    }
                    received += 1;
                    accepted += 1;
                    // A prime stride avoids repeatedly sampling the same flow
                    // in a power-of-two round-robin stream.
                    if received % 1021 == 0 {
                        samples += 1;
                        let id = u16::from_be_bytes([b[18], b[19]]) as usize;
                        if id >= expected.len() || b != expected[id] || !nat::valid(b) {
                            bad_output += 1
                        }
                    }
                    recycled.push(m);
                } else {
                    if flags & ((1 << 7) | (1 << 8)) != ((1 << 7) | (1 << 8)) {
                        fallback += 1;
                        let good_ip = rpkt::ether::EtherFrame::parse(rpkt::Cursor::new(m.data()))
                            .ok()
                            .and_then(|e| rpkt::ipv4::Ipv4::parse(e.payload()).ok())
                            .map(|p| {
                                rpkt::checksum::from_slice(
                                    &m.data()[14..14 + p.header_len() as usize],
                                ) == 65535
                            })
                            .unwrap_or(false);
                        if !good_ip || !common::verify_transport(&m) {
                            bad_checksum += 1;
                            continue;
                        }
                    }
                    if !f(m.data_mut(), &table) {
                        rejected += 1;
                        continue;
                    }
                    received += 1;
                    accepted += 1;
                    m.set_tx_offload(0);
                    tx.push(m);
                }
            }
            Mempool::free_batch(&mut recycled);
            if accepted != 0 {
                let now = start.elapsed();
                let begin = *first.get_or_insert(now);
                last = now;
                let index = (now - begin).as_secs() as usize;
                if index < bins.len() {
                    bins[index] += accepted
                }
            }
        }
        if !tx.is_empty() {
            let offered = tx.len();
            let n = txq.tx(&mut tx);
            sent += n as u64;
            if n < offered {
                partial += 1;
                unsent += tx.len() as u64
            }
            Mempool::free_batch(&mut tx);
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    let active = first
        .map(|first| (last - first).as_secs_f64())
        .unwrap_or(0.0);
    if ROLE == 2 {
        eprintln!("QUEUE_RX {:?}", &queue_rx[..queue_count]);
        eprintln!(
            "PROFILE_WINDOW {:.9} {:.9}",
            mono_origin + first.unwrap_or(Duration::ZERO).as_secs_f64(),
            mono_origin + last.as_secs_f64()
        );
    }
    barrier.wait(); // Primary stats query includes every worker's completed run.
    let ra = rs.as_mut().map(|q| q.query()).unwrap_or_default();
    let tx_errors_after = ts
        .as_mut()
        .map(|q| q.query().oerrors())
        .unwrap_or(ra.oerrors());
    println!("{{\"mode\":\"{}\",\"core\":{},\"worker\":{qid},\"pattern\":\"{}\",\"bytes\":{},\"flows\":{},\"seconds\":{:.6},\"active_seconds\":{:.6},\"tx\":{},\"rx\":{},\"rejected\":{},\"bad_checksum\":{},\"checksum_fallback\":{},\"output_samples\":{},\"bad_output\":{},\"unsent\":{},\"partial_tx\":{},\"rx_missed\":{},\"rx_no_mbuf\":{},\"tx_errors\":{},\"rx_bins_1s\":{:?}}}",
        c.mode,c.core + u32::from(qid),c.pattern,c.size,c.flows,elapsed,active,sent,received,rejected,bad_checksum,fallback,samples,bad_output,unsent,partial,
        ra.imissed().saturating_sub(rb.imissed()),ra.rx_nombuf().saturating_sub(rb.rx_nombuf()),tx_errors_after.saturating_sub(tx_errors_before),&bins[..(active as usize+1).min(64)]);
}
fn traffic<const ROLE: u8>(c: &Config) {
    let barrier = Barrier::new(usize::from(c.workers));
    std::thread::scope(|scope| {
        for qid in 1..c.workers {
            let barrier = &barrier;
            scope.spawn(move || run::<ROLE, _>(c, |_, _| false, qid, barrier));
        }
        run::<ROLE, _>(c, |_, _| false, 0, &barrier);
    });
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let usage="nat_loop <gen|sink|rpkt|cursor|pnet|smoltcp|io> CORE RX TX SECONDS SIZE FLOWS <udp|tcp|mixed|tcpopts> -- EAL_ARGS";
    let sep = args.iter().position(|s| s == "--").expect(usage);
    assert_eq!(sep, 8, "{usage}");
    let c = Config {
        mode: args[0].clone(),
        core: args[1].parse().unwrap(),
        rx: args[2].parse().unwrap(),
        tx: args[3].parse().unwrap(),
        seconds: args[4].parse().unwrap(),
        size: args[5].parse().unwrap(),
        flows: args[6].parse().unwrap(),
        pattern: args[7].clone(),
        workers: if matches!(args[0].as_str(), "gen" | "sink") {
            std::env::var("RPKT_TRAFFIC_WORKERS")
                .unwrap_or_else(|_| "1".into())
                .parse()
                .unwrap()
        } else {
            1
        },
        io_only: args[0] == "io" || std::env::var_os("RPKT_NAT_IO_ONLY").is_some(),
        dut_queues: if matches!(args[0].as_str(), "gen" | "sink") {
            1
        } else {
            std::env::var("RPKT_DUT_QUEUES")
                .unwrap_or_else(|_| "1".into())
                .parse()
                .unwrap()
        },
    };
    assert!(matches!(
        c.mode.as_str(),
        "gen" | "sink" | "rpkt" | "cursor" | "pnet" | "smoltcp" | "io"
    ));
    assert!((1..=4).contains(&c.workers));
    assert!((1..=4).contains(&c.dut_queues));
    assert!(matches!(
        c.pattern.as_str(),
        "udp" | "tcp" | "mixed" | "tcpopts"
    ));
    assert!(
        (1..=60).contains(&c.seconds)
            && (64..=1514).contains(&c.size)
            && (1..=65536).contains(&c.flows)
    );
    if !matches!(c.mode.as_str(), "gen" | "sink") {
        assert_ne!(c.rx, c.tx)
    }
    DpdkOption::new().args(&args[sep + 1..]).init().unwrap();
    service().thread_bind_to(c.core).unwrap();
    service().register_as_rte_thread().unwrap();
    let worker = service().current_lcore().unwrap();
    let ports = if c.rx == c.tx {
        vec![c.rx]
    } else {
        vec![c.rx, c.tx]
    };
    for &port in &ports {
        let info = service().dev_info(port).unwrap();
        assert_eq!(worker.socket_id, info.socket_id);
        let name = format!("nat_{port}");
        service()
            .mempool_alloc(&name, 16383, 256, 2176, info.socket_id as i32)
            .unwrap();
        let mut conf = EthConf::default();
        conf.mtu = 1500;
        conf.rx_offloads =
            info.rx_offload_capa() & u64::from(rpkt_dpdk::ffi::RPKT_RX_CHECKSUM_OFFLOADS);
        if (c.mode == "sink" && c.workers > 1) || c.dut_queues > 1 {
            conf.rss_hf = (1 << 4 | 1 << 5) & info.flow_type_rss_offloads();
            assert_eq!(conf.rss_hf, 1 << 4 | 1 << 5, "IPv4 TCP/UDP RSS required");
            // The library's repeating symmetric key can cancel correlated
            // address/port increments in this synthetic NAT dataset. Use a
            // reproducible nonperiodic key for the traffic receiver only.
            let mut state = 0x91e10da5u32;
            conf.rss_hash_key = (0..info.hash_key_size())
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect();
        }
        service()
            .dev_configure_and_start(
                port,
                &conf,
                &(0..c.workers.max(c.dut_queues))
                    .map(|_| RxqConf::new(2048, info.socket_id, &name))
                    .collect::<Vec<_>>(),
                &(0..c.workers.max(c.dut_queues))
                    .map(|_| TxqConf::new(2048, info.socket_id))
                    .collect::<Vec<_>>(),
            )
            .unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    for port in ports {
        loop {
            // SAFETY: this port has been configured; wrapper abstracts DPDK ABI.
            let up = unsafe { rpkt_dpdk::ffi::rte_eth_link_up_(port) };
            assert!(up >= 0);
            if up == 1 {
                break;
            }
            assert!(Instant::now() < deadline, "link timeout");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let barrier = Barrier::new(1);
    match c.mode.as_str() {
        "gen" => traffic::<0>(&c),
        "sink" => traffic::<1>(&c),
        "rpkt" => run::<2, _>(&c, kernels::rpkt, 0, &barrier),
        "cursor" => run::<2, _>(&c, kernels::rpkt_cursor, 0, &barrier),
        "pnet" => run::<2, _>(&c, kernels::pnet, 0, &barrier),
        "smoltcp" => run::<2, _>(&c, kernels::smoltcp, 0, &barrier),
        "io" => run::<2, _>(&c, kernels::io, 0, &barrier),
        _ => unreachable!(),
    }
    service().graceful_cleanup().unwrap();
}
