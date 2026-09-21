//! Closed-loop, byte-checked TCP over the same DPDK Device in both builds.
use rpkt_dpdk::tcp_device::{RX_OFFLOADS, TX_OFFLOADS};
use rpkt_dpdk::{tcp_device::DpdkDevice, *};
use std::time::{Duration, Instant};
use tcp_eval::{stack::time::Instant as TcpTime, Endpoint};

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert!(
        args.len() >= 9,
        "client|server CORE PORT SECONDS CONNECTIONS REQUEST echo|bulk timestamps|plain -- EAL..."
    );
    let client = match args[0].as_str() {
        "client" => true,
        "server" => false,
        _ => panic!("role"),
    };
    let core = args[1].parse::<u32>().unwrap();
    let port = args[2].parse::<u16>().unwrap();
    let seconds = args[3].parse::<u64>().unwrap();
    let connections = args[4].parse::<usize>().unwrap();
    let request = args[5].parse::<usize>().unwrap();
    let echo = args[6] == "echo";
    let timestamps = args[7] == "timestamps";
    let offloads = std::env::var("RPKT_TCP_OFFLOADS").as_deref() == Ok("1");
    let force_linearize = std::env::var("RPKT_TCP_FORCE_LINEARIZE").as_deref() == Ok("1");
    assert!((1..=60).contains(&seconds));
    assert_eq!(args[8], "--");
    DpdkOption::new().args(&args[9..]).init().unwrap();
    service().thread_bind_to(core).unwrap();
    let info = service().dev_info(port).unwrap();
    assert_eq!(service().current_lcore().unwrap().socket_id, info.socket_id);
    eprintln!(
        "CAPS rx={:#x} tx={:#x} max_lro={} offloads={offloads}",
        info.rx_offload_capa(),
        info.tx_offload_capa(),
        info.max_lro_pkt_size()
    );
    service()
        .mempool_alloc("tcp", 16383, 256, 2176, info.socket_id as i32)
        .unwrap();
    let mut conf = EthConf::default();
    conf.mtu = 1500;
    if offloads {
        assert_eq!(
            info.rx_offload_capa() & RX_OFFLOADS,
            RX_OFFLOADS,
            "RX LRO/scatter/checksum unsupported"
        );
        assert_eq!(
            info.tx_offload_capa() & TX_OFFLOADS,
            TX_OFFLOADS,
            "TX TSO/checksum unsupported"
        );
        assert!(info.max_lro_pkt_size() >= 65280);
        conf.rx_offloads = RX_OFFLOADS;
        conf.tx_offloads = TX_OFFLOADS;
        conf.max_lro_pkt_size = 65280;
        service()
            .mempool_alloc("tcp-tx", 2047, 256, 64768, info.socket_id as i32)
            .unwrap();
    }
    service()
        .dev_configure_and_start(
            port,
            &conf,
            &vec![RxqConf::new(2048, info.socket_id, "tcp")],
            &vec![TxqConf::new(2048, info.socket_id)],
        )
        .unwrap();
    let mut device = DpdkDevice::with_offloads(
        service().rx_queue(port, 0).unwrap(),
        service().tx_queue(port, 0).unwrap(),
        service()
            .mempool(if offloads { "tcp-tx" } else { "tcp" })
            .unwrap(),
        offloads,
    );
    let start = Instant::now();
    device.force_linearization(force_linearize);
    let mut endpoint = Endpoint::new(
        &mut device,
        client,
        connections,
        request,
        echo,
        timestamps,
        TcpTime::from_millis(0),
    );
    eprintln!("READY role={} backend={}", args[0], tcp_eval::BACKEND);
    let mut measurement = None;
    let mut established_at = None;
    let mut baseline_bytes = 0;
    let mut baseline_responses = 0;
    let mut end_bytes = 0;
    let mut end_responses = 0;
    let mut measured_ns = 0;
    let mut closing = false;
    while start.elapsed() < Duration::from_secs(seconds + 12) {
        let elapsed = start.elapsed();
        let now = TcpTime::from_micros(elapsed.as_micros() as i64);
        if established_at.is_none() && endpoint.established() == connections {
            established_at = Some(elapsed);
        }
        if measurement.is_none()
            && established_at.is_some_and(|at| elapsed - at >= Duration::from_secs(2))
        {
            measurement = Some(elapsed);
            baseline_bytes = endpoint.bytes;
            baseline_responses = endpoint.responses;
        }
        let done = measurement.is_some_and(|begin| elapsed - begin >= Duration::from_secs(seconds));
        if done && !closing {
            measured_ns = (elapsed - measurement.unwrap()).as_nanos();
            end_bytes = endpoint.bytes - baseline_bytes;
            end_responses = endpoint.responses - baseline_responses;
            if client {
                endpoint.close();
            }
            closing = true;
        }
        if measurement.is_some_and(|begin| elapsed - begin >= Duration::from_secs(seconds + 2)) {
            break;
        }
        device.begin_poll();
        endpoint.poll(&mut device, now, !done);
        device.flush();
    }
    let stats = service().stats_query(port).unwrap().query();
    eprintln!("OFFLOAD_COUNTERS {:?}", device.counters);
    println!("{{\"backend\":\"{}\",\"role\":\"{}\",\"connections\":{},\"request\":{},\"echo\":{},\"timestamps\":{},\"seconds\":{},\"measured_ns\":{},\"congestion\":\"reno\",\"measured\":{},\"bytes\":{},\"responses\":{},\"errors\":{},\"rx\":{},\"tx\":{},\"rejected\":{},\"no_mbuf\":{},\"pending_tx\":{},\"rx_missed\":{},\"tx_errors\":{},\"offloads\":{},\"chains\":{},\"lro\":{},\"linearized_bytes\":{},\"tso\":{},\"max_rx_len\":{}}}",
        tcp_eval::BACKEND,args[0],connections,request,echo,timestamps,seconds,measured_ns,measurement.is_some()&&closing,end_bytes,end_responses,endpoint.errors,device.counters.rx,device.counters.tx,device.counters.rejected,device.counters.no_mbuf,device.pending_tx(),stats.imissed(),stats.oerrors(),offloads,device.counters.chains,device.counters.lro,device.counters.linearized_bytes,device.counters.tso,device.counters.max_rx_len);
    assert!(
        measurement.is_some() && closing,
        "connections never established"
    );
    assert_eq!(endpoint.errors, 0);
    assert!(client && !echo || end_bytes != 0, "transfer stalled");
    drop(endpoint);
    drop(device);
    service().graceful_cleanup().unwrap();
}
