//! Shared setup for device feature demonstrations.
#![allow(dead_code)]
use rpkt_dpdk::{constant, error::Result, service, EthConf, RxqConf, TxqConf};

pub fn init_mempool(name: &str, count: u32, cache: u32, socket: u32) -> Result<()> {
    service()
        .mempool_alloc(
            name,
            count,
            cache,
            constant::MBUF_DATAROOM_SIZE + constant::MBUF_HEADROOM_SIZE,
            socket as i32,
        )
        .map(drop)
}

pub fn pseudo_sum(
    src: core::net::Ipv4Addr,
    dst: core::net::Ipv4Addr,
    protocol: u8,
    len: usize,
) -> u16 {
    rpkt::checksum::combine(&[
        rpkt::checksum::from_slice(&src.octets()),
        rpkt::checksum::from_slice(&dst.octets()),
        protocol as u16,
        u16::try_from(len).unwrap(),
    ])
}

pub fn adjust_udp<T: rpkt::PktBufMut>(
    mut udp: rpkt::udp::Udp<T>,
    src: core::net::Ipv4Addr,
    dst: core::net::Ipv4Addr,
) -> rpkt::udp::Udp<T> {
    udp.set_checksum(0);
    let len = udp.packet_len() as usize;
    let mut buf = udp.release();
    let sum = rpkt::checksum::from_buf(&mut buf, len);
    buf.move_back(len);
    let mut udp = rpkt::udp::Udp::parse_unchecked(buf);
    let value = !rpkt::checksum::combine(&[sum, pseudo_sum(src, dst, 17, len)]);
    udp.set_checksum(if value == 0 { 0xffff } else { value });
    udp
}

pub fn adjust_tcp<T: rpkt::PktBufMut>(
    mut tcp: rpkt::tcp::Tcp<T>,
    src: core::net::Ipv4Addr,
    dst: core::net::Ipv4Addr,
) -> rpkt::tcp::Tcp<T> {
    tcp.set_checksum(0);
    let mut buf = tcp.release();
    let len = buf.remaining();
    let sum = rpkt::checksum::from_buf(&mut buf, len);
    buf.move_back(len);
    let mut tcp = rpkt::tcp::Tcp::parse_unchecked(buf);
    tcp.set_checksum(!rpkt::checksum::combine(&[
        sum,
        pseudo_sum(src, dst, 6, len),
    ]));
    tcp
}

// Verification may copy segmented bytes; this diagnostic path is not timed.
pub fn verify_transport(mbuf: &rpkt_dpdk::Mbuf) -> bool {
    use rpkt::{
        ether::EtherFrame,
        ipv4::{IpProtocol, Ipv4},
        Buf, Cursor,
    };
    let bytes: Vec<u8> = mbuf.seg_iter().flatten().copied().collect();
    let Ok(eth) = EtherFrame::parse(Cursor::new(&bytes)) else {
        return false;
    };
    let Ok(ip) = Ipv4::parse(eth.payload()) else {
        return false;
    };
    let (src, dst, protocol) = (ip.src_addr(), ip.dst_addr(), ip.protocol());
    let payload = ip.payload();
    let (len, protocol) = match protocol {
        IpProtocol::UDP => {
            let Ok(udp) = rpkt::udp::Udp::parse(payload) else {
                return false;
            };
            if udp.checksum() == 0 {
                return true;
            }
            (udp.packet_len() as usize, 17)
        }
        IpProtocol::TCP => (payload.remaining(), 6),
        _ => return false,
    };
    rpkt::checksum::combine(&[
        rpkt::checksum::from_slice(&payload.chunk()[..len]),
        pseudo_sum(src, dst, protocol, len),
    ]) == 0xffff
}

pub fn init_port(
    port: u16,
    rx: u16,
    tx: u16,
    rxd: u16,
    pool: &str,
    txd: u16,
    socket: u32,
) -> Result<()> {
    init_port_mtu(port, rx, tx, rxd, pool, txd, socket, 1500)
}

pub fn init_port_mtu(
    port: u16,
    rx: u16,
    tx: u16,
    rxd: u16,
    pool: &str,
    txd: u16,
    socket: u32,
    mtu: u32,
) -> Result<()> {
    let info = service().dev_info(port)?;
    assert_eq!(
        info.socket_id, socket,
        "select a memory pool on the NIC NUMA node"
    );
    let mut conf = EthConf::default();
    conf.mtu = mtu;
    conf.rx_offloads = (1 << 1) | (1 << 2) | (1 << 3);
    conf.tx_offloads = (1 << 1) | (1 << 2) | (1 << 3);
    if mtu > 1500 {
        conf.rx_offloads |= 1 << 13; // scatter
        conf.tx_offloads |= 1 << 15; // multi-segment packets
    }
    assert_eq!(
        info.rx_offload_capa() & conf.rx_offloads,
        conf.rx_offloads,
        "missing RX offload capability"
    );
    assert_eq!(
        info.tx_offload_capa() & conf.tx_offloads,
        conf.tx_offloads,
        "missing TX offload capability"
    );
    if rx > 1 {
        conf.rss_hf = info.flow_type_rss_offloads() & ((1 << 4) | (1 << 5) | (1 << 10) | (1 << 11));
        assert_ne!(conf.rss_hf, 0, "RSS is required for multiple RX queues");
        conf.rss_hash_key = match info.hash_key_size() {
            40 => constant::DEFAULT_RSS_KEY_40B.to_vec(),
            52 => constant::DEFAULT_RSS_KEY_52B.to_vec(),
            n => panic!("unsupported RSS key size: {n}"),
        };
    }
    service().dev_configure_and_start(
        port,
        &conf,
        &vec![RxqConf::new(rxd, socket, pool); rx as usize],
        &vec![TxqConf::new(txd, socket); tx as usize],
    )
}
