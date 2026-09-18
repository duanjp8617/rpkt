use rpkt::{checksum, ether::*, ipv4::*, template::UdpIpv4Flow, udp::*, Buf, CursorMut};

pub fn flow() -> UdpIpv4Flow {
    UdpIpv4Flow {
        src_mac: EtherAddr([2, 0, 0, 0, 0, 1]),
        dst_mac: EtherAddr([2, 0, 0, 0, 0, 2]),
        src_ip: Ipv4Addr::new(10, 0, 0, 1),
        dst_ip: Ipv4Addr::new(10, 0, 0, 2),
        src_port: 1234,
        dst_port: 4321,
        ttl: 64,
    }
}

pub fn ordinary(output: &mut [u8], payload: &[u8], ident: u16, flow: UdpIpv4Flow) {
    let size = 42 + payload.len();
    output[42..size].copy_from_slice(payload);
    let mut cursor = CursorMut::new(&mut output[..size]);
    cursor.advance(42);
    let mut udp = Udp::prepend_header(cursor, &UDP_HEADER_TEMPLATE);
    udp.set_src_port(flow.src_port);
    udp.set_dst_port(flow.dst_port);
    udp.set_checksum(0);
    let sum = checksum::combine(&[
        checksum::from_slice(&flow.src_ip.octets()),
        checksum::from_slice(&flow.dst_ip.octets()),
        17,
        udp.packet_len(),
        checksum::from_slice(udp.buf().chunk()),
    ]);
    udp.set_checksum(if sum == 0xffff { 0xffff } else { !sum });
    let mut ip = Ipv4::prepend_header(udp.release(), &IPV4_HEADER_TEMPLATE);
    ip.set_ident(ident);
    ip.set_flag_reserved(0);
    ip.set_ttl(flow.ttl);
    ip.set_src_addr(flow.src_ip);
    ip.set_dst_addr(flow.dst_ip);
    ip.set_protocol(IpProtocol::UDP);
    ip.set_checksum(0);
    ip.set_checksum(!checksum::from_slice(ip.fix_header_slice()));
    let mut eth = EtherFrame::prepend_header(ip.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_src_addr(flow.src_mac);
    eth.set_dst_addr(flow.dst_mac);
    eth.set_ethertype(EtherType::IPV4);
}
