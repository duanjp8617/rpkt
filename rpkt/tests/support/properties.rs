use rpkt::{
    checksum, ether::*, ipv4::*, tcp::*, udp::*, Buf, Cursor, CursorMut, PktBuf, PktBufMut,
};
use rpkt::{ipv4::options::Ipv4OptionsIter, tcp::options::TcpOptionsIter};

// Shared by deterministic property tests and the coverage-guided fuzz target.
pub fn exercise(data: &[u8]) {
    macro_rules! check {
        ($packet:path) => {
            if let Ok(packet) = <$packet>::parse(Cursor::new(data)) {
                assert!(packet.fix_header_slice().len() <= data.len());
            }
        };
    }
    check!(EtherFrame<_>);
    check!(Ipv4<_>);
    check!(rpkt::ipv6::Ipv6<_>);
    check!(Tcp<_>);
    check!(Udp<_>);
    check!(rpkt::vlan::VlanFrame<_>);
    // Parts parsers must accept exactly the same structural lengths as their
    // cursor counterparts.
    macro_rules! parts {
        ($packet:ident) => {{
            let expected = $packet::parse_from_cursor(Cursor::new(data)).is_ok();
            assert_eq!($packet::parse_parts(data).is_ok(), expected);
            let mut storage = data.to_vec();
            assert_eq!($packet::parse_parts_mut(&mut storage).is_ok(), expected);
            assert_eq!(storage, data);
        }};
    }
    parts!(EtherFrame);
    parts!(Ipv4);
    parts!(Tcp);
    parts!(Udp);
    if let Ok(ip) = Ipv4::parse(Cursor::new(data)) {
        let expected = ip.packet_len() as usize - ip.header_len() as usize;
        assert_eq!(ip.payload().remaining(), expected);
    }
    if let Ok(udp) = Udp::parse(Cursor::new(data)) {
        let expected = udp.packet_len() as usize - UDP_HEADER_LEN;
        assert_eq!(udp.payload().remaining(), expected);
    }
    let mut options = TcpOptionsIter::from_slice(data);
    let mut previous = data.len();
    while options.next().is_some() {
        assert!(options.buf().len() < previous);
        previous = options.buf().len();
    }
    let mut options = Ipv4OptionsIter::from_slice(data);
    let mut previous = data.len();
    while options.next().is_some() {
        assert!(options.buf().len() < previous);
        previous = options.buf().len();
    }
    // Odd segment boundaries must not introduce padding into the checksum.
    for split in [0, data.len() / 2, data.len().min(1), data.len()] {
        let chain = (&data[..split]).chain(&data[split..]);
        assert_eq!(
            checksum::from_buf(chain, data.len()),
            checksum::from_slice(data)
        );
    }
    // Moving and trimming a mutable cursor preserves its bounds and contents.
    let mut storage = data.to_vec();
    let mut cursor = CursorMut::new(&mut storage);
    let offset = data.len() / 2;
    cursor.advance(offset);
    assert_eq!(cursor.chunk(), &data[offset..]);
    cursor.move_back(offset);
    cursor.trim_off(offset);
    assert_eq!(cursor.chunk_mut(), &data[..data.len() - offset]);
}

pub fn roundtrip(payload: &[u8], src: u16, dst: u16) {
    if payload.len() > 65507 {
        return;
    }
    let mut bytes = vec![0; 42 + payload.len()];
    bytes[42..].copy_from_slice(payload);
    let mut cursor = CursorMut::new(&mut bytes);
    cursor.advance(42);
    let mut udp = Udp::prepend_header(cursor, &UDP_HEADER_TEMPLATE);
    udp.set_src_port(src);
    udp.set_dst_port(dst);
    let mut ip = Ipv4::prepend_header(udp.release(), &IPV4_HEADER_TEMPLATE);
    ip.set_protocol(IpProtocol::UDP);
    let mut eth = EtherFrame::prepend_header(ip.release(), &ETHER_FRAME_HEADER_TEMPLATE);
    eth.set_ethertype(EtherType::IPV4);
    let eth = EtherFrame::parse(Cursor::new(&bytes)).unwrap();
    let ip = Ipv4::parse(eth.payload()).unwrap();
    let udp = Udp::parse(ip.payload()).unwrap();
    assert_eq!((udp.src_port(), udp.dst_port()), (src, dst));
    assert_eq!(udp.payload().chunk(), payload);
    // Every truncation before the declared packet end must fail at some layer.
    for end in [0, 13, 14, 33, 34, 41, bytes.len() - 1] {
        let parsed = EtherFrame::parse(Cursor::new(&bytes[..end]))
            .and_then(|eth| Ipv4::parse(eth.payload()))
            .and_then(|ip| Udp::parse(ip.payload()));
        assert!(parsed.is_err());
    }
}
