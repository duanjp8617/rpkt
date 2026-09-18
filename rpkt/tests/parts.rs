use rpkt::{
    ether::EtherFrame,
    ipv4::{Ipv4, Ipv4Addr},
    tcp::Tcp,
    udp::Udp,
    Cursor,
};

#[test]
fn disjoint_views_preserve_options_padding_and_endianness() {
    let mut bytes = [0xa5; 100];
    bytes[0] = 0x46;
    bytes[2..4].copy_from_slice(&64u16.to_be_bytes());
    let (mut fields, options, payload) = Ipv4::parse_parts_mut(&mut bytes).unwrap();
    assert_eq!((options.len(), payload.len()), (4, 40));
    fields.set_src_addr(Ipv4Addr::new(1, 128, 254, 255));
    fields.set_dst_addr(Ipv4Addr::new(255, 254, 128, 1));
    fields.set_ttl(17);
    // All three disjoint mutable borrows remain alive simultaneously.
    options.fill(0x11);
    payload.fill(0x22);
    assert_eq!(fields.src_addr().octets(), [1, 128, 254, 255]);
    assert_eq!(fields.dst_addr().octets(), [255, 254, 128, 1]);
    assert_eq!(&bytes[12..20], &[1, 128, 254, 255, 255, 254, 128, 1]);
    assert_eq!(&bytes[20..24], &[0x11; 4]);
    assert_eq!(&bytes[24..64], &[0x22; 40]);
    assert_eq!(&bytes[64..], &[0xa5; 36]);
    let (fields, options, payload) = Ipv4::parse_parts(&bytes).unwrap();
    assert_eq!(fields.header_len(), 24);
    assert_eq!(fields.packet_len(), 64);
    assert_eq!(fields.ttl(), 17);
    assert_eq!(options.len(), 4);
    assert_eq!(payload.len(), 40);
}

#[test]
fn parts_match_checked_parsers_at_all_length_boundaries() {
    for len in [
        0, 1, 7, 8, 13, 14, 19, 20, 21, 23, 24, 39, 40, 59, 60, 63, 64, 65, 100,
    ] {
        for ihl in 0..16 {
            for total in [
                0u16, 1, 7, 8, 19, 20, 21, 23, 24, 59, 60, 63, 64, 65, 100, 101, 65535,
            ] {
                let mut bytes = [0; 100];
                bytes[0] = 0x40 | ihl;
                bytes[2..4].copy_from_slice(&total.to_be_bytes());
                let ok = Ipv4::parse_from_cursor(Cursor::new(&bytes[..len])).is_ok();
                assert_eq!(Ipv4::parse_parts(&bytes[..len]).is_ok(), ok);
                let old = bytes;
                let result = Ipv4::parse_parts_mut(&mut bytes[..len]);
                assert_eq!(result.is_ok(), ok);
                if let Ok((fields, options, payload)) = result {
                    assert_eq!(options.len(), ihl as usize * 4 - 20);
                    assert_eq!(payload.len(), total as usize - ihl as usize * 4);
                    assert_eq!(fields.packet_len(), total);
                }
                assert_eq!(bytes, old);
            }
        }
    }
    for len in 0..80 {
        let mut bytes = [0; 80];
        assert_eq!(EtherFrame::parse_parts(&bytes[..len]).is_ok(), len >= 14);
        for header in 0..16 {
            bytes[12] = header << 4;
            let ok = Tcp::parse_from_cursor(Cursor::new(&bytes[..len])).is_ok();
            assert_eq!(Tcp::parse_parts(&bytes[..len]).is_ok(), ok);
            assert_eq!(Tcp::parse_parts_mut(&mut bytes[..len]).is_ok(), ok);
        }
        for total in [0u16, 1, 7, 8, 9, 79, 80, 81, 65535] {
            bytes[4..6].copy_from_slice(&total.to_be_bytes());
            let ok = Udp::parse_from_cursor(Cursor::new(&bytes[..len])).is_ok();
            assert_eq!(Udp::parse_parts(&bytes[..len]).is_ok(), ok);
            assert_eq!(Udp::parse_parts_mut(&mut bytes[..len]).is_ok(), ok);
        }
    }
}

#[test]
fn fields_preserve_neighboring_bits() {
    let mut bytes = rpkt::tcp::TCP_HEADER_TEMPLATE;
    bytes[12] = 0x5b;
    bytes[13] = 0xa5;
    let (mut p, options, payload) = Tcp::parse_parts_mut(&mut bytes).unwrap();
    p.set_syn(true);
    p.set_ack(false);
    p.set_src_port(0xabcd);
    p.set_dst_port(0x0123);
    assert_eq!(p.header_len(), 20);
    assert_eq!(p.reserved(), 11);
    assert!(p.syn());
    assert!(!p.ack());
    assert!(p.cwr());
    assert!(p.urg());
    assert!(options.is_empty());
    assert!(payload.is_empty());
    assert_eq!(&bytes[..4], &[0xab, 0xcd, 1, 0x23]);
    assert_eq!(bytes[13], 0xa7);
}

#[test]
fn paired_stores_match_independent_setters() {
    for a in [0, 1, 255, 256, 32767, 32768, 65535] {
        for b in [0, 1, 255, 256, 32767, 32768, 65535] {
            let mut one = rpkt::udp::UDP_HEADER_TEMPLATE;
            let mut two = one;
            let (mut p, _, _) = Udp::parse_parts_mut(&mut one).unwrap();
            p.set_src_port_and_dst_port(a, b);
            assert_eq!(
                p.src_port_and_dst_port_bits(),
                (u32::from(a) << 16) | u32::from(b)
            );
            let mut p = Udp::from_header_array_mut(&mut two);
            p.set_src_port(a);
            p.set_dst_port(b);
            assert_eq!(one, two);
        }
    }
    for bits in [0, 1, 0x1fff, 0x2000, 0x4000, 0x6000, 0x8000, 0xffffu16] {
        let mut header = rpkt::ipv4::IPV4_HEADER_TEMPLATE;
        header[6..8].copy_from_slice(&bits.to_be_bytes());
        let (p, _, _) = Ipv4::parse_parts(&header).unwrap();
        assert_eq!(p.more_frag(), bits & 0x2000 != 0);
        assert_eq!(p.dont_frag(), bits & 0x4000 != 0);
        assert_eq!(p.frag_offset(), bits & 0x1fff);
    }
}
