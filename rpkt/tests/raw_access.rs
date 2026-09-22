//! Small enough for Miri: lengths, unaligned storage, mutation and cloning.
use rpkt::{ether::EtherFrame, ipv4::Ipv4, tcp::Tcp, udp::Udp, Buf, Cursor, CursorMut};

#[test]
fn parse_checks_every_short_header_before_unchecked_fields() {
    for n in 0..60 {
        let bytes = vec![0; n];
        assert_eq!(EtherFrame::parse(Cursor::new(&bytes)).is_ok(), n >= 14);
        assert!(Ipv4::parse(Cursor::new(&bytes)).is_err());
        assert!(Tcp::parse(Cursor::new(&bytes)).is_err());
        assert!(Udp::parse(Cursor::new(&bytes)).is_err());
    }
}

#[test]
fn slice_fields_are_unaligned_and_preserve_neighbors() {
    for offset in 0..8 {
        let mut storage = [0xa5; 40];
        storage[offset..offset + 20].copy_from_slice(&Ipv4::default_header());
        let mut ip =
            Ipv4::parse_from_cursor_mut(CursorMut::new(&mut storage[offset..offset + 20])).unwrap();
        ip.set_src_addr_and_dst_addr([1, 2, 3, 4].into(), [5, 6, 7, 8].into());
        ip.set_dscp(37);
        ip.set_ecn(2);
        ip.set_more_frag(true);
        ip.set_frag_offset(8191);
        ip.set_more_frag(false);
        assert_eq!(ip.src_addr_and_dst_addr_bits(), 0x0102030405060708);
        assert_eq!((ip.dscp(), ip.ecn()), (37, 2));
        assert_eq!(ip.frag_offset(), 8191);
        assert!(!ip.more_frag());
        assert_eq!(ip.header_len(), 20);
        assert_eq!(ip.release().chunk().len(), 20);
        assert!(storage[..offset].iter().all(|&b| b == 0xa5));
        assert!(storage[offset + 20..].iter().all(|&b| b == 0xa5));
    }
}

#[test]
fn owned_clone_and_checked_parts_retain_the_validated_header() {
    let bytes = bytes::Bytes::copy_from_slice(&Ipv4::default_header());
    let ip = Ipv4::parse(bytes).unwrap();
    let cloned = ip.clone();
    drop(ip);
    assert_eq!(cloned.header_len(), 20);
    let mut bytes = Ipv4::default_header();
    let (mut fields, options, payload) = Ipv4::parse_parts_mut(&mut bytes).unwrap();
    fields.set_ttl(17);
    assert_eq!(fields.ttl(), 17);
    assert!(options.is_empty() && payload.is_empty());
    assert_eq!(fields.into_inner().chunk().len(), 20);
}

#[test]
#[should_panic]
fn checked_field_constructor_rejects_short_slices() {
    rpkt::ipv4::Ipv4Fields::from_header(Cursor::new(&[0; 19]));
}
