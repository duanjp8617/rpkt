#[allow(dead_code)]
mod nat_support;
use nat_support::{input, pnet, reference, rpkt, rpkt_cursor, smoltcp, table, valid};

#[test]
fn misses_and_non_forwardable_packets_remain_unchanged() {
    for tcp in [false, true] {
        for options in [false, true] {
            let original = input(128, 0, tcp, options);
            let empty = table(0);
            for forward in [rpkt, rpkt_cursor, pnet, smoltcp] {
                let mut bytes = original.clone();
                assert!(!forward(&mut bytes, &empty));
                assert_eq!(bytes, original);
            }
            for (offset, value) in [(12, 0x86), (14, 0x65), (22, 0), (22, 1), (23, 1)] {
                let mut invalid = original.clone();
                invalid[offset] = value;
                for forward in [rpkt, rpkt_cursor, pnet, smoltcp] {
                    let mut bytes = invalid.clone();
                    assert!(!forward(&mut bytes, &table(1)));
                    assert_eq!(bytes, invalid);
                }
            }
        }
    }
}

#[test]
fn omitted_udp_checksum_with_ip_options_and_padding() {
    let mut original = input(128, 0, false, true);
    original[44..46].fill(0); // Ethernet 14 + IPv4 24 + UDP checksum offset 6.
    original.extend_from_slice(&[0xfe; 17]);
    let mut expected = original.clone();
    assert!(reference(&mut expected, &table(1)));
    assert!(valid(&expected));
    for forward in [rpkt, rpkt_cursor, pnet, smoltcp] {
        let mut bytes = original.clone();
        assert!(forward(&mut bytes, &table(1)));
        assert_eq!(bytes, expected);
        assert_eq!(&bytes[44..46], &[0, 0]);
        assert_eq!(&bytes[128..], &[0xfe; 17]);
    }
}
