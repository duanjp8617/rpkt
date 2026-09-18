use rpkt::checksum::*;

#[test]
fn rfc1624_zero_representations() {
    assert_eq!(replace_word(0xdd2f, 0x5555, 0x3285), 0);
    assert_eq!(replace_word(0, 0x3285, 0x5555), 0xdd2f);
    assert_eq!(replace_udp_ipv4_word(0xdd2f, 0x5555, 0x3285), 0xffff);
    assert_eq!(replace_udp_ipv4_word(0, 0x5555, 0x3285), 0);
}

#[test]
fn word_ttl_address_and_pseudo_header_updates_match_recomputation() {
    let mut state = 0x12345678u32;
    for _ in 0..10000 {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        // Header words other than the checksum field. Include nonzero words so
        // the negative-zero ambiguity of an all-zero message is excluded.
        let mut bytes = [
            0x45, 0, 0, 60, 0, 1, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        bytes[4..6].copy_from_slice(&(state as u16).to_be_bytes());
        let checksum = !from_slice(&bytes);
        let ttl_update = replace_word(checksum, 0x4011, 0x3f11);
        bytes[8] = 63;
        assert_eq!(ttl_update, !from_slice(&bytes));
        let address_update = replace_u32(ttl_update, 0x0a000001, state);
        bytes[12..16].copy_from_slice(&state.to_be_bytes());
        assert_eq!(address_update, !from_slice(&bytes));

        let mut pseudo_and_udp = vec![
            10, 0, 0, 1, 10, 0, 0, 2, 0, 17, 0, 9, 0, 1, 0, 2, 0, 9, 0, 0, 0x61,
        ];
        let original = !from_slice(&pseudo_and_udp);
        let updated = replace_u32(original, 0x0a000001, state);
        pseudo_and_udp[..4].copy_from_slice(&state.to_be_bytes());
        assert_eq!(updated, !from_slice(&pseudo_and_udp));
    }
}
