#[path = "support/properties.rs"]
mod properties;

#[test]
fn malformed_packets_and_roundtrips() {
    let mut state = 0x4d595df4d0f33173u64;
    let limit = if cfg!(miri) { 64 } else { 2048 };
    for len in 0..limit {
        let mut bytes = vec![0; len];
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        properties::exercise(&bytes);
        properties::roundtrip(&bytes, state as u16, (state >> 16) as u16);
        bytes.fill(0xff);
        properties::exercise(&bytes);
        bytes.fill(0);
        properties::exercise(&bytes);
    }
}
