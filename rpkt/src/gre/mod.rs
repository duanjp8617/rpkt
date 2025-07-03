/// So gre protocol is some-what tricky, because some of the appearance of some gre
/// header field is determined by the value of other header bits.
/// Therefore, we want to use the following method

// From left to right, we have 16 bits:
// checksum (1)
// routing (1)
// key (1)
// sequence number (1)
// strict source route (1)
// recursion control (3)
// ack (1)
// flags (4)
// verison (3)
#[inline]
fn gre_fixed_header_len(indicator_field: u16) -> usize {
    let options = [
        // checksum
        indicator_field & (1 << 15) != 0,
        // key
        indicator_field & (1 << 13) != 0,
        // seq
        indicator_field & (1 << 12) != 0,
        // ack
        indicator_field & (1 << 7) != 0,
    ];

    4 + options.iter().fold(0, |mut aggre, item| {
        if *item {
            aggre += 4;
        }
        aggre
    })
}

#[inline]
fn pptp_gre_fixed_header_len(indicator_field: u16) -> usize {
    let options = [
        // seq
        indicator_field & (1 << 12) != 0,
        // ack
        indicator_field & (1 << 7) != 0,
    ];

    8 + options.iter().fold(0, |mut aggre, item| {
        if *item {
            aggre += 4;
        }
        aggre
    })
}
