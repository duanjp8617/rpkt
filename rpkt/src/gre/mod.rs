mod generated;
pub use generated::GreGroup;
pub use generated::{Gre, GRE_HEADER_LEN, GRE_HEADER_TEMPLATE};
pub use generated::{GreForPPTP, GREFORPPTP_HEADER_LEN, GREFORPPTP_HEADER_TEMPLATE};
pub use generated::{PPTP, PPTP_HEADER_LEN, PPTP_HEADER_TEMPLATE};

#[inline]
fn gre_header_len(indicator_field: u16) -> usize {
    let options = [
        // checksum
        ((indicator_field & (1 << 15) != 0) | (indicator_field & (1 << 14) != 0)),
        // key
        indicator_field & (1 << 13) != 0,
        // seq
        indicator_field & (1 << 12) != 0,
    ];

    options.iter().fold(4, |mut aggre, item| {
        if *item {
            aggre += 4;
        }
        aggre
    })
}

#[inline]
fn gre_pptp_header_len(indicator_field: u16) -> usize {
    let options = [
        // seq
        indicator_field & (1 << 12) != 0,
        // ack
        indicator_field & (1 << 7) != 0,
    ];

    options.iter().fold(8, |mut aggre, item| {
        if *item {
            aggre += 4;
        }
        aggre
    })
}
