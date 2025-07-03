use crate::cursors::*;
use crate::ether::EtherType;
use crate::traits::*;

mod generated;
pub use generated::{GREBASE_HEADER_LEN, GREBASE_HEADER_TEMPLATE};

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
        ((indicator_field & (1 << 15) != 0) | (indicator_field & (1 << 14) != 0)),
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