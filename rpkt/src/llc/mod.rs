mod generated;
pub use generated::{LlcPacket, LLC_HEADER_LEN, LLC_HEADER_TEMPLATE};

/// Currently, Llc protocol only supports BPDU type.
pub const BPDU_CONST: u8 = 0x42;
