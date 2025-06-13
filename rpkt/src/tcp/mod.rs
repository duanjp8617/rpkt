//! Tcp protocol.

mod generated;
pub use generated::{TcpPacket, TCP_HEADER_LEN, TCP_HEADER_TEMPLATE};

/// Tcp options.
pub mod options {
    pub use super::generated::{EolMessage, EOL_HEADER_LEN, EOL_HEADER_TEMPLATE};

    pub use super::generated::{NopMessage, NOP_HEADER_LEN, NOP_HEADER_TEMPLATE};

    pub use super::generated::{MssMessage, MSS_HEADER_LEN, MSS_HEADER_TEMPLATE};

    pub use super::generated::{WsoptMessage, WSOPT_HEADER_LEN, WSOPT_HEADER_TEMPLATE};

    pub use super::generated::{SackpermMessage, SACKPERM_HEADER_LEN, SACKPERM_HEADER_TEMPLATE};

    pub use super::generated::{SackMessage, SACK_HEADER_LEN, SACK_HEADER_TEMPLATE};

    pub use super::generated::{TsMessage, TS_HEADER_LEN, TS_HEADER_TEMPLATE};

    pub use super::generated::{FoMessage, FO_HEADER_LEN, FO_HEADER_TEMPLATE};

    pub use super::generated::TcpOptGroup;
}
