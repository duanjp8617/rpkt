//! Tcp protocol.

mod generated;
pub use generated::{TcpPacket, TCP_HEADER_LEN, TCP_HEADER_TEMPLATE};

/// Tcp options.
pub mod options {
    pub use super::generated::{EolMessage, EOL_HEADER_ARRAY};

    pub use super::generated::{NopMessage, NOP_HEADER_ARRAY};

    pub use super::generated::{MssMessage, MSS_HEADER_ARRAY};

    pub use super::generated::{WsoptMessage, WSOPT_HEADER_ARRAY};

    pub use super::generated::{SackpermMessage, SACKPERM_HEADER_ARRAY};

    pub use super::generated::{SackMessage, SACK_HEADER_ARRAY};

    pub use super::generated::{TsMessage, TS_HEADER_ARRAY};

    pub use super::generated::{FoMessage, FO_HEADER_ARRAY};

    pub use super::generated::TcpOptGroup;
}
