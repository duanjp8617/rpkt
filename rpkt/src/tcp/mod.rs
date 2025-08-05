//! Tcp protocol.

mod generated;
pub use generated::{Tcp, TCP_HEADER_LEN, TCP_HEADER_TEMPLATE};

/// Tcp options.
pub mod options {
    pub use super::generated::{Eol, EOL_HEADER_LEN, EOL_HEADER_TEMPLATE};

    pub use super::generated::{Nop, NOP_HEADER_LEN, NOP_HEADER_TEMPLATE};

    pub use super::generated::{Mss, MSS_HEADER_LEN, MSS_HEADER_TEMPLATE};

    pub use super::generated::{
        WindowScale, WINDOW_SCALE_HEADER_LEN, WINDOW_SCALE_HEADER_TEMPLATE,
    };

    pub use super::generated::{
        SackPermitted, SACK_PERMITTED_HEADER_LEN, SACK_PERMITTED_HEADER_TEMPLATE,
    };

    pub use super::generated::{Sack, SACK_HEADER_LEN, SACK_HEADER_TEMPLATE};

    pub use super::generated::{Timestamp, TIMESTAMP_HEADER_LEN, TIMESTAMP_HEADER_TEMPLATE};

    pub use super::generated::{FastOpen, FAST_OPEN_HEADER_LEN, FAST_OPEN_HEADER_TEMPLATE};

    pub use super::generated::{TcpOptions, TcpOptionsIter, TcpOptionsIterMut};
}
