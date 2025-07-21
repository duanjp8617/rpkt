//! Tcp protocol.

mod generated;
pub use generated::{Tcp, TCP_HEADER_LEN, TCP_HEADER_TEMPLATE};

/// Tcp options.
pub mod options {
    pub use super::generated::{EolOption, EOL_OPTION_HEADER_LEN, EOL_OPTION_HEADER_TEMPLATE};

    pub use super::generated::{NopOption, NOP_OPTION_HEADER_LEN, NOP_OPTION_HEADER_TEMPLATE};

    pub use super::generated::{MssOption, MSS_OPTION_HEADER_LEN, MSS_OPTION_HEADER_TEMPLATE};

    pub use super::generated::{
        WsoptOption, WSOPT_OPTION_HEADER_LEN, WSOPT_OPTION_HEADER_TEMPLATE,
    };

    pub use super::generated::{
        SackpermOption, SACKPERM_OPTION_HEADER_LEN, SACKPERM_OPTION_HEADER_TEMPLATE,
    };

    pub use super::generated::{SackOption, SACK_OPTION_HEADER_LEN, SACK_OPTION_HEADER_TEMPLATE};

    pub use super::generated::{TsOption, TS_OPTION_HEADER_LEN, TS_OPTION_HEADER_TEMPLATE};

    pub use super::generated::{FoOption, FO_OPTION_HEADER_LEN, FO_OPTION_HEADER_TEMPLATE};

    pub use super::generated::{TcpOptions, TcpOptionsIter, TcpOptionsIterMut};
}
