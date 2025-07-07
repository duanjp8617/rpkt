//! Tcp protocol.

mod generated;
pub use generated::{Tcp, TCP_HEADER_LEN, TCP_HEADER_TEMPLATE};

/// Tcp options.
pub mod options {
    pub use super::generated::{EolOption, EOLOPTION_HEADER_LEN, EOLOPTION_HEADER_TEMPLATE};

    pub use super::generated::{NopOption, NOPOPTION_HEADER_LEN, NOPOPTION_HEADER_TEMPLATE};

    pub use super::generated::{MssOption, MSSOPTION_HEADER_LEN, MSSOPTION_HEADER_TEMPLATE};

    pub use super::generated::{WsoptOption, WSOPTOPTION_HEADER_LEN, WSOPTOPTION_HEADER_TEMPLATE};

    pub use super::generated::{
        SackpermOption, SACKPERMOPTION_HEADER_LEN, SACKPERMOPTION_HEADER_TEMPLATE,
    };

    pub use super::generated::{SackOption, SACKOPTION_HEADER_LEN, SACKOPTION_HEADER_TEMPLATE};

    pub use super::generated::{TsOption, TSOPTION_HEADER_LEN, TSOPTION_HEADER_TEMPLATE};

    pub use super::generated::{FoOption, FOOPTION_HEADER_LEN, FOOPTION_HEADER_TEMPLATE};

    pub use super::generated::{TcpOptions, TcpOptionsIter, TcpOptionsIterMut};
}
