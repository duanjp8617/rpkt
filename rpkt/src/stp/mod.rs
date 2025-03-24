mod generated;

pub use generated::{StpTcnBpduMessage, STPTCNBPDU_HEADER_ARRAY};

pub use generated::{StpConfBpduMessage, STPCONFBPDU_HEADER_ARRAY};

pub use generated::{RstpConfBpduMessage, RSTPCONFBPDU_HEADER_ARRAY};

pub use generated::{MstpConfBpduMessage, MSTPCONFBPDU_HEADER_ARRAY};

pub use generated::{MstiConfMessage, MSTICONF_HEADER_ARRAY};

pub use generated::StpMessageGroup;

enum_sim! {
    /// An enum-like type for representing Stp version.
    pub struct StpVersion (u8) {
        /// The underlying buffer contains `StpConfBpduMessage`.
        STP = 0x00,

        /// The underlying buffer contains `StpTcnBpduMessage`.
        RSTP = 0x2,

        /// The underlying buffer contains `RstpConfBpduMessage` or `MstpConfBpduMessage`.
        MSTP =  0x3,
    }
}

enum_sim! {
    /// An enum-like type for representing Stp types.
    pub struct StpType (u8) {
        /// The underlying buffer contains `StpConfBpduMessage`.
        STP_CONF = 0x00,

        /// The underlying buffer contains `StpTcnBpduMessage`.
        STP_TCN = 0x80,

        /// The underlying buffer contains `RstpConfBpduMessage` or `MstpConfBpduMessage`.
        RSTP_OR_MSTP =  0x02,
    }
}
