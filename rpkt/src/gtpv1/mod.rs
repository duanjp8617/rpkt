mod generated;
pub use generated::{Gtpv1, GTPV1_HEADER_LEN, GTPV1_HEADER_TEMPLATE};

enum_sim! {
    /// An enum-like type for representing different protocols in IPv4/v6.
    pub struct GtpNextExtention (u8) {
        NO_EXTENTION = 0,
        LONG_PDU_NUMBER_T1 = 0x03,
        SERVICE_CLASS_INDICATOR = 0x20,
        UDP_PORT = 0x40,
        RAN_CONTAINER = 0x81,
        LONG_PDU_NUMBER_T2 = 0x82,
        XW_RAN_CONTAINER = 0x83,
        NR_RAN_CONTAINER = 0x84,
        PDU_SESSION_CONTAINER = 0x85,
        PDU_NUMBER = 0xC0,
    }
}

