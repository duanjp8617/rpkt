mod generated;
pub use generated::PppoeGroup;
pub use generated::{PppoeDiscovery, PPPOE_DISCOVERY_HEADER_LEN, PPPOE_DISCOVERY_HEADER_TEMPLATE};
pub use generated::{PppoeSession, PPPOE_SESSION_HEADER_LEN, PPPOE_SESSION_HEADER_TEMPLATE};
pub use generated::{
    PppoeTag, PppoeTagIter, PppoeTagIterMut, PPPOE_TAG_HEADER_LEN, PPPOE_TAG_HEADER_TEMPLATE,
};

enum_sim! {
    /// An enum-like type for representing the PPPoE code.
    pub struct PppoeCode (u8) {
        /// PPPoE seession code.
        SESSION = 0x00,
        /// PPPoE discovery PADO
        PADO = 0x07,
        /// PPPoE discovery PADI
        PADI = 0x09,
        /// PPPoE discovery PADG
        PADG = 0x0a,
        /// PPPoE discovery PADC
        PADC = 0x0b,
        /// PPPoE discovery PADQ
        PADQ = 0x0c,
        /// PPPoE discovery PADR
        PADR = 0x19,
        /// PPPoE discovery PADS
        PADS = 0x65,
        /// PPPoE discovery PADT
        PADT = 0xa7,
        /// PPPoE discovery PADM
        PADM = 0xd3,
        /// PPPoE discovery PADN
        PADN = 0xd4
    }
}

enum_sim! {
    /// An enum-like type for representing the tag field of the PPPoE discovery packet.
    pub struct PppoeTagType(u16) {
        /// End-Of-List tag type
        EOL = 0x0000,
        /// Service-Name tag type
        SVC_NAME = 0x0101,
        /// AC-Name tag type
        AC_NAME = 0x0102,
        /// Host-Uniq tag type
        HOST_UNIQ = 0x0103,
        /// AC-Cookie tag type
        AC_COOKIE = 0x0104,
        /// Vendor-Specific tag type
        VENDOR = 0x0105,
        /// Credits tag type
        CREDITS = 0x0106,
        /// Metrics tag type
        METRICS = 0x0107,
        /// Sequence Number tag type
        SEQ_NUM = 0x0108,
        /// Credit Scale Factor tag type
        CRED_SCALE = 0x0109,
        /// Relay-Session-Id tag type
        RELAY_ID = 0x0110,
        /// HURL tag type
        HURL = 0x0111,
        /// MOTM tag type
        MOTM = 0x0112,
        /// PPP-Max-Payload tag type
        MAX_PAYLD = 0x0120,
        /// IP_Route_Add tag type
        IP_RT_ADD = 0x0121,
        /// Service-Name-Error tag type
        SVC_ERR = 0x0201,
        /// AC-System-Error tag type
        AC_ERR = 0x0202,
        /// Generic-Error tag type
        GENERIC_ERR = 0x0203
    }
}
