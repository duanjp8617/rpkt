enum_sim! {
    pub struct IcmpType (u8) {
        ECHO_REPLY = 0,
        DST_UNREACHABLE = 3,
        REDIRECT_MESSAGE = 5,
        ECHO_REQUEST = 8,
        ROUTER_ADVERTISEMENT = 9,
        ROUTER_SOLICITATION = 10,
        TIME_EXCEEDED = 11,
        PARAMETER_PROBLEM = 12,
        TIMESTAMP = 13,
        TIMESTAMP_REPLY = 14
    }
}

mod header;
pub use header::{Icmpv4Header, ICMPV4_HEADER_LEN, ICMPV4_HEADER_TEMPLATE};

mod packet;
pub use self::packet::Icmpv4Packet;