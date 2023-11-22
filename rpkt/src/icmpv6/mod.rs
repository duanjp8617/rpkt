enum_sim! {
    /// See https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    pub struct Icmpv6MsgType (u8) {
        // general icmp messages
        DST_UNREACHABLE = 1,
        PKT_TOO_BIG = 2,
        TIME_EXCEED =  3,
        PARAM_PROBLEM = 4,
        ECHO_REQUEST = 128,
        ECHO_REPLY =    129,
        // ndp messages
        NDP_ROUTER_SOLICIT = 133,
        NDP_ROUTER_ADV = 134,
        NDP_NEIGHBOR_SOLICIT = 135,
        NDP_NEIGHBOR_ADV = 136,
        NDP_REDIRECT = 137,
        // mld messages,
        MLDV2_LISTENER_QUERY = 130,
        MLDV2_LISTENER_REPORT = 143,
        MLDV1_LISTENER_REPORT = 131,
        MLDV1_LISTENER_DONE = 132,
    }
}

mod packet;
pub use packet::Icmpv6Packet;

mod mld;
mod msg;
mod ndp;
