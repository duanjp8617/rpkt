//! IPv4 protocol.

pub use core::net::Ipv4Addr;

enum_sim! {
    /// An enum-like type for representing different protocols in IPv4/v6.
    pub struct IpProtocol (u8) {
        /// IP packet payload is ICMP protocol.
        ICMP = 1,

        /// IP packet payload is TCP protocol.
        TCP = 6,

        /// IP packet payload is UDP protocol.
        UDP =  17,

        /// IP packet payload is Hop-by-hop extention number.
        HOPOPT = 0,

        /// IP packet payload is IPv6 Route.
        IPV6_ROUTE = 43,

        /// IP packet payload is IPv6 Fragmentation.
        IPV6_FRAG = 44,

        /// IP packet payload is ESP.
        ESP = 50,

        /// IP packet payload is AH.
        AH = 51,

        /// IP packet payload is IPv6 no extention.
        IPV6_NO_NXT = 59,

        /// IP packet payload is IPv6 OPTS.
        IPV6_OPTS = 60,
    }
}

mod generated;
pub use generated::{Ipv4Header, Ipv4Packet, IPV4_HEADER_LEN, IPV4_HEADER_TEMPLATE};

/// The Ipv4 options.
pub mod options {
    // The Ipv4 Eol option
    pub use super::generated::{EolMessage, EOL_HEADER_ARRAY};

    // The Ipv4 Nop option
    pub use super::generated::{NopMessage, NOP_HEADER_ARRAY};

    pub use super::generated::{TimestampMessage, TIMESTAMP_HEADER_ARRAY};

    pub use super::generated::{RecordRouteMessage, RECORDROUTE_HEADER_ARRAY};

    pub use super::generated::{RouteAlertMessage, ROUTEALERT_HEADER_ARRAY};

    pub use super::generated::Ipv4OptGroup;
}
