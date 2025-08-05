mod generated;
pub use generated::{Ipv6, IPV6_HEADER_LEN, IPV6_HEADER_TEMPLATE};

/// The Ipv6 extentions.
pub mod extentions {
    pub use super::generated::{
        AuthenticationHeader, AUTHENTICATION_HEADER_HEADER_LEN,
        AUTHENTICATION_HEADER_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        DestOptions, DEST_OPTIONS_HEADER_LEN, DEST_OPTIONS_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        FragmentHeader, FRAGMENT_HEADER_HEADER_LEN, FRAGMENT_HEADER_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        HopByHopOption, HOP_BY_HOP_OPTION_HEADER_LEN, HOP_BY_HOP_OPTION_HEADER_TEMPLATE,
    };
    pub use super::generated::{
        RoutingHeader, ROUTING_HEADER_HEADER_LEN, ROUTING_HEADER_HEADER_TEMPLATE,
    };
}

/// The ipv6 options for certain extentions.
pub mod options {
    pub use super::generated::{Generic, GENERIC_HEADER_LEN, GENERIC_HEADER_TEMPLATE};
    pub use super::generated::{Ipv6Options, Ipv6OptionsIter, Ipv6OptionsIterMut};
    pub use super::generated::{Pad0, PAD0_HEADER_LEN, PAD0_HEADER_TEMPLATE};
    pub use super::generated::{Padn, PADN_HEADER_LEN, PADN_HEADER_TEMPLATE};
    pub use super::generated::{
        RouterAlert, ROUTER_ALERT_HEADER_LEN, ROUTER_ALERT_HEADER_TEMPLATE,
    };
}
