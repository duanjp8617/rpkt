//! Arp protocol.

enum_sim! {
    /// Hardware type of the arp protocol.
    pub struct Hardware (u16) {
        /// The contained hardware address is Ethernet address.
        ETHERNET = 1
    }
}

enum_sim! {
    /// Operation type of the arp protocol.
    pub struct Operation (u16) {
        /// Arp request.
        REQUEST = 1,
        /// Arp response.
        REPLY = 2
    }
}

mod generated;
pub use generated::{Arp, ARP_HEADER_LEN, ARP_HEADER_TEMPLATE};
