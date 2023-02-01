enum_sim! {
    pub struct Hardware (u16) {
        ETHERNET = 1
    }
}

enum_sim! {
    pub struct Operation (u16) {
        REQUEST = 1,
        REPLY = 2
    }
}

mod header;
pub use header::{ArpHeader, ARP_HEADER_LEN, ARP_HEADER_TEMPLATE};

mod packet;
pub use self::packet::ArpPacket;
