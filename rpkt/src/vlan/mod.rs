mod generated;

pub use generated::{VlanPacket, VLAN_HEADER_LEN, VLAN_HEADER_TEMPLATE};

/// Check if the vlan tag is added to a Ethernet II frame.
pub fn vlan_tag_for_ether_frame<T: AsRef<[u8]>>(buf: T) -> bool {
    if buf.as_ref().len() >= 4 {
        // Ethertypes: These are 16-bit identifiers appearing as the initial
        // two octets after the MAC destination and source (or after a
        // tag) which, when considered as an unsigned integer, are equal
        // to or larger than 0x0600.
        //
        // From: https://tools.ietf.org/html/rfc5342#section-2.3.2.1
        // More: IEEE Std 802.3 Clause 3.2.6
        let value = u16::from_be_bytes((&buf.as_ref()[2..4]).try_into().unwrap());
        value >= 0x0600
    } else {
        false
    }
}

pub use generated::{VlanDot3Packet, VLANDOT3_HEADER_LEN, VLANDOT3_HEADER_TEMPLATE};

/// Check if the vlan tag is added to a IEEE 802.3 frame.
pub fn vlan_tag_for_dot3_frame<T: AsRef<[u8]>>(buf: T) -> bool {
    if buf.as_ref().len() >= 4 {
        // LSAPs: ... Such a length must, when considered as an
        // unsigned integer, be less than 0x5DC or it could be mistaken as
        // an Ethertype...
        //
        // From: https://tools.ietf.org/html/rfc5342#section-2.3.2.1
        // More: IEEE Std 802.3 Clause 3.2.6
        let value = u16::from_be_bytes((&buf.as_ref()[2..4]).try_into().unwrap());
        value <= 0x05DC
    } else {
        false
    }
}
