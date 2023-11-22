use std::fmt;

use byteorder::{ByteOrder, NetworkEndian};

use crate::ipv4::Ipv4Addr;

// A full implementation of IPv6 includes implementation of the
//    following extension headers:

//       Hop-by-Hop Options
//       Fragment
//       Destination Options
//       Routing
//       Authentication
//       Encapsulating Security Payload

//    The first four are specified in this document (RFC8200); the last two are
//    specified in [RFC4302] and [RFC4303], respectively.  The current list
//    of IPv6 extension headers can be found at [IANA-EH].

/// A sixteen-octet IPv6 address.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Ipv6Addr(pub [u8; 16]);

impl Ipv6Addr {
    pub const UNSPECIFIED: Ipv6Addr = Ipv6Addr([0x00; 16]);

    pub const LINK_LOCAL_ALL_NODES: Ipv6Addr = Ipv6Addr([
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);

    pub const LINK_LOCAL_ALL_ROUTERS: Ipv6Addr = Ipv6Addr([
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ]);

    pub const LOOPBACK: Ipv6Addr = Ipv6Addr([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);

    const IPV4_MAPPED_PREFIX: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0];

    pub const fn new(
        a0: u16,
        a1: u16,
        a2: u16,
        a3: u16,
        a4: u16,
        a5: u16,
        a6: u16,
        a7: u16,
    ) -> Ipv6Addr {
        Ipv6Addr([
            (a0 >> 8) as u8,
            a0 as u8,
            (a1 >> 8) as u8,
            a1 as u8,
            (a2 >> 8) as u8,
            a2 as u8,
            (a3 >> 8) as u8,
            a3 as u8,
            (a4 >> 8) as u8,
            a4 as u8,
            (a5 >> 8) as u8,
            a5 as u8,
            (a6 >> 8) as u8,
            a6 as u8,
            (a7 >> 8) as u8,
            a7 as u8,
        ])
    }

    pub fn from_bytes(data: &[u8]) -> Ipv6Addr {
        let mut bytes = [0; 16];
        bytes.copy_from_slice(data);
        Ipv6Addr(bytes)
    }

    pub fn from_parts(data: &[u16]) -> Ipv6Addr {
        assert!(data.len() >= 8);
        let mut bytes = [0; 16];
        for (word_idx, chunk) in bytes.chunks_mut(2).enumerate() {
            NetworkEndian::write_u16(chunk, data[word_idx]);
        }
        Ipv6Addr(bytes)
    }

    pub fn write_parts(&self, data: &mut [u16]) {
        assert!(data.len() >= 8);
        for (i, chunk) in self.0.chunks(2).enumerate() {
            data[i] = NetworkEndian::read_u16(chunk);
        }
    }

    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_unicast(&self) -> bool {
        !(self.is_multicast() || self.is_unspecified())
    }

    pub const fn is_multicast(&self) -> bool {
        self.0[0] == 0xff
    }

    pub fn is_unspecified(&self) -> bool {
        *self == Self::UNSPECIFIED
    }

    pub fn is_link_local(&self) -> bool {
        self.0[0..8] == [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    }

    pub fn is_loopback(&self) -> bool {
        *self == Self::LOOPBACK
    }

    pub fn is_ipv4_mapped(&self) -> bool {
        self.0[..12] == Self::IPV4_MAPPED_PREFIX[..12]
    }

    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        if self.is_ipv4_mapped() {
            Some(Ipv4Addr::from_bytes(&self.0[12..]))
        } else {
            None
        }
    }

    pub fn solicited_node(&self) -> Ipv6Addr {
        assert!(self.is_unicast());
        Ipv6Addr([
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF,
            self.0[13], self.0[14], self.0[15],
        ])
    }
}

impl From<::std::net::Ipv6Addr> for Ipv6Addr {
    fn from(x: ::std::net::Ipv6Addr) -> Ipv6Addr {
        Ipv6Addr(x.octets())
    }
}

impl From<Ipv6Addr> for ::std::net::Ipv6Addr {
    fn from(x: Ipv6Addr) -> ::std::net::Ipv6Addr {
        x.into()
    }
}

impl From<Ipv4Addr> for Ipv6Addr {
    fn from(x: Ipv4Addr) -> Ipv6Addr {
        let mut bytes = Self::IPV4_MAPPED_PREFIX;
        (&mut bytes[12..16]).copy_from_slice(x.as_bytes());
        Ipv6Addr(bytes)
    }
}

impl fmt::Display for Ipv6Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_ipv4_mapped() {
            return write!(
                f,
                "::ffff:{}.{}.{}.{}",
                self.0[12 + 0],
                self.0[12 + 1],
                self.0[12 + 2],
                self.0[12 + 3]
            );
        }

        // See https://tools.ietf.org/html/rfc4291#section-2.2
        enum State {
            Head,
            HeadBody,
            Tail,
            TailBody,
        }
        let mut words = [0u16; 8];
        self.write_parts(&mut words);
        let mut state = State::Head;
        for word in words.iter() {
            state = match (*word, &state) {
                // Once a u16 equal to zero write a double colon and
                // skip to the next non-zero u16.
                (0, &State::Head) | (0, &State::HeadBody) => {
                    write!(f, "::")?;
                    State::Tail
                }
                // Continue iterating without writing any characters until
                // we hit a non-zero value.
                (0, &State::Tail) => State::Tail,
                // When the state is Head or Tail write a u16 in hexadecimal
                // without the leading colon if the value is not 0.
                (_, &State::Head) => {
                    write!(f, "{word:x}")?;
                    State::HeadBody
                }
                (_, &State::Tail) => {
                    write!(f, "{word:x}")?;
                    State::TailBody
                }
                // Write the u16 with a leading colon when parsing a value
                // that isn't the first in a section
                (_, &State::HeadBody) | (_, &State::TailBody) => {
                    write!(f, ":{word:x}")?;
                    state
                }
            }
        }
        Ok(())
    }
}

mod header;
pub use header::{Ipv6Header, IPV6_HEADER_LEN};

mod packet;
pub use packet::Ipv6Packet;

pub mod extentions;
