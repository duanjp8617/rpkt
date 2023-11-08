use byteorder::{ByteOrder, NetworkEndian};

use super::Ipv4Addr;
use super::Ipv4OptionType;

pub struct RouterAlert<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> RouterAlert<T> {
    #[inline]
    pub fn value(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[2..4])
    }
}

impl<T: AsMut<[u8]>> RouterAlert<T> {
    /// init_value: 0 - Router shall examine packet
    ///             1-65535 - Reserved
    pub fn new_from_mut(mut buf: T, init_value: u16) -> Result<Self, T> {
        if buf.as_mut().len() != 4 {
            Err(buf)
        } else {
            buf.as_mut()[0] = Ipv4OptionType::ROUTER_ALERT.into();
            buf.as_mut()[1] = 4;

            let mut option = RouterAlert { buf };
            option.set_value(init_value);

            Ok(option)
        }
    }

    #[inline]
    pub fn set_value(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[2..4], value);
    }
}

pub struct RouteIter<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for RouteIter<'a> {
    type Item = Ipv4Addr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.len() < 4 {
            None
        } else {
            let addr = Ipv4Addr::from_bytes(&self.bytes[..4]);
            self.bytes = &self.bytes[4..];
            Some(addr)
        }
    }
}

pub struct RouteRecord<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> RouteRecord<T> {
    #[inline]
    fn option_type(&self) -> Ipv4OptionType {
        self.buf.as_ref()[0].into()
    }

    #[inline]
    pub fn option_len(&self) -> u8 {
        self.buf.as_ref()[1]
    }

    #[inline]
    pub fn pointer(&self) -> u8 {
        self.buf.as_ref()[2]
    }

    #[inline]
    pub fn recorded_routes(&self) -> RouteIter {
        assert!(self.pointer() > 0);
        RouteIter {
            bytes: &self.buf.as_ref()[3..usize::from(self.pointer()) - 1],
        }
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> RouteRecord<T> {
    #[inline]
    pub fn append_route(&mut self, addr: Ipv4Addr) {
        assert!(self.pointer() > 0);
        let write_idx = usize::from(self.pointer() - 1);
        (&mut self.buf.as_mut()[write_idx..write_idx + 4]).copy_from_slice(addr.as_bytes());
        self.buf.as_mut()[2] += 4;
    }
}
