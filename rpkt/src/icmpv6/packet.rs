use byteorder::{ByteOrder, NetworkEndian};
use bytes::Buf;

use crate::ipv4::IpProtocol;
use crate::PktMut;
use crate::{Cursor, CursorMut};

#[derive(Debug)]
#[repr(transparent)]
pub struct Icmpv6Packet<T> {
    buf: T,
}

impl<T: Buf> Icmpv6Packet<T> {
    #[inline]
    pub fn parse_unchecked(buf: T) -> Self {
        Self { buf }
    }

    #[inline]
    pub fn buf(&self) -> &T {
        &self.buf
    }

    #[inline]
    pub fn release(self) -> T {
        self.buf
    }

    #[inline]
    pub fn msg_type(&self) -> u8 {
        self.buf.chunk()[0]
    }

    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = &self.buf.chunk()[2..4];
        NetworkEndian::read_u16(data)
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.buf.chunk()[4..]
    }

    #[inline]
    pub fn parse(buf: T) -> Result<Icmpv6Packet<T>, T> {
        if buf.chunk().len() >= 4 && buf.chunk().len() == buf.remaining() {
            Ok(Icmpv6Packet { buf })
        } else {
            Err(buf)
        }
    }
}

impl<T: PktMut> Icmpv6Packet<T> {
    #[inline]
    pub fn set_msg_type(&mut self, value: u8) {
        self.buf.chunk_mut()[0] = value;
    }

    #[inline]
    pub fn set_code(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }

    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = &mut self.buf.chunk_mut()[2..4];
        NetworkEndian::write_u16(data, value);
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf.chunk_mut()[4..]
    }
}
