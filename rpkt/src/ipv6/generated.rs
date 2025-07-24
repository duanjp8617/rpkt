#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::endian::{read_uint_from_be_bytes, write_uint_as_be_bytes};
use crate::ipv4::IpProtocol;
use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

/// A constant that defines the fixed byte length of the Ipv6 protocol header.
pub const IPV6_HEADER_LEN: usize = 40;
/// A fixed Ipv6 header.
pub const IPV6_HEADER_TEMPLATE: [u8; 40] = [
    0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct Ipv6<T> {
    buf: T,
}
impl<T: Buf> Ipv6<T> {
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
    pub fn parse(buf: T) -> Result<Self, T> {
        let chunk_len = buf.chunk().len();
        if chunk_len < 40 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.payload_len() as usize) + 40 > container.buf.remaining() {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..40]
    }
    #[inline]
    pub fn version(&self) -> u8 {
        self.buf.chunk()[0] >> 4
    }
    #[inline]
    pub fn traffic_class(&self) -> u8 {
        ((u16::from_be_bytes((&self.buf.chunk()[0..2]).try_into().unwrap()) >> 4) & 0xff) as u8
    }
    #[inline]
    pub fn flow_label(&self) -> u32 {
        (read_uint_from_be_bytes(&self.buf.chunk()[1..4]) & 0xfffff) as u32
    }
    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        IpProtocol::from(self.buf.chunk()[6])
    }
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        self.buf.chunk()[7]
    }
    #[inline]
    pub fn src_addr(&self) -> &[u8] {
        &self.buf.chunk()[8..24]
    }
    #[inline]
    pub fn dst_addr(&self) -> &[u8] {
        &self.buf.chunk()[24..40]
    }
    #[inline]
    pub fn payload_len(&self) -> u16 {
        (u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap()))
    }
}
impl<T: PktBuf> Ipv6<T> {
    #[inline]
    pub fn payload(self) -> T {
        assert!(40 + self.payload_len() as usize <= self.buf.remaining());
        let trim_size = self.buf.remaining() - (40 + self.payload_len() as usize);
        let mut buf = self.buf;
        if trim_size > 0 {
            buf.trim_off(trim_size);
        }
        buf.advance(40);
        buf
    }
}
impl<T: PktBufMut> Ipv6<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 40]) -> Self {
        assert!(buf.chunk_headroom() >= 40);
        let payload_len = buf.remaining();
        assert!(payload_len <= 65535);
        buf.move_back(40);
        (&mut buf.chunk_mut()[0..40]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_payload_len(payload_len as u16);
        container
    }
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_traffic_class(&mut self, value: u8) {
        let write_value = ((value << 4) as u16)
            | (((self.buf.chunk_mut()[0] & 0xf0) as u16) << 8)
            | ((self.buf.chunk_mut()[1] & 0xf) as u16);
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_flow_label(&mut self, value: u32) {
        assert!(value <= 0xfffff);
        let write_value = (value as u64) | (((self.buf.chunk_mut()[1] & 0xf0) as u64) << 16);
        write_uint_as_be_bytes(&mut self.buf.chunk_mut()[1..4], write_value);
    }
    #[inline]
    pub fn set_next_header(&mut self, value: IpProtocol) {
        self.buf.chunk_mut()[6] = u8::from(value);
    }
    #[inline]
    pub fn set_hop_limit(&mut self, value: u8) {
        self.buf.chunk_mut()[7] = value;
    }
    #[inline]
    pub fn set_src_addr(&mut self, value: &[u8]) {
        (&mut self.buf.chunk_mut()[8..24]).copy_from_slice(value);
    }
    #[inline]
    pub fn set_dst_addr(&mut self, value: &[u8]) {
        (&mut self.buf.chunk_mut()[24..40]).copy_from_slice(value);
    }
    #[inline]
    pub fn set_payload_len(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&(value).to_be_bytes());
    }
}
impl<'a> Ipv6<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 40 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.payload_len() as usize) + 40 > remaining_len {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let payload_len = self.payload_len() as usize;
        Cursor::new(&self.buf.chunk()[40..(40 + payload_len)])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 40]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 40] {
        IPV6_HEADER_TEMPLATE.clone()
    }
}
impl<'a> Ipv6<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 40 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.payload_len() as usize) + 40 > remaining_len {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let payload_len = self.payload_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[40..(40 + payload_len)])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 40]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}
