#![allow(missing_docs)]

use crate::cursors::{CursorIndex, CursorIndexMut};
use crate::ether::{EtherAddr, EtherType};
use crate::ipv4::Ipv4Addr;
use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

use super::{Hardware, Operation};

/// A constant that defines the fixed byte length of the Arp protocol header.
pub const ARP_HEADER_LEN: usize = 28;
/// A fixed Arp header.
pub const ARP_HEADER_TEMPLATE: [u8; 28] = [
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct Arp<T> {
    buf: T,
}
impl<T: Buf> Arp<T> {
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
        if chunk_len < 28 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..28]
    }
    #[inline]
    pub fn hardware_type(&self) -> Hardware {
        Hardware::from(u16::from_be_bytes(
            (&self.buf.chunk()[0..2]).try_into().unwrap(),
        ))
    }
    #[inline]
    pub fn protocol_type(&self) -> EtherType {
        EtherType::from(u16::from_be_bytes(
            (&self.buf.chunk()[2..4]).try_into().unwrap(),
        ))
    }
    #[inline]
    pub fn hardware_addr_len(&self) -> u8 {
        self.buf.chunk()[4]
    }
    #[inline]
    pub fn protocol_addr_len(&self) -> u8 {
        self.buf.chunk()[5]
    }
    #[inline]
    pub fn operation(&self) -> Operation {
        Operation::from(u16::from_be_bytes(
            (&self.buf.chunk()[6..8]).try_into().unwrap(),
        ))
    }
    #[inline]
    pub fn sender_ether_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.chunk()[8..14])
    }
    #[inline]
    pub fn sender_ipv4_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be_bytes(
            (&self.buf.chunk()[14..18]).try_into().unwrap(),
        ))
    }
    #[inline]
    pub fn target_ether_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.chunk()[18..24])
    }
    #[inline]
    pub fn target_ipv4_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be_bytes(
            (&self.buf.chunk()[24..28]).try_into().unwrap(),
        ))
    }
}
impl<T: PktBuf> Arp<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(28);
        buf
    }
}
impl<T: PktBufMut> Arp<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 28]) -> Self {
        assert!(buf.chunk_headroom() >= 28);
        buf.move_back(28);
        (&mut buf.chunk_mut()[0..28]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_hardware_type(&mut self, value: Hardware) {
        let value = u16::from(value);
        assert!(value == 1);
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_protocol_type(&mut self, value: EtherType) {
        let value = u16::from(value);
        assert!(value == 2048);
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_hardware_addr_len(&mut self, value: u8) {
        assert!(value == 6);
        self.buf.chunk_mut()[4] = value;
    }
    #[inline]
    pub fn set_protocol_addr_len(&mut self, value: u8) {
        assert!(value == 4);
        self.buf.chunk_mut()[5] = value;
    }
    #[inline]
    pub fn set_operation(&mut self, value: Operation) {
        (&mut self.buf.chunk_mut()[6..8]).copy_from_slice(&u16::from(value).to_be_bytes());
    }
    #[inline]
    pub fn set_sender_ether_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.chunk_mut()[8..14]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_sender_ipv4_addr(&mut self, value: Ipv4Addr) {
        (&mut self.buf.chunk_mut()[14..18]).copy_from_slice(&u32::from(value).to_be_bytes());
    }
    #[inline]
    pub fn set_target_ether_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.chunk_mut()[18..24]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_target_ipv4_addr(&mut self, value: Ipv4Addr) {
        (&mut self.buf.chunk_mut()[24..28]).copy_from_slice(&u32::from(value).to_be_bytes());
    }
}
impl<'a> Arp<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 28 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        self.buf.index_(28..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 28]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 28] {
        ARP_HEADER_TEMPLATE.clone()
    }
}
impl<'a> Arp<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 28 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        self.buf.index_mut_(28..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 28]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}
