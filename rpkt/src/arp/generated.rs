#![allow(missing_docs)]

use byteorder::{ByteOrder, NetworkEndian};

use crate::ether::{EtherAddr, EtherType};
use crate::ipv4::Ipv4Addr;
use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

use super::{Hardware, Operation};

/// A constant that defines the fixed byte length of the Arp protocol header.
pub const ARP_HEADER_LEN: usize = 28;
/// A fixed Arp header.
pub const ARP_HEADER_TEMPLATE: ArpHeader<[u8; 28]> = ArpHeader {
    buf: [
        0x00, 0x01, 0x08, 0x06, 0x06, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ],
};

#[derive(Debug, Clone, Copy)]
pub struct ArpHeader<T> {
    buf: T,
}
impl<T: AsRef<[u8]>> ArpHeader<T> {
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
        let remaining_len = buf.as_ref().len();
        if remaining_len < 28 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.as_ref()[0..28]
    }
    #[inline]
    pub fn hardware_type(&self) -> Hardware {
        Hardware::from(NetworkEndian::read_u16(&self.buf.as_ref()[0..2]))
    }
    #[inline]
    pub fn protocol_type(&self) -> EtherType {
        EtherType::from(NetworkEndian::read_u16(&self.buf.as_ref()[2..4]))
    }
    #[inline]
    pub fn hardware_addr_len(&self) -> u8 {
        self.buf.as_ref()[4]
    }
    #[inline]
    pub fn protocol_addr_len(&self) -> u8 {
        self.buf.as_ref()[5]
    }
    #[inline]
    pub fn operation(&self) -> Operation {
        Operation::from(NetworkEndian::read_u16(&self.buf.as_ref()[6..8]))
    }
    #[inline]
    pub fn sender_hardware_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.as_ref()[8..14])
    }
    #[inline]
    pub fn sender_protocol_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(NetworkEndian::read_u32(&self.buf.as_ref()[14..18]))
    }
    #[inline]
    pub fn target_hardware_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.as_ref()[18..24])
    }
    #[inline]
    pub fn target_protocol_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(NetworkEndian::read_u32(&self.buf.as_ref()[24..28]))
    }
}
impl<T: AsMut<[u8]>> ArpHeader<T> {
    #[inline]
    pub fn header_slice_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[0..28]
    }
    #[inline]
    pub fn set_hardware_type(&mut self, value: Hardware) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[0..2], u16::from(value));
    }
    #[inline]
    pub fn set_protocol_type(&mut self, value: EtherType) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[2..4], u16::from(value));
    }
    #[inline]
    pub fn set_hardware_addr_len(&mut self, value: u8) {
        self.buf.as_mut()[4] = value;
    }
    #[inline]
    pub fn set_protocol_addr_len(&mut self, value: u8) {
        self.buf.as_mut()[5] = value;
    }
    #[inline]
    pub fn set_operation(&mut self, value: Operation) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[6..8], u16::from(value));
    }
    #[inline]
    pub fn set_sender_hardware_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.as_mut()[8..14]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_sender_protocol_addr(&mut self, value: Ipv4Addr) {
        NetworkEndian::write_u32(&mut self.buf.as_mut()[14..18], u32::from(value));
    }
    #[inline]
    pub fn set_target_hardware_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.as_mut()[18..24]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_target_protocol_addr(&mut self, value: Ipv4Addr) {
        NetworkEndian::write_u32(&mut self.buf.as_mut()[24..28], u32::from(value));
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ArpPacket<T> {
    buf: T,
}
impl<T: Buf> ArpPacket<T> {
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
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..28]
    }
    #[inline]
    pub fn hardware_type(&self) -> Hardware {
        Hardware::from(NetworkEndian::read_u16(&self.buf.chunk()[0..2]))
    }
    #[inline]
    pub fn protocol_type(&self) -> EtherType {
        EtherType::from(NetworkEndian::read_u16(&self.buf.chunk()[2..4]))
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
        Operation::from(NetworkEndian::read_u16(&self.buf.chunk()[6..8]))
    }
    #[inline]
    pub fn sender_hardware_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.chunk()[8..14])
    }
    #[inline]
    pub fn sender_protocol_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(NetworkEndian::read_u32(&self.buf.chunk()[14..18]))
    }
    #[inline]
    pub fn target_hardware_addr(&self) -> EtherAddr {
        EtherAddr::from_bytes(&self.buf.chunk()[18..24])
    }
    #[inline]
    pub fn target_protocol_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(NetworkEndian::read_u32(&self.buf.chunk()[24..28]))
    }
}
impl<T: PktBuf> ArpPacket<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(28);
        buf
    }
}
impl<T: PktBufMut> ArpPacket<T> {
    #[inline]
    pub fn prepend_header<HT: AsRef<[u8]>>(mut buf: T, header: &ArpHeader<HT>) -> Self {
        assert!(buf.chunk_headroom() >= 28);
        buf.move_back(28);
        (&mut buf.chunk_mut()[0..28]).copy_from_slice(header.header_slice());
        Self { buf }
    }
    #[inline]
    pub fn set_hardware_type(&mut self, value: Hardware) {
        NetworkEndian::write_u16(&mut self.buf.chunk_mut()[0..2], u16::from(value));
    }
    #[inline]
    pub fn set_protocol_type(&mut self, value: EtherType) {
        NetworkEndian::write_u16(&mut self.buf.chunk_mut()[2..4], u16::from(value));
    }
    #[inline]
    pub fn set_hardware_addr_len(&mut self, value: u8) {
        self.buf.chunk_mut()[4] = value;
    }
    #[inline]
    pub fn set_protocol_addr_len(&mut self, value: u8) {
        self.buf.chunk_mut()[5] = value;
    }
    #[inline]
    pub fn set_operation(&mut self, value: Operation) {
        NetworkEndian::write_u16(&mut self.buf.chunk_mut()[6..8], u16::from(value));
    }
    #[inline]
    pub fn set_sender_hardware_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.chunk_mut()[8..14]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_sender_protocol_addr(&mut self, value: Ipv4Addr) {
        NetworkEndian::write_u32(&mut self.buf.chunk_mut()[14..18], u32::from(value));
    }
    #[inline]
    pub fn set_target_hardware_addr(&mut self, value: EtherAddr) {
        (&mut self.buf.chunk_mut()[18..24]).copy_from_slice(value.as_bytes());
    }
    #[inline]
    pub fn set_target_protocol_addr(&mut self, value: Ipv4Addr) {
        NetworkEndian::write_u32(&mut self.buf.chunk_mut()[24..28], u32::from(value));
    }
}
impl<'a> ArpPacket<Cursor<'a>> {
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
        Cursor::new(&self.buf.chunk()[28..])
    }
}
impl<'a> ArpPacket<CursorMut<'a>> {
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
        CursorMut::new(&mut self.buf.chunk_mut()[28..])
    }
}
