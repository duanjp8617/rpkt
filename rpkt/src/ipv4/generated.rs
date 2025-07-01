#![allow(missing_docs)]
#![allow(unused_parens)]

use super::{IpProtocol, Ipv4Addr};
use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

/// A constant that defines the fixed byte length of the Ipv4 protocol header.
pub const IPV4_HEADER_LEN: usize = 20;
/// A fixed Ipv4 header.
pub const IPV4_HEADER_TEMPLATE: [u8; 20] = [
    0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct Ipv4Packet<T> {
    buf: T,
}
impl<T: Buf> Ipv4Packet<T> {
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
        if chunk_len < 20 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 20)
            || ((container.header_len() as usize) > chunk_len)
            || ((container.packet_len() as usize) < (container.header_len() as usize))
            || ((container.packet_len() as usize) > container.buf.remaining())
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..20]
    }
    #[inline]
    pub fn option_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[20..header_len]
    }
    #[inline]
    pub fn version(&self) -> u8 {
        self.buf.chunk()[0] >> 4
    }
    #[inline]
    pub fn dscp(&self) -> u8 {
        self.buf.chunk()[1] >> 2
    }
    #[inline]
    pub fn ecn(&self) -> u8 {
        self.buf.chunk()[1] & 0x3
    }
    #[inline]
    pub fn ident(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap())
    }
    #[inline]
    pub fn flag_reserved(&self) -> u8 {
        self.buf.chunk()[6] >> 7
    }
    #[inline]
    pub fn dont_frag(&self) -> bool {
        self.buf.chunk()[6] & 0x40 != 0
    }
    #[inline]
    pub fn more_frag(&self) -> bool {
        self.buf.chunk()[6] & 0x20 != 0
    }
    #[inline]
    pub fn frag_offset(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[6..8]).try_into().unwrap()) & 0x1fff
    }
    #[inline]
    pub fn ttl(&self) -> u8 {
        self.buf.chunk()[8]
    }
    #[inline]
    pub fn protocol(&self) -> IpProtocol {
        IpProtocol::from(self.buf.chunk()[9])
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[10..12]).try_into().unwrap())
    }
    #[inline]
    pub fn src_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be_bytes(
            (&self.buf.chunk()[12..16]).try_into().unwrap(),
        ))
    }
    #[inline]
    pub fn dst_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be_bytes(
            (&self.buf.chunk()[16..20]).try_into().unwrap(),
        ))
    }
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[0] & 0xf) * 4
    }
    #[inline]
    pub fn packet_len(&self) -> u16 {
        (u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap()))
    }
}
impl<T: PktBuf> Ipv4Packet<T> {
    #[inline]
    pub fn payload(self) -> T {
        assert!((self.packet_len() as usize) <= self.buf.remaining());
        let trim_size = self.buf.remaining() - self.packet_len() as usize;
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        if trim_size > 0 {
            buf.trim_off(trim_size);
        }
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> Ipv4Packet<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 20], header_len: u8) -> Self {
        assert!((header_len >= 20) && (header_len as usize <= buf.chunk_headroom()));
        buf.move_back(header_len as usize);
        let packet_len = buf.remaining();
        assert!(packet_len <= 65535);
        (&mut buf.chunk_mut()[0..20]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_packet_len(packet_len as u16);
        container.set_header_len(header_len);
        container
    }
    #[inline]
    pub fn option_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[20..header_len]
    }
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        assert!(value == 4);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_dscp(&mut self, value: u8) {
        assert!(value <= 0x3f);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0x03) | (value << 2);
    }
    #[inline]
    pub fn set_ecn(&mut self, value: u8) {
        assert!(value <= 0x3);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xfc) | value;
    }
    #[inline]
    pub fn set_ident(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_flag_reserved(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[6] = (self.buf.chunk_mut()[6] & 0x7f) | (value << 7);
    }
    #[inline]
    pub fn set_dont_frag(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[6] = self.buf.chunk_mut()[6] | 0x40
        } else {
            self.buf.chunk_mut()[6] = self.buf.chunk_mut()[6] & 0xbf
        }
    }
    #[inline]
    pub fn set_more_frag(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[6] = self.buf.chunk_mut()[6] | 0x20
        } else {
            self.buf.chunk_mut()[6] = self.buf.chunk_mut()[6] & 0xdf
        }
    }
    #[inline]
    pub fn set_frag_offset(&mut self, value: u16) {
        assert!(value <= 0x1fff);
        let write_value = value | (((self.buf.chunk_mut()[6] & 0xe0) as u16) << 8);
        (&mut self.buf.chunk_mut()[6..8]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_ttl(&mut self, value: u8) {
        self.buf.chunk_mut()[8] = value;
    }
    #[inline]
    pub fn set_protocol(&mut self, value: IpProtocol) {
        self.buf.chunk_mut()[9] = u8::from(value);
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[10..12]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_src_addr(&mut self, value: Ipv4Addr) {
        (&mut self.buf.chunk_mut()[12..16]).copy_from_slice(&u32::from(value).to_be_bytes());
    }
    #[inline]
    pub fn set_dst_addr(&mut self, value: Ipv4Addr) {
        (&mut self.buf.chunk_mut()[16..20]).copy_from_slice(&u32::from(value).to_be_bytes());
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        assert!((value <= 60) && (value % 4 == 0));
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf0) | (value / 4);
    }
    #[inline]
    pub fn set_packet_len(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&(value).to_be_bytes());
    }
}
impl<'a> Ipv4Packet<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 20 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 20)
            || ((container.packet_len() as usize) < (container.header_len() as usize))
            || ((container.packet_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        let packet_len = self.packet_len() as usize;
        Cursor::new(&self.buf.chunk()[header_len..packet_len])
    }
}
impl<'a> Ipv4Packet<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 20 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 20)
            || ((container.packet_len() as usize) < (container.header_len() as usize))
            || ((container.packet_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        let packet_len = self.packet_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[header_len..packet_len])
    }
}

/*
impl<T: Buf> Ipv4Packet<T> {
    #[inline]
    pub fn src_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buf.chunk()[12],
            self.buf.chunk()[13],
            self.buf.chunk()[14],
            self.buf.chunk()[15],
        )
    }
    #[inline]
    pub fn dst_ip(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buf.chunk()[16],
            self.buf.chunk()[17],
            self.buf.chunk()[18],
            self.buf.chunk()[19],
        )
    }
}
impl<T: PktBufMut> Ipv4Packet<T> {
    #[inline]
    pub fn set_src_ip(&mut self, value: Ipv4Addr) {
        (&mut self.buf.chunk_mut()[12..16]).copy_from_slice(&value.octets());
    }
    #[inline]
    pub fn set_dst_ip(&mut self, value: Ipv4Addr) {
        (&mut self.buf.chunk_mut()[16..20]).copy_from_slice(&value.octets());
    }
}
*/

/// A constant that defines the fixed byte length of the Eol protocol header.
pub const EOL_HEADER_LEN: usize = 1;
/// A fixed Eol header.
pub const EOL_HEADER_TEMPLATE: [u8; 1] = [0x00];

#[derive(Debug, Clone, Copy)]
pub struct EolMessage<T> {
    buf: T,
}
impl<T: Buf> EolMessage<T> {
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
        if chunk_len < 1 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..1]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
}
impl<T: PktBuf> EolMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(1);
        buf
    }
}
impl<T: PktBufMut> EolMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 1]) -> Self {
        assert!(buf.chunk_headroom() >= 1);
        buf.move_back(1);
        (&mut buf.chunk_mut()[0..1]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[0] = value;
    }
}
impl<'a> EolMessage<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 1 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[1..])
    }
}
impl<'a> EolMessage<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 1 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[1..])
    }
}

/// A constant that defines the fixed byte length of the Nop protocol header.
pub const NOP_HEADER_LEN: usize = 1;
/// A fixed Nop header.
pub const NOP_HEADER_TEMPLATE: [u8; 1] = [0x01];

#[derive(Debug, Clone, Copy)]
pub struct NopMessage<T> {
    buf: T,
}
impl<T: Buf> NopMessage<T> {
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
        if chunk_len < 1 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..1]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
}
impl<T: PktBuf> NopMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(1);
        buf
    }
}
impl<T: PktBufMut> NopMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 1]) -> Self {
        assert!(buf.chunk_headroom() >= 1);
        buf.move_back(1);
        (&mut buf.chunk_mut()[0..1]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 1);
        self.buf.chunk_mut()[0] = value;
    }
}
impl<'a> NopMessage<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 1 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[1..])
    }
}
impl<'a> NopMessage<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 1 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[1..])
    }
}

/// A constant that defines the fixed byte length of the Timestamp protocol header.
pub const TIMESTAMP_HEADER_LEN: usize = 4;
/// A fixed Timestamp header.
pub const TIMESTAMP_HEADER_TEMPLATE: [u8; 4] = [0x44, 0x04, 0x05, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct TimestampMessage<T> {
    buf: T,
}
impl<T: Buf> TimestampMessage<T> {
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
        if chunk_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 4)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..4]
    }
    #[inline]
    pub fn option_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[4..header_len]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn pointer(&self) -> u8 {
        self.buf.chunk()[2]
    }
    #[inline]
    pub fn oflw(&self) -> u8 {
        self.buf.chunk()[3] >> 4
    }
    #[inline]
    pub fn flg(&self) -> u8 {
        self.buf.chunk()[3] & 0xf
    }
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[1])
    }
}
impl<T: PktBuf> TimestampMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> TimestampMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4], header_len: u8) -> Self {
        assert!((header_len >= 4) && (header_len as usize <= buf.chunk_headroom()));
        buf.move_back(header_len as usize);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_header_len(header_len);
        container
    }
    #[inline]
    pub fn option_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[4..header_len]
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 68);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_pointer(&mut self, value: u8) {
        self.buf.chunk_mut()[2] = value;
    }
    #[inline]
    pub fn set_oflw(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_flg(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xf0) | value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = (value);
    }
}
impl<'a> TimestampMessage<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 4)
            || ((container.header_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        Cursor::new(&self.buf.chunk()[header_len..])
    }
}
impl<'a> TimestampMessage<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 4)
            || ((container.header_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[header_len..])
    }
}

/// A constant that defines the fixed byte length of the RecordRoute protocol header.
pub const RECORDROUTE_HEADER_LEN: usize = 3;
/// A fixed RecordRoute header.
pub const RECORDROUTE_HEADER_TEMPLATE: [u8; 3] = [0x07, 0x03, 0x04];

#[derive(Debug, Clone, Copy)]
pub struct RecordRouteMessage<T> {
    buf: T,
}
impl<T: Buf> RecordRouteMessage<T> {
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
        if chunk_len < 3 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 3)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..3]
    }
    #[inline]
    pub fn option_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[3..header_len]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn pointer(&self) -> u8 {
        self.buf.chunk()[2]
    }
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[1])
    }
}
impl<T: PktBuf> RecordRouteMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> RecordRouteMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 3], header_len: u8) -> Self {
        assert!((header_len >= 3) && (header_len as usize <= buf.chunk_headroom()));
        buf.move_back(header_len as usize);
        (&mut buf.chunk_mut()[0..3]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_header_len(header_len);
        container
    }
    #[inline]
    pub fn option_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[3..header_len]
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 7);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_pointer(&mut self, value: u8) {
        self.buf.chunk_mut()[2] = value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = (value);
    }
}
impl<'a> RecordRouteMessage<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 3 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 3)
            || ((container.header_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        Cursor::new(&self.buf.chunk()[header_len..])
    }
}
impl<'a> RecordRouteMessage<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 3 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 3)
            || ((container.header_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[header_len..])
    }
}

/// A constant that defines the fixed byte length of the RouteAlert protocol header.
pub const ROUTEALERT_HEADER_LEN: usize = 4;
/// A fixed RouteAlert header.
pub const ROUTEALERT_HEADER_TEMPLATE: [u8; 4] = [0x94, 0x04, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct RouteAlertMessage<T> {
    buf: T,
}
impl<T: Buf> RouteAlertMessage<T> {
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
        if chunk_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) != 4)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..4]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn data(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[1])
    }
}
impl<T: PktBuf> RouteAlertMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> RouteAlertMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4], header_len: u8) -> Self {
        assert!((header_len == 4) && (header_len as usize <= buf.chunk_headroom()));
        buf.move_back(header_len as usize);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_header_len(header_len);
        container
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 148);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_data(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        assert!((value == 4));
        self.buf.chunk_mut()[1] = (value);
    }
}
impl<'a> RouteAlertMessage<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.header_len() as usize) != 4 {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        Cursor::new(&self.buf.chunk()[header_len..])
    }
}
impl<'a> RouteAlertMessage<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.header_len() as usize) != 4 {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[header_len..])
    }
}

#[derive(Debug)]
pub enum Ipv4OptGroup<T> {
    Eol_(EolMessage<T>),
    Nop_(NopMessage<T>),
    Timestamp_(TimestampMessage<T>),
    RecordRoute_(RecordRouteMessage<T>),
    RouteAlert_(RouteAlertMessage<T>),
}
impl<T: Buf> Ipv4OptGroup<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 1 {
            return Err(buf);
        }
        let cond_value = buf.chunk()[0];
        match cond_value {
            0 => EolMessage::parse(buf).map(|msg| Ipv4OptGroup::Eol_(msg)),
            1 => NopMessage::parse(buf).map(|msg| Ipv4OptGroup::Nop_(msg)),
            68 => TimestampMessage::parse(buf).map(|msg| Ipv4OptGroup::Timestamp_(msg)),
            7 => RecordRouteMessage::parse(buf).map(|msg| Ipv4OptGroup::RecordRoute_(msg)),
            148 => RouteAlertMessage::parse(buf).map(|msg| Ipv4OptGroup::RouteAlert_(msg)),
            _ => Err(buf),
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct Ipv4OptGroupIter<'a> {
    buf: &'a [u8],
}
impl<'a> Ipv4OptGroupIter<'a> {
    pub fn from_message_slice(message_slice: &'a [u8]) -> Self {
        Self { buf: message_slice }
    }

    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }
}
#[derive(Debug)]
pub struct Ipv4OptGroupIterMut<'a> {
    buf: &'a mut [u8],
}
impl<'a> Ipv4OptGroupIterMut<'a> {
    pub fn from_message_slice_mut(message_slice_mut: &'a mut [u8]) -> Self {
        Self {
            buf: message_slice_mut,
        }
    }

    pub fn buf(&self) -> &[u8] {
        &self.buf[..]
    }
}
impl<'a> Iterator for Ipv4OptGroupIter<'a> {
    type Item = Ipv4OptGroup<Cursor<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 1 {
            return None;
        }
        let cond_value = self.buf[0];
        match cond_value {
            0 => EolMessage::parse(self.buf)
                .map(|_msg| {
                    let result = EolMessage {
                        buf: Cursor::new(&self.buf[..1]),
                    };
                    self.buf = &self.buf[1..];
                    Ipv4OptGroup::Eol_(result)
                })
                .ok(),
            1 => NopMessage::parse(self.buf)
                .map(|_msg| {
                    let result = NopMessage {
                        buf: Cursor::new(&self.buf[..1]),
                    };
                    self.buf = &self.buf[1..];
                    Ipv4OptGroup::Nop_(result)
                })
                .ok(),
            68 => TimestampMessage::parse(self.buf)
                .map(|_msg| {
                    let result = TimestampMessage {
                        buf: Cursor::new(&self.buf[.._msg.header_len() as usize]),
                    };
                    self.buf = &self.buf[_msg.header_len() as usize..];
                    Ipv4OptGroup::Timestamp_(result)
                })
                .ok(),
            7 => RecordRouteMessage::parse(self.buf)
                .map(|_msg| {
                    let result = RecordRouteMessage {
                        buf: Cursor::new(&self.buf[.._msg.header_len() as usize]),
                    };
                    self.buf = &self.buf[_msg.header_len() as usize..];
                    Ipv4OptGroup::RecordRoute_(result)
                })
                .ok(),
            148 => RouteAlertMessage::parse(self.buf)
                .map(|_msg| {
                    let result = RouteAlertMessage {
                        buf: Cursor::new(&self.buf[.._msg.header_len() as usize]),
                    };
                    self.buf = &self.buf[_msg.header_len() as usize..];
                    Ipv4OptGroup::RouteAlert_(result)
                })
                .ok(),
            _ => None,
        }
    }
}
impl<'a> Iterator for Ipv4OptGroupIterMut<'a> {
    type Item = Ipv4OptGroup<CursorMut<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 1 {
            return None;
        }
        let cond_value = self.buf[0];
        match cond_value {
            0 => match EolMessage::parse(&self.buf[..]) {
                Ok(_msg) => {
                    let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(1);
                    self.buf = snd;
                    let result = EolMessage {
                        buf: CursorMut::new(fst),
                    };
                    Some(Ipv4OptGroup::Eol_(result))
                }
                Err(_) => None,
            },
            1 => match NopMessage::parse(&self.buf[..]) {
                Ok(_msg) => {
                    let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(1);
                    self.buf = snd;
                    let result = NopMessage {
                        buf: CursorMut::new(fst),
                    };
                    Some(Ipv4OptGroup::Nop_(result))
                }
                Err(_) => None,
            },
            68 => match TimestampMessage::parse(&self.buf[..]) {
                Ok(_msg) => {
                    let header_len = _msg.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = TimestampMessage {
                        buf: CursorMut::new(fst),
                    };
                    Some(Ipv4OptGroup::Timestamp_(result))
                }
                Err(_) => None,
            },
            7 => match RecordRouteMessage::parse(&self.buf[..]) {
                Ok(_msg) => {
                    let header_len = _msg.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = RecordRouteMessage {
                        buf: CursorMut::new(fst),
                    };
                    Some(Ipv4OptGroup::RecordRoute_(result))
                }
                Err(_) => None,
            },
            148 => match RouteAlertMessage::parse(&self.buf[..]) {
                Ok(_msg) => {
                    let header_len = _msg.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = RouteAlertMessage {
                        buf: CursorMut::new(fst),
                    };
                    Some(Ipv4OptGroup::RouteAlert_(result))
                }
                Err(_) => None,
            },
            _ => None,
        }
    }
}
