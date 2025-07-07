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
pub struct Ipv4<T> {
    buf: T,
}
impl<T: Buf> Ipv4<T> {
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
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..20]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
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
impl<T: PktBuf> Ipv4<T> {
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
impl<T: PktBufMut> Ipv4<T> {
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
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
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
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[6] = (self.buf.chunk_mut()[6] & 0xbf) | (value << 6);
    }
    #[inline]
    pub fn set_more_frag(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[6] = (self.buf.chunk_mut()[6] & 0xdf) | (value << 5);
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
impl<'a> Ipv4<Cursor<'a>> {
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
impl<'a> Ipv4<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the EolOption protocol header.
pub const EOLOPTION_HEADER_LEN: usize = 1;
/// A fixed EolOption header.
pub const EOLOPTION_HEADER_TEMPLATE: [u8; 1] = [0x00];

#[derive(Debug, Clone, Copy)]
pub struct EolOption<T> {
    buf: T,
}
impl<T: Buf> EolOption<T> {
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
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..1]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
}
impl<T: PktBuf> EolOption<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(1);
        buf
    }
}
impl<T: PktBufMut> EolOption<T> {
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
impl<'a> EolOption<Cursor<'a>> {
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
impl<'a> EolOption<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the NopOption protocol header.
pub const NOPOPTION_HEADER_LEN: usize = 1;
/// A fixed NopOption header.
pub const NOPOPTION_HEADER_TEMPLATE: [u8; 1] = [0x01];

#[derive(Debug, Clone, Copy)]
pub struct NopOption<T> {
    buf: T,
}
impl<T: Buf> NopOption<T> {
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
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..1]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
}
impl<T: PktBuf> NopOption<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(1);
        buf
    }
}
impl<T: PktBufMut> NopOption<T> {
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
impl<'a> NopOption<Cursor<'a>> {
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
impl<'a> NopOption<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the TimestampOption protocol header.
pub const TIMESTAMPOPTION_HEADER_LEN: usize = 4;
/// A fixed TimestampOption header.
pub const TIMESTAMPOPTION_HEADER_TEMPLATE: [u8; 4] = [0x44, 0x04, 0x05, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct TimestampOption<T> {
    buf: T,
}
impl<T: Buf> TimestampOption<T> {
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
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..4]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
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
impl<T: PktBuf> TimestampOption<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> TimestampOption<T> {
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
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
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
impl<'a> TimestampOption<Cursor<'a>> {
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
impl<'a> TimestampOption<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the RecordRouteOption protocol header.
pub const RECORDROUTEOPTION_HEADER_LEN: usize = 3;
/// A fixed RecordRouteOption header.
pub const RECORDROUTEOPTION_HEADER_TEMPLATE: [u8; 3] = [0x07, 0x03, 0x04];

#[derive(Debug, Clone, Copy)]
pub struct RecordRouteOption<T> {
    buf: T,
}
impl<T: Buf> RecordRouteOption<T> {
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
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..3]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
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
impl<T: PktBuf> RecordRouteOption<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> RecordRouteOption<T> {
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
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
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
impl<'a> RecordRouteOption<Cursor<'a>> {
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
impl<'a> RecordRouteOption<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the RouteAlertOption protocol header.
pub const ROUTEALERTOPTION_HEADER_LEN: usize = 4;
/// A fixed RouteAlertOption header.
pub const ROUTEALERTOPTION_HEADER_TEMPLATE: [u8; 4] = [0x94, 0x04, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct RouteAlertOption<T> {
    buf: T,
}
impl<T: Buf> RouteAlertOption<T> {
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
    pub fn fix_header_slice(&self) -> &[u8] {
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
impl<T: PktBuf> RouteAlertOption<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> RouteAlertOption<T> {
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
impl<'a> RouteAlertOption<Cursor<'a>> {
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
impl<'a> RouteAlertOption<CursorMut<'a>> {
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
pub enum Ipv4Options<T> {
    EolOption_(EolOption<T>),
    NopOption_(NopOption<T>),
    TimestampOption_(TimestampOption<T>),
    RecordRouteOption_(RecordRouteOption<T>),
    RouteAlertOption_(RouteAlertOption<T>),
}
impl<T: Buf> Ipv4Options<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 1 {
            return Err(buf);
        }
        let cond_value = buf.chunk()[0];
        match cond_value {
            0 => EolOption::parse(buf).map(|pkt| Ipv4Options::EolOption_(pkt)),
            1 => NopOption::parse(buf).map(|pkt| Ipv4Options::NopOption_(pkt)),
            68 => TimestampOption::parse(buf).map(|pkt| Ipv4Options::TimestampOption_(pkt)),
            7 => RecordRouteOption::parse(buf).map(|pkt| Ipv4Options::RecordRouteOption_(pkt)),
            148 => RouteAlertOption::parse(buf).map(|pkt| Ipv4Options::RouteAlertOption_(pkt)),
            _ => Err(buf),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv4OptionsIter<'a> {
    buf: &'a [u8],
}
impl<'a> Ipv4OptionsIter<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Self {
        Self { buf: slice }
    }

    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }
}
impl<'a> Iterator for Ipv4OptionsIter<'a> {
    type Item = Ipv4Options<Cursor<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 1 {
            return None;
        }
        let cond_value = self.buf[0];
        match cond_value {
            0 => EolOption::parse(self.buf)
                .map(|_pkt| {
                    let result = EolOption {
                        buf: Cursor::new(&self.buf[..1]),
                    };
                    self.buf = &self.buf[1..];
                    Ipv4Options::EolOption_(result)
                })
                .ok(),
            1 => NopOption::parse(self.buf)
                .map(|_pkt| {
                    let result = NopOption {
                        buf: Cursor::new(&self.buf[..1]),
                    };
                    self.buf = &self.buf[1..];
                    Ipv4Options::NopOption_(result)
                })
                .ok(),
            68 => TimestampOption::parse(self.buf)
                .map(|_pkt| {
                    let result = TimestampOption {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Ipv4Options::TimestampOption_(result)
                })
                .ok(),
            7 => RecordRouteOption::parse(self.buf)
                .map(|_pkt| {
                    let result = RecordRouteOption {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Ipv4Options::RecordRouteOption_(result)
                })
                .ok(),
            148 => RouteAlertOption::parse(self.buf)
                .map(|_pkt| {
                    let result = RouteAlertOption {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Ipv4Options::RouteAlertOption_(result)
                })
                .ok(),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Ipv4OptionsIterMut<'a> {
    buf: &'a mut [u8],
}
impl<'a> Ipv4OptionsIterMut<'a> {
    pub fn from_slice_mut(slice_mut: &'a mut [u8]) -> Self {
        Self { buf: slice_mut }
    }

    pub fn buf(&self) -> &[u8] {
        &self.buf[..]
    }
}
impl<'a> Iterator for Ipv4OptionsIterMut<'a> {
    type Item = Ipv4Options<CursorMut<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 1 {
            return None;
        }
        let cond_value = self.buf[0];
        match cond_value {
            0 => match EolOption::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(1);
                    self.buf = snd;
                    let result = EolOption {
                        buf: CursorMut::new(fst),
                    };
                    Some(Ipv4Options::EolOption_(result))
                }
                Err(_) => None,
            },
            1 => match NopOption::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(1);
                    self.buf = snd;
                    let result = NopOption {
                        buf: CursorMut::new(fst),
                    };
                    Some(Ipv4Options::NopOption_(result))
                }
                Err(_) => None,
            },
            68 => match TimestampOption::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = TimestampOption {
                        buf: CursorMut::new(fst),
                    };
                    Some(Ipv4Options::TimestampOption_(result))
                }
                Err(_) => None,
            },
            7 => match RecordRouteOption::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = RecordRouteOption {
                        buf: CursorMut::new(fst),
                    };
                    Some(Ipv4Options::RecordRouteOption_(result))
                }
                Err(_) => None,
            },
            148 => match RouteAlertOption::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = RouteAlertOption {
                        buf: CursorMut::new(fst),
                    };
                    Some(Ipv4Options::RouteAlertOption_(result))
                }
                Err(_) => None,
            },
            _ => None,
        }
    }
}
