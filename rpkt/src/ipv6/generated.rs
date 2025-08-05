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

/// A constant that defines the fixed byte length of the DestOptions protocol header.
pub const DEST_OPTIONS_HEADER_LEN: usize = 2;
/// A fixed DestOptions header.
pub const DEST_OPTIONS_HEADER_TEMPLATE: [u8; 2] = [0x04, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct DestOptions<T> {
    buf: T,
}
impl<T: Buf> DestOptions<T> {
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
        if chunk_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 2)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..2]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[2..header_len]
    }
    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        IpProtocol::from(self.buf.chunk()[0])
    }
    #[inline]
    pub fn header_len(&self) -> u16 {
        (self.buf.chunk()[1]) as u16 * 8 + 8
    }
}
impl<T: PktBuf> DestOptions<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> DestOptions<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        let header_len = DestOptions::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 2) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..2]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[2..header_len]
    }
    #[inline]
    pub fn set_next_header(&mut self, value: IpProtocol) {
        self.buf.chunk_mut()[0] = u8::from(value);
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u16) {
        assert!((value <= 2048) && (value >= 8) && ((value - 8) % 8 == 0));
        self.buf.chunk_mut()[1] = (((value - 8) / 8) as u8);
    }
}
impl<'a> DestOptions<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 2)
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
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 2]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 2] {
        DEST_OPTIONS_HEADER_TEMPLATE.clone()
    }
}
impl<'a> DestOptions<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 2)
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
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 2]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the HopByHopOption protocol header.
pub const HOP_BY_HOP_OPTION_HEADER_LEN: usize = 2;
/// A fixed HopByHopOption header.
pub const HOP_BY_HOP_OPTION_HEADER_TEMPLATE: [u8; 2] = [0x04, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct HopByHopOption<T> {
    buf: T,
}
impl<T: Buf> HopByHopOption<T> {
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
        if chunk_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 2)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..2]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[2..header_len]
    }
    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        IpProtocol::from(self.buf.chunk()[0])
    }
    #[inline]
    pub fn header_len(&self) -> u16 {
        (self.buf.chunk()[1]) as u16 * 8 + 8
    }
}
impl<T: PktBuf> HopByHopOption<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> HopByHopOption<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        let header_len = HopByHopOption::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 2) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..2]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[2..header_len]
    }
    #[inline]
    pub fn set_next_header(&mut self, value: IpProtocol) {
        self.buf.chunk_mut()[0] = u8::from(value);
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u16) {
        assert!((value <= 2048) && (value >= 8) && ((value - 8) % 8 == 0));
        self.buf.chunk_mut()[1] = (((value - 8) / 8) as u8);
    }
}
impl<'a> HopByHopOption<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 2)
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
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 2]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 2] {
        HOP_BY_HOP_OPTION_HEADER_TEMPLATE.clone()
    }
}
impl<'a> HopByHopOption<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 2)
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
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 2]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the RoutingHeader protocol header.
pub const ROUTING_HEADER_HEADER_LEN: usize = 8;
/// A fixed RoutingHeader header.
pub const ROUTING_HEADER_HEADER_TEMPLATE: [u8; 8] =
    [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct RoutingHeader<T> {
    buf: T,
}
impl<T: Buf> RoutingHeader<T> {
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
        if chunk_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 8)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..8]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[8..header_len]
    }
    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        IpProtocol::from(self.buf.chunk()[0])
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[2]
    }
    #[inline]
    pub fn segments_left(&self) -> u8 {
        self.buf.chunk()[3]
    }
    #[inline]
    pub fn type_specific_data(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[4..8]).try_into().unwrap())
    }
    #[inline]
    pub fn header_len(&self) -> u16 {
        (self.buf.chunk()[1]) as u16 * 8 + 8
    }
}
impl<T: PktBuf> RoutingHeader<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> RoutingHeader<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        let header_len = RoutingHeader::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 8) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[8..header_len]
    }
    #[inline]
    pub fn set_next_header(&mut self, value: IpProtocol) {
        self.buf.chunk_mut()[0] = u8::from(value);
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        self.buf.chunk_mut()[2] = value;
    }
    #[inline]
    pub fn set_segments_left(&mut self, value: u8) {
        self.buf.chunk_mut()[3] = value;
    }
    #[inline]
    pub fn set_type_specific_data(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[4..8]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u16) {
        assert!((value <= 2048) && (value >= 8) && ((value - 8) % 8 == 0));
        self.buf.chunk_mut()[1] = (((value - 8) / 8) as u8);
    }
}
impl<'a> RoutingHeader<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 8)
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
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 8]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 8] {
        ROUTING_HEADER_HEADER_TEMPLATE.clone()
    }
}
impl<'a> RoutingHeader<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 8)
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
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 8]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the FragmentHeader protocol header.
pub const FRAGMENT_HEADER_HEADER_LEN: usize = 8;
/// A fixed FragmentHeader header.
pub const FRAGMENT_HEADER_HEADER_TEMPLATE: [u8; 8] =
    [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct FragmentHeader<T> {
    buf: T,
}
impl<T: Buf> FragmentHeader<T> {
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
        if chunk_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..8]
    }
    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        IpProtocol::from(self.buf.chunk()[0])
    }
    #[inline]
    pub fn reserved(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn offset(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap()) >> 3
    }
    #[inline]
    pub fn reserved1(&self) -> u8 {
        (self.buf.chunk()[3] >> 1) & 0x3
    }
    #[inline]
    pub fn more_frag(&self) -> bool {
        self.buf.chunk()[3] & 0x1 != 0
    }
    #[inline]
    pub fn ident(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[4..8]).try_into().unwrap())
    }
}
impl<T: PktBuf> FragmentHeader<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> FragmentHeader<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_next_header(&mut self, value: IpProtocol) {
        self.buf.chunk_mut()[0] = u8::from(value);
    }
    #[inline]
    pub fn set_reserved(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_offset(&mut self, value: u16) {
        assert!(value <= 0x1fff);
        let write_value = (value << 3) | ((self.buf.chunk_mut()[3] & 0x7) as u16);
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&write_value.to_be_bytes());
    }
    #[inline]
    pub fn set_reserved1(&mut self, value: u8) {
        assert!(value <= 0x3);
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xf9) | (value << 1);
    }
    #[inline]
    pub fn set_more_frag(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[3] = (self.buf.chunk_mut()[3] & 0xfe) | value;
    }
    #[inline]
    pub fn set_ident(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[4..8]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> FragmentHeader<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[8..])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 8]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 8] {
        FRAGMENT_HEADER_HEADER_TEMPLATE.clone()
    }
}
impl<'a> FragmentHeader<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[8..])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 8]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the AuthenticationHeader protocol header.
pub const AUTHENTICATION_HEADER_HEADER_LEN: usize = 12;
/// A fixed AuthenticationHeader header.
pub const AUTHENTICATION_HEADER_HEADER_TEMPLATE: [u8; 12] = [
    0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct AuthenticationHeader<T> {
    buf: T,
}
impl<T: Buf> AuthenticationHeader<T> {
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
        if chunk_len < 12 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 12)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..12]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[12..header_len]
    }
    #[inline]
    pub fn next_header(&self) -> IpProtocol {
        IpProtocol::from(self.buf.chunk()[0])
    }
    #[inline]
    pub fn reserved(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn security_parameters_index(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[4..8]).try_into().unwrap())
    }
    #[inline]
    pub fn seq_num_field(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[8..12]).try_into().unwrap())
    }
    #[inline]
    pub fn header_len(&self) -> u16 {
        (self.buf.chunk()[1]) as u16 * 4 + 8
    }
}
impl<T: PktBuf> AuthenticationHeader<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> AuthenticationHeader<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 12]) -> Self {
        let header_len = AuthenticationHeader::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 12) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..12]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[12..header_len]
    }
    #[inline]
    pub fn set_next_header(&mut self, value: IpProtocol) {
        self.buf.chunk_mut()[0] = u8::from(value);
    }
    #[inline]
    pub fn set_reserved(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_security_parameters_index(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[4..8]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_seq_num_field(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[8..12]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u16) {
        assert!((value <= 1028) && (value >= 8) && ((value - 8) % 4 == 0));
        self.buf.chunk_mut()[1] = (((value - 8) / 4) as u8);
    }
}
impl<'a> AuthenticationHeader<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 12 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 12)
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
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 12]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 12] {
        AUTHENTICATION_HEADER_HEADER_TEMPLATE.clone()
    }
}
impl<'a> AuthenticationHeader<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 12 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 12)
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
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 12]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the Generic protocol header.
pub const GENERIC_HEADER_LEN: usize = 2;
/// A fixed Generic header.
pub const GENERIC_HEADER_TEMPLATE: [u8; 2] = [0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct Generic<T> {
    buf: T,
}
impl<T: Buf> Generic<T> {
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
        if chunk_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 2)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..2]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[2..header_len]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn header_len(&self) -> u16 {
        (self.buf.chunk()[1]) as u16 + 2
    }
}
impl<T: PktBuf> Generic<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> Generic<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        let header_len = Generic::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 2) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..2]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[2..header_len]
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u16) {
        assert!((value <= 257) && (value >= 2));
        self.buf.chunk_mut()[1] = ((value - 2) as u8);
    }
}
impl<'a> Generic<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 2)
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
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 2]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 2] {
        GENERIC_HEADER_TEMPLATE.clone()
    }
}
impl<'a> Generic<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 2)
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
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 2]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the RouterAlert protocol header.
pub const ROUTER_ALERT_HEADER_LEN: usize = 4;
/// A fixed RouterAlert header.
pub const ROUTER_ALERT_HEADER_TEMPLATE: [u8; 4] = [0x05, 0x02, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct RouterAlert<T> {
    buf: T,
}
impl<T: Buf> RouterAlert<T> {
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
    pub fn router_alert(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn header_len(&self) -> u16 {
        (self.buf.chunk()[1]) as u16 + 2
    }
}
impl<T: PktBuf> RouterAlert<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> RouterAlert<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        let header_len = RouterAlert::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len == 4) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 5);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_router_alert(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u16) {
        assert!((value == 4));
        self.buf.chunk_mut()[1] = ((value - 2) as u8);
    }
}
impl<'a> RouterAlert<Cursor<'a>> {
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
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 4]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 4] {
        ROUTER_ALERT_HEADER_TEMPLATE.clone()
    }
}
impl<'a> RouterAlert<CursorMut<'a>> {
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
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 4]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the Padn protocol header.
pub const PADN_HEADER_LEN: usize = 2;
/// A fixed Padn header.
pub const PADN_HEADER_TEMPLATE: [u8; 2] = [0x01, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct Padn<T> {
    buf: T,
}
impl<T: Buf> Padn<T> {
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
        if chunk_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 2)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..2]
    }
    #[inline]
    pub fn var_header_slice(&self) -> &[u8] {
        let header_len = (self.header_len() as usize);
        &self.buf.chunk()[2..header_len]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn header_len(&self) -> u16 {
        (self.buf.chunk()[1]) as u16 + 2
    }
}
impl<T: PktBuf> Padn<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> Padn<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        let header_len = Padn::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 2) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..2]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[2..header_len]
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 1);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u16) {
        assert!((value <= 257) && (value >= 2));
        self.buf.chunk_mut()[1] = ((value - 2) as u8);
    }
}
impl<'a> Padn<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 2)
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
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 2]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 2] {
        PADN_HEADER_TEMPLATE.clone()
    }
}
impl<'a> Padn<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 2)
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
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 2]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the Pad0 protocol header.
pub const PAD0_HEADER_LEN: usize = 1;
/// A fixed Pad0 header.
pub const PAD0_HEADER_TEMPLATE: [u8; 1] = [0x00];

#[derive(Debug, Clone, Copy)]
pub struct Pad0<T> {
    buf: T,
}
impl<T: Buf> Pad0<T> {
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
impl<T: PktBuf> Pad0<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(1);
        buf
    }
}
impl<T: PktBufMut> Pad0<T> {
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
impl<'a> Pad0<Cursor<'a>> {
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
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 1]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 1] {
        PAD0_HEADER_TEMPLATE.clone()
    }
}
impl<'a> Pad0<CursorMut<'a>> {
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
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 1]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

#[derive(Debug)]
pub enum Ipv6Options<T> {
    Generic_(Generic<T>),
    RouterAlert_(RouterAlert<T>),
    Padn_(Padn<T>),
    Pad0_(Pad0<T>),
}
impl<T: Buf> Ipv6Options<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 1 {
            return Err(buf);
        }
        let cond_value0 = buf.chunk()[0];
        match cond_value0 {
            2..=255 => Generic::parse(buf).map(|pkt| Ipv6Options::Generic_(pkt)),
            5 => RouterAlert::parse(buf).map(|pkt| Ipv6Options::RouterAlert_(pkt)),
            1 => Padn::parse(buf).map(|pkt| Ipv6Options::Padn_(pkt)),
            0 => Pad0::parse(buf).map(|pkt| Ipv6Options::Pad0_(pkt)),
            _ => Err(buf),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Ipv6OptionsIter<'a> {
    buf: &'a [u8],
}
impl<'a> Ipv6OptionsIter<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Self {
        Self { buf: slice }
    }

    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }
}
impl<'a> Iterator for Ipv6OptionsIter<'a> {
    type Item = Ipv6Options<Cursor<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 1 {
            return None;
        }
        let cond_value0 = self.buf[0];
        match cond_value0 {
            2..=255 => Generic::parse(self.buf)
                .map(|_pkt| {
                    let result = Generic {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Ipv6Options::Generic_(result)
                })
                .ok(),
            5 => RouterAlert::parse(self.buf)
                .map(|_pkt| {
                    let result = RouterAlert {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Ipv6Options::RouterAlert_(result)
                })
                .ok(),
            1 => Padn::parse(self.buf)
                .map(|_pkt| {
                    let result = Padn {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    Ipv6Options::Padn_(result)
                })
                .ok(),
            0 => Pad0::parse(self.buf)
                .map(|_pkt| {
                    let result = Pad0 {
                        buf: Cursor::new(&self.buf[..1]),
                    };
                    self.buf = &self.buf[1..];
                    Ipv6Options::Pad0_(result)
                })
                .ok(),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Ipv6OptionsIterMut<'a> {
    buf: &'a mut [u8],
}
impl<'a> Ipv6OptionsIterMut<'a> {
    pub fn from_slice_mut(slice_mut: &'a mut [u8]) -> Self {
        Self { buf: slice_mut }
    }

    pub fn buf(&self) -> &[u8] {
        &self.buf[..]
    }
}
impl<'a> Iterator for Ipv6OptionsIterMut<'a> {
    type Item = Ipv6Options<CursorMut<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 1 {
            return None;
        }
        let cond_value0 = self.buf[0];
        match cond_value0 {
            2..=255 => match Generic::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = Generic {
                        buf: CursorMut::new(fst),
                    };
                    Some(Ipv6Options::Generic_(result))
                }
                Err(_) => None,
            },
            5 => match RouterAlert::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = RouterAlert {
                        buf: CursorMut::new(fst),
                    };
                    Some(Ipv6Options::RouterAlert_(result))
                }
                Err(_) => None,
            },
            1 => match Padn::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = Padn {
                        buf: CursorMut::new(fst),
                    };
                    Some(Ipv6Options::Padn_(result))
                }
                Err(_) => None,
            },
            0 => match Pad0::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(1);
                    self.buf = snd;
                    let result = Pad0 {
                        buf: CursorMut::new(fst),
                    };
                    Some(Ipv6Options::Pad0_(result))
                }
                Err(_) => None,
            },
            _ => None,
        }
    }
}
