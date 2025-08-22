#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::ipv4::Ipv4Addr;
use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};
use crate::endian::{read_uint_from_be_bytes, write_uint_as_be_bytes};

/// A constant that defines the fixed byte length of the EchoReply protocol header.
pub const ECHO_REPLY_HEADER_LEN: usize = 8;
/// A fixed EchoReply header.
pub const ECHO_REPLY_HEADER_TEMPLATE: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct EchoReply<T> {
    buf: T,
}
impl<T: Buf> EchoReply<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap())
    }
    #[inline]
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[6..8]).try_into().unwrap())
    }
}
impl<T: PktBuf> EchoReply<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> EchoReply<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_identifier(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_sequence(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[6..8]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> EchoReply<Cursor<'a>> {
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
        ECHO_REPLY_HEADER_TEMPLATE.clone()
    }
}
impl<'a> EchoReply<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the DestUnreachable protocol header.
pub const DEST_UNREACHABLE_HEADER_LEN: usize = 8;
/// A fixed DestUnreachable header.
pub const DEST_UNREACHABLE_HEADER_TEMPLATE: [u8; 8] =
    [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct DestUnreachable<T> {
    buf: T,
}
impl<T: Buf> DestUnreachable<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn unused(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[4..8]).try_into().unwrap())
    }
}
impl<T: PktBuf> DestUnreachable<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> DestUnreachable<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 3);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_unused(&mut self, value: u32) {
        assert!(value == 0);
        (&mut self.buf.chunk_mut()[4..8]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> DestUnreachable<Cursor<'a>> {
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
        DEST_UNREACHABLE_HEADER_TEMPLATE.clone()
    }
}
impl<'a> DestUnreachable<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the SourceQuench protocol header.
pub const SOURCE_QUENCH_HEADER_LEN: usize = 8;
/// A fixed SourceQuench header.
pub const SOURCE_QUENCH_HEADER_TEMPLATE: [u8; 8] = [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct SourceQuench<T> {
    buf: T,
}
impl<T: Buf> SourceQuench<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn unused(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[4..8]).try_into().unwrap())
    }
}
impl<T: PktBuf> SourceQuench<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> SourceQuench<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 4);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_unused(&mut self, value: u32) {
        assert!(value == 0);
        (&mut self.buf.chunk_mut()[4..8]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> SourceQuench<Cursor<'a>> {
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
        SOURCE_QUENCH_HEADER_TEMPLATE.clone()
    }
}
impl<'a> SourceQuench<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the Redirect protocol header.
pub const REDIRECT_HEADER_LEN: usize = 8;
/// A fixed Redirect header.
pub const REDIRECT_HEADER_TEMPLATE: [u8; 8] = [0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct Redirect<T> {
    buf: T,
}
impl<T: Buf> Redirect<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn gateway_addr(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be_bytes(
            (&self.buf.chunk()[4..8]).try_into().unwrap(),
        ))
    }
}
impl<T: PktBuf> Redirect<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> Redirect<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 5);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_gateway_addr(&mut self, value: Ipv4Addr) {
        (&mut self.buf.chunk_mut()[4..8]).copy_from_slice(&u32::from(value).to_be_bytes());
    }
}
impl<'a> Redirect<Cursor<'a>> {
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
        REDIRECT_HEADER_TEMPLATE.clone()
    }
}
impl<'a> Redirect<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the EchoRequest protocol header.
pub const ECHO_REQUEST_HEADER_LEN: usize = 8;
/// A fixed EchoRequest header.
pub const ECHO_REQUEST_HEADER_TEMPLATE: [u8; 8] = [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct EchoRequest<T> {
    buf: T,
}
impl<T: Buf> EchoRequest<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap())
    }
    #[inline]
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[6..8]).try_into().unwrap())
    }
}
impl<T: PktBuf> EchoRequest<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> EchoRequest<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 8);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_identifier(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_sequence(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[6..8]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> EchoRequest<Cursor<'a>> {
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
        ECHO_REQUEST_HEADER_TEMPLATE.clone()
    }
}
impl<'a> EchoRequest<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the RouterAdvertisement protocol header.
pub const ROUTER_ADVERTISEMENT_HEADER_LEN: usize = 8;
/// A fixed RouterAdvertisement header.
pub const ROUTER_ADVERTISEMENT_HEADER_TEMPLATE: [u8; 8] =
    [0x09, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct RouterAdvertisement<T> {
    buf: T,
}
impl<T: Buf> RouterAdvertisement<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn num_addrs(&self) -> u8 {
        self.buf.chunk()[4]
    }
    #[inline]
    pub fn addr_entry_size(&self) -> u8 {
        self.buf.chunk()[5]
    }
    #[inline]
    pub fn lifetime(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[6..8]).try_into().unwrap())
    }
}
impl<T: PktBuf> RouterAdvertisement<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> RouterAdvertisement<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 9);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_num_addrs(&mut self, value: u8) {
        self.buf.chunk_mut()[4] = value;
    }
    #[inline]
    pub fn set_addr_entry_size(&mut self, value: u8) {
        assert!(value == 2);
        self.buf.chunk_mut()[5] = value;
    }
    #[inline]
    pub fn set_lifetime(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[6..8]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> RouterAdvertisement<Cursor<'a>> {
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
        ROUTER_ADVERTISEMENT_HEADER_TEMPLATE.clone()
    }
}
impl<'a> RouterAdvertisement<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the RouterSolicitation protocol header.
pub const ROUTER_SOLICITATION_HEADER_LEN: usize = 8;
/// A fixed RouterSolicitation header.
pub const ROUTER_SOLICITATION_HEADER_TEMPLATE: [u8; 8] =
    [0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct RouterSolicitation<T> {
    buf: T,
}
impl<T: Buf> RouterSolicitation<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn reserved(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[4..8]).try_into().unwrap())
    }
}
impl<T: PktBuf> RouterSolicitation<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> RouterSolicitation<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 10);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_reserved(&mut self, value: u32) {
        assert!(value == 0);
        (&mut self.buf.chunk_mut()[4..8]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> RouterSolicitation<Cursor<'a>> {
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
        ROUTER_SOLICITATION_HEADER_TEMPLATE.clone()
    }
}
impl<'a> RouterSolicitation<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the TimeExceeded protocol header.
pub const TIME_EXCEEDED_HEADER_LEN: usize = 8;
/// A fixed TimeExceeded header.
pub const TIME_EXCEEDED_HEADER_TEMPLATE: [u8; 8] = [0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct TimeExceeded<T> {
    buf: T,
}
impl<T: Buf> TimeExceeded<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn unused(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[4..8]).try_into().unwrap())
    }
}
impl<T: PktBuf> TimeExceeded<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> TimeExceeded<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 11);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_unused(&mut self, value: u32) {
        assert!(value == 0);
        (&mut self.buf.chunk_mut()[4..8]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> TimeExceeded<Cursor<'a>> {
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
        TIME_EXCEEDED_HEADER_TEMPLATE.clone()
    }
}
impl<'a> TimeExceeded<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the ParameterProblem protocol header.
pub const PARAMETER_PROBLEM_HEADER_LEN: usize = 8;
/// A fixed ParameterProblem header.
pub const PARAMETER_PROBLEM_HEADER_TEMPLATE: [u8; 8] =
    [0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct ParameterProblem<T> {
    buf: T,
}
impl<T: Buf> ParameterProblem<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn pointer(&self) -> u8 {
        self.buf.chunk()[4]
    }
    #[inline]
    pub fn unused(&self) -> u32 {
        (read_uint_from_be_bytes(&self.buf.chunk()[5..8])) as u32
    }
}
impl<T: PktBuf> ParameterProblem<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> ParameterProblem<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 12);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_pointer(&mut self, value: u8) {
        self.buf.chunk_mut()[4] = value;
    }
    #[inline]
    pub fn set_unused(&mut self, value: u32) {
        assert!(value == 0);
        write_uint_as_be_bytes(&mut self.buf.chunk_mut()[5..8], (value as u64));
    }
}
impl<'a> ParameterProblem<Cursor<'a>> {
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
        PARAMETER_PROBLEM_HEADER_TEMPLATE.clone()
    }
}
impl<'a> ParameterProblem<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the TimestampRequest protocol header.
pub const TIMESTAMP_REQUEST_HEADER_LEN: usize = 20;
/// A fixed TimestampRequest header.
pub const TIMESTAMP_REQUEST_HEADER_TEMPLATE: [u8; 20] = [
    0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct TimestampRequest<T> {
    buf: T,
}
impl<T: Buf> TimestampRequest<T> {
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
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..20]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap())
    }
    #[inline]
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[6..8]).try_into().unwrap())
    }
    #[inline]
    pub fn originate_timestamp(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[8..12]).try_into().unwrap())
    }
    #[inline]
    pub fn receive_timestamp(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[12..16]).try_into().unwrap())
    }
    #[inline]
    pub fn transmit_timestamp(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[16..20]).try_into().unwrap())
    }
}
impl<T: PktBuf> TimestampRequest<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(20);
        buf
    }
}
impl<T: PktBufMut> TimestampRequest<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 20]) -> Self {
        assert!(buf.chunk_headroom() >= 20);
        buf.move_back(20);
        (&mut buf.chunk_mut()[0..20]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 13);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_identifier(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_sequence(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[6..8]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_originate_timestamp(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[8..12]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_receive_timestamp(&mut self, value: u32) {
        assert!(value == 0);
        (&mut self.buf.chunk_mut()[12..16]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_transmit_timestamp(&mut self, value: u32) {
        assert!(value == 0);
        (&mut self.buf.chunk_mut()[16..20]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> TimestampRequest<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 20 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[20..])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 20]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 20] {
        TIMESTAMP_REQUEST_HEADER_TEMPLATE.clone()
    }
}
impl<'a> TimestampRequest<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 20 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[20..])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 20]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the TimestampReply protocol header.
pub const TIMESTAMP_REPLY_HEADER_LEN: usize = 20;
/// A fixed TimestampReply header.
pub const TIMESTAMP_REPLY_HEADER_TEMPLATE: [u8; 20] = [
    0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct TimestampReply<T> {
    buf: T,
}
impl<T: Buf> TimestampReply<T> {
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
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..20]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap())
    }
    #[inline]
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[6..8]).try_into().unwrap())
    }
    #[inline]
    pub fn originate_timestamp(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[8..12]).try_into().unwrap())
    }
    #[inline]
    pub fn receive_timestamp(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[12..16]).try_into().unwrap())
    }
    #[inline]
    pub fn transmit_timestamp(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[16..20]).try_into().unwrap())
    }
}
impl<T: PktBuf> TimestampReply<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(20);
        buf
    }
}
impl<T: PktBufMut> TimestampReply<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 20]) -> Self {
        assert!(buf.chunk_headroom() >= 20);
        buf.move_back(20);
        (&mut buf.chunk_mut()[0..20]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 14);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_identifier(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_sequence(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[6..8]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_originate_timestamp(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[8..12]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_receive_timestamp(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[12..16]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_transmit_timestamp(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[16..20]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> TimestampReply<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 20 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[20..])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 20]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 20] {
        TIMESTAMP_REPLY_HEADER_TEMPLATE.clone()
    }
}
impl<'a> TimestampReply<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 20 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[20..])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 20]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the InformationRequest protocol header.
pub const INFORMATION_REQUEST_HEADER_LEN: usize = 8;
/// A fixed InformationRequest header.
pub const INFORMATION_REQUEST_HEADER_TEMPLATE: [u8; 8] =
    [0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct InformationRequest<T> {
    buf: T,
}
impl<T: Buf> InformationRequest<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap())
    }
    #[inline]
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[6..8]).try_into().unwrap())
    }
}
impl<T: PktBuf> InformationRequest<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> InformationRequest<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 15);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_identifier(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_sequence(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[6..8]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> InformationRequest<Cursor<'a>> {
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
        INFORMATION_REQUEST_HEADER_TEMPLATE.clone()
    }
}
impl<'a> InformationRequest<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the InformationReply protocol header.
pub const INFORMATION_REPLY_HEADER_LEN: usize = 8;
/// A fixed InformationReply header.
pub const INFORMATION_REPLY_HEADER_TEMPLATE: [u8; 8] =
    [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct InformationReply<T> {
    buf: T,
}
impl<T: Buf> InformationReply<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap())
    }
    #[inline]
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[6..8]).try_into().unwrap())
    }
}
impl<T: PktBuf> InformationReply<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> InformationReply<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 16);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_identifier(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_sequence(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[6..8]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> InformationReply<Cursor<'a>> {
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
        INFORMATION_REPLY_HEADER_TEMPLATE.clone()
    }
}
impl<'a> InformationReply<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the AddressMaskRequest protocol header.
pub const ADDRESS_MASK_REQUEST_HEADER_LEN: usize = 12;
/// A fixed AddressMaskRequest header.
pub const ADDRESS_MASK_REQUEST_HEADER_TEMPLATE: [u8; 12] = [
    0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct AddressMaskRequest<T> {
    buf: T,
}
impl<T: Buf> AddressMaskRequest<T> {
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
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..12]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap())
    }
    #[inline]
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[6..8]).try_into().unwrap())
    }
    #[inline]
    pub fn address_mask(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be_bytes(
            (&self.buf.chunk()[8..12]).try_into().unwrap(),
        ))
    }
}
impl<T: PktBuf> AddressMaskRequest<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(12);
        buf
    }
}
impl<T: PktBufMut> AddressMaskRequest<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 12]) -> Self {
        assert!(buf.chunk_headroom() >= 12);
        buf.move_back(12);
        (&mut buf.chunk_mut()[0..12]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 17);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_identifier(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_sequence(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[6..8]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_address_mask(&mut self, value: Ipv4Addr) {
        let value = u32::from(value);
        assert!(value == 0);
        (&mut self.buf.chunk_mut()[8..12]).copy_from_slice(&value.to_be_bytes());
    }
}
impl<'a> AddressMaskRequest<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 12 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[12..])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 12]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 12] {
        ADDRESS_MASK_REQUEST_HEADER_TEMPLATE.clone()
    }
}
impl<'a> AddressMaskRequest<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 12 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[12..])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 12]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the AddressMaskReply protocol header.
pub const ADDRESS_MASK_REPLY_HEADER_LEN: usize = 12;
/// A fixed AddressMaskReply header.
pub const ADDRESS_MASK_REPLY_HEADER_TEMPLATE: [u8; 12] = [
    0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct AddressMaskReply<T> {
    buf: T,
}
impl<T: Buf> AddressMaskReply<T> {
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
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..12]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap())
    }
    #[inline]
    pub fn sequence(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[6..8]).try_into().unwrap())
    }
    #[inline]
    pub fn address_mask(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from_be_bytes(
            (&self.buf.chunk()[8..12]).try_into().unwrap(),
        ))
    }
}
impl<T: PktBuf> AddressMaskReply<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(12);
        buf
    }
}
impl<T: PktBufMut> AddressMaskReply<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 12]) -> Self {
        assert!(buf.chunk_headroom() >= 12);
        buf.move_back(12);
        (&mut buf.chunk_mut()[0..12]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 18);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_identifier(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_sequence(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[6..8]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_address_mask(&mut self, value: Ipv4Addr) {
        (&mut self.buf.chunk_mut()[8..12]).copy_from_slice(&u32::from(value).to_be_bytes());
    }
}
impl<'a> AddressMaskReply<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 12 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[12..])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 12]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 12] {
        ADDRESS_MASK_REPLY_HEADER_TEMPLATE.clone()
    }
}
impl<'a> AddressMaskReply<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 12 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[12..])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 12]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the ExtendedEchoRequest protocol header.
pub const EXTENDED_ECHO_REQUEST_HEADER_LEN: usize = 8;
/// A fixed ExtendedEchoRequest header.
pub const EXTENDED_ECHO_REQUEST_HEADER_TEMPLATE: [u8; 8] =
    [0x2a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct ExtendedEchoRequest<T> {
    buf: T,
}
impl<T: Buf> ExtendedEchoRequest<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap())
    }
    #[inline]
    pub fn sequence(&self) -> u8 {
        self.buf.chunk()[6]
    }
    #[inline]
    pub fn req(&self) -> bool {
        self.buf.chunk()[7] & 0x80 != 0
    }
    #[inline]
    pub fn reserved(&self) -> u8 {
        self.buf.chunk()[7] & 0x7f
    }
}
impl<T: PktBuf> ExtendedEchoRequest<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> ExtendedEchoRequest<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 42);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_identifier(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_sequence(&mut self, value: u8) {
        self.buf.chunk_mut()[6] = value;
    }
    #[inline]
    pub fn set_req(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[7] = (self.buf.chunk_mut()[7] & 0x7f) | (value << 7);
    }
    #[inline]
    pub fn set_reserved(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[7] = (self.buf.chunk_mut()[7] & 0x80) | value;
    }
}
impl<'a> ExtendedEchoRequest<Cursor<'a>> {
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
        EXTENDED_ECHO_REQUEST_HEADER_TEMPLATE.clone()
    }
}
impl<'a> ExtendedEchoRequest<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the ExtendedEchoReply protocol header.
pub const EXTENDED_ECHO_REPLY_HEADER_LEN: usize = 8;
/// A fixed ExtendedEchoReply header.
pub const EXTENDED_ECHO_REPLY_HEADER_TEMPLATE: [u8; 8] =
    [0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct ExtendedEchoReply<T> {
    buf: T,
}
impl<T: Buf> ExtendedEchoReply<T> {
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.chunk()[1]
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap())
    }
    #[inline]
    pub fn sequence(&self) -> u8 {
        self.buf.chunk()[6]
    }
    #[inline]
    pub fn req(&self) -> bool {
        self.buf.chunk()[7] & 0x80 != 0
    }
    #[inline]
    pub fn state(&self) -> u8 {
        (self.buf.chunk()[7] >> 4) & 0x7
    }
    #[inline]
    pub fn reserved(&self) -> u8 {
        self.buf.chunk()[7] & 0xf
    }
}
impl<T: PktBuf> ExtendedEchoReply<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> ExtendedEchoReply<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 43);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_identifier(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_sequence(&mut self, value: u8) {
        self.buf.chunk_mut()[6] = value;
    }
    #[inline]
    pub fn set_req(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[7] = (self.buf.chunk_mut()[7] & 0x7f) | (value << 7);
    }
    #[inline]
    pub fn set_state(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[7] = (self.buf.chunk_mut()[7] & 0x8f) | (value << 4);
    }
    #[inline]
    pub fn set_reserved(&mut self, value: u8) {
        assert!(value == 0);
        self.buf.chunk_mut()[7] = (self.buf.chunk_mut()[7] & 0xf0) | value;
    }
}
impl<'a> ExtendedEchoReply<Cursor<'a>> {
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
        EXTENDED_ECHO_REPLY_HEADER_TEMPLATE.clone()
    }
}
impl<'a> ExtendedEchoReply<CursorMut<'a>> {
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

#[derive(Debug)]
pub enum Icmpv4<T> {
    EchoReply_(EchoReply<T>),
    DestUnreachable_(DestUnreachable<T>),
    SourceQuench_(SourceQuench<T>),
    Redirect_(Redirect<T>),
    EchoRequest_(EchoRequest<T>),
    RouterAdvertisement_(RouterAdvertisement<T>),
    RouterSolicitation_(RouterSolicitation<T>),
    TimeExceeded_(TimeExceeded<T>),
    ParameterProblem_(ParameterProblem<T>),
    TimestampRequest_(TimestampRequest<T>),
    TimestampReply_(TimestampReply<T>),
    InformationRequest_(InformationRequest<T>),
    InformationReply_(InformationReply<T>),
    AddressMaskRequest_(AddressMaskRequest<T>),
    AddressMaskReply_(AddressMaskReply<T>),
    ExtendedEchoRequest_(ExtendedEchoRequest<T>),
    ExtendedEchoReply_(ExtendedEchoReply<T>),
}
impl<T: Buf> Icmpv4<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 1 {
            return Err(buf);
        }
        let cond_value0 = buf.chunk()[0];
        match cond_value0 {
            0 => EchoReply::parse(buf).map(|pkt| Icmpv4::EchoReply_(pkt)),
            3 => DestUnreachable::parse(buf).map(|pkt| Icmpv4::DestUnreachable_(pkt)),
            4 => SourceQuench::parse(buf).map(|pkt| Icmpv4::SourceQuench_(pkt)),
            5 => Redirect::parse(buf).map(|pkt| Icmpv4::Redirect_(pkt)),
            8 => EchoRequest::parse(buf).map(|pkt| Icmpv4::EchoRequest_(pkt)),
            9 => RouterAdvertisement::parse(buf).map(|pkt| Icmpv4::RouterAdvertisement_(pkt)),
            10 => RouterSolicitation::parse(buf).map(|pkt| Icmpv4::RouterSolicitation_(pkt)),
            11 => TimeExceeded::parse(buf).map(|pkt| Icmpv4::TimeExceeded_(pkt)),
            12 => ParameterProblem::parse(buf).map(|pkt| Icmpv4::ParameterProblem_(pkt)),
            13 => TimestampRequest::parse(buf).map(|pkt| Icmpv4::TimestampRequest_(pkt)),
            14 => TimestampReply::parse(buf).map(|pkt| Icmpv4::TimestampReply_(pkt)),
            15 => InformationRequest::parse(buf).map(|pkt| Icmpv4::InformationRequest_(pkt)),
            16 => InformationReply::parse(buf).map(|pkt| Icmpv4::InformationReply_(pkt)),
            17 => AddressMaskRequest::parse(buf).map(|pkt| Icmpv4::AddressMaskRequest_(pkt)),
            18 => AddressMaskReply::parse(buf).map(|pkt| Icmpv4::AddressMaskReply_(pkt)),
            42 => ExtendedEchoRequest::parse(buf).map(|pkt| Icmpv4::ExtendedEchoRequest_(pkt)),
            43 => ExtendedEchoReply::parse(buf).map(|pkt| Icmpv4::ExtendedEchoReply_(pkt)),
            _ => Err(buf),
        }
    }
}

// ICMP message type constants
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply = 0,
    DestUnreachable = 3,
    SourceQuench = 4,
    Redirect = 5,
    EchoRequest = 8,
    RouterAdvertisement = 9,
    RouterSolicitation = 10,
    TimeExceeded = 11,
    ParameterProblem = 12,
    TimestampRequest = 13,
    TimestampReply = 14,
    InformationRequest = 15,
    InformationReply = 16,
    AddressMaskRequest = 17,
    AddressMaskReply = 18,
    ExtendedEchoRequest = 42,
    ExtendedEchoReply = 43,
}

impl From<u8> for IcmpType {
    fn from(value: u8) -> Self {
        match value {
            0 => IcmpType::EchoReply,
            3 => IcmpType::DestUnreachable,
            4 => IcmpType::SourceQuench,
            5 => IcmpType::Redirect,
            8 => IcmpType::EchoRequest,
            9 => IcmpType::RouterAdvertisement,
            10 => IcmpType::RouterSolicitation,
            11 => IcmpType::TimeExceeded,
            12 => IcmpType::ParameterProblem,
            13 => IcmpType::TimestampRequest,
            14 => IcmpType::TimestampReply,
            15 => IcmpType::InformationRequest,
            16 => IcmpType::InformationReply,
            17 => IcmpType::AddressMaskRequest,
            18 => IcmpType::AddressMaskReply,
            42 => IcmpType::ExtendedEchoRequest,
            43 => IcmpType::ExtendedEchoReply,
            _ => panic!("Unknown ICMP type: {}", value),
        }
    }
}

impl From<IcmpType> for u8 {
    fn from(icmp_type: IcmpType) -> Self {
        icmp_type as u8
    }
}

// ICMP Destination Unreachable codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestUnreachableCode {
    NetworkUnreachable = 0,
    HostUnreachable = 1,
    ProtocolUnreachable = 2,
    PortUnreachable = 3,
    FragmentationNeededDfSet = 4,
    SourceRouteFailed = 5,
    DestNetworkUnknown = 6,
    DestHostUnknown = 7,
    SourceHostIsolated = 8,
    NetworkProhibited = 9,
    HostProhibited = 10,
    NetworkUnreachableForTos = 11,
    HostUnreachableForTos = 12,
    CommunicationProhibited = 13,
    HostPrecedenceViolation = 14,
    PrecedenceCutoffInEffect = 15,
}

// ICMP Redirect codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectCode {
    RedirectForNetwork = 0,
    RedirectForHost = 1,
    RedirectForTosAndNetwork = 2,
    RedirectForTosAndHost = 3,
}

// ICMP Time Exceeded codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeExceededCode {
    TtlExceededInTransit = 0,
    FragmentReassemblyTimeExceeded = 1,
}

// ICMP Parameter Problem codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterProblemCode {
    PointerIndicatesError = 0,
    MissingRequiredOption = 1,
    BadLength = 2,
}

// Helper function to calculate ICMP checksum
pub fn calculate_icmp_checksum(icmp_data: &[u8]) -> u16 {
    let mut checksum: u32 = 0;
    let mut i = 0;

    // Sum all 16-bit words
    while i < icmp_data.len() - 1 {
        let word = ((icmp_data[i] as u32) << 8) | (icmp_data[i + 1] as u32);
        checksum += word;
        i += 2;
    }

    // Add the odd byte if present
    if i < icmp_data.len() {
        checksum += (icmp_data[i] as u32) << 8;
    }

    // Fold 32-bit checksum to 16 bits
    while (checksum >> 16) != 0 {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    // One's complement
    !checksum as u16
}
