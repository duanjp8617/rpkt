#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::cursors::{CursorIndex, CursorIndexMut};
use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

/// A constant that defines the fixed byte length of the Tcp protocol header.
pub const TCP_HEADER_LEN: usize = 20;
/// A fixed Tcp header.
pub const TCP_HEADER_TEMPLATE: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct Tcp<T> {
    buf: T,
}
impl<T: Buf> Tcp<T> {
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
        let header_len = container.header_len() as usize;
        if (header_len < 20) || (header_len > chunk_len) {
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
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[0..2]).try_into().unwrap())
    }
    #[inline]
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn seq_num(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[4..8]).try_into().unwrap())
    }
    #[inline]
    pub fn ack_num(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[8..12]).try_into().unwrap())
    }
    #[inline]
    pub fn reserved(&self) -> u8 {
        self.buf.chunk()[12] & 0xf
    }
    #[inline]
    pub fn cwr(&self) -> bool {
        self.buf.chunk()[13] & 0x80 != 0
    }
    #[inline]
    pub fn ece(&self) -> bool {
        self.buf.chunk()[13] & 0x40 != 0
    }
    #[inline]
    pub fn urg(&self) -> bool {
        self.buf.chunk()[13] & 0x20 != 0
    }
    #[inline]
    pub fn ack(&self) -> bool {
        self.buf.chunk()[13] & 0x10 != 0
    }
    #[inline]
    pub fn psh(&self) -> bool {
        self.buf.chunk()[13] & 0x8 != 0
    }
    #[inline]
    pub fn rst(&self) -> bool {
        self.buf.chunk()[13] & 0x4 != 0
    }
    #[inline]
    pub fn syn(&self) -> bool {
        self.buf.chunk()[13] & 0x2 != 0
    }
    #[inline]
    pub fn fin(&self) -> bool {
        self.buf.chunk()[13] & 0x1 != 0
    }
    #[inline]
    pub fn window_size(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[14..16]).try_into().unwrap())
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[16..18]).try_into().unwrap())
    }
    #[inline]
    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[18..20]).try_into().unwrap())
    }
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[12] >> 4) * 4
    }
}
impl<T: PktBuf> Tcp<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> Tcp<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 20]) -> Self {
        let header_len = Tcp::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 20) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..20]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[20..header_len]
    }
    #[inline]
    pub fn set_src_port(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_dst_port(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_seq_num(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[4..8]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_ack_num(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[8..12]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_reserved(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[12] = (self.buf.chunk_mut()[12] & 0xf0) | value;
    }
    #[inline]
    pub fn set_cwr(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[13] = (self.buf.chunk_mut()[13] & 0x7f) | (value << 7);
    }
    #[inline]
    pub fn set_ece(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[13] = (self.buf.chunk_mut()[13] & 0xbf) | (value << 6);
    }
    #[inline]
    pub fn set_urg(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[13] = (self.buf.chunk_mut()[13] & 0xdf) | (value << 5);
    }
    #[inline]
    pub fn set_ack(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[13] = (self.buf.chunk_mut()[13] & 0xef) | (value << 4);
    }
    #[inline]
    pub fn set_psh(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[13] = (self.buf.chunk_mut()[13] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_rst(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[13] = (self.buf.chunk_mut()[13] & 0xfb) | (value << 2);
    }
    #[inline]
    pub fn set_syn(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[13] = (self.buf.chunk_mut()[13] & 0xfd) | (value << 1);
    }
    #[inline]
    pub fn set_fin(&mut self, value: bool) {
        let value = if value { 1 } else { 0 };
        self.buf.chunk_mut()[13] = (self.buf.chunk_mut()[13] & 0xfe) | value;
    }
    #[inline]
    pub fn set_window_size(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[14..16]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[16..18]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_urgent_pointer(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[18..20]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        assert!((value <= 60) && (value % 4 == 0));
        self.buf.chunk_mut()[12] = (self.buf.chunk_mut()[12] & 0x0f) | ((value / 4) << 4);
    }
}
impl<'a> Tcp<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 20 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if (header_len < 20) || (header_len > remaining_len) {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_(header_len..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 20]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 20] {
        TCP_HEADER_TEMPLATE.clone()
    }
}
impl<'a> Tcp<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 20 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if (header_len < 20) || (header_len > remaining_len) {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_mut_(header_len..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 20]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the Eol protocol header.
pub const EOL_HEADER_LEN: usize = 1;
/// A fixed Eol header.
pub const EOL_HEADER_TEMPLATE: [u8; 1] = [0x00];

#[derive(Debug, Clone, Copy)]
pub struct Eol<T> {
    buf: T,
}
impl<T: Buf> Eol<T> {
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
impl<T: PktBuf> Eol<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(1);
        buf
    }
}
impl<T: PktBufMut> Eol<T> {
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
impl<'a> Eol<Cursor<'a>> {
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
        self.buf.index_(1..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 1]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 1] {
        EOL_HEADER_TEMPLATE.clone()
    }
}
impl<'a> Eol<CursorMut<'a>> {
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
        self.buf.index_mut_(1..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 1]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the Nop protocol header.
pub const NOP_HEADER_LEN: usize = 1;
/// A fixed Nop header.
pub const NOP_HEADER_TEMPLATE: [u8; 1] = [0x01];

#[derive(Debug, Clone, Copy)]
pub struct Nop<T> {
    buf: T,
}
impl<T: Buf> Nop<T> {
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
impl<T: PktBuf> Nop<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(1);
        buf
    }
}
impl<T: PktBufMut> Nop<T> {
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
impl<'a> Nop<Cursor<'a>> {
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
        self.buf.index_(1..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 1]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 1] {
        NOP_HEADER_TEMPLATE.clone()
    }
}
impl<'a> Nop<CursorMut<'a>> {
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
        self.buf.index_mut_(1..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 1]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the Mss protocol header.
pub const MSS_HEADER_LEN: usize = 4;
/// A fixed Mss header.
pub const MSS_HEADER_TEMPLATE: [u8; 4] = [0x02, 0x04, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct Mss<T> {
    buf: T,
}
impl<T: Buf> Mss<T> {
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
        let header_len = container.header_len() as usize;
        if header_len != 4 {
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
    pub fn mss(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[1])
    }
}
impl<T: PktBuf> Mss<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> Mss<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        let header_len = Mss::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len == 4) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 2);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_mss(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        assert!((value == 4));
        self.buf.chunk_mut()[1] = (value);
    }
}
impl<'a> Mss<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if header_len != 4 {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_(header_len..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 4]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 4] {
        MSS_HEADER_TEMPLATE.clone()
    }
}
impl<'a> Mss<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if header_len != 4 {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_mut_(header_len..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 4]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the WindowScale protocol header.
pub const WINDOW_SCALE_HEADER_LEN: usize = 3;
/// A fixed WindowScale header.
pub const WINDOW_SCALE_HEADER_TEMPLATE: [u8; 3] = [0x03, 0x03, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct WindowScale<T> {
    buf: T,
}
impl<T: Buf> WindowScale<T> {
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
        let header_len = container.header_len() as usize;
        if header_len != 3 {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..3]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn shift_count(&self) -> u8 {
        self.buf.chunk()[2]
    }
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[1])
    }
}
impl<T: PktBuf> WindowScale<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> WindowScale<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 3]) -> Self {
        let header_len = WindowScale::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len == 3) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..3]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 3);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_shift_count(&mut self, value: u8) {
        self.buf.chunk_mut()[2] = value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        assert!((value == 3));
        self.buf.chunk_mut()[1] = (value);
    }
}
impl<'a> WindowScale<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 3 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if header_len != 3 {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_(header_len..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 3]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 3] {
        WINDOW_SCALE_HEADER_TEMPLATE.clone()
    }
}
impl<'a> WindowScale<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 3 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if header_len != 3 {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_mut_(header_len..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 3]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the SackPermitted protocol header.
pub const SACK_PERMITTED_HEADER_LEN: usize = 2;
/// A fixed SackPermitted header.
pub const SACK_PERMITTED_HEADER_TEMPLATE: [u8; 2] = [0x04, 0x02];

#[derive(Debug, Clone, Copy)]
pub struct SackPermitted<T> {
    buf: T,
}
impl<T: Buf> SackPermitted<T> {
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
        let header_len = container.header_len() as usize;
        if header_len != 2 {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..2]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[1])
    }
}
impl<T: PktBuf> SackPermitted<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> SackPermitted<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        let header_len = SackPermitted::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len == 2) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..2]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 4);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        assert!((value == 2));
        self.buf.chunk_mut()[1] = (value);
    }
}
impl<'a> SackPermitted<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if header_len != 2 {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_(header_len..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 2]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 2] {
        SACK_PERMITTED_HEADER_TEMPLATE.clone()
    }
}
impl<'a> SackPermitted<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if header_len != 2 {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_mut_(header_len..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 2]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the Sack protocol header.
pub const SACK_HEADER_LEN: usize = 2;
/// A fixed Sack header.
pub const SACK_HEADER_TEMPLATE: [u8; 2] = [0x05, 0x0a];

#[derive(Debug, Clone, Copy)]
pub struct Sack<T> {
    buf: T,
}
impl<T: Buf> Sack<T> {
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
        let header_len = container.header_len() as usize;
        if (header_len < 2) || (header_len > chunk_len) {
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
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[1])
    }
}
impl<T: PktBuf> Sack<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> Sack<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        let header_len = Sack::parse_unchecked(&header[..]).header_len() as usize;
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
        assert!(value == 5);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = (value);
    }
}
impl<'a> Sack<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if (header_len < 2) || (header_len > remaining_len) {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_(header_len..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 2]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 2] {
        SACK_HEADER_TEMPLATE.clone()
    }
}
impl<'a> Sack<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if (header_len < 2) || (header_len > remaining_len) {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_mut_(header_len..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 2]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the Timestamp protocol header.
pub const TIMESTAMP_HEADER_LEN: usize = 10;
/// A fixed Timestamp header.
pub const TIMESTAMP_HEADER_TEMPLATE: [u8; 10] =
    [0x08, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct Timestamp<T> {
    buf: T,
}
impl<T: Buf> Timestamp<T> {
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
        if chunk_len < 10 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if header_len != 10 {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..10]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn ts(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[2..6]).try_into().unwrap())
    }
    #[inline]
    pub fn ts_echo(&self) -> u32 {
        u32::from_be_bytes((&self.buf.chunk()[6..10]).try_into().unwrap())
    }
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[1])
    }
}
impl<T: PktBuf> Timestamp<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> Timestamp<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 10]) -> Self {
        let header_len = Timestamp::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len == 10) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..10]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 8);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_ts(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[2..6]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_ts_echo(&mut self, value: u32) {
        (&mut self.buf.chunk_mut()[6..10]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        assert!((value == 10));
        self.buf.chunk_mut()[1] = (value);
    }
}
impl<'a> Timestamp<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 10 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if header_len != 10 {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_(header_len..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 10]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 10] {
        TIMESTAMP_HEADER_TEMPLATE.clone()
    }
}
impl<'a> Timestamp<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 10 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if header_len != 10 {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_mut_(header_len..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 10]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the FastOpen protocol header.
pub const FAST_OPEN_HEADER_LEN: usize = 2;
/// A fixed FastOpen header.
pub const FAST_OPEN_HEADER_TEMPLATE: [u8; 2] = [0x22, 0x12];

#[derive(Debug, Clone, Copy)]
pub struct FastOpen<T> {
    buf: T,
}
impl<T: Buf> FastOpen<T> {
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
        let header_len = container.header_len() as usize;
        if (header_len < 2) || (header_len > chunk_len) {
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
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[1])
    }
}
impl<T: PktBuf> FastOpen<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> FastOpen<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        let header_len = FastOpen::parse_unchecked(&header[..]).header_len() as usize;
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
        assert!(value == 34);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        self.buf.chunk_mut()[1] = (value);
    }
}
impl<'a> FastOpen<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if (header_len < 2) || (header_len > remaining_len) {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_(header_len..)
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 2]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
    #[inline]
    pub fn default_header() -> [u8; 2] {
        FAST_OPEN_HEADER_TEMPLATE.clone()
    }
}
impl<'a> FastOpen<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        let header_len = container.header_len() as usize;
        if (header_len < 2) || (header_len > remaining_len) {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let header_len = self.header_len() as usize;
        self.buf.index_mut_(header_len..)
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 2]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

#[derive(Debug)]
pub enum TcpOptions<T> {
    Eol_(Eol<T>),
    Nop_(Nop<T>),
    Mss_(Mss<T>),
    WindowScale_(WindowScale<T>),
    SackPermitted_(SackPermitted<T>),
    Sack_(Sack<T>),
    Timestamp_(Timestamp<T>),
    FastOpen_(FastOpen<T>),
}
impl<T: Buf> TcpOptions<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 1 {
            return Err(buf);
        }
        let cond_value0 = buf.chunk()[0];
        match cond_value0 {
            0 => Eol::parse(buf).map(|pkt| TcpOptions::Eol_(pkt)),
            1 => Nop::parse(buf).map(|pkt| TcpOptions::Nop_(pkt)),
            2 => Mss::parse(buf).map(|pkt| TcpOptions::Mss_(pkt)),
            3 => WindowScale::parse(buf).map(|pkt| TcpOptions::WindowScale_(pkt)),
            4 => SackPermitted::parse(buf).map(|pkt| TcpOptions::SackPermitted_(pkt)),
            5 => Sack::parse(buf).map(|pkt| TcpOptions::Sack_(pkt)),
            8 => Timestamp::parse(buf).map(|pkt| TcpOptions::Timestamp_(pkt)),
            34 => FastOpen::parse(buf).map(|pkt| TcpOptions::FastOpen_(pkt)),
            _ => Err(buf),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TcpOptionsIter<'a> {
    buf: &'a [u8],
}
impl<'a> TcpOptionsIter<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Self {
        Self { buf: slice }
    }

    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }
}
impl<'a> Iterator for TcpOptionsIter<'a> {
    type Item = TcpOptions<Cursor<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 1 {
            return None;
        }
        let cond_value0 = self.buf[0];
        match cond_value0 {
            0 => Eol::parse(self.buf)
                .map(|_pkt| {
                    let result = Eol {
                        buf: Cursor::new(&self.buf[..1]),
                    };
                    self.buf = &self.buf[1..];
                    TcpOptions::Eol_(result)
                })
                .ok(),
            1 => Nop::parse(self.buf)
                .map(|_pkt| {
                    let result = Nop {
                        buf: Cursor::new(&self.buf[..1]),
                    };
                    self.buf = &self.buf[1..];
                    TcpOptions::Nop_(result)
                })
                .ok(),
            2 => Mss::parse(self.buf)
                .map(|_pkt| {
                    let result = Mss {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    TcpOptions::Mss_(result)
                })
                .ok(),
            3 => WindowScale::parse(self.buf)
                .map(|_pkt| {
                    let result = WindowScale {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    TcpOptions::WindowScale_(result)
                })
                .ok(),
            4 => SackPermitted::parse(self.buf)
                .map(|_pkt| {
                    let result = SackPermitted {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    TcpOptions::SackPermitted_(result)
                })
                .ok(),
            5 => Sack::parse(self.buf)
                .map(|_pkt| {
                    let result = Sack {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    TcpOptions::Sack_(result)
                })
                .ok(),
            8 => Timestamp::parse(self.buf)
                .map(|_pkt| {
                    let result = Timestamp {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    TcpOptions::Timestamp_(result)
                })
                .ok(),
            34 => FastOpen::parse(self.buf)
                .map(|_pkt| {
                    let result = FastOpen {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    TcpOptions::FastOpen_(result)
                })
                .ok(),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct TcpOptionsIterMut<'a> {
    buf: &'a mut [u8],
}
impl<'a> TcpOptionsIterMut<'a> {
    pub fn from_slice_mut(slice_mut: &'a mut [u8]) -> Self {
        Self { buf: slice_mut }
    }

    pub fn buf(&self) -> &[u8] {
        &self.buf[..]
    }
}
impl<'a> Iterator for TcpOptionsIterMut<'a> {
    type Item = TcpOptions<CursorMut<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.len() < 1 {
            return None;
        }
        let cond_value0 = self.buf[0];
        match cond_value0 {
            0 => match Eol::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(1);
                    self.buf = snd;
                    let result = Eol {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::Eol_(result))
                }
                Err(_) => None,
            },
            1 => match Nop::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(1);
                    self.buf = snd;
                    let result = Nop {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::Nop_(result))
                }
                Err(_) => None,
            },
            2 => match Mss::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = Mss {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::Mss_(result))
                }
                Err(_) => None,
            },
            3 => match WindowScale::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = WindowScale {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::WindowScale_(result))
                }
                Err(_) => None,
            },
            4 => match SackPermitted::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = SackPermitted {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::SackPermitted_(result))
                }
                Err(_) => None,
            },
            5 => match Sack::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = Sack {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::Sack_(result))
                }
                Err(_) => None,
            },
            8 => match Timestamp::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = Timestamp {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::Timestamp_(result))
                }
                Err(_) => None,
            },
            34 => match FastOpen::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = FastOpen {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::FastOpen_(result))
                }
                Err(_) => None,
            },
            _ => None,
        }
    }
}
