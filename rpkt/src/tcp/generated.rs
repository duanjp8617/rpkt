#![allow(missing_docs)]
#![allow(unused_parens)]

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
        if ((container.header_len() as usize) < 20)
            || ((container.header_len() as usize) > chunk_len)
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
        if ((container.header_len() as usize) < 20)
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
impl<'a> Tcp<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 20 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) < 20)
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

/// A constant that defines the fixed byte length of the MssOption protocol header.
pub const MSSOPTION_HEADER_LEN: usize = 4;
/// A fixed MssOption header.
pub const MSSOPTION_HEADER_TEMPLATE: [u8; 4] = [0x02, 0x04, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct MssOption<T> {
    buf: T,
}
impl<T: Buf> MssOption<T> {
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
    pub fn mss(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[1])
    }
}
impl<T: PktBuf> MssOption<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> MssOption<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        let header_len = MssOption::parse_unchecked(&header[..]).header_len() as usize;
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
impl<'a> MssOption<Cursor<'a>> {
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
impl<'a> MssOption<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the WsoptOption protocol header.
pub const WSOPTOPTION_HEADER_LEN: usize = 3;
/// A fixed WsoptOption header.
pub const WSOPTOPTION_HEADER_TEMPLATE: [u8; 3] = [0x03, 0x03, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct WsoptOption<T> {
    buf: T,
}
impl<T: Buf> WsoptOption<T> {
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
        if ((container.header_len() as usize) != 3)
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn wsopt(&self) -> u8 {
        self.buf.chunk()[2]
    }
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[1])
    }
}
impl<T: PktBuf> WsoptOption<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> WsoptOption<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 3]) -> Self {
        let header_len = WsoptOption::parse_unchecked(&header[..]).header_len() as usize;
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
    pub fn set_wsopt(&mut self, value: u8) {
        self.buf.chunk_mut()[2] = value;
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        assert!((value == 3));
        self.buf.chunk_mut()[1] = (value);
    }
}
impl<'a> WsoptOption<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 3 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.header_len() as usize) != 3 {
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
impl<'a> WsoptOption<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 3 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.header_len() as usize) != 3 {
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

/// A constant that defines the fixed byte length of the SackpermOption protocol header.
pub const SACKPERMOPTION_HEADER_LEN: usize = 2;
/// A fixed SackpermOption header.
pub const SACKPERMOPTION_HEADER_TEMPLATE: [u8; 2] = [0x04, 0x02];

#[derive(Debug, Clone, Copy)]
pub struct SackpermOption<T> {
    buf: T,
}
impl<T: Buf> SackpermOption<T> {
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
        if ((container.header_len() as usize) != 2)
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
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[1])
    }
}
impl<T: PktBuf> SackpermOption<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> SackpermOption<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        let header_len = SackpermOption::parse_unchecked(&header[..]).header_len() as usize;
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
impl<'a> SackpermOption<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.header_len() as usize) != 2 {
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
impl<'a> SackpermOption<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 2 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.header_len() as usize) != 2 {
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

/// A constant that defines the fixed byte length of the SackOption protocol header.
pub const SACKOPTION_HEADER_LEN: usize = 2;
/// A fixed SackOption header.
pub const SACKOPTION_HEADER_TEMPLATE: [u8; 2] = [0x05, 0x0a];

#[derive(Debug, Clone, Copy)]
pub struct SackOption<T> {
    buf: T,
}
impl<T: Buf> SackOption<T> {
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
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[1])
    }
}
impl<T: PktBuf> SackOption<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> SackOption<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2]) -> Self {
        let header_len = SackOption::parse_unchecked(&header[..]).header_len() as usize;
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
impl<'a> SackOption<Cursor<'a>> {
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
}
impl<'a> SackOption<CursorMut<'a>> {
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
}

/// A constant that defines the fixed byte length of the TsOption protocol header.
pub const TSOPTION_HEADER_LEN: usize = 10;
/// A fixed TsOption header.
pub const TSOPTION_HEADER_TEMPLATE: [u8; 10] =
    [0x08, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct TsOption<T> {
    buf: T,
}
impl<T: Buf> TsOption<T> {
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
        if ((container.header_len() as usize) != 10)
            || ((container.header_len() as usize) > chunk_len)
        {
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
impl<T: PktBuf> TsOption<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> TsOption<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 10]) -> Self {
        let header_len = TsOption::parse_unchecked(&header[..]).header_len() as usize;
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
impl<'a> TsOption<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 10 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.header_len() as usize) != 10 {
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
impl<'a> TsOption<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 10 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.header_len() as usize) != 10 {
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

/// A constant that defines the fixed byte length of the FoOption protocol header.
pub const FOOPTION_HEADER_LEN: usize = 18;
/// A fixed FoOption header.
pub const FOOPTION_HEADER_TEMPLATE: [u8; 18] = [
    0x22, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct FoOption<T> {
    buf: T,
}
impl<T: Buf> FoOption<T> {
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
        if chunk_len < 18 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.header_len() as usize) != 18)
            || ((container.header_len() as usize) > chunk_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..18]
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0]
    }
    #[inline]
    pub fn fo(&self) -> &[u8] {
        &self.buf.chunk()[2..18]
    }
    #[inline]
    pub fn header_len(&self) -> u8 {
        (self.buf.chunk()[1])
    }
}
impl<T: PktBuf> FoOption<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> FoOption<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 18]) -> Self {
        let header_len = FoOption::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len == 18) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..18]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 34);
        self.buf.chunk_mut()[0] = value;
    }
    #[inline]
    pub fn set_fo(&mut self, value: &[u8]) {
        (&mut self.buf.chunk_mut()[2..18]).copy_from_slice(value);
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        assert!((value == 18));
        self.buf.chunk_mut()[1] = (value);
    }
}
impl<'a> FoOption<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 18 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.header_len() as usize) != 18 {
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
impl<'a> FoOption<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 18 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.header_len() as usize) != 18 {
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
pub enum TcpOptions<T> {
    EolOption_(EolOption<T>),
    NopOption_(NopOption<T>),
    MssOption_(MssOption<T>),
    WsoptOption_(WsoptOption<T>),
    SackpermOption_(SackpermOption<T>),
    SackOption_(SackOption<T>),
    TsOption_(TsOption<T>),
    FoOption_(FoOption<T>),
}
impl<T: Buf> TcpOptions<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 1 {
            return Err(buf);
        }
        let cond_value = buf.chunk()[0];
        match cond_value {
            0 => EolOption::parse(buf).map(|pkt| TcpOptions::EolOption_(pkt)),
            1 => NopOption::parse(buf).map(|pkt| TcpOptions::NopOption_(pkt)),
            2 => MssOption::parse(buf).map(|pkt| TcpOptions::MssOption_(pkt)),
            3 => WsoptOption::parse(buf).map(|pkt| TcpOptions::WsoptOption_(pkt)),
            4 => SackpermOption::parse(buf).map(|pkt| TcpOptions::SackpermOption_(pkt)),
            5 => SackOption::parse(buf).map(|pkt| TcpOptions::SackOption_(pkt)),
            8 => TsOption::parse(buf).map(|pkt| TcpOptions::TsOption_(pkt)),
            34 => FoOption::parse(buf).map(|pkt| TcpOptions::FoOption_(pkt)),
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
        let cond_value = self.buf[0];
        match cond_value {
            0 => EolOption::parse(self.buf)
                .map(|_pkt| {
                    let result = EolOption {
                        buf: Cursor::new(&self.buf[..1]),
                    };
                    self.buf = &self.buf[1..];
                    TcpOptions::EolOption_(result)
                })
                .ok(),
            1 => NopOption::parse(self.buf)
                .map(|_pkt| {
                    let result = NopOption {
                        buf: Cursor::new(&self.buf[..1]),
                    };
                    self.buf = &self.buf[1..];
                    TcpOptions::NopOption_(result)
                })
                .ok(),
            2 => MssOption::parse(self.buf)
                .map(|_pkt| {
                    let result = MssOption {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    TcpOptions::MssOption_(result)
                })
                .ok(),
            3 => WsoptOption::parse(self.buf)
                .map(|_pkt| {
                    let result = WsoptOption {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    TcpOptions::WsoptOption_(result)
                })
                .ok(),
            4 => SackpermOption::parse(self.buf)
                .map(|_pkt| {
                    let result = SackpermOption {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    TcpOptions::SackpermOption_(result)
                })
                .ok(),
            5 => SackOption::parse(self.buf)
                .map(|_pkt| {
                    let result = SackOption {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    TcpOptions::SackOption_(result)
                })
                .ok(),
            8 => TsOption::parse(self.buf)
                .map(|_pkt| {
                    let result = TsOption {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    TcpOptions::TsOption_(result)
                })
                .ok(),
            34 => FoOption::parse(self.buf)
                .map(|_pkt| {
                    let result = FoOption {
                        buf: Cursor::new(&self.buf[.._pkt.header_len() as usize]),
                    };
                    self.buf = &self.buf[_pkt.header_len() as usize..];
                    TcpOptions::FoOption_(result)
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
        let cond_value = self.buf[0];
        match cond_value {
            0 => match EolOption::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(1);
                    self.buf = snd;
                    let result = EolOption {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::EolOption_(result))
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
                    Some(TcpOptions::NopOption_(result))
                }
                Err(_) => None,
            },
            2 => match MssOption::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = MssOption {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::MssOption_(result))
                }
                Err(_) => None,
            },
            3 => match WsoptOption::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = WsoptOption {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::WsoptOption_(result))
                }
                Err(_) => None,
            },
            4 => match SackpermOption::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = SackpermOption {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::SackpermOption_(result))
                }
                Err(_) => None,
            },
            5 => match SackOption::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = SackOption {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::SackOption_(result))
                }
                Err(_) => None,
            },
            8 => match TsOption::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = TsOption {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::TsOption_(result))
                }
                Err(_) => None,
            },
            34 => match FoOption::parse(&self.buf[..]) {
                Ok(_pkt) => {
                    let header_len = _pkt.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = FoOption {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptions::FoOption_(result))
                }
                Err(_) => None,
            },
            _ => None,
        }
    }
}
