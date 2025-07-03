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
pub struct TcpPacket<T> {
    buf: T,
}
impl<T: Buf> TcpPacket<T> {
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
impl<T: PktBuf> TcpPacket<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> TcpPacket<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 20], header_len: u8) -> Self {
        assert!((header_len >= 20) && (header_len as usize <= buf.chunk_headroom()));
        buf.move_back(header_len as usize);
        (&mut buf.chunk_mut()[0..20]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_header_len(header_len);
        container
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
        if value {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] | 0x80
        } else {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] & 0x7f
        }
    }
    #[inline]
    pub fn set_ece(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] | 0x40
        } else {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] & 0xbf
        }
    }
    #[inline]
    pub fn set_urg(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] | 0x20
        } else {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] & 0xdf
        }
    }
    #[inline]
    pub fn set_ack(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] | 0x10
        } else {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] & 0xef
        }
    }
    #[inline]
    pub fn set_psh(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] | 0x8
        } else {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] & 0xf7
        }
    }
    #[inline]
    pub fn set_rst(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] | 0x4
        } else {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] & 0xfb
        }
    }
    #[inline]
    pub fn set_syn(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] | 0x2
        } else {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] & 0xfd
        }
    }
    #[inline]
    pub fn set_fin(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] | 0x1
        } else {
            self.buf.chunk_mut()[13] = self.buf.chunk_mut()[13] & 0xfe
        }
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
impl<'a> TcpPacket<Cursor<'a>> {
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
impl<'a> TcpPacket<CursorMut<'a>> {
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
    pub fn fix_header_slice(&self) -> &[u8] {
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
    pub fn fix_header_slice(&self) -> &[u8] {
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

/// A constant that defines the fixed byte length of the Mss protocol header.
pub const MSS_HEADER_LEN: usize = 4;
/// A fixed Mss header.
pub const MSS_HEADER_TEMPLATE: [u8; 4] = [0x02, 0x04, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct MssMessage<T> {
    buf: T,
}
impl<T: Buf> MssMessage<T> {
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
impl<T: PktBuf> MssMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> MssMessage<T> {
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
impl<'a> MssMessage<Cursor<'a>> {
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
impl<'a> MssMessage<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the Wsopt protocol header.
pub const WSOPT_HEADER_LEN: usize = 3;
/// A fixed Wsopt header.
pub const WSOPT_HEADER_TEMPLATE: [u8; 3] = [0x03, 0x03, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct WsoptMessage<T> {
    buf: T,
}
impl<T: Buf> WsoptMessage<T> {
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
impl<T: PktBuf> WsoptMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> WsoptMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 3], header_len: u8) -> Self {
        assert!((header_len == 3) && (header_len as usize <= buf.chunk_headroom()));
        buf.move_back(header_len as usize);
        (&mut buf.chunk_mut()[0..3]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_header_len(header_len);
        container
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
impl<'a> WsoptMessage<Cursor<'a>> {
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
impl<'a> WsoptMessage<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the Sackperm protocol header.
pub const SACKPERM_HEADER_LEN: usize = 2;
/// A fixed Sackperm header.
pub const SACKPERM_HEADER_TEMPLATE: [u8; 2] = [0x04, 0x02];

#[derive(Debug, Clone, Copy)]
pub struct SackpermMessage<T> {
    buf: T,
}
impl<T: Buf> SackpermMessage<T> {
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
impl<T: PktBuf> SackpermMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> SackpermMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2], header_len: u8) -> Self {
        assert!((header_len == 2) && (header_len as usize <= buf.chunk_headroom()));
        buf.move_back(header_len as usize);
        (&mut buf.chunk_mut()[0..2]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_header_len(header_len);
        container
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
impl<'a> SackpermMessage<Cursor<'a>> {
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
impl<'a> SackpermMessage<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the Sack protocol header.
pub const SACK_HEADER_LEN: usize = 2;
/// A fixed Sack header.
pub const SACK_HEADER_TEMPLATE: [u8; 2] = [0x05, 0x0a];

#[derive(Debug, Clone, Copy)]
pub struct SackMessage<T> {
    buf: T,
}
impl<T: Buf> SackMessage<T> {
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
impl<T: PktBuf> SackMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> SackMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 2], header_len: u8) -> Self {
        assert!((header_len >= 2) && (header_len as usize <= buf.chunk_headroom()));
        buf.move_back(header_len as usize);
        (&mut buf.chunk_mut()[0..2]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_header_len(header_len);
        container
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
impl<'a> SackMessage<Cursor<'a>> {
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
impl<'a> SackMessage<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the Ts protocol header.
pub const TS_HEADER_LEN: usize = 10;
/// A fixed Ts header.
pub const TS_HEADER_TEMPLATE: [u8; 10] =
    [0x08, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct TsMessage<T> {
    buf: T,
}
impl<T: Buf> TsMessage<T> {
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
impl<T: PktBuf> TsMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> TsMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 10], header_len: u8) -> Self {
        assert!((header_len == 10) && (header_len as usize <= buf.chunk_headroom()));
        buf.move_back(header_len as usize);
        (&mut buf.chunk_mut()[0..10]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_header_len(header_len);
        container
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
impl<'a> TsMessage<Cursor<'a>> {
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
impl<'a> TsMessage<CursorMut<'a>> {
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

/// A constant that defines the fixed byte length of the Fo protocol header.
pub const FO_HEADER_LEN: usize = 18;
/// A fixed Fo header.
pub const FO_HEADER_TEMPLATE: [u8; 18] = [
    0x22, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
];

#[derive(Debug, Clone, Copy)]
pub struct FoMessage<T> {
    buf: T,
}
impl<T: Buf> FoMessage<T> {
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
impl<T: PktBuf> FoMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> FoMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 18], header_len: u8) -> Self {
        assert!((header_len == 18) && (header_len as usize <= buf.chunk_headroom()));
        buf.move_back(header_len as usize);
        (&mut buf.chunk_mut()[0..18]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_header_len(header_len);
        container
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
impl<'a> FoMessage<Cursor<'a>> {
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
impl<'a> FoMessage<CursorMut<'a>> {
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
pub enum TcpOptGroup<T> {
    Eol_(EolMessage<T>),
    Nop_(NopMessage<T>),
    Mss_(MssMessage<T>),
    Wsopt_(WsoptMessage<T>),
    Sackperm_(SackpermMessage<T>),
    Sack_(SackMessage<T>),
    Ts_(TsMessage<T>),
    Fo_(FoMessage<T>),
}
impl<T: Buf> TcpOptGroup<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 1 {
            return Err(buf);
        }
        let cond_value = buf.chunk()[0];
        match cond_value {
            0 => EolMessage::parse(buf).map(|msg| TcpOptGroup::Eol_(msg)),
            1 => NopMessage::parse(buf).map(|msg| TcpOptGroup::Nop_(msg)),
            2 => MssMessage::parse(buf).map(|msg| TcpOptGroup::Mss_(msg)),
            3 => WsoptMessage::parse(buf).map(|msg| TcpOptGroup::Wsopt_(msg)),
            4 => SackpermMessage::parse(buf).map(|msg| TcpOptGroup::Sackperm_(msg)),
            5 => SackMessage::parse(buf).map(|msg| TcpOptGroup::Sack_(msg)),
            8 => TsMessage::parse(buf).map(|msg| TcpOptGroup::Ts_(msg)),
            34 => FoMessage::parse(buf).map(|msg| TcpOptGroup::Fo_(msg)),
            _ => Err(buf),
        }
    }
}
#[derive(Debug, Clone, Copy)]
pub struct TcpOptGroupIter<'a> {
    buf: &'a [u8],
}
impl<'a> TcpOptGroupIter<'a> {
    pub fn from_message_slice(message_slice: &'a [u8]) -> Self {
        Self { buf: message_slice }
    }

    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }
}
#[derive(Debug)]
pub struct TcpOptGroupIterMut<'a> {
    buf: &'a mut [u8],
}
impl<'a> TcpOptGroupIterMut<'a> {
    pub fn from_message_slice_mut(message_slice_mut: &'a mut [u8]) -> Self {
        Self {
            buf: message_slice_mut,
        }
    }

    pub fn buf(&self) -> &[u8] {
        &self.buf[..]
    }
}
impl<'a> Iterator for TcpOptGroupIter<'a> {
    type Item = TcpOptGroup<Cursor<'a>>;
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
                    TcpOptGroup::Eol_(result)
                })
                .ok(),
            1 => NopMessage::parse(self.buf)
                .map(|_msg| {
                    let result = NopMessage {
                        buf: Cursor::new(&self.buf[..1]),
                    };
                    self.buf = &self.buf[1..];
                    TcpOptGroup::Nop_(result)
                })
                .ok(),
            2 => MssMessage::parse(self.buf)
                .map(|_msg| {
                    let result = MssMessage {
                        buf: Cursor::new(&self.buf[.._msg.header_len() as usize]),
                    };
                    self.buf = &self.buf[_msg.header_len() as usize..];
                    TcpOptGroup::Mss_(result)
                })
                .ok(),
            3 => WsoptMessage::parse(self.buf)
                .map(|_msg| {
                    let result = WsoptMessage {
                        buf: Cursor::new(&self.buf[.._msg.header_len() as usize]),
                    };
                    self.buf = &self.buf[_msg.header_len() as usize..];
                    TcpOptGroup::Wsopt_(result)
                })
                .ok(),
            4 => SackpermMessage::parse(self.buf)
                .map(|_msg| {
                    let result = SackpermMessage {
                        buf: Cursor::new(&self.buf[.._msg.header_len() as usize]),
                    };
                    self.buf = &self.buf[_msg.header_len() as usize..];
                    TcpOptGroup::Sackperm_(result)
                })
                .ok(),
            5 => SackMessage::parse(self.buf)
                .map(|_msg| {
                    let result = SackMessage {
                        buf: Cursor::new(&self.buf[.._msg.header_len() as usize]),
                    };
                    self.buf = &self.buf[_msg.header_len() as usize..];
                    TcpOptGroup::Sack_(result)
                })
                .ok(),
            8 => TsMessage::parse(self.buf)
                .map(|_msg| {
                    let result = TsMessage {
                        buf: Cursor::new(&self.buf[.._msg.header_len() as usize]),
                    };
                    self.buf = &self.buf[_msg.header_len() as usize..];
                    TcpOptGroup::Ts_(result)
                })
                .ok(),
            34 => FoMessage::parse(self.buf)
                .map(|_msg| {
                    let result = FoMessage {
                        buf: Cursor::new(&self.buf[.._msg.header_len() as usize]),
                    };
                    self.buf = &self.buf[_msg.header_len() as usize..];
                    TcpOptGroup::Fo_(result)
                })
                .ok(),
            _ => None,
        }
    }
}
impl<'a> Iterator for TcpOptGroupIterMut<'a> {
    type Item = TcpOptGroup<CursorMut<'a>>;
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
                    Some(TcpOptGroup::Eol_(result))
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
                    Some(TcpOptGroup::Nop_(result))
                }
                Err(_) => None,
            },
            2 => match MssMessage::parse(&self.buf[..]) {
                Ok(_msg) => {
                    let header_len = _msg.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = MssMessage {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptGroup::Mss_(result))
                }
                Err(_) => None,
            },
            3 => match WsoptMessage::parse(&self.buf[..]) {
                Ok(_msg) => {
                    let header_len = _msg.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = WsoptMessage {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptGroup::Wsopt_(result))
                }
                Err(_) => None,
            },
            4 => match SackpermMessage::parse(&self.buf[..]) {
                Ok(_msg) => {
                    let header_len = _msg.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = SackpermMessage {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptGroup::Sackperm_(result))
                }
                Err(_) => None,
            },
            5 => match SackMessage::parse(&self.buf[..]) {
                Ok(_msg) => {
                    let header_len = _msg.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = SackMessage {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptGroup::Sack_(result))
                }
                Err(_) => None,
            },
            8 => match TsMessage::parse(&self.buf[..]) {
                Ok(_msg) => {
                    let header_len = _msg.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = TsMessage {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptGroup::Ts_(result))
                }
                Err(_) => None,
            },
            34 => match FoMessage::parse(&self.buf[..]) {
                Ok(_msg) => {
                    let header_len = _msg.header_len() as usize;
                    let (fst, snd) =
                        std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                    self.buf = snd;
                    let result = FoMessage {
                        buf: CursorMut::new(fst),
                    };
                    Some(TcpOptGroup::Fo_(result))
                }
                Err(_) => None,
            },
            _ => None,
        }
    }
}
