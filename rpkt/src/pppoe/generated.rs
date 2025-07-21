#![allow(missing_docs)]
#![allow(unused_parens)]
#![allow(unreachable_patterns)]

use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

use super::{PppoeCode, PppoeTagType};

/// A constant that defines the fixed byte length of the PppoeSession protocol header.
pub const PPPOE_SESSION_HEADER_LEN: usize = 8;
/// A fixed PppoeSession header.
pub const PPPOE_SESSION_HEADER_TEMPLATE: [u8; 8] = [0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct PppoeSession<T> {
    buf: T,
}
impl<T: Buf> PppoeSession<T> {
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
        if ((container.packet_len() as usize) < 8)
            || ((container.packet_len() as usize) > container.buf.remaining())
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
    pub fn version(&self) -> u8 {
        self.buf.chunk()[0] >> 4
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0] & 0xf
    }
    #[inline]
    pub fn code(&self) -> PppoeCode {
        PppoeCode::from(self.buf.chunk()[1])
    }
    #[inline]
    pub fn session_id(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn data_type(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[6..8]).try_into().unwrap())
    }
    #[inline]
    pub fn packet_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap())) as u32 + 6
    }
}
impl<T: PktBuf> PppoeSession<T> {
    #[inline]
    pub fn payload(self) -> T {
        assert!((self.packet_len() as usize) <= self.buf.remaining());
        let trim_size = self.buf.remaining() - self.packet_len() as usize;
        let mut buf = self.buf;
        if trim_size > 0 {
            buf.trim_off(trim_size);
        }
        buf.advance(8);
        buf
    }
}
impl<T: PktBufMut> PppoeSession<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 8]) -> Self {
        assert!(buf.chunk_headroom() >= 8);
        buf.move_back(8);
        let packet_len = buf.remaining();
        assert!(packet_len <= 65541);
        (&mut buf.chunk_mut()[0..8]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_packet_len(packet_len as u32);
        container
    }
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        assert!(value == 1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf0) | value;
    }
    #[inline]
    pub fn set_code(&mut self, value: PppoeCode) {
        let value = u8::from(value);
        assert!(value == 0);
        self.buf.chunk_mut()[1] = value;
    }
    #[inline]
    pub fn set_session_id(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_data_type(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[6..8]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_packet_len(&mut self, value: u32) {
        assert!((value <= 65541) && (value >= 6));
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&((value - 6) as u16).to_be_bytes());
    }
}
impl<'a> PppoeSession<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.packet_len() as usize) < 8)
            || ((container.packet_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let packet_len = self.packet_len() as usize;
        Cursor::new(&self.buf.chunk()[8..packet_len])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 8]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> PppoeSession<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 8 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.packet_len() as usize) < 8)
            || ((container.packet_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let packet_len = self.packet_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[8..packet_len])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 8]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

/// A constant that defines the fixed byte length of the PppoeDiscovery protocol header.
pub const PPPOE_DISCOVERY_HEADER_LEN: usize = 6;
/// A fixed PppoeDiscovery header.
pub const PPPOE_DISCOVERY_HEADER_TEMPLATE: [u8; 6] = [0x11, 0x65, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct PppoeDiscovery<T> {
    buf: T,
}
impl<T: Buf> PppoeDiscovery<T> {
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
        if chunk_len < 6 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.packet_len() as usize) < 6)
            || ((container.packet_len() as usize) > container.buf.remaining())
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn fix_header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..6]
    }
    #[inline]
    pub fn version(&self) -> u8 {
        self.buf.chunk()[0] >> 4
    }
    #[inline]
    pub fn type_(&self) -> u8 {
        self.buf.chunk()[0] & 0xf
    }
    #[inline]
    pub fn code(&self) -> PppoeCode {
        PppoeCode::from(self.buf.chunk()[1])
    }
    #[inline]
    pub fn session_id(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn packet_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap())) as u32 + 6
    }
}
impl<T: PktBuf> PppoeDiscovery<T> {
    #[inline]
    pub fn payload(self) -> T {
        assert!((self.packet_len() as usize) <= self.buf.remaining());
        let trim_size = self.buf.remaining() - self.packet_len() as usize;
        let mut buf = self.buf;
        if trim_size > 0 {
            buf.trim_off(trim_size);
        }
        buf.advance(6);
        buf
    }
}
impl<T: PktBufMut> PppoeDiscovery<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 6]) -> Self {
        assert!(buf.chunk_headroom() >= 6);
        buf.move_back(6);
        let packet_len = buf.remaining();
        assert!(packet_len <= 65541);
        (&mut buf.chunk_mut()[0..6]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_packet_len(packet_len as u32);
        container
    }
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        assert!(value == 1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x0f) | (value << 4);
    }
    #[inline]
    pub fn set_type_(&mut self, value: u8) {
        assert!(value == 1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf0) | value;
    }
    #[inline]
    pub fn set_code(&mut self, value: PppoeCode) {
        self.buf.chunk_mut()[1] = u8::from(value);
    }
    #[inline]
    pub fn set_session_id(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_packet_len(&mut self, value: u32) {
        assert!((value <= 65541) && (value >= 6));
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&((value - 6) as u16).to_be_bytes());
    }
}
impl<'a> PppoeDiscovery<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 6 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.packet_len() as usize) < 6)
            || ((container.packet_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let packet_len = self.packet_len() as usize;
        Cursor::new(&self.buf.chunk()[6..packet_len])
    }
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 6]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> PppoeDiscovery<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 6 {
            return Err(buf);
        }
        let container = Self { buf };
        if ((container.packet_len() as usize) < 6)
            || ((container.packet_len() as usize) > remaining_len)
        {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let packet_len = self.packet_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[6..packet_len])
    }
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 6]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

#[derive(Debug)]
pub enum PppoeGroup<T> {
    PppoeSession_(PppoeSession<T>),
    PppoeDiscovery_(PppoeDiscovery<T>),
}
impl<T: Buf> PppoeGroup<T> {
    pub fn group_parse(buf: T) -> Result<Self, T> {
        if buf.chunk().len() < 2 {
            return Err(buf);
        }
        let cond_value0 = buf.chunk()[1];
        match cond_value0 {
            0 => PppoeSession::parse(buf).map(|pkt| PppoeGroup::PppoeSession_(pkt)),
            1..=255 => PppoeDiscovery::parse(buf).map(|pkt| PppoeGroup::PppoeDiscovery_(pkt)),
            _ => Err(buf),
        }
    }
}

/// A constant that defines the fixed byte length of the PppoeTag protocol header.
pub const PPPOE_TAG_HEADER_LEN: usize = 4;
/// A fixed PppoeTag header.
pub const PPPOE_TAG_HEADER_TEMPLATE: [u8; 4] = [0x00, 0x00, 0x00, 0x04];

#[derive(Debug, Clone, Copy)]
pub struct PppoeTag<T> {
    buf: T,
}
impl<T: Buf> PppoeTag<T> {
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
    pub fn type_(&self) -> PppoeTagType {
        PppoeTagType::from(u16::from_be_bytes(
            (&self.buf.chunk()[0..2]).try_into().unwrap(),
        ))
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())) as u32 + 4
    }
}
impl<T: PktBuf> PppoeTag<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> PppoeTag<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        let header_len = PppoeTag::parse_unchecked(&header[..]).header_len() as usize;
        assert!((header_len >= 4) && (header_len <= buf.chunk_headroom()));
        buf.move_back(header_len);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[4..header_len]
    }
    #[inline]
    pub fn set_type_(&mut self, value: PppoeTagType) {
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&u16::from(value).to_be_bytes());
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65539) && (value >= 4));
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&((value - 4) as u16).to_be_bytes());
    }
}
impl<'a> PppoeTag<Cursor<'a>> {
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
    #[inline]
    pub fn from_header_array(header_array: &'a [u8; 4]) -> Self {
        Self {
            buf: Cursor::new(header_array.as_slice()),
        }
    }
}
impl<'a> PppoeTag<CursorMut<'a>> {
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
    #[inline]
    pub fn from_header_array_mut(header_array: &'a mut [u8; 4]) -> Self {
        Self {
            buf: CursorMut::new(header_array.as_mut_slice()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PppoeTagIter<'a> {
    buf: &'a [u8],
}
impl<'a> PppoeTagIter<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Self {
        Self { buf: slice }
    }

    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }
}
impl<'a> Iterator for PppoeTagIter<'a> {
    type Item = PppoeTag<Cursor<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        PppoeTag::parse(self.buf)
            .map(|pkt| {
                let result = PppoeTag {
                    buf: Cursor::new(&self.buf[..pkt.header_len() as usize]),
                };
                self.buf = &self.buf[pkt.header_len() as usize..];
                result
            })
            .ok()
    }
}

#[derive(Debug)]
pub struct PppoeTagIterMut<'a> {
    buf: &'a mut [u8],
}
impl<'a> PppoeTagIterMut<'a> {
    pub fn from_slice_mut(slice_mut: &'a mut [u8]) -> Self {
        Self { buf: slice_mut }
    }

    pub fn buf(&self) -> &[u8] {
        &self.buf[..]
    }
}
impl<'a> Iterator for PppoeTagIterMut<'a> {
    type Item = PppoeTag<CursorMut<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        match PppoeTag::parse(&self.buf[..]) {
            Ok(pkt) => {
                let header_len = pkt.header_len() as usize;
                let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                self.buf = snd;
                let result = PppoeTag {
                    buf: CursorMut::new(fst),
                };
                Some(result)
            }
            Err(_) => None,
        }
    }
}
