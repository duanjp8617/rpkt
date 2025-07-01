#![allow(missing_docs)]
#![allow(unused_parens)]

use crate::{Buf, PktBuf, PktBufMut};
use crate::{Cursor, CursorMut};

use super::{PPPoECode, PPPoETagType};

/// A constant that defines the fixed byte length of the PPPoE protocol header.
pub const PPPOE_HEADER_LEN: usize = 6;
/// A fixed PPPoE header.
pub const PPPOE_HEADER_TEMPLATE: [u8; 6] = [0x11, 0x00, 0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct PPPoEPacket<T> {
    buf: T,
}
impl<T: Buf> PPPoEPacket<T> {
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
        if (container.payload_len() as usize) + 6 > container.buf.remaining() {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
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
    pub fn code(&self) -> PPPoECode {
        PPPoECode::from(self.buf.chunk()[1])
    }
    #[inline]
    pub fn session_id(&self) -> u16 {
        u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())
    }
    #[inline]
    pub fn payload_len(&self) -> u16 {
        (u16::from_be_bytes((&self.buf.chunk()[4..6]).try_into().unwrap()))
    }
}
impl<T: PktBuf> PPPoEPacket<T> {
    #[inline]
    pub fn payload(self) -> T {
        assert!(6 + self.payload_len() as usize <= self.buf.remaining());
        let trim_size = self.buf.remaining() - (6 + self.payload_len() as usize);
        let mut buf = self.buf;
        if trim_size > 0 {
            buf.trim_off(trim_size);
        }
        buf.advance(6);
        buf
    }
}
impl<T: PktBufMut> PPPoEPacket<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 6]) -> Self {
        assert!(buf.chunk_headroom() >= 6);
        let payload_len = buf.remaining();
        assert!(payload_len <= 65535);
        buf.move_back(6);
        (&mut buf.chunk_mut()[0..6]).copy_from_slice(&header.as_ref()[..]);
        let mut container = Self { buf };
        container.set_payload_len(payload_len as u16);
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
    pub fn set_code(&mut self, value: PPPoECode) {
        self.buf.chunk_mut()[1] = u8::from(value);
    }
    #[inline]
    pub fn set_session_id(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&value.to_be_bytes());
    }
    #[inline]
    pub fn set_payload_len(&mut self, value: u16) {
        (&mut self.buf.chunk_mut()[4..6]).copy_from_slice(&(value).to_be_bytes());
    }
}
impl<'a> PPPoEPacket<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 6 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.payload_len() as usize) + 6 > remaining_len {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        let payload_len = self.payload_len() as usize;
        Cursor::new(&self.buf.chunk()[6..(6 + payload_len)])
    }
}
impl<'a> PPPoEPacket<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 6 {
            return Err(buf);
        }
        let container = Self { buf };
        if (container.payload_len() as usize) + 6 > remaining_len {
            return Err(container.buf);
        }
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        let payload_len = self.payload_len() as usize;
        CursorMut::new(&mut self.buf.chunk_mut()[6..(6 + payload_len)])
    }
}

impl<T: PktBuf> PPPoEPacket<T> {
    /// Get PPP session's payload type and payload buffer from a PPPoE packet.
    ///
    /// The returned packet buffer only contains the PPP session payload, the
    /// payload type is removed from the buffer.
    ///
    /// # Panics
    /// This function panics if the `code` field is not 0 and the chunk length
    /// of the underlying packet buffer is smaller than 8.    
    pub fn session_payload(self) -> (u16, T) {
        assert!(self.code() == PPPoECode::SESSION && self.buf.chunk().len() >= 8);

        let data_type = u16::from_be_bytes((&self.buf.chunk()[6..8]).try_into().unwrap());
        let mut payload = self.payload();
        payload.advance(2);
        (data_type, payload)
    }
}

impl<T: PktBufMut> PPPoEPacket<T> {
    /// Prepend the payload type to the start of the payload buffer.
    ///
    /// The returned packet buffer contains the actual PPPoE session payload,
    /// which can be used to construct the final PPPoE packet.
    ///
    /// # Panics
    /// This function panics if `buf.chunk_headroom() < 2`.
    pub fn prepend_session_payload_type(mut buf: T, payload_type: u16) -> T {
        assert!(buf.chunk_headroom() >= 2);
        buf.move_back(2);
        (&mut buf.chunk_mut()[..2]).copy_from_slice(&payload_type.to_be_bytes());
        buf
    }
}

/// A constant that defines the fixed byte length of the PPPoETag protocol header.
pub const PPPOETAG_HEADER_LEN: usize = 4;
/// A fixed PPPoETag header.
pub const PPPOETAG_HEADER_TEMPLATE: [u8; 4] = [0x00, 0x00, 0x00, 0x04];

#[derive(Debug, Clone, Copy)]
pub struct PPPoETagMessage<T> {
    buf: T,
}
impl<T: Buf> PPPoETagMessage<T> {
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
    pub fn type_(&self) -> PPPoETagType {
        PPPoETagType::from(u16::from_be_bytes(
            (&self.buf.chunk()[0..2]).try_into().unwrap(),
        ))
    }
    #[inline]
    pub fn header_len(&self) -> u32 {
        (u16::from_be_bytes((&self.buf.chunk()[2..4]).try_into().unwrap())) as u32 + 4
    }
}
impl<T: PktBuf> PPPoETagMessage<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> PPPoETagMessage<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4], header_len: u32) -> Self {
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
    pub fn set_type_(&mut self, value: PPPoETagType) {
        (&mut self.buf.chunk_mut()[0..2]).copy_from_slice(&u16::from(value).to_be_bytes());
    }
    #[inline]
    pub fn set_header_len(&mut self, value: u32) {
        assert!((value <= 65539) && (value >= 4));
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&((value - 4) as u16).to_be_bytes());
    }
}
impl<'a> PPPoETagMessage<Cursor<'a>> {
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
impl<'a> PPPoETagMessage<CursorMut<'a>> {
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

#[derive(Debug, Clone, Copy)]
pub struct PPPoETagMessageIter<'a> {
    buf: &'a [u8],
}
impl<'a> PPPoETagMessageIter<'a> {
    pub fn from_message_slice(message_slice: &'a [u8]) -> Self {
        Self { buf: message_slice }
    }

    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }
}
#[derive(Debug)]
pub struct PPPoETagMessageIterMut<'a> {
    buf: &'a mut [u8],
}
impl<'a> PPPoETagMessageIterMut<'a> {
    pub fn from_message_slice_mut(message_slice_mut: &'a mut [u8]) -> Self {
        Self {
            buf: message_slice_mut,
        }
    }

    pub fn buf(&self) -> &[u8] {
        &self.buf[..]
    }
}
impl<'a> Iterator for PPPoETagMessageIter<'a> {
    type Item = PPPoETagMessage<Cursor<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        PPPoETagMessage::parse(self.buf)
            .map(|msg| {
                let result = PPPoETagMessage {
                    buf: Cursor::new(&self.buf[..msg.header_len() as usize]),
                };
                self.buf = &self.buf[msg.header_len() as usize..];
                result
            })
            .ok()
    }
}
impl<'a> Iterator for PPPoETagMessageIterMut<'a> {
    type Item = PPPoETagMessage<CursorMut<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        match PPPoETagMessage::parse(&self.buf[..]) {
            Ok(msg) => {
                let header_len = msg.header_len() as usize;
                let (fst, snd) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(header_len);
                self.buf = snd;
                let result = PPPoETagMessage {
                    buf: CursorMut::new(fst),
                };
                Some(result)
            }
            Err(_) => None,
        }
    }
}
