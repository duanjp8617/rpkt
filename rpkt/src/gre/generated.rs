use crate::cursors::*;
use crate::ether::EtherType;
use crate::traits::*;

/// A constant that defines the fixed byte length of the GreBase protocol header.
pub const GREBASE_HEADER_LEN: usize = 4;
/// A fixed GreBase header.
pub const GREBASE_HEADER_TEMPLATE: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct GreBasePacket<T> {
    buf: T,
}
impl<T: Buf> GreBasePacket<T> {
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
        Ok(container)
    }
    #[inline]
    pub fn header_slice(&self) -> &[u8] {
        &self.buf.chunk()[0..4]
    }
    #[inline]
    pub fn checksum_present(&self) -> u8 {
        self.buf.chunk()[0] >> 7
    }
    #[inline]
    pub fn routing_present(&self) -> u8 {
        (self.buf.chunk()[0] >> 6) & 0x1
    }
    #[inline]
    pub fn key_present(&self) -> u8 {
        (self.buf.chunk()[0] >> 5) & 0x1
    }
    #[inline]
    pub fn sequence_present(&self) -> u8 {
        (self.buf.chunk()[0] >> 4) & 0x1
    }
    #[inline]
    pub fn strict_source_route(&self) -> u8 {
        (self.buf.chunk()[0] >> 3) & 0x1
    }
    #[inline]
    pub fn recursion_control(&self) -> u8 {
        self.buf.chunk()[0] & 0x7
    }
    #[inline]
    pub fn flags(&self) -> u8 {
        self.buf.chunk()[1] >> 3
    }
    #[inline]
    pub fn version(&self) -> u8 {
        self.buf.chunk()[1] & 0x7
    }
    #[inline]
    pub fn protocol_type(&self) -> EtherType {
        EtherType::from(u16::from_be_bytes(
            (&self.buf.chunk()[2..4]).try_into().unwrap(),
        ))
    }
}
impl<T: PktBuf> GreBasePacket<T> {
    #[inline]
    pub fn payload(self) -> T {
        let mut buf = self.buf;
        buf.advance(4);
        buf
    }
}
impl<T: PktBufMut> GreBasePacket<T> {
    #[inline]
    pub fn prepend_header<'a>(mut buf: T, header: &'a [u8; 4]) -> Self {
        assert!(buf.chunk_headroom() >= 4);
        buf.move_back(4);
        (&mut buf.chunk_mut()[0..4]).copy_from_slice(&header.as_ref()[..]);
        Self { buf }
    }
    #[inline]
    pub fn set_checksum_present(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0x7f) | (value << 7);
    }
    #[inline]
    pub fn set_routing_present(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xbf) | (value << 6);
    }
    #[inline]
    pub fn set_key_present(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xdf) | (value << 5);
    }
    #[inline]
    pub fn set_sequence_present(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xef) | (value << 4);
    }
    #[inline]
    pub fn set_strict_source_route(&mut self, value: u8) {
        assert!(value <= 0x1);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf7) | (value << 3);
    }
    #[inline]
    pub fn set_recursion_control(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf8) | value;
    }
    #[inline]
    pub fn set_flags(&mut self, value: u8) {
        assert!(value <= 0x1f);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0x07) | (value << 3);
    }
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0xf8) | value;
    }
    #[inline]
    pub fn set_protocol_type(&mut self, value: EtherType) {
        (&mut self.buf.chunk_mut()[2..4]).copy_from_slice(&u16::from(value).to_be_bytes());
    }
}
impl<'a> GreBasePacket<Cursor<'a>> {
    #[inline]
    pub fn parse_from_cursor(buf: Cursor<'a>) -> Result<Self, Cursor<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor(&self) -> Cursor<'_> {
        Cursor::new(&self.buf.chunk()[4..])
    }
}
impl<'a> GreBasePacket<CursorMut<'a>> {
    #[inline]
    pub fn parse_from_cursor_mut(buf: CursorMut<'a>) -> Result<Self, CursorMut<'a>> {
        let remaining_len = buf.chunk().len();
        if remaining_len < 4 {
            return Err(buf);
        }
        let container = Self { buf };
        Ok(container)
    }
    #[inline]
    pub fn payload_as_cursor_mut(&mut self) -> CursorMut<'_> {
        CursorMut::new(&mut self.buf.chunk_mut()[4..])
    }
}
