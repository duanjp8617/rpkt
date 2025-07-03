use crate::cursors::*;
use crate::ether::EtherType;
use crate::traits::*;

/// A constant that defines the fixed byte length of the Gre protocol header.
pub const GRE_HEADER_LEN: usize = 4;
/// A fixed Gre header.
pub const GRE_HEADER_TEMPLATE: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

#[derive(Debug, Clone, Copy)]
pub struct GrePacket<T> {
    buf: T,
}
impl<T: Buf> GrePacket<T> {
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
    pub fn checksum_present(&self) -> bool {
        self.buf.chunk()[0] & 0x80 != 0
    }
    #[inline]
    pub fn routing_present(&self) -> bool {
        self.buf.chunk()[0] & 0x40 != 0
    }
    #[inline]
    pub fn key_present(&self) -> bool {
        self.buf.chunk()[0] & 0x20 != 0
    }
    #[inline]
    pub fn sequence_present(&self) -> bool {
        self.buf.chunk()[0] & 0x10 != 0
    }
    #[inline]
    pub fn strict_source_route(&self) -> bool {
        self.buf.chunk()[0] & 0x8 != 0
    }
    #[inline]
    pub fn recursion_control(&self) -> u8 {
        self.buf.chunk()[0] & 0x7
    }
    #[inline]
    pub fn ack_present(&self) -> bool {
        self.buf.chunk()[1] & 0x80 != 0
    }
    #[inline]
    pub fn flags(&self) -> u8 {
        (self.buf.chunk()[1] >> 3) & 0xf
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
impl<T: PktBuf> GrePacket<T> {
    #[inline]
    pub fn payload(self) -> T {
        let header_len = self.header_len() as usize;
        let mut buf = self.buf;
        buf.advance(header_len);
        buf
    }
}
impl<T: PktBufMut> GrePacket<T> {
    #[inline]
    pub fn var_header_slice_mut(&mut self) -> &mut [u8] {
        let header_len = (self.header_len() as usize);
        &mut self.buf.chunk_mut()[4..header_len]
    }
    #[inline]
    pub fn set_checksum_present(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] | 0x80
        } else {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] & 0x7f
        }
    }
    #[inline]
    pub fn set_routing_present(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] | 0x40
        } else {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] & 0xbf
        }
    }
    #[inline]
    pub fn set_key_present(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] | 0x20
        } else {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] & 0xdf
        }
    }
    #[inline]
    pub fn set_sequence_present(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] | 0x10
        } else {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] & 0xef
        }
    }
    #[inline]
    pub fn set_strict_source_route(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] | 0x8
        } else {
            self.buf.chunk_mut()[0] = self.buf.chunk_mut()[0] & 0xf7
        }
    }
    #[inline]
    pub fn set_recursion_control(&mut self, value: u8) {
        assert!(value <= 0x7);
        self.buf.chunk_mut()[0] = (self.buf.chunk_mut()[0] & 0xf8) | value;
    }
    #[inline]
    pub fn set_ack_present(&mut self, value: bool) {
        if value {
            self.buf.chunk_mut()[1] = self.buf.chunk_mut()[1] | 0x80
        } else {
            self.buf.chunk_mut()[1] = self.buf.chunk_mut()[1] & 0x7f
        }
    }
    #[inline]
    pub fn set_flags(&mut self, value: u8) {
        assert!(value <= 0xf);
        self.buf.chunk_mut()[1] = (self.buf.chunk_mut()[1] & 0x87) | (value << 3);
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
impl<'a> GrePacket<Cursor<'a>> {
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
impl<'a> GrePacket<CursorMut<'a>> {
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
