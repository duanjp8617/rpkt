use byteorder::{ByteOrder, NetworkEndian};

pub struct Icmpv6MsgGeneric<T> {
    pub(crate) buf: T,
}

impl<T: AsRef<[u8]>> Icmpv6MsgGeneric<T> {
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.as_ref()[1]
    }

    #[inline]
    pub fn check_reserved(&self) -> bool {
        &self.buf.as_ref()[4..8] == &[0, 0, 0, 0][..]
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.buf.as_ref()[8..]
    }
}

impl<T: AsMut<[u8]>> Icmpv6MsgGeneric<T> {
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        self.buf.as_mut()[1] = value;
    }

    #[inline]
    pub fn adjust_reserved(&mut self) {
        (&mut self.buf.as_mut()[4..8]).fill(0);
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[8..]
    }
}

pub struct Icmpv6MsgMtu<T> {
    pub(crate) buf: T,
}

impl<T: AsRef<[u8]>> Icmpv6MsgMtu<T> {
    #[inline]
    pub fn mtu(&self) -> u32 {
        let data = &self.buf.as_ref()[4..8];
        NetworkEndian::read_u32(data)
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.buf.as_ref()[8..]
    }
}

impl<T: AsMut<[u8]>> Icmpv6MsgMtu<T> {
    #[inline]
    pub fn set_mtu(&mut self, value: u32) {
        let data = &mut self.buf.as_mut()[4..8];
        NetworkEndian::write_u32(data, value);
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[8..]
    }
}

pub struct Icmpv6MsgPtr<T> {
    pub(crate) buf: T,
}

impl<T: AsRef<[u8]>> Icmpv6MsgPtr<T> {
    #[inline]
    pub fn code(&self) -> u8 {
        self.buf.as_ref()[1]
    }

    #[inline]
    pub fn ptr(&self) -> u32 {
        let data = &self.buf.as_ref()[4..8];
        NetworkEndian::read_u32(data)
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.buf.as_ref()[8..]
    }
}

impl<T: AsMut<[u8]>> Icmpv6MsgPtr<T> {
    #[inline]
    pub fn set_code(&mut self, value: u8) {
        self.buf.as_mut()[1] = value;
    }

    #[inline]
    pub fn set_ptr(&mut self, value: u32) {
        let data = &mut self.buf.as_mut()[4..8];
        NetworkEndian::write_u32(data, value);
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[8..]
    }
}

pub struct Icmpv6MsgEcho<T> {
    pub(crate) buf: T,
}

impl<T: AsRef<[u8]>> Icmpv6MsgEcho<T> {
    #[inline]
    pub fn ident(&self) -> u16 {
        let data = &self.buf.as_ref()[4..6];
        NetworkEndian::read_u16(data)
    }

    #[inline]
    pub fn seq(&self) -> u16 {
        let data = &self.buf.as_ref()[6..8];
        NetworkEndian::read_u16(data)
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.buf.as_ref()[8..]
    }
}

impl<T: AsMut<[u8]>> Icmpv6MsgEcho<T> {
    #[inline]
    pub fn set_ident(&mut self, value: u16) {
        let data = &mut self.buf.as_mut()[4..6];
        NetworkEndian::write_u16(data, value);
    }

    #[inline]
    pub fn set_seq(&mut self, value: u16) {
        let data = &mut self.buf.as_mut()[6..8];
        NetworkEndian::write_u16(data, value);
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf.as_mut()[8..]
    }
}
