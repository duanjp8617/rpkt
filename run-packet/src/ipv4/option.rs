use byteorder::{ByteOrder, NetworkEndian};

const END_OF_LIST: u8 = 0;
const NOP: u8 = 1;
const TIMESTAMP: u8 = 68;
const RECORD_ROUTE: u8 = 7;
const ROUTE_ALERT: u8 = 20 | 0x80;

pub enum Ipv4Option<'a> {
    Eol,
    Nop,
    Ts(Timestamp<&'a [u8]>),
    RR(RecordRoute<&'a [u8]>),
    RA(RouteAlert<&'a [u8]>),
    Unknown(&'a [u8]),
}

pub enum Ipv4OptionMut<'a> {
    Eol,
    Nop,
    Ts(Timestamp<&'a mut [u8]>),
    RR(RecordRoute<&'a mut [u8]>),
    RA(RouteAlert<&'a mut [u8]>),
    Unknown(&'a mut [u8]),
}

pub struct Timestamp<T> {
    buf: T,
}

impl<T> Timestamp<T> {
    pub const TIME_STAMP_ONLY: u8 = 0;
    pub const IPV4_ADDR_TIME_STAMP: u8 = 1;
    pub const PRESPECIFIED_TIME_STAMP: u8 = 3;
}

impl<T: AsRef<[u8]>> Timestamp<T> {
    pub fn flg(&self) -> u8 {
        self.buf.as_ref()[3] & 0x0f
    }

    pub fn overflow(&self) -> u8 {
        self.buf.as_ref()[3] >> 4
    }

    pub fn buf(&self) -> &[u8] {
        &self.buf.as_ref()[4..usize::from(self.buf.as_ref()[1])]
    }

    pub fn payload_len(&self) -> usize {
        usize::from(self.buf.as_ref()[2]) - 5
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> Timestamp<T> {
    pub fn set_flg(&mut self, value: u8) {
        self.buf.as_mut()[3] = (self.buf.as_mut()[3] & 0xf0) | (value & 0x0f);
    }

    pub fn inc_overflow(&mut self) {
        self.buf.as_mut()[3] += 1 << 4;
    }

    pub fn buf_mut(&mut self) -> &mut [u8] {
        let len = usize::from(self.buf.as_mut()[1]);
        &mut self.buf.as_mut()[4..len]
    }

    pub fn inc_payload_len(&mut self, value: usize) {
        assert!(value + self.payload_len() <= self.buf().len());
        self.buf.as_mut()[2] += value as u8;
    }
}

pub struct RecordRoute<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> RecordRoute<T> {
    pub fn buf(&self) -> &[u8] {
        &self.buf.as_ref()[3..usize::from(self.buf.as_ref()[1])]
    }

    pub fn payload_len(&self) -> usize {
        usize::from(self.buf.as_ref()[2]) - 4
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> RecordRoute<T> {
    pub fn buf_mut(&mut self) -> &mut [u8] {
        let len = usize::from(self.buf.as_mut()[1]);
        &mut self.buf.as_mut()[3..len]
    }

    pub fn inc_payload_len(&mut self, value: usize) {
        assert!(value + self.payload_len() <= self.buf().len());
        self.buf.as_mut()[2] += value as u8;
    }
}

pub struct RouteAlert<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> RouteAlert<T> {
    pub fn alert_value(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[2..4])
    }
}

impl<T: AsMut<[u8]>> RouteAlert<T> {
    pub fn set_alert_value(&mut self, value: u16) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[2..4], value);
    }
}

pub struct OptionWriter<'a> {
    buf: &'a mut [u8],
}

impl<'a> OptionWriter<'a> {
    pub fn eol(&mut self) {
        assert!(self.buf.len() > 0);

        self.buf[0] = END_OF_LIST;

        let (_, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(1);
        self.buf = remaining;
    }

    pub fn nop(&mut self) {
        assert!(self.buf.len() > 0);

        self.buf[0] = NOP;

        let (_, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(1);
        self.buf = remaining;
    }

    pub fn ts(&mut self, len: usize) -> Timestamp<&'a mut [u8]> {
        assert!(len >= 4 && len <= 40 && len % 4 == 0 && self.buf.len() >= len);

        self.buf[0] = TIMESTAMP;
        self.buf[1] = len as u8;
        self.buf[2] = 5;
        (&mut self.buf[4..len]).fill(0);

        let (buf, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(len);
        self.buf = remaining;

        Timestamp { buf }
    }

    pub fn rr(&mut self, len: usize) -> RecordRoute<&'a mut [u8]> {
        assert!(len >= 3 && len <= 40 && (len - 3) % 4 == 0 && self.buf.len() >= len);

        self.buf[0] = RECORD_ROUTE;
        self.buf[1] = len as u8;
        self.buf[2] = 4;
        (&mut self.buf[3..len]).fill(0);

        let (buf, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(len);
        self.buf = remaining;

        RecordRoute { buf }
    }

    pub fn ra(&mut self) -> RouteAlert<&'a mut [u8]> {
        assert!(self.buf.len() >= 4);

        self.buf[0] = ROUTE_ALERT;
        self.buf[1] = 4;

        let (buf, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(4);
        self.buf = remaining;

        RouteAlert { buf }
    }
}

pub struct OptionIter<'a> {
    buf: &'a [u8],
    valid: bool,
}

impl<'a> OptionIter<'a> {
    pub fn from_option_bytes(buf: &'a [u8]) -> OptionIter<'a> {
        Self { buf, valid: true }
    }

    pub fn check_option_bytes(buf: &'a [u8]) -> bool {
        let mut reader = Self::from_option_bytes(buf);
        while let Some(_) = (&mut reader).next() {}
        reader.valid
    }
}

impl<'a> Iterator for OptionIter<'a> {
    type Item = Ipv4Option<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.valid || self.buf.len() == 0 {
            return None;
        }

        let opt_type = self.buf[0];
        match opt_type {
            END_OF_LIST => {
                self.buf = &self.buf[1..];
                if self.buf.len() > 0 {
                    self.valid = false;
                }
                Some(Ipv4Option::Eol)
            }
            NOP => {
                self.buf = &self.buf[1..];
                Some(Ipv4Option::Nop)
            }
            _ => {
                if self.buf.len() < 2 {
                    self.valid = false;
                    return None;
                }

                match opt_type {
                    TIMESTAMP => {
                        let opt_len = usize::from(self.buf[1]);

                        #[inline]
                        fn opt_len_valid(len: usize) -> bool {
                            len >= 4 && len <= 40 && len % 4 == 0
                        }

                        #[inline]
                        fn pointer_valid(val: u8) -> bool {
                            val >= 5 && val <= 41 && (val - 5) % 4 == 0
                        }

                        if !opt_len_valid(opt_len)
                            || self.buf.len() < opt_len
                            || !pointer_valid(self.buf[2])
                        {
                            self.valid = false;
                            None
                        } else {
                            let opt = Timestamp {
                                buf: &self.buf[..opt_len],
                            };
                            self.buf = &self.buf[opt_len..];
                            Some(Ipv4Option::Ts(opt))
                        }
                    }
                    RECORD_ROUTE => {
                        let opt_len = usize::from(self.buf[1]);

                        #[inline]
                        fn opt_len_valid(len: usize) -> bool {
                            len >= 3 && len <= 40 && (len - 3) % 4 == 0
                        }

                        #[inline]
                        fn pointer_valid(val: u8) -> bool {
                            val >= 4 && val <= 40 && (val - 4) % 4 == 0
                        }

                        if !opt_len_valid(opt_len)
                            || self.buf.len() < opt_len
                            || !pointer_valid(self.buf[2])
                        {
                            self.valid = false;
                            None
                        } else {
                            let opt = RecordRoute {
                                buf: &self.buf[..opt_len],
                            };
                            self.buf = &self.buf[opt_len..];
                            Some(Ipv4Option::RR(opt))
                        }
                    }
                    ROUTE_ALERT => {
                        if self.buf[1] != 4 || self.buf.len() < 4 {
                            self.valid = false;
                            None
                        } else {
                            let opt = RouteAlert {
                                buf: &self.buf[..4],
                            };
                            self.buf = &self.buf[4..];
                            Some(Ipv4Option::RA(opt))
                        }
                    }
                    _ => {
                        let opt_len = usize::from(self.buf[1]);
                        if self.buf.len() < opt_len {
                            self.valid = false;
                            None
                        } else {
                            let opt = &self.buf[..opt_len];
                            self.buf = &self.buf[opt_len..];
                            Some(Ipv4Option::Unknown(opt))
                        }
                    }
                }
            }
        }
    }
}

pub struct OptionIterMut<'a> {
    buf: &'a mut [u8],
    valid: bool,
}

impl<'a> OptionIterMut<'a> {
    pub fn from_option_bytes(buf: &'a mut [u8]) -> OptionIterMut<'a> {
        Self { buf, valid: true }
    }
}

impl<'a> Iterator for OptionIterMut<'a> {
    type Item = Ipv4OptionMut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.valid || self.buf.len() == 0 {
            return None;
        }

        let opt_type = self.buf[0];
        match opt_type {
            END_OF_LIST => {
                let (_, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(1);
                self.buf = remaining;

                if self.buf.len() > 0 {
                    self.valid = false;
                }
                Some(Ipv4OptionMut::Eol)
            }
            NOP => {
                let (_, remaining) = std::mem::replace(&mut self.buf, &mut []).split_at_mut(1);
                self.buf = remaining;

                Some(Ipv4OptionMut::Nop)
            }
            _ => {
                if self.buf.len() < 2 {
                    self.valid = false;
                    return None;
                }

                match opt_type {
                    TIMESTAMP => {
                        let opt_len = usize::from(self.buf[1]);

                        #[inline]
                        fn opt_len_valid(len: usize) -> bool {
                            len >= 4 && len <= 40 && len % 4 == 0
                        }

                        #[inline]
                        fn pointer_valid(val: u8) -> bool {
                            val >= 5 && val <= 41 && (val - 5) % 4 == 0
                        }

                        if !opt_len_valid(opt_len)
                            || self.buf.len() < opt_len
                            || !pointer_valid(self.buf[2])
                        {
                            self.valid = false;
                            None
                        } else {
                            let (buf, remaining) =
                                std::mem::replace(&mut self.buf, &mut []).split_at_mut(opt_len);
                            self.buf = remaining;

                            let opt = Timestamp { buf };
                            Some(Ipv4OptionMut::Ts(opt))
                        }
                    }
                    RECORD_ROUTE => {
                        let opt_len = usize::from(self.buf[1]);

                        #[inline]
                        fn opt_len_valid(len: usize) -> bool {
                            len >= 3 && len <= 40 && (len - 3) % 4 == 0
                        }

                        #[inline]
                        fn pointer_valid(val: u8) -> bool {
                            val >= 4 && val <= 40 && (val - 4) % 4 == 0
                        }

                        if !opt_len_valid(opt_len)
                            || self.buf.len() < opt_len
                            || !pointer_valid(self.buf[2])
                        {
                            self.valid = false;
                            None
                        } else {
                            let (buf, remaining) =
                                std::mem::replace(&mut self.buf, &mut []).split_at_mut(opt_len);
                            self.buf = remaining;

                            let opt = RecordRoute { buf };
                            Some(Ipv4OptionMut::RR(opt))
                        }
                    }
                    ROUTE_ALERT => {
                        if self.buf[1] != 4 || self.buf.len() < 4 {
                            self.valid = false;
                            None
                        } else {
                            let (buf, remaining) =
                                std::mem::replace(&mut self.buf, &mut []).split_at_mut(4);
                            self.buf = remaining;

                            let opt = RouteAlert { buf };
                            Some(Ipv4OptionMut::RA(opt))
                        }
                    }
                    _ => {
                        let opt_len = usize::from(self.buf[1]);
                        if self.buf.len() < opt_len {
                            self.valid = false;
                            None
                        } else {
                            let (buf, remaining) =
                                std::mem::replace(&mut self.buf, &mut []).split_at_mut(4);
                            self.buf = remaining;

                            Some(Ipv4OptionMut::Unknown(buf))
                        }
                    }
                }
            }
        }
    }
}
