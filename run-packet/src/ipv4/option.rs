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

impl<T: AsRef<[u8]>> Timestamp<T> {
    pub fn flg(&self) -> u8 {
        self.buf.as_ref()[3] & 0x0f
    }

    pub fn overflow(&self) -> u8 {
        self.buf.as_ref()[3] >> 4
    }

    pub fn readable(&self) -> &[u8] {
        let readable_len = usize::from(self.buf.as_ref()[2]) - 5;
        &self.buf.as_ref()[4..4 + readable_len]
    }

    pub fn remaining(&self) -> usize {
        (usize::from(self.buf.as_ref()[1]) + 1) - usize::from(self.buf.as_ref()[2])
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> Timestamp<T> {
    /// possible value: 0, 1, 3
    pub fn set_flg(&mut self, value: u8) {
        self.buf.as_mut()[3] = (self.buf.as_mut()[3] & 0xf0) | (value & 0x0f);
    }

    pub fn inc_overflow(&mut self) {
        self.buf.as_mut()[3] += 1 << 4;
    }

    pub fn writable(&mut self) -> &mut [u8] {
        let start = usize::from(self.buf.as_ref()[2]) - 1;
        let len = usize::from(self.buf.as_mut()[1]);
        &mut self.buf.as_mut()[start..len]
    }

    pub fn inc_readable_size(&mut self, value: usize) {
        assert!(value <= self.remaining());
        self.buf.as_mut()[2] += value as u8;
    }
}

pub struct RecordRoute<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> RecordRoute<T> {
    pub fn readable(&self) -> &[u8] {
        let readable_len = usize::from(self.buf.as_ref()[2]) - 4;
        &self.buf.as_ref()[3..3 + readable_len]
    }

    pub fn remaining(&self) -> usize {
        (usize::from(self.buf.as_ref()[1]) + 1) - usize::from(self.buf.as_ref()[2])
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> RecordRoute<T> {
    pub fn writable(&mut self) -> &mut [u8] {
        let start = usize::from(self.buf.as_ref()[2]) - 1;
        let len = usize::from(self.buf.as_mut()[1]);
        &mut self.buf.as_mut()[start..len]
    }

    pub fn inc_readable_size(&mut self, value: usize) {
        assert!(value <= self.remaining());
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
        (&mut self.buf[3..len]).fill(0);

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

    pub fn from_option_bytes(buf: &'a mut [u8]) -> Self {
        Self { buf }
    }

    pub fn remaining_bytes(&self) -> usize {
        self.buf.len()
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
                            val >= 4 && val <= 40 && val % 4 == 0
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
    pub fn from_option_bytes_mut(buf: &'a mut [u8]) -> OptionIterMut<'a> {
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
                            val >= 4 && val <= 40 && val % 4 == 0
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

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{ByteOrder, NetworkEndian};

    #[test]
    fn test_ipv4_option() {
        let mut buf = [0; 200];

        let mut writer = OptionWriter::from_option_bytes(&mut buf[..]);

        let mut ts = writer.ts(16);
        let mut rr = writer.rr(15);
        writer.nop();
        let mut ra = writer.ra();
        writer.nop();
        writer.nop();
        writer.nop();
        writer.eol();

        assert_eq!(ts.flg(), 0);
        assert_eq!(ts.overflow(), 0);
        assert_eq!(ts.readable().len(), 0);
        assert_eq!(ts.remaining(), 12);
        assert_eq!(ts.writable().len(), 12);

        ts.set_flg(3);
        ts.inc_overflow();
        NetworkEndian::write_u32(&mut ts.writable()[..4], 167);
        NetworkEndian::write_u32(&mut ts.writable()[4..8], 171);
        ts.inc_readable_size(8);

        assert_eq!(ts.flg(), 3);
        assert_eq!(ts.overflow(), 1);
        assert_eq!(ts.readable().len(), 8);
        assert_eq!(ts.remaining(), 4);
        assert_eq!(ts.writable().len(), 4);
        assert_eq!(NetworkEndian::read_u32(&ts.readable()[..4]), 167);
        assert_eq!(NetworkEndian::read_u32(&ts.readable()[4..8]), 171);

        assert_eq!(rr.readable().len(), 0);
        assert_eq!(rr.remaining(), 12);
        assert_eq!(rr.writable().len(), 12);

        (&mut rr.writable()[..4]).copy_from_slice(&[1, 2, 3, 4]);
        rr.inc_readable_size(4);

        assert_eq!(rr.readable().len(), 4);
        assert_eq!(rr.remaining(), 8);
        assert_eq!(rr.writable().len(), 8);
        assert_eq!(&rr.readable()[..4], &[1, 2, 3, 4]);

        ra.set_alert_value(566);
        assert_eq!(ra.alert_value(), 566);

        assert_eq!(writer.remaining_bytes(), 160);

        let mut opt_iter = OptionIter::from_option_bytes(&buf[..40]);

        if let Ipv4Option::Ts(ts) = opt_iter.next().unwrap() {
            assert_eq!(ts.flg(), 3);
            assert_eq!(ts.overflow(), 1);
            assert_eq!(ts.readable().len(), 8);
            assert_eq!(ts.remaining(), 4);
            assert_eq!(NetworkEndian::read_u32(&ts.readable()[..4]), 167);
            assert_eq!(NetworkEndian::read_u32(&ts.readable()[4..8]), 171);
        } else {
            assert!(false);
        }

        if let Ipv4Option::RR(rr) = opt_iter.next().unwrap() {
            assert_eq!(rr.readable().len(), 4);
            assert_eq!(rr.remaining(), 8);
            assert_eq!(&rr.readable()[..4], &[1, 2, 3, 4]);
        } else {
            assert!(false);
        }

        if let Ipv4Option::Nop = opt_iter.next().unwrap() {
            assert!(true);
        } else {
            assert!(false);
        }

        if let Ipv4Option::RA(ra) = opt_iter.next().unwrap() {
            assert_eq!(ra.alert_value(), 566);
        } else {
            assert!(false);
        }

        if let Ipv4Option::Nop = opt_iter.next().unwrap() {
            assert!(true);
        } else {
            assert!(false);
        }

        if let Ipv4Option::Nop = opt_iter.next().unwrap() {
            assert!(true);
        } else {
            assert!(false);
        }

        if let Ipv4Option::Nop = opt_iter.next().unwrap() {
            assert!(true);
        } else {
            assert!(false);
        }

        if let Ipv4Option::Eol = opt_iter.next().unwrap() {
            assert!(true);
        } else {
            assert!(false);
        }

        let mut opt_iter = OptionIterMut::from_option_bytes_mut(&mut buf[..40]);

        if let Ipv4OptionMut::Ts(mut ts) = opt_iter.next().unwrap() {
            NetworkEndian::write_u32(&mut ts.writable()[..], 256);
            ts.inc_readable_size(4);
        } else {
            assert!(false);
        }

        if let Ipv4OptionMut::RR(mut rr) = opt_iter.next().unwrap() {
            (&mut rr.writable()[..4]).copy_from_slice(&[2, 4, 6, 8]);
            rr.inc_readable_size(4);
        } else {
            assert!(false);
        }

        opt_iter.next().unwrap();

        if let Ipv4OptionMut::RA(mut ra) = opt_iter.next().unwrap() {
            ra.set_alert_value(820);
        } else {
            assert!(false);
        }

        let mut opt_iter = OptionIterMut::from_option_bytes_mut(&mut buf[..40]);

        if let Ipv4OptionMut::Ts(ts) = opt_iter.next().unwrap() {
            assert_eq!(ts.flg(), 3);
            assert_eq!(ts.overflow(), 1);
            assert_eq!(ts.readable().len(), 12);
            assert_eq!(ts.remaining(), 0);
            assert_eq!(NetworkEndian::read_u32(&ts.readable()[..4]), 167);
            assert_eq!(NetworkEndian::read_u32(&ts.readable()[4..8]), 171);
            assert_eq!(NetworkEndian::read_u32(&ts.readable()[8..12]), 256);
        } else {
            assert!(false);
        }

        if let Ipv4OptionMut::RR(rr) = opt_iter.next().unwrap() {
            assert_eq!(rr.readable().len(), 8);
            assert_eq!(rr.remaining(), 4);
            assert_eq!(&rr.readable()[..4], &[1, 2, 3, 4]);
            assert_eq!(&rr.readable()[4..8], &[2, 4, 6, 8]);
        } else {
            assert!(false);
        }

        if let Ipv4OptionMut::Nop = opt_iter.next().unwrap() {
            assert!(true);
        } else {
            assert!(false);
        }

        if let Ipv4OptionMut::RA(ra) = opt_iter.next().unwrap() {
            assert_eq!(ra.alert_value(), 820);
        } else {
            assert!(false);
        }

        if let Ipv4OptionMut::Nop = opt_iter.next().unwrap() {
            assert!(true);
        } else {
            assert!(false);
        }

        if let Ipv4OptionMut::Nop = opt_iter.next().unwrap() {
            assert!(true);
        } else {
            assert!(false);
        }

        if let Ipv4OptionMut::Nop = opt_iter.next().unwrap() {
            assert!(true);
        } else {
            assert!(false);
        }

        if let Ipv4OptionMut::Eol = opt_iter.next().unwrap() {
            assert!(true);
        } else {
            assert!(false);
        }
    }
}
