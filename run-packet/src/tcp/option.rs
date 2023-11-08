use byteorder::{ByteOrder, NetworkEndian};

const END_OF_LIST: u8 = 0;
const NOP: u8 = 1;
const MAX_SEG_SIZE: u8 = 2;
const WINDOW_SCALE: u8 = 3;
const SACK_PERMITTED: u8 = 4;
const SELECTIVE_ACK: u8 = 5;
const TIMESTAMPS: u8 = 8;
const TCP_FASTOPEN: u8 = 34;

pub enum TcpOption<'a> {
    Eol,
    Nop,
    Mss(u16),
    Wsopt(u8),
    SackPerm,
    Sack(SelectiveAck<&'a [u8]>),
    Ts(u32, u32),
    Fo(&'a [u8]),
    Unknown(&'a [u8]),
}

pub struct SelectiveAck<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> SelectiveAck<T> {
    pub fn num_blocks(&self) -> usize {
        (usize::from(self.buf.as_ref()[1]) - 2) / 8
    }

    pub fn sack(&self, idx: usize) -> (u32, u32) {
        assert!(idx < self.num_blocks());
        (
            NetworkEndian::read_u32(&self.buf.as_ref()[2 + 8 * idx..6 + 8 * idx]),
            NetworkEndian::read_u32(&self.buf.as_ref()[6 + 8 * idx..10 + 8 * idx]),
        )
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> SelectiveAck<T> {
    pub fn set_sack(&mut self, idx: usize, sack: (u32, u32)) {
        assert!(idx < self.num_blocks());
        NetworkEndian::write_u32(&mut self.buf.as_mut()[2 + 8 * idx..6 + 8 * idx], sack.0);
        NetworkEndian::write_u32(&mut self.buf.as_mut()[6 + 8 * idx..6 + 10 * idx], sack.1);
    }
}

pub struct OptionWriter<'a> {
    buf: &'a mut [u8],
    cursor: usize,
}

impl<'a> OptionWriter<'a> {
    pub fn eol(&mut self) {
        assert!(self.cursor < self.buf.len());

        self.buf[self.cursor] = END_OF_LIST;

        self.cursor += 1;
    }

    pub fn nop(&mut self) {
        assert!(self.cursor < self.buf.len());

        self.buf[self.cursor] = NOP;

        self.cursor += 1;
    }

    pub fn mss(&mut self, mss: u16) {
        assert!(self.buf.len() - self.cursor >= 4);

        self.buf[self.cursor] = MAX_SEG_SIZE;
        self.buf[self.cursor + 1] = 4;
        NetworkEndian::write_u16(&mut self.buf[self.cursor + 2..self.cursor + 4], mss);

        self.cursor += 4;
    }

    pub fn wsopt(&mut self, value: u8) {
        assert!(self.buf.len() - self.cursor >= 3);

        self.buf[self.cursor] = WINDOW_SCALE;
        self.buf[self.cursor + 1] = 3;
        self.buf[self.cursor + 2] = value;

        self.cursor += 3;
    }

    pub fn sack_perm(&mut self) {
        assert!(self.buf.len() - self.cursor >= 2);

        self.buf[self.cursor] = SACK_PERMITTED;
        self.buf[self.cursor + 1] = 2;

        self.cursor += 2;
    }

    pub fn sack<'b: 'a>(&'b mut self, num_sacks: usize) -> SelectiveAck<&'b mut [u8]> {
        assert!(num_sacks <= 4);
        let opt_len = 2 + num_sacks * 8;
        assert!(self.buf.len() >= opt_len);

        self.buf[self.cursor] = SELECTIVE_ACK;
        self.buf[self.cursor + 1] = opt_len as u8;
        let sack_option = SelectiveAck {
            buf: &mut self.buf[self.cursor..self.cursor + opt_len],
        };

        self.cursor += opt_len;

        sack_option
    }

    pub fn ts(&mut self, ts: u32, ts_echo: u32) {
        assert!(self.buf.len() - self.cursor >= 10);

        self.buf[self.cursor] = TIMESTAMPS;
        self.buf[self.cursor + 1] = 10;
        NetworkEndian::write_u32(&mut self.buf[self.cursor + 2..self.cursor + 6], ts);
        NetworkEndian::write_u32(&mut self.buf[self.cursor + 6..self.cursor + 10], ts_echo);

        self.cursor += 10;
    }

    pub fn fo(&mut self, cookie: &[u8]) {
        assert!(self.buf.len() - self.cursor >= 18);

        self.buf[self.cursor] = TCP_FASTOPEN;
        self.buf[self.cursor + 1] = 18;
        (&mut self.buf[self.cursor + 2..self.cursor + 18]).copy_from_slice(cookie);

        self.cursor += 18;
    }

    pub fn from_option_bytes(buf: &'a mut [u8]) -> Self {
        Self { buf, cursor: 0 }
    }

    pub fn remaining_bytes(&self) -> usize {
        self.buf.len() - self.cursor
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
    type Item = TcpOption<'a>;

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
                Some(TcpOption::Eol)
            }
            NOP => {
                self.buf = &self.buf[1..];
                Some(TcpOption::Nop)
            }
            MAX_SEG_SIZE => {
                if self.buf[1] != 4 || self.buf.len() < 4 {
                    self.valid = false;
                    None
                } else {
                    let mss = NetworkEndian::read_u16(&self.buf[2..4]);
                    self.buf = &self.buf[4..];
                    Some(TcpOption::Mss(mss))
                }
            }
            WINDOW_SCALE => {
                if self.buf[1] != 3 || self.buf.len() < 3 {
                    self.valid = false;
                    None
                } else {
                    let ws = self.buf[2];
                    self.buf = &self.buf[3..];
                    Some(TcpOption::Wsopt(ws))
                }
            }
            SACK_PERMITTED => {
                if self.buf[1] != 2 || self.buf.len() < 2 {
                    self.valid = false;
                    None
                } else {
                    self.buf = &self.buf[2..];
                    Some(TcpOption::SackPerm)
                }
            }
            SELECTIVE_ACK => {
                let opt_len = usize::from(self.buf[1]);

                #[inline]
                fn opt_len_valid(len: usize) -> bool {
                    len >= 2 && len <= 40 && (len - 2) % 8 == 0
                }

                if !opt_len_valid(opt_len) || self.buf.len() < opt_len {
                    self.valid = false;
                    None
                } else {
                    let opt = SelectiveAck {
                        buf: &self.buf[..opt_len],
                    };
                    self.buf = &self.buf[opt_len..];
                    Some(TcpOption::Sack(opt))
                }
            }
            TIMESTAMPS => {
                if self.buf[1] != 10 || self.buf.len() < 10 {
                    self.valid = false;
                    None
                } else {
                    let ts = NetworkEndian::read_u32(&self.buf[2..6]);
                    let ts_echo = NetworkEndian::read_u32(&self.buf[6..10]);
                    self.buf = &self.buf[10..];
                    Some(TcpOption::Ts(ts, ts_echo))
                }
            }
            TCP_FASTOPEN => {
                if self.buf[1] != 18 || self.buf.len() < 18 {
                    self.valid = false;
                    None
                } else {
                    let buf = &self.buf[2..18];
                    self.buf = &self.buf[18..];
                    Some(TcpOption::Fo(buf))
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
                    Some(TcpOption::Unknown(opt))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static OPTIONS: [u8; 70] = [
        0x01, 0x02, 0x04, 0x05, 0xdc, 0x03, 0x03, 0x0c, 0x4, 0x02, 0x05, 0x0a, 0x00, 0x00, 0x01,
        0xf4, 0x00, 0x00, 0x05, 0xdc, 0x05, 0x12, 0x00, 0x00, 0x03, 0x6b, 0x00, 0x00, 0x04, 0xc9,
        0x00, 0x00, 0x05, 0xdc, 0x00, 0x00, 0x09, 0xc4, 0x05, 0x1a, 0x00, 0x0d, 0x59, 0xf8, 0x00,
        0x12, 0xb1, 0x28, 0x00, 0x16, 0xe3, 0x60, 0x00, 0x26, 0x25, 0xa0, 0x34, 0x3e, 0xfc, 0xea,
        0x34, 0x40, 0xae, 0xf0, 0x0c, 0x05, 0x01, 0x02, 0x03, 0x00,
    ];

    #[test]
    fn option_parse() {
        let mut opt_iter = OptionIter::from_option_bytes(&OPTIONS[..]);

        let opt = opt_iter.next().unwrap();
        assert_eq!(
            if let TcpOption::Nop = opt {
                true
            } else {
                false
            },
            true
        );

        let opt = opt_iter.next().unwrap();
        assert_eq!(
            if let TcpOption::Mss(mss) = opt {
                assert_eq!(mss, 1500);
                true
            } else {
                false
            },
            true
        );

        let opt = opt_iter.next().unwrap();
        assert_eq!(
            if let TcpOption::Wsopt(ws) = opt {
                assert_eq!(ws, 12);
                true
            } else {
                false
            },
            true
        );

        let opt = opt_iter.next().unwrap();
        assert_eq!(
            if let TcpOption::SackPerm = opt {
                true
            } else {
                false
            },
            true
        );

        let opt = opt_iter.next().unwrap();
        assert_eq!(
            if let TcpOption::Sack(sack) = opt {
                assert_eq!(sack.num_blocks(), 1);
                assert_eq!(sack.sack(0), (500, 1500));
                true
            } else {
                false
            },
            true
        );

        let opt = opt_iter.next().unwrap();
        assert_eq!(
            if let TcpOption::Sack(sack) = opt {
                assert_eq!(sack.num_blocks(), 2);
                assert_eq!(sack.sack(0), (875, 1225));
                assert_eq!(sack.sack(1), (1500, 2500));
                true
            } else {
                false
            },
            true
        );

        let opt = opt_iter.next().unwrap();
        assert_eq!(
            if let TcpOption::Sack(sack) = opt {
                assert_eq!(sack.num_blocks(), 3);
                assert_eq!(sack.sack(0), (875000, 1225000));
                assert_eq!(sack.sack(1), (1500000, 2500000));
                assert_eq!(sack.sack(2), (876543210, 876654320));
                true
            } else {
                false
            },
            true
        );

        let opt = opt_iter.next().unwrap();
        assert_eq!(
            if let TcpOption::Unknown(b) = opt {
                assert_eq!(b, &[0x0c, 0x05, 0x01, 0x02, 0x03]);
                true
            } else {
                false
            },
            true
        );

        let opt = opt_iter.next().unwrap();
        assert_eq!(
            if let TcpOption::Eol = opt {
                true
            } else {
                false
            },
            true
        );

        assert_eq!(OptionIter::check_option_bytes(&OPTIONS[..]), true);
    }

    #[test]
    fn option_build() {
        let mut buf: [u8; 70] = [0; 70];
        let mut opt_writer = OptionWriter::from_option_bytes(&mut buf[..]);

        opt_writer.nop();
        opt_writer.mss(1500);
        opt_writer.wsopt(12);
        opt_writer.sack_perm();
        opt_writer.sack(1).set_sack(0, (500, 1500));

        let mut sack = opt_writer.sack(2);
        sack.set_sack(0, (875, 1225));
        sack.set_sack(1, (1500, 2500));

        // let mut sack = opt_writer.sack(3);
        // sack.set_sack(0, (875000, 1225000));
        // sack.set_sack(1, (1500000, 2500000));
        // sack.set_sack(2, (876543210, 876654320));

        assert_eq!(&buf[..64], &OPTIONS[..64]);
    }
}
