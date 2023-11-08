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

    pub fn sack(&'a mut self, num_sacks: usize) -> SelectiveAck<&'a mut [u8]> {
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
