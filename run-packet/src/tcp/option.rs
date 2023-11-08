use byteorder::{ByteOrder, NetworkEndian};

const END_OF_LIST: u8 = 0;
const NOP: u8 = 1;
const MAX_SEG_SIZE: u8 = 2;
const WINDOW_SCALE: u8 = 3;
const SACK_PERMITTED: u8 = 4;
const SELECTIVE_ACK: u8 = 5;
const TIMESTAMPS: u8 = 8;
const TCP_FASTOPEN: u8 = 34;

pub struct MaxSegSize<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> MaxSegSize<T> {
    pub fn max_seg_size(&self) -> u16 {
        NetworkEndian::read_u16(&self.buf.as_ref()[2..4])
    }
}

impl<T: AsMut<[u8]>> MaxSegSize<T> {
    pub fn set_max_seg_size(&mut self, mss: u16) {
        NetworkEndian::write_u16(&mut self.buf.as_mut()[2..4], mss);
    }
}

pub struct WindowScale<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> WindowScale<T> {
    pub fn window_scale(&self) -> u8 {
        self.buf.as_ref()[2]
    }
}

impl<T: AsMut<[u8]>> WindowScale<T> {
    pub fn fill_buf(buf: &mut [u8], value: u8) -> (WindowScale<&mut [u8]>, &mut [u8]) {
        assert!(buf.len() >= 3);
        let (buf, remaining) = buf.split_at_mut(3);
        let mut ws_option = WindowScale { buf };

        ws_option.buf.as_mut()[0] = WINDOW_SCALE;
        ws_option.buf.as_mut()[1] = 3;
        ws_option.set_window_scale(value);

        (ws_option, remaining)
    }

    pub fn set_window_scale(&mut self, value: u8) {
        self.buf.as_mut()[2] = value;
    }
}

pub fn fill_sack_permitted(buf: &mut [u8]) -> &mut [u8] {
    assert!(buf.len() >= 2);
    buf[0] = SACK_PERMITTED;
    buf[1] = 2;
    &mut buf[2..]
}

pub struct SelectiveAck<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> SelectiveAck<T> {
    pub fn num_blocks(&self) -> usize {
        // assert!(self.option_len() >= 2 && (self.option_len() - 2) % 8 == 0);
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
    pub fn fill_buf(buf: &mut [u8], num_sacks: usize) -> (SelectiveAck<&mut [u8]>, &mut [u8]) {
        assert!(num_sacks <= 4 && buf.len() >= 2 + num_sacks * 8);
        let (buf, remaining) = buf.split_at_mut(2 + num_sacks * 8);
        let sack_option = SelectiveAck { buf };

        sack_option.buf.as_mut()[0] = SELECTIVE_ACK;
        sack_option.buf.as_mut()[1] = (2 + num_sacks * 8) as u8;

        (sack_option, remaining)
    }

    pub fn set_sack(&mut self, idx: usize, sack: (u32, u32)) {
        assert!(idx < self.num_blocks());
        NetworkEndian::write_u32(&mut self.buf.as_mut()[2 + 8 * idx..6 + 8 * idx], sack.0);
        NetworkEndian::write_u32(&mut self.buf.as_mut()[6 + 8 * idx..6 + 10 * idx], sack.1);
    }
}

pub struct Timestamps<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> Timestamps<T> {
    pub fn timestamp(&self) -> u32 {
        NetworkEndian::read_u32(&self.buf.as_ref()[2..6])
    }

    pub fn timestamp_echo(&self) -> u32 {
        NetworkEndian::read_u32(&self.buf.as_ref()[6..10])
    }
}

impl<T: AsMut<[u8]>> Timestamps<T> {
    pub fn fill_buf(
        buf: &mut [u8],
        timestamp: u32,
        timestamp_echo: u32,
    ) -> (Timestamps<&mut [u8]>, &mut [u8]) {
        assert!(buf.len() >= 10);
        let (buf, remaining) = buf.split_at_mut(10);
        let mut ts_option = Timestamps { buf };

        ts_option.buf.as_mut()[0] = TIMESTAMPS;
        ts_option.buf.as_mut()[1] = 10;

        ts_option.set_timestamp(timestamp);
        ts_option.set_timestamp_echo(timestamp_echo);

        (ts_option, remaining)
    }

    pub fn set_timestamp(&mut self, value: u32) {
        NetworkEndian::write_u32(&mut self.buf.as_mut()[2..6], value);
    }

    pub fn set_timestamp_echo(&mut self, value: u32) {
        NetworkEndian::write_u32(&mut self.buf.as_mut()[6..10], value);
    }
}

pub struct TcpFastopen<T> {
    buf: T,
}

impl<T: AsRef<[u8]>> TcpFastopen<T> {
    pub fn cookie(&self) -> &[u8] {
        &self.buf.as_ref()[2..18]
    }
}

impl<T: AsMut<[u8]>> TcpFastopen<T> {
    pub fn fill_buf<'a>(
        buf: &'a mut [u8],
        value: &'a [u8],
    ) -> (TcpFastopen<&'a mut [u8]>, &'a mut [u8]) {
        assert!(buf.len() >= 18);
        let (buf, remaining) = buf.split_at_mut(18);
        let mut fastopen_option = TcpFastopen { buf };

        fastopen_option.buf.as_mut()[0] = TCP_FASTOPEN;
        fastopen_option.buf.as_mut()[1] = 18;
        fastopen_option.set_cookie(value);

        (fastopen_option, remaining)
    }

    pub fn set_cookie(&mut self, value: &[u8]) {
        (&mut self.buf.as_mut()[2..18]).copy_from_slice(value);
    }
}

pub enum TcpOption<'a> {
    Eol,
    Nop,
    Mss(MaxSegSize<&'a [u8]>),
    Wsopt(WindowScale<&'a [u8]>),
    SackPerm,
    Sack(SelectiveAck<&'a [u8]>),
    Ts(Timestamps<&'a [u8]>),
    Fo(TcpFastopen<&'a [u8]>),
    Unknown(&'a [u8]),
}

pub struct OptionWriter<'a> {
    buf: &'a mut [u8],
    cursor: usize,
}

impl<'a> OptionWriter<'a> {
    pub fn eol(&mut self) -> Option<()> {
        if self.cursor < self.buf.len() {
            self.buf[self.cursor] = END_OF_LIST;
            self.cursor += 1;

            Some(())
        } else {
            None
        }
    }

    pub fn nop(&mut self) -> Option<()> {
        if self.cursor < self.buf.len() {
            self.buf[self.cursor] = NOP;
            self.cursor += 1;

            Some(())
        } else {
            None
        }
    }

    pub fn mss(&'a mut self, mss: u16) -> Option<MaxSegSize<&'a mut [u8]>> {
        if self.buf.len() - self.cursor >= 4 {
            let buf = &mut self.buf[self.cursor..self.cursor + 4];
            self.cursor += 4;

            let mut mss_option = MaxSegSize { buf };
            mss_option.buf.as_mut()[0] = MAX_SEG_SIZE;
            mss_option.buf.as_mut()[1] = 4;
            mss_option.set_max_seg_size(mss);

            Some(mss_option)
        } else {
            None
        }
    }
}

pub struct OptionReader<'a> {
    buf: &'a [u8],
    valid: bool,
}

impl<'a> OptionReader<'a> {
    pub fn from_option_bytes(buf: &'a [u8]) -> OptionReader<'a> {
        Self { buf, valid: true }
    }

    pub fn check_option_bytes(buf: &'a [u8]) -> bool {
        let mut reader = Self::from_option_bytes(buf);
        while let Some(_) = (&mut reader).next() {}
        reader.valid()
    }

    pub fn valid(&self) -> bool {
        self.valid
    }
}

impl<'a> Iterator for &mut OptionReader<'a> {
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
            _ => match opt_type {
                MAX_SEG_SIZE => {
                    if self.buf[1] != 4 || self.buf.len() < 4 {
                        self.valid = false;
                        None
                    } else {
                        let opt = MaxSegSize {
                            buf: &self.buf[..4],
                        };
                        self.buf = &self.buf[4..];
                        Some(TcpOption::Mss(opt))
                    }
                }
                WINDOW_SCALE => {
                    if self.buf[1] != 3 || self.buf.len() < 3 {
                        self.valid = false;
                        None
                    } else {
                        let opt = WindowScale {
                            buf: &self.buf[..3],
                        };
                        self.buf = &self.buf[3..];
                        Some(TcpOption::Wsopt(opt))
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
                        let opt = Timestamps {
                            buf: &self.buf[..10],
                        };
                        self.buf = &self.buf[10..];
                        Some(TcpOption::Ts(opt))
                    }
                }
                TCP_FASTOPEN => {
                    if self.buf[1] != 18 || self.buf.len() < 18 {
                        self.valid = false;
                        None
                    } else {
                        let opt = TcpFastopen {
                            buf: &self.buf[..18],
                        };
                        self.buf = &self.buf[18..];
                        Some(TcpOption::Fo(opt))
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
            },
        }
    }
}
