use bytes::Buf;

use crate::{PktBuf, PktMut};

#[derive(Debug)]
pub struct Cursor<'a> {
    buf: &'a [u8],
    start: *const u8,
}

impl<'a> Cursor<'a> {
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor {
            buf,
            start: buf.as_ptr(),
        }
    }

    #[inline]
    pub fn original_buf(&self) -> &'a [u8] {
        unsafe { std::slice::from_raw_parts(self.start, self.cursor() + self.buf.len()) }
    }

    #[inline]
    pub fn current_buf(&self) -> &'a [u8] {
        self.buf
    }

    #[inline]
    pub fn cursor(&self) -> usize {
        unsafe { self.buf.as_ptr().offset_from(self.start) as usize }
    }
}

// custom implementation for &[u8]
impl<'a> Buf for Cursor<'a> {
    #[inline]
    fn remaining(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.buf
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.buf.len());
        self.buf = &self.buf[cnt..];
    }
}

impl<'a> PktBuf for Cursor<'a> {
    #[inline]
    fn move_back(&mut self, cnt: usize) {
        assert!(cnt <= self.cursor());
        self.buf =
            unsafe { std::slice::from_raw_parts(self.buf.as_ptr().sub(cnt), self.buf.len() + cnt) };
    }

    #[inline]
    fn trim_off(&mut self, cnt: usize) {
        assert!(cnt <= self.buf.len());
        self.buf = &self.buf[..(self.buf.len() - cnt)];
    }
}

#[derive(Debug)]
pub struct CursorMut<'a> {
    buf: &'a mut [u8],
    start: *const u8,
}

impl<'a> CursorMut<'a> {
    #[inline]
    pub fn new(buf: &'a mut [u8]) -> Self {
        let start = buf.as_mut_ptr();
        CursorMut { buf, start }
    }

    #[inline]
    pub fn original_buf(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.start, self.cursor() + self.buf.len()) }
    }

    #[inline]
    pub fn current_buf(self) -> &'a mut [u8] {
        self.buf
    }

    #[inline]
    pub fn cursor(&self) -> usize {
        unsafe { self.buf.as_ptr().offset_from(self.start) as usize }
    }
}

impl<'a> Buf for CursorMut<'a> {
    #[inline]
    fn remaining(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.buf
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.buf.len());
        self.buf = unsafe {
            std::slice::from_raw_parts_mut(self.buf.as_mut_ptr().add(cnt), self.buf.len() - cnt)
        };
    }
}

impl<'a> PktBuf for CursorMut<'a> {
    #[inline]
    fn move_back(&mut self, cnt: usize) {
        assert!(cnt <= self.cursor());
        self.buf = unsafe {
            std::slice::from_raw_parts_mut(self.buf.as_mut_ptr().sub(cnt), self.buf.len() + cnt)
        };
    }

    #[inline]
    fn trim_off(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining());
        self.buf =
            unsafe { std::slice::from_raw_parts_mut(self.buf.as_mut_ptr(), self.buf.len() - cnt) };
    }
}

impl<'a> PktMut for CursorMut<'a> {
    #[inline]
    fn chunk_mut(&mut self) -> &mut [u8] {
        self.buf
    }

    #[inline]
    fn chunk_headroom(&self) -> usize {
        self.cursor()
    }
}

#[cfg(test)]
mod test_cursors {
    use super::*;

    #[test]
    fn test_cursor() {
        let b = [10; 1000];
        for c_pos in 0..1001 {
            let mut cursor = Cursor::new(&b[..]);
            cursor.advance(c_pos);

            assert_eq!(c_pos, cursor.cursor());
            assert_eq!(cursor.original_buf(), &b[..]);
            assert_eq!(cursor.remaining(), 1000 - c_pos);
            assert_eq!(cursor.chunk(), &b[c_pos..]);
        }

        for c_pos in 0..1001 {
            let mut cursor = Cursor::new(&b[..]);
            cursor.advance(1000);
            cursor.move_back(c_pos);

            assert_eq!(1000 - c_pos, cursor.cursor());
            assert_eq!(cursor.original_buf(), &b[..]);
            assert_eq!(cursor.remaining(), c_pos);
            assert_eq!(cursor.chunk(), &b[1000 - c_pos..]);
        }

        let n = 300;
        for c_pos in 0..(1000 - n + 1) {
            let mut cursor = Cursor::new(&b[..]);
            cursor.advance(n);

            cursor.trim_off(c_pos);
            assert_eq!(cursor.remaining(), 1000 - n - c_pos);
            assert_eq!(cursor.chunk(), &b[n..(1000 - c_pos)]);
        }
    }

    #[test]
    fn test_cursor_mut() {
        let mut b = [10; 1000];
        let mut c: [u8; 1000] = [10; 1000];
        for c_pos in 0..1001 {
            let mut cursor = CursorMut::new(&mut b[..]);
            cursor.advance(c_pos);

            assert_eq!(c_pos, cursor.cursor());
            assert_eq!(cursor.original_buf(), &c[..]);
            assert_eq!(cursor.remaining(), 1000 - c_pos);
            assert_eq!(cursor.chunk_mut(), &mut c[c_pos..]);
        }

        for c_pos in 0..1001 {
            let mut cursor = CursorMut::new(&mut b[..]);
            cursor.advance(1000);
            cursor.move_back(c_pos);

            assert_eq!(1000 - c_pos, cursor.cursor());
            assert_eq!(cursor.original_buf(), &c[..]);
            assert_eq!(cursor.remaining(), c_pos);
            assert_eq!(cursor.chunk_mut(), &mut c[1000 - c_pos..]);
        }

        let n = 300;
        for c_pos in 0..(1000 - n + 1) {
            let mut cursor = CursorMut::new(&mut b[..]);
            cursor.advance(n);

            cursor.trim_off(c_pos);
            assert_eq!(cursor.remaining(), 1000 - n - c_pos);
            assert_eq!(cursor.chunk_mut(), &mut c[n..(1000 - c_pos)]);
        }
    }
}
