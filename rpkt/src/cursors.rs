use core::ops::{Range, RangeFrom, RangeFull, RangeTo};
use core::{marker::PhantomData, slice};

use bytes::Buf;

use crate::{PktBuf, PktBufMut};

// A specialized index trait for cursor.
// It is used to simulate the std index behavior, but
// return a owned Cursor instead of a reference.
pub(crate) trait CursorIndex<Idx: ?Sized> {
    /// Performs the indexing (`container[index]`) operation.
    ///
    /// # Panics
    ///
    /// May panic if the index is out of bounds.
    fn index_(&self, index: Idx) -> Cursor<'_>;
}

// A specialized mutable index trait for cursor.
// It is used to simulate the std mutable index behavior, but
// return a owned Cursor instead of a reference.
pub(crate) trait CursorIndexMut<Idx: ?Sized> {
    /// Performs the mutable indexing (`container[index]`) operation.
    ///
    /// # Panics
    ///
    /// May panic if the index is out of bounds.
    fn index_mut_(&mut self, index: Idx) -> CursorMut<'_>;
}

/// A container type that turns a byte slice into `PktBuf`.
#[derive(Debug, Clone, Copy)]
pub struct Cursor<'a> {
    chunk: &'a [u8],
    start_addr: *const u8,
}

impl<'a> Cursor<'a> {
    /// Create a new `Cursor` from a byte slice.
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor {
            chunk: buf,
            start_addr: buf.as_ptr(),
        }
    }

    /// Return the original byte slice.
    #[inline]
    pub fn buf(&self) -> &'a [u8] {
        unsafe { slice::from_raw_parts(self.start_addr, self.cursor() + self.chunk.len()) }
    }

    /// Calculate the current cursor position.
    #[inline]
    pub fn cursor(&self) -> usize {
        unsafe { self.chunk.as_ptr().offset_from(self.start_addr) as usize }
    }
}

// implement Buf
impl<'a> Buf for Cursor<'a> {
    #[inline]
    fn remaining(&self) -> usize {
        self.chunk.len()
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.chunk
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.chunk.len());
        self.chunk = &self.chunk[cnt..];
    }
}

// implement PktBuf
impl<'a> PktBuf for Cursor<'a> {
    #[inline]
    fn move_back(&mut self, cnt: usize) {
        assert!(cnt <= self.cursor());
        let new_cursor = self.cursor() - cnt;
        unsafe {
            let new_chunk_start = self.start_addr.add(new_cursor);
            let new_chunk_len = self.chunk.len() + cnt;
            self.chunk = slice::from_raw_parts(new_chunk_start, new_chunk_len);
        }
    }

    #[inline]
    fn trim_off(&mut self, cnt: usize) {
        assert!(cnt <= self.chunk.len());
        self.chunk = &self.chunk[..(self.chunk.len() - cnt)];
    }
}

// Implement `CursorIndex` trait for Cursor
impl<'a> CursorIndex<Range<usize>> for Cursor<'a> {
    #[inline]
    fn index_(&self, idx: Range<usize>) -> Cursor<'a> {
        Cursor {
            chunk: &self.chunk[idx],
            start_addr: self.start_addr,
        }
    }
}

impl<'a> CursorIndex<RangeFrom<usize>> for Cursor<'a> {
    #[inline]
    fn index_(&self, idx: RangeFrom<usize>) -> Cursor<'a> {
        Cursor {
            chunk: &self.chunk[idx],
            start_addr: self.start_addr,
        }
    }
}

impl<'a> CursorIndex<RangeTo<usize>> for Cursor<'a> {
    #[inline]
    fn index_(&self, idx: RangeTo<usize>) -> Cursor<'a> {
        Cursor {
            chunk: &self.chunk[idx],
            start_addr: self.start_addr,
        }
    }
}

impl<'a> CursorIndex<RangeFull> for Cursor<'a> {
    #[inline]
    fn index_(&self, idx: RangeFull) -> Cursor<'a> {
        Cursor {
            chunk: &self.chunk[idx],
            start_addr: self.start_addr,
        }
    }
}

/// A mutable container type that turns a mutable byte slice into `PktBufMut`.
#[derive(Debug)]
pub struct CursorMut<'a> {
    chunk_addr: *mut u8,
    chunk_len: usize,
    start_addr: *mut u8,
    _data: PhantomData<&'a mut [u8]>,
}

impl<'a> CursorMut<'a> {
    /// Create a new `CursorMut` from a byte slice.
    #[inline]
    pub fn new(buf: &'a mut [u8]) -> Self {
        let start_addr = buf.as_mut_ptr();
        let chunk_len = buf.len();
        CursorMut {
            chunk_addr: start_addr,
            chunk_len,
            start_addr,
            _data: PhantomData,
        }
    }

    /// Return the original byte slice.
    #[inline]
    pub fn buf(&mut self) -> &mut [u8] {
        let len = self.cursor() + self.chunk_len;
        unsafe { slice::from_raw_parts_mut(self.start_addr, len) }
    }

    /// Calculate the current cursor position.
    #[inline]
    pub fn cursor(&self) -> usize {
        unsafe { self.chunk_addr.offset_from(self.start_addr) as usize }
    }
}

// implement Buf
impl<'a> Buf for CursorMut<'a> {
    #[inline]
    fn remaining(&self) -> usize {
        self.chunk_len
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.chunk_addr as *const u8, self.chunk_len) }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.chunk_len);
        unsafe {
            self.chunk_addr = self.chunk_addr.add(cnt);
            self.chunk_len -= cnt;
        }
    }
}

// implement PktBuf
impl<'a> PktBuf for CursorMut<'a> {
    #[inline]
    fn move_back(&mut self, cnt: usize) {
        assert!(cnt <= self.cursor());
        unsafe {
            self.chunk_addr = self.chunk_addr.sub(cnt);
            self.chunk_len += cnt;
        }
    }

    #[inline]
    fn trim_off(&mut self, cnt: usize) {
        assert!(cnt <= self.chunk_len);
        self.chunk_len -= cnt;
    }
}

// implement PktBufMut
impl<'a> PktBufMut for CursorMut<'a> {
    #[inline]
    fn chunk_mut(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.chunk_addr, self.chunk_len) }
    }

    #[inline]
    fn chunk_headroom(&self) -> usize {
        self.cursor()
    }
}

// Implement `CursorMutIndex` trait for CursorMut
impl<'a> CursorIndexMut<Range<usize>> for CursorMut<'a> {
    #[inline]
    fn index_mut_(&mut self, idx: Range<usize>) -> CursorMut<'_> {
        let chunk = &mut self.chunk_mut()[idx];
        CursorMut {
            chunk_addr: chunk.as_mut_ptr(),
            chunk_len: chunk.len(),
            start_addr: self.start_addr,
            _data: PhantomData,
        }
    }
}

impl<'a> CursorIndexMut<RangeFrom<usize>> for CursorMut<'a> {
    #[inline]
    fn index_mut_(&mut self, idx: RangeFrom<usize>) -> CursorMut<'_> {
        let chunk = &mut self.chunk_mut()[idx];
        CursorMut {
            chunk_addr: chunk.as_mut_ptr(),
            chunk_len: chunk.len(),
            start_addr: self.start_addr,
            _data: PhantomData,
        }
    }
}

impl<'a> CursorIndexMut<RangeTo<usize>> for CursorMut<'a> {
    #[inline]
    fn index_mut_(&mut self, idx: RangeTo<usize>) -> CursorMut<'_> {
        let chunk = &mut self.chunk_mut()[idx];
        CursorMut {
            chunk_addr: chunk.as_mut_ptr(),
            chunk_len: chunk.len(),
            start_addr: self.start_addr,
            _data: PhantomData,
        }
    }
}

impl<'a> CursorIndexMut<RangeFull> for CursorMut<'a> {
    #[inline]
    fn index_mut_(&mut self, idx: RangeFull) -> CursorMut<'_> {
        let chunk = &mut self.chunk_mut()[idx];
        CursorMut {
            chunk_addr: chunk.as_mut_ptr(),
            chunk_len: chunk.len(),
            start_addr: self.start_addr,
            _data: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cursor() {
        let b = [10; 1000];
        for c_pos in 0..1001 {
            let mut cursor = Cursor::new(&b[..]);
            cursor.advance(c_pos);

            assert_eq!(c_pos, cursor.cursor());
            assert_eq!(cursor.buf(), &b[..]);
            assert_eq!(cursor.remaining(), 1000 - c_pos);
            assert_eq!(cursor.chunk(), &b[c_pos..]);
        }

        for c_pos in 0..1001 {
            let mut cursor = Cursor::new(&b[..]);
            cursor.advance(1000);
            cursor.move_back(c_pos);

            assert_eq!(1000 - c_pos, cursor.cursor());
            assert_eq!(cursor.buf(), &b[..]);
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
            assert_eq!(cursor.buf(), &c[..]);
            assert_eq!(cursor.remaining(), 1000 - c_pos);
            assert_eq!(cursor.chunk(), &mut c[c_pos..]);
        }

        for c_pos in 0..1001 {
            let mut cursor = CursorMut::new(&mut b[..]);
            cursor.advance(1000);
            cursor.move_back(c_pos);

            assert_eq!(1000 - c_pos, cursor.cursor());
            assert_eq!(cursor.buf(), &c[..]);
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

    #[test]
    #[should_panic]
    fn cursor_advance_too_much() {
        let mut b = [10; 1000];
        let mut cursor = Cursor::new(&mut b[..]);
        cursor.advance(407);
        cursor.advance(10000);
    }

    #[test]
    #[should_panic]
    fn cursor_moveback_too_much() {
        let mut b = [10; 1000];
        let mut cursor = Cursor::new(&mut b[..]);
        cursor.advance(407);
        cursor.move_back(10000);
    }

    #[test]
    #[should_panic]
    fn cursor_trimoff_too_much() {
        let mut b = [10; 1000];
        let mut cursor = Cursor::new(&mut b[..]);
        cursor.advance(407);
        cursor.trim_off(10000);
    }

    #[test]
    #[should_panic]
    fn cursor_mut_advance_too_much() {
        let mut b = [10; 1000];
        let mut cursor = CursorMut::new(&mut b[..]);
        cursor.advance(407);
        cursor.advance(10000);
    }

    #[test]
    #[should_panic]
    fn cursor_mut_moveback_too_much() {
        let mut b = [10; 1000];
        let mut cursor = CursorMut::new(&mut b[..]);
        cursor.advance(407);
        cursor.move_back(10000);
    }

    #[test]
    #[should_panic]
    fn cursor_mut_trimoff_too_much() {
        let mut b = [10; 1000];
        let mut cursor = CursorMut::new(&mut b[..]);
        cursor.advance(407);
        cursor.trim_off(10000);
    }
}
