use std::marker::PhantomData;

use rpkt::{Buf, PktBuf, PktBufMut};

use crate::mbuf::{data_addr, Mbuf};
use crate::sys::rte_mbuf;

#[derive(Debug)]
pub struct Pbuf<'a> {
    mbuf_head: *mut Mbuf,
    mbuf_cur: *mut rte_mbuf,
    chunk_start: *mut u8,
    chunk_len: usize,
    segs_len: usize,
    _data: PhantomData<&'a mut Mbuf>,
}

impl<'a> Pbuf<'a> {
    #[inline]
    pub fn new(mbuf: &'a mut Mbuf) -> Self {
        unsafe {
            let mbuf_cur = mbuf.as_mut_ptr();
            let chunk_len = usize::from((*mbuf_cur).data_len);

            Self {
                mbuf_head: mbuf as *mut Mbuf,
                mbuf_cur,
                chunk_start: data_addr(&*mbuf_cur),
                chunk_len,
                segs_len: chunk_len,
                _data: PhantomData,
            }
        }
    }

    #[inline]
    pub fn buf(&self) -> &Mbuf {
        unsafe { &*self.mbuf_head }
    }

    #[inline]
    pub fn cursor(&self) -> usize {
        self.segs_len - self.chunk_len
    }

    // Advance the cursor to the `target_cursor` position.
    // Note: this method should only be used by the `advance` and `move_back` trait method.
    #[inline]
    unsafe fn advance_common(&mut self, target_cursor: usize) {
        while self.segs_len <= target_cursor && !(*self.mbuf_cur).next.is_null() {
            self.mbuf_cur = (*self.mbuf_cur).next;
            self.segs_len += usize::from((*self.mbuf_cur).data_len);
        }

        self.chunk_len = self.segs_len - target_cursor;
        self.chunk_start =
            data_addr(&*self.mbuf_cur).add(usize::from((*self.mbuf_cur).data_len) - self.chunk_len);
    }

    fn advance_slow(&mut self, cnt: usize) {
        unsafe {
            assert!(cnt <= (*self.mbuf_head).pkt_len() - self.cursor());
            self.advance_common(self.cursor() + cnt);
        }
    }

    fn move_back_slow(&mut self, cnt: usize) {
        assert!(cnt <= self.cursor());

        // the new cursor position
        let target_cursor = self.cursor() - cnt;
        unsafe {
            // reset the `cur_seg` to the first segment
            self.mbuf_cur = (*self.mbuf_head).as_mut_ptr();
            self.segs_len = usize::from((*self.mbuf_cur).data_len);

            self.advance_common(target_cursor);
        }
    }
}

impl<'a> Buf for Pbuf<'a> {
    #[inline]
    fn chunk(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.chunk_start, self.chunk_len) }
    }

    #[inline]
    fn advance(&mut self, cnt: usize) {
        if cnt >= self.chunk_len {
            self.advance_slow(cnt);
        } else {
            unsafe {
                self.chunk_start = self.chunk_start.add(cnt);
                self.chunk_len -= cnt;
            }
        }
    }

    #[inline]
    fn remaining(&self) -> usize {
        unsafe { (*self.mbuf_head).pkt_len() - self.cursor() }
    }
}

impl<'a> PktBuf for Pbuf<'a> {
    #[inline]
    fn move_back(&mut self, cnt: usize) {
        unsafe {
            if cnt > self.chunk_headroom() {
                self.move_back_slow(cnt);
            } else {
                self.chunk_start = self.chunk_start.sub(cnt);
                self.chunk_len += cnt;
            }
        }
    }

    fn trim_off(&mut self, cnt: usize) {
        let cursor = self.cursor();
        assert!(cnt <= self.remaining());

        let new_len = unsafe { (*self.mbuf_head).pkt_len() - cnt };
        if cursor == new_len && self.chunk_headroom() == 0 {
            unsafe {
                (*self.mbuf_head).truncate_to(new_len);

                self.mbuf_cur = (*self.mbuf_head).as_mut_ptr();
                self.segs_len = usize::from((*self.mbuf_cur).data_len);

                self.advance_common(cursor);
            }
        } else {
            unsafe {
                (*self.mbuf_head).truncate_to(new_len);
            }
            if new_len < self.segs_len {
                self.chunk_len = new_len - cursor;
                self.segs_len = new_len;
            }
        }
    }
}

impl<'a> PktBufMut for Pbuf<'a> {
    #[inline]
    fn chunk_headroom(&self) -> usize {
        unsafe { usize::from((*self.mbuf_cur).data_len) - self.chunk_len }
    }

    #[inline]
    fn chunk_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.chunk_start, self.chunk_len) }
    }
}