use std::ptr::NonNull;

use rpkt_dpdk_sys as ffi;

use crate::offload::{MbufRxOffload, MbufTxOffload};

#[derive(Debug)]
pub struct Mbuf {
    ptr: NonNull<ffi::rte_mbuf>,
}

unsafe impl Send for Mbuf {}
unsafe impl Sync for Mbuf {}

impl Mbuf {
    #[inline]
    pub fn len(&self) -> usize {
        unsafe { self.ptr.as_ref().data_len.into() }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        unsafe {
            usize::from(
                self.ptr.as_ref().buf_len - self.ptr.as_ref().data_off - self.ptr.as_ref().data_len,
            )
        }
    }

    #[inline]
    pub fn front_capacity(&self) -> usize {
        unsafe { usize::from(self.ptr.as_ref().data_off) }
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                data_addr(self.ptr.as_ref()),
                usize::from(self.ptr.as_ref().data_len),
            )
        }
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(
                data_addr(self.ptr.as_ref()),
                usize::from(self.ptr.as_ref().data_len),
            )
        }
    }

    /// # Panic:
    /// This function panics if `cnt` exceeds the capacity of the mbuf.
    #[inline]
    pub unsafe fn extend(&mut self, cnt: usize) {
        assert!(self.capacity() >= cnt);
        self.ptr.as_mut().data_len += cnt as u16;
        self.ptr.as_mut().pkt_len += cnt as u32;
    }

    /// # Panic:
    /// This function panics if the length of the slice exceeds the capacity of the mbuf.
    #[inline]
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        let old_len = self.len();
        unsafe { self.extend(slice.len()) };
        self.data_mut()[old_len..].copy_from_slice(slice);
    }

    #[inline]
    pub unsafe fn extend_front(&mut self, cnt: usize) {
        assert!(self.front_capacity() >= cnt);
        self.ptr.as_mut().data_len += cnt as u16;
        self.ptr.as_mut().pkt_len += cnt as u32;
        self.ptr.as_mut().data_off -= cnt as u16;
    }

    #[inline]
    pub fn extend_front_from_slice(&mut self, slice: &[u8]) {
        unsafe { self.extend_front(slice.len()) };
        self.data_mut()[..slice.len()].copy_from_slice(slice);
    }

    #[inline]
    pub fn truncate(&mut self, cnt: usize) {
        assert!(cnt <= self.len());
        unsafe {
            self.ptr.as_mut().data_len = cnt as u16;
            self.ptr.as_mut().pkt_len = cnt as u32;
        }
    }

    #[inline]
    pub fn trim_front(&mut self, cnt: usize) {
        assert!(cnt <= self.len());
        unsafe {
            self.ptr.as_mut().data_len -= cnt as u16;
            self.ptr.as_mut().pkt_len -= cnt as u32;
            self.ptr.as_mut().data_off += cnt as u16;
        }
    }

    // rx offload
    #[inline]
    pub fn rx_offload(&self) -> MbufRxOffload {
        MbufRxOffload(unsafe { self.ptr.as_ref().ol_flags })
    }

    #[inline]
    pub fn rss(&self) -> u32 {
        unsafe { self.ptr.as_ref().__bindgen_anon_2.hash.rss }
    }

    #[inline]
    pub fn set_tx_offload(&mut self, tx_offload: MbufTxOffload) {
        unsafe {
            self.ptr.as_mut().ol_flags = tx_offload.0;
        }
    }

    #[inline]
    pub fn set_l2_len(&mut self, val: u64) {
        unsafe {
            self.ptr
                .as_mut()
                .__bindgen_anon_3
                .__bindgen_anon_1
                .set_l2_len(val);
        }
    }

    #[inline]
    pub fn set_l3_len(&mut self, val: u64) {
        unsafe {
            self.ptr
                .as_mut()
                .__bindgen_anon_3
                .__bindgen_anon_1
                .set_l3_len(val);
        }
    }

    // modified to pub for netbricks_port
    #[inline]
    pub unsafe fn from_raw(ptr: *mut ffi::rte_mbuf) -> Self {
        Self {
            ptr: NonNull::new_unchecked(ptr),
        }
    }
}

impl Drop for Mbuf {
    fn drop(&mut self) {
        let raw = self.ptr.as_ptr();
        unsafe { ffi::rte_pktmbuf_free_(raw) };
    }
}

#[inline]
unsafe fn data_addr(mbuf: &ffi::rte_mbuf) -> *mut u8 {
    let data_off = usize::from(mbuf.data_off);
    (mbuf.buf_addr as *mut u8).add(data_off)
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn mbuf_data_append_remove() {
        DpdkOption::new().init().unwrap();

        {
            let mut config = MempoolConf::default();
            config.nb_mbufs = 128;
            let mp = service().mempool_create("wtf", &config).unwrap();

            let mut content: [u8; 1024] = [0; 1024];
            for i in 0..1024 {
                content[i] = (i % u8::MAX as usize) as u8;
            }
            let mut mbuf = mp.try_alloc().unwrap();

            mbuf.extend_from_slice(&content[..512]);
            assert_eq!(mbuf.data(), &content[..512]);
            assert_eq!(mbuf.len(), 512);
            assert_eq!(mbuf.capacity(), MempoolConf::DATAROOM as usize - 512);

            unsafe { mbuf.extend(512) };
            mbuf.data_mut()[512..].copy_from_slice(&content[512..]);
            assert_eq!(mbuf.data(), content);
            assert_eq!(mbuf.len(), 1024);
            assert_eq!(mbuf.capacity(), MempoolConf::DATAROOM as usize - 1024);

            let mut front_content: [u8; 64] = [54; 64];
            (&mut front_content[..32]).copy_from_slice(&[44; 32][..]);
            let mut new_content: [u8; 1088] = [0; 1088];
            new_content[0..64].copy_from_slice(&front_content[..]);
            new_content[64..].copy_from_slice(&content[..]);

            assert_eq!(mbuf.front_capacity(), Mempool::MBUF_HEADROOM as usize);

            unsafe { mbuf.extend_front(32) };
            mbuf.data_mut()[..32].copy_from_slice(&front_content[32..]);
            assert_eq!(mbuf.front_capacity(), Mempool::MBUF_HEADROOM as usize - 32);
            assert_eq!(mbuf.data(), &new_content[32..]);
            assert_eq!(mbuf.len(), 1024 + 32);
            assert_eq!(mbuf.front_capacity(), Mempool::MBUF_HEADROOM as usize - 32);
            assert_eq!(mbuf.capacity(), MempoolConf::DATAROOM as usize - 1024);

            mbuf.extend_front_from_slice(&front_content[..32]);
            assert_eq!(mbuf.front_capacity(), Mempool::MBUF_HEADROOM as usize - 64);
            assert_eq!(mbuf.data(), &new_content[..]);
            assert_eq!(mbuf.len(), 1024 + 64);
            assert_eq!(mbuf.front_capacity(), Mempool::MBUF_HEADROOM as usize - 64);
            assert_eq!(mbuf.capacity(), MempoolConf::DATAROOM as usize - 1024);

            mbuf.truncate(512);
            assert_eq!(mbuf.len(), 512);
            assert_eq!(mbuf.data(), &new_content[..512]);
            assert_eq!(
                mbuf.capacity(),
                MempoolConf::DATAROOM as usize - 1024 + (1024 + 64 - 512)
            );

            mbuf.trim_front(44);
            assert_eq!(mbuf.len(), 512 - 44);
            assert_eq!(mbuf.data(), &new_content[44..512]);
            assert_eq!(
                mbuf.capacity(),
                MempoolConf::DATAROOM as usize - 1024 + (1024 + 64 - 512)
            );
            assert_eq!(
                mbuf.front_capacity(),
                Mempool::MBUF_HEADROOM as usize - 64 + 44
            );
        }

        service().mempool_free("wtf").unwrap();
    }
}
