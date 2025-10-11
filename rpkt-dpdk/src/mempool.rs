use std::ptr::NonNull;
use std::sync::Arc;

use arrayvec::ArrayVec;

use crate::sys as ffi;
use crate::Mbuf;

#[derive(Clone)]
pub struct Mempool {
    ptr: NonNull<ffi::rte_mempool>,
    counter: Arc<()>,
}

unsafe impl Send for Mempool {}
unsafe impl Sync for Mempool {}

// PktmbufPool
impl Mempool {
    #[inline]
    pub fn try_alloc(&self) -> Option<Mbuf> {
        let raw = unsafe { ffi::rte_pktmbuf_alloc_(self.ptr.as_ptr()) };
        if !raw.is_null() {
            Some(unsafe { Mbuf::from_raw(raw) })
        } else {
            None
        }
    }

    #[inline]
    pub fn fill_up_batch<const N: usize>(&self, batch: &mut ArrayVec<Mbuf, N>) {
        assert!(N <= usize::from(u16::MAX));
        let batch_len = batch.len();
        unsafe {
            let mbufs = std::mem::transmute::<*mut Mbuf, *mut *mut ffi::rte_mbuf>(
                batch.as_mut_ptr().add(batch_len),
            );
            let alloc_nb =
                ffi::rte_pktmbuf_alloc_bulk_(self.ptr.as_ptr(), mbufs, (N - batch_len) as u32);
            if alloc_nb == 0 {
                batch.set_len(N);
            }
        }
    }

    #[inline]
    pub fn free_batch<const N: usize>(batch: &mut ArrayVec<Mbuf, N>) {
        assert!(N <= usize::from(u16::MAX));
        let batch_len = batch.len();
        if batch_len == 0 {
            return;
        }
        unsafe {
            let mbufs =
                std::mem::transmute::<*mut Mbuf, *mut *mut ffi::rte_mbuf>(batch.as_mut_ptr());
            ffi::rte_pktmbuf_free_bulk(mbufs, batch_len as u32);
            batch.set_len(0);
        }
    }

    #[inline]
    pub fn nb_mbufs(&self) -> u32 {
        unsafe { ffi::rte_mempool_avail_count(self.as_ptr()) }
    }

    // modified to pub for netbricks_port
    pub fn as_ptr(&self) -> *const ffi::rte_mempool {
        self.ptr.as_ptr()
    }

    pub(crate) fn new(ptr: NonNull<ffi::rte_mempool>) -> Self {
        Self {
            ptr,
            counter: Arc::new(()),
        }
    }

    pub(crate) fn in_use(&self) -> bool {
        Arc::<()>::strong_count(&self.counter) != 1
    }

    pub(crate) fn full(&self) -> bool {
        unsafe {
            let raw = self.ptr.as_ptr();
            ffi::rte_mempool_full_(raw) == 1
        }
    }
}
