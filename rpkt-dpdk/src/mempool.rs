use std::ptr::NonNull;
use std::sync::Arc;

use arrayvec::ArrayVec;

use crate::ffi;
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
    /// Try to allocate a `Mbuf` from the mempool.
    ///
    /// # Examples
    /// ```rust
    /// use rpkt_dpdk::{constant, service, DpdkOption};
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init()
    ///     .unwrap();
    /// {
    ///     let mp = service()
    ///         .mempool_alloc("mp", 8, 0, constant::MBUF_HEADROOM_SIZE + 2048, -1)
    ///         .unwrap();
    ///     let mut mbufs = vec![];
    ///     for _ in 0..8 {
    ///         // The first 8 allocations are guaranteed to succeed.
    ///         let res = mp.try_alloc();
    ///         assert_eq!(res.is_some(), true);
    ///         mbufs.push(res.unwrap());
    ///     }
    ///     // no more mbufs in the mempool, the allocation fails.
    ///     let res = mp.try_alloc();
    ///     assert_eq!(res.is_some(), false);
    /// }
    /// service().graceful_cleanup().unwrap();
    /// ```
    #[inline]
    pub fn try_alloc(&self) -> Option<Mbuf> {
        let raw = unsafe { ffi::rte_pktmbuf_alloc_(self.ptr.as_ptr()) };
        if !raw.is_null() {
            Some(unsafe { Mbuf::from_raw(raw) })
        } else {
            None
        }
    }

    /// Fill up the [`Mbuf`]s to the unocuupied area of `batch`.
    ///
    /// The return value indicates the total number of [`Mbuf`]s allocated.
    ///
    /// # Examples
    /// ```rust
    /// use arrayvec::ArrayVec;
    /// use rpkt_dpdk::{constant, service, DpdkOption};
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init()
    ///     .unwrap();
    /// {
    ///     let mp = service()
    ///         .mempool_alloc("mp", 32, 0, constant::MBUF_HEADROOM_SIZE + 2048, -1)
    ///         .unwrap();
    ///
    ///     let mut batch = ArrayVec::<_, 32>::new();
    ///     // allocate a single mbuf to the batch
    ///     batch.push(mp.try_alloc().unwrap());
    ///     // we can fill up the remaining 31 slots of the batch
    ///     let alloc = mp.fill_up_batch(&mut batch);
    ///     assert_eq!(alloc, 31);
    ///     // mempool is empty, no more allocation can be made
    ///     let alloc = mp.fill_up_batch(&mut batch);
    ///     assert_eq!(alloc, 0);
    ///     let mut new_batch = ArrayVec::<_, 32>::new();
    ///     let alloc = mp.fill_up_batch(&mut new_batch);
    ///     assert_eq!(alloc, 0);
    /// }
    /// service().graceful_cleanup().unwrap();
    /// ```
    #[inline]
    pub fn fill_up_batch<const N: usize>(&self, batch: &mut ArrayVec<Mbuf, N>) -> usize {
        assert!(N <= usize::from(u16::MAX));
        let batch_len = batch.len();
        unsafe {
            let mbufs = std::mem::transmute::<*mut Mbuf, *mut *mut ffi::rte_mbuf>(
                batch.as_mut_ptr().add(batch_len),
            );
            let alloc_nb =
                ffi::rte_pktmbuf_alloc_bulk_(self.ptr.as_ptr(), mbufs, (N - batch_len) as u32);

            if alloc_nb == 0 {
                // allocation succeed
                batch.set_len(N);
                return N - batch_len;
            } else {
                // allocation fail
                return 0;
            }
        }
    }

    /// Deallocate all the [`Mbuf`]s stored in the `batch`.
    ///
    /// You can also free the mbufs by dropping `batch`. However, this will
    /// cause the drop function of [`Mbuf`] to be called for `N` consecutive
    /// times.
    ///
    /// This method is a safe wrapper for [`ffi::rte_pktmbuf_free_bulk`], which
    /// can quickly free the mbufs using dpdk's native ffi API.
    ///
    /// After `free_batch` returns, `batch` length is reset to 0.
    ///
    /// # Examples
    /// ```rust
    /// use arrayvec::ArrayVec;
    /// use rpkt_dpdk::{constant, service, DpdkOption, Mempool};
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init()
    ///     .unwrap();
    /// {
    ///     let mp1 = service()
    ///         .mempool_alloc("mp1", 32, 0, constant::MBUF_HEADROOM_SIZE + 2048, -1)
    ///         .unwrap();
    ///     let mp2 = service()
    ///         .mempool_alloc("mp2", 32, 0, constant::MBUF_HEADROOM_SIZE + 2048, -1)
    ///         .unwrap();
    ///
    ///     let mut batch = ArrayVec::<_, 32>::new();
    ///     // fill up the batch by allocating 16 mbufs from mp1 and 16 mbufs from mp2.
    ///     for _ in 0..16 {
    ///         batch.push(mp1.try_alloc().unwrap());
    ///     }
    ///     for _ in 0..16 {
    ///         batch.push(mp2.try_alloc().unwrap());
    ///     }
    ///     assert_eq!(mp1.nb_mbufs(), 16);
    ///     assert_eq!(mp2.nb_mbufs(), 16);
    ///     assert_eq!(batch.len(), 32);
    ///     // quickly free the batch
    ///     Mempool::free_batch(&mut batch);
    ///     assert_eq!(batch.len(), 0);
    ///     assert_eq!(mp1.nb_mbufs(), 32);
    ///     assert_eq!(mp2.nb_mbufs(), 32);
    /// }
    /// service().graceful_cleanup().unwrap();
    /// ```
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

    /// Query the remaining number of [`Mbuf`]s on the current mempool.
    #[inline]
    pub fn nb_mbufs(&self) -> u32 {
        unsafe { ffi::rte_mempool_avail_count(self.as_ptr()) }
    }

    pub(crate) fn new(ptr: NonNull<ffi::rte_mempool>) -> Self {
        Self {
            ptr,
            counter: Arc::new(()),
        }
    }

    // modified to pub for netbricks_port
    pub(crate) fn as_ptr(&self) -> *const ffi::rte_mempool {
        self.ptr.as_ptr()
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
