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
    pub const MBUF_HEADROOM_SIZE: u16 = ffi::RTE_PKTMBUF_HEADROOM as u16;

    pub const MBUF_DATAROOM_SIZE: u16 = ffi::RTE_MBUF_DEFAULT_DATAROOM as u16;

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
    pub fn alloc_in_batch<const N: usize>(&self, batch: &mut ArrayVec<Mbuf, N>) {
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

#[cfg(test)]
mod tests {
    use crate::*;
    use arrayvec::*;

    #[test]
    fn create_mempool_with_same_name() {
        DpdkOption::default().init().unwrap();

        {
            let res = service().mempool_alloc("wtf", 128, 0, Mempool::MBUF_DATAROOM_SIZE, -1);
            assert_eq!(res.is_err(), false);

            let res = service().mempool_alloc("wtf", 128, 0, Mempool::MBUF_DATAROOM_SIZE, -1);
            assert_eq!(res.is_err(), true);
        }

        let res = service().mempool_free("wtf");
        assert_eq!(res.is_err(), false);

        let res = service().mempool_free("wtf");
        assert_eq!(res.is_err(), true);
    }

    #[test]
    fn mbuf_alloc_and_size_check() {
        DpdkOption::default().init().unwrap();

        {
            let mp = service().mempool_alloc("wtf", 128, 0, 512, -1).unwrap();

            for _ in 0..512 {
                let mut mbuf = mp.try_alloc().unwrap();
                mbuf.extend_from_slice(&[0xff; 265][..]);
            }

            for _ in 0..128 {
                let mbuf = mp.try_alloc().unwrap();
                assert_eq!(mbuf.capacity(), 512 - Mempool::MBUF_HEADROOM_SIZE as usize);
                assert_eq!(mbuf.front_capacity(), Mempool::MBUF_HEADROOM_SIZE as usize);
                assert_eq!(mbuf.len(), 0);
            }

            for _ in 0..(128 / 32) {
                let mut batch = ArrayVec::<_, 32>::new();
                mp.alloc_in_batch(&mut batch);
                for mbuf in batch.iter() {
                    assert_eq!(mbuf.capacity(), 512 - Mempool::MBUF_HEADROOM_SIZE as usize);
                    assert_eq!(mbuf.front_capacity(), Mempool::MBUF_HEADROOM_SIZE as usize);
                    assert_eq!(mbuf.len(), 0);
                }
            }
        }

        service().mempool_free("wtf").unwrap();
    }

    #[test]
    fn mbuf_data_unchanged_after_realloc() {
        DpdkOption::default().init().unwrap();

        {
            let mp = service()
                .mempool_alloc("wtf", 128, 0, Mempool::MBUF_DATAROOM_SIZE, -1)
                .unwrap();
            let mut sb = [0; 1];

            let mut mbufs = vec![];
            for i in 0..128 {
                let mut mbuf = mp.try_alloc().unwrap();
                sb[0] = i + 1;
                mbuf.extend_from_slice(&sb[..]);
                assert_eq!(mbuf.data()[0], i + 1);
                mbufs.push(mbuf);
            }
            assert_eq!(mp.try_alloc().is_none(), true);

            drop(mbufs);
            for i in 0..128 {
                let mut mbuf = mp.try_alloc().unwrap();
                unsafe { mbuf.extend(1) };
                assert_eq!(mbuf.data()[0], i + 1);
            }
        }

        service().mempool_free("wtf").unwrap();
    }

    #[test]
    fn alloc_mbuf_from_multiple_threads() {
        DpdkOption::default().init().unwrap();
        assert_eq!(service().lcores().len() >= 4, true);

        service()
            .mempool_alloc(
                "wtf",
                512,
                32,
                Mempool::MBUF_DATAROOM_SIZE + Mempool::MBUF_HEADROOM_SIZE,
                -1,
            )
            .unwrap();

        let mut jhs = Vec::new();
        for i in 2..4 {
            let jh = std::thread::spawn(move || {
                service().lcore_bind(i).unwrap();
                service().rte_thread_register().unwrap();

                let mp = service().mempool("wtf").unwrap();

                let mut batch = ArrayVec::<_, 32>::new();
                for _ in 0..100 {
                    mp.alloc_in_batch(&mut batch);
                    for mbuf in batch.drain(..) {
                        assert_eq!(mbuf.capacity(), Mempool::MBUF_DATAROOM_SIZE as usize);
                        assert_eq!(mbuf.front_capacity(), Mempool::MBUF_HEADROOM_SIZE as usize);
                    }
                }
            });
            jhs.push(jh);
        }

        for jh in jhs {
            jh.join().unwrap();
        }

        service().mempool_free("wtf").unwrap();
    }

    #[test]
    fn secondary_process_mempool() {
        // run examples/mempool_primary first
        DpdkOption::with_eal_arg("-l 2 -n 4 --file-prefix mempool_primary --proc-type=secondary")
            .init()
            .unwrap();
        assert_eq!(service().is_primary_process().unwrap(), false);

        assert_eq!(
            service().mempool_alloc("wtf", 127, 0, 200, -1).is_err(),
            true
        );

        let mp = service().mempool("wtf").unwrap();
        let mut mbufs = vec![];
        for _ in 0..127 {
            let mbuf = mp.try_alloc().unwrap();
            assert_eq!(mbuf.capacity(), 200 - Mempool::MBUF_HEADROOM_SIZE as usize);
            assert_eq!(mbuf.front_capacity(), Mempool::MBUF_HEADROOM_SIZE as usize);
            assert_eq!(mbuf.len(), 0);
            mbufs.push(mbuf);
        }
        assert_eq!(mp.try_alloc().is_none(), true);
        assert_eq!(mbufs.len(), 127);

        assert_eq!(service().mempool_free("wtf").is_err(), true);
    }
}
