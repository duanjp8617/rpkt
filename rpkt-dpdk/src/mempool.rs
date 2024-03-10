use std::convert::TryFrom;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr::NonNull;
use std::sync::Arc;

use arrayvec::ArrayVec;
use rpkt_dpdk_sys as ffi;

use crate::error::*;
use crate::Mbuf;

#[derive(Clone, Copy, Debug)]
pub struct MempoolConf {
    pub nb_mbufs: u32,
    pub per_core_caches: u32,
    pub dataroom: u16,
    pub socket_id: u32,
}

impl MempoolConf {
    pub const DATAROOM: u16 = ffi::RTE_MBUF_DEFAULT_DATAROOM as u16;
    pub const NB_MBUFS: u32 = 2048;
    pub const PER_CORE_CACHES: u32 = 0;

    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_nb_mbufs(&mut self, val: u32) {
        self.nb_mbufs = val;
    }

    pub fn set_per_core_caches(&mut self, val: u32) {
        self.per_core_caches = val;
    }

    pub fn set_dataroom(&mut self, val: u16) {
        self.dataroom = val;
    }

    pub fn set_socket_id(&mut self, val: u32) {
        self.socket_id = val;
    }
}

impl Default for MempoolConf {
    fn default() -> Self {
        Self {
            nb_mbufs: Self::NB_MBUFS,
            per_core_caches: Self::PER_CORE_CACHES,
            dataroom: Self::DATAROOM,
            socket_id: 0,
        }
    }
}

#[derive(Clone)]
pub struct Mempool {
    ptr: NonNull<ffi::rte_mempool>,
    counter: Arc<()>,
}

unsafe impl Send for Mempool {}
unsafe impl Sync for Mempool {}

impl Mempool {
    pub const MBUF_HEADROOM: u16 = ffi::RTE_PKTMBUF_HEADROOM as u16;

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
    pub fn fill_batch<const N: usize>(&self, batch: &mut ArrayVec<Mbuf, N>) {
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

    pub(crate) fn try_create(mpool_name: String, conf: &MempoolConf) -> Result<Self> {
        let err = Error::service_err("invalid mempool config");
        let data_room_size = conf.dataroom.checked_add(Self::MBUF_HEADROOM).ok_or(err)?;
        let socket_id = i32::try_from(conf.socket_id).map_err(|_| err)?;

        // create the mempool
        let cname =
            CString::new(mpool_name).map_err(|_| Error::service_err("invalid mempool name"))?;
        let raw = unsafe {
            ffi::rte_pktmbuf_pool_create(
                cname.as_bytes_with_nul().as_ptr() as *const c_char,
                conf.nb_mbufs,
                conf.per_core_caches,
                0,
                data_room_size,
                socket_id,
            )
        };

        let ptr = NonNull::new(raw).ok_or_else(|| {
            Error::ffi_err(unsafe { ffi::rte_errno_() }, "fail to allocate mempool")
        })?;

        Ok(Self {
            ptr,
            counter: Arc::new(()),
        })
    }

    pub(crate) unsafe fn delete(self) {
        assert!(self.full() == true && self.in_use() == false);
        ffi::rte_mempool_free(self.ptr.as_ptr());
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
        DpdkOption::new().init().unwrap();

        {
            let mut config = MempoolConf::default();
            config.nb_mbufs = 128;

            let res = service().mempool_create("wtf", &config);
            assert_eq!(res.is_err(), false);

            let res = service().mempool_create("wtf", &config);
            assert_eq!(res.is_err(), true);
        }

        let res = service().mempool_free("wtf");
        assert_eq!(res.is_err(), false);

        let res = service().mempool_free("wtf");
        assert_eq!(res.is_err(), true);
    }

    #[test]
    fn mbuf_alloc_and_size_check() {
        DpdkOption::new().init().unwrap();

        {
            let mut config = MempoolConf::default();
            config.nb_mbufs = 128;
            config.dataroom = 512;
            let mp = service().mempool_create("wtf", &config).unwrap();

            for _ in 0..512 {
                let mut mbuf = mp.try_alloc().unwrap();
                mbuf.extend_from_slice(&[0xff; 265][..]);
            }

            for _ in 0..128 {
                let mbuf = mp.try_alloc().unwrap();
                assert_eq!(mbuf.capacity(), 512);
                assert_eq!(mbuf.front_capacity(), Mempool::MBUF_HEADROOM as usize);
                assert_eq!(mbuf.len(), 0);
            }

            for _ in 0..(128 / 32) {
                let mut batch = ArrayVec::<_, 32>::new();
                mp.fill_batch(&mut batch);
                for mbuf in batch.iter() {
                    assert_eq!(mbuf.capacity(), 512);
                    assert_eq!(mbuf.front_capacity(), Mempool::MBUF_HEADROOM as usize);
                    assert_eq!(mbuf.len(), 0);
                }
            }
        }

        service().mempool_free("wtf").unwrap();
    }

    #[test]
    fn mbuf_data_unchanged_after_realloc() {
        DpdkOption::new().init().unwrap();

        {
            let mut config = MempoolConf::default();
            config.nb_mbufs = 128;
            let mp = service().mempool_create("wtf", &config).unwrap();
            let mut sb = [0; 1];

            for i in 0..128 {
                let mut mbuf = mp.try_alloc().unwrap();
                sb[0] = i + 1;
                mbuf.extend_from_slice(&sb[..]);
                assert_eq!(mbuf.data()[0], i + 1);
            }

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
        DpdkOption::new().init().unwrap();
        assert_eq!(service().lcores().len() >= 4, true);

        let mut config = MempoolConf::default();
        config.nb_mbufs = 512;
        config.per_core_caches = 32;
        service().mempool_create("wtf", &config).unwrap();

        let mut jhs = Vec::new();
        for i in 2..4 {
            let jh = std::thread::spawn(move || {
                service().lcore_bind(i).unwrap();
                let mp = service().mempool("wtf").unwrap();
                let mut batch = ArrayVec::<_, 32>::new();
                for _ in 0..100 {
                    mp.fill_batch(&mut batch);
                    for mbuf in batch.drain(..) {
                        assert_eq!(mbuf.capacity(), MempoolConf::DATAROOM as usize);
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
}
