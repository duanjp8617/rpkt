#[cfg(miri)]
use std::os::raw::c_void;

use std::ptr::NonNull;

use crate::sys as ffi;

#[derive(Debug)]
pub struct Mbuf {
    ptr: NonNull<ffi::rte_mbuf>,
}

unsafe impl Send for Mbuf {}
unsafe impl Sync for Mbuf {}

impl Mbuf {
    /// Total data length in bytes.
    #[inline]
    pub fn data_len(&self) -> usize {
        unsafe { self.ptr.as_ref().data_len.into() }
    }

    /// Remaining byte length at the back for storing data.
    #[inline]
    pub fn capacity(&self) -> usize {
        unsafe {
            usize::from(
                self.ptr.as_ref().buf_len - self.ptr.as_ref().data_off - self.ptr.as_ref().data_len,
            )
        }
    }

    /// Remaining byte length at the front for storing data.
    #[inline]
    pub fn front_capacity(&self) -> usize {
        unsafe { usize::from(self.ptr.as_ref().data_off) }
    }

    /// Return the current data as a byte slice.
    #[inline]
    pub fn data(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                data_addr(self.ptr.as_ref()),
                usize::from(self.ptr.as_ref().data_len),
            )
        }
    }

    /// Return the current data as a mutable byte slice.
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
    /// This function panics if the length of the slice exceeds the capacity of
    /// the mbuf.
    #[inline]
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        assert!(self.capacity() >= slice.len());
        let old_len = self.data_len();
        unsafe { self.set_data_len(old_len + slice.len()) };
        self.data_mut()[old_len..].copy_from_slice(slice);
    }

    #[inline]
    pub fn extend_front_from_slice(&mut self, slice: &[u8]) {
        assert!(slice.len() <= self.front_capacity());
        unsafe { self.increase_len_at_front(slice.len()) };
        self.data_mut()[..slice.len()].copy_from_slice(slice);
    }

    /// # Panic:
    /// This function panics if `cnt` exceeds the capacity of the mbuf.
    #[inline]
    pub unsafe fn set_data_len(&mut self, new_len: usize) {
        debug_assert!(
            new_len <= usize::from(self.ptr.as_ref().buf_len - self.ptr.as_ref().data_off)
        );
        self.ptr.as_mut().data_len = new_len as u16;
        self.ptr.as_mut().pkt_len = new_len as u32;
    }

    #[inline]
    pub unsafe fn increase_len_at_front(&mut self, cnt: usize) {
        debug_assert!(self.front_capacity() >= cnt);
        self.ptr.as_mut().data_len += cnt as u16;
        self.ptr.as_mut().pkt_len += cnt as u32;
        self.ptr.as_mut().data_off -= cnt as u16;
    }

    #[inline]
    pub unsafe fn decrease_len_at_front(&mut self, cnt: usize) {
        debug_assert!(cnt <= self.data_len());
        unsafe {
            self.ptr.as_mut().data_len -= cnt as u16;
            self.ptr.as_mut().pkt_len -= cnt as u32;
            self.ptr.as_mut().data_off += cnt as u16;
        }
    }

    // modified to pub for netbricks_port
    #[inline]
    pub const unsafe fn from_raw(ptr: *mut ffi::rte_mbuf) -> Self {
        Self {
            ptr: NonNull::new_unchecked(ptr),
        }
    }

    #[inline]
    pub const unsafe fn into_raw(self) -> *mut ffi::rte_mbuf {
        let res = self.ptr.as_ptr();
        std::mem::forget(self);
        res
    }
}

impl Mbuf {
    /// The rx_offload for the mbuf. 
    /// 
    /// By reading from the rx_offload field, we obtain the offloading result
    /// computed by the NIC. Examples include rss hash and ip/l4 checksum offload results.
    /// 
    /// rx_offload supports the following bit fields:
    /// 
    /// bit value : rx offload name
    /// 
    /// - 1 << 1: RTE_MBUF_F_RX_RSS_HASH      
    /// - 1 << 4: RTE_MBUF_F_RX_IP_CKSUM_BAD
    /// - 1 << 7: RTE_MBUF_F_RX_IP_CKSUM_GOOD
    /// - 1 << 3: RTE_MBUF_F_RX_L4_CKSUM_BAD
    /// - 1 << 8: RTE_MBUF_F_RX_L4_CKSUM_GOOD
    #[inline]
    pub fn rx_offload(&self) -> u64 {
        unsafe { self.ptr.as_ref().ol_flags }
    }

    #[inline]
    pub fn rss(&self) -> u32 {
        unsafe { self.ptr.as_ref().__bindgen_anon_2.hash.rss }
    }

    /// The tx_offload for the mbuf. 
    /// 
    /// By setting the tx_offload field, we can enable NIC hardware tx
    /// offload for this mbuf. Examples include IP/UDP/TCP checksum offload, 
    /// and TCP segment offloading (TSO).
    /// 
    /// tx_offload supports the following bit fields:
    /// 
    /// bit value : tx offload name
    /// 
    /// - 1 << 54: RTE_MBUF_F_TX_IP_CKSUM
    /// - 1 << 55: RTE_MBUF_F_TX_IPV4
    /// - 1 << 56: RTE_MBUF_F_TX_IPV6
    /// - 3 << 52: RTE_MBUF_F_TX_UDP_CKSUM
    /// - 1 << 52: RTE_MBUF_F_TX_TCP_CKSUM
    /// - 1 << 50: RTE_MBUF_F_TX_TCP_SEG
    #[inline]
    pub fn set_tx_offload(&mut self, tx_offload: u64) {
        unsafe {
            self.ptr.as_mut().ol_flags = tx_offload;
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
}

#[cfg(not(miri))]
impl Drop for Mbuf {
    fn drop(&mut self) {
        let raw = self.ptr.as_ptr();
        unsafe { ffi::rte_pktmbuf_free_(raw) };
    }
}

#[cfg(miri)]
impl Drop for Mbuf {
    fn drop(&mut self) {
        // Custom drop for miri test.
        unsafe {
            let buf_len = self.ptr.as_mut().buf_len;
            let buf_addr = self.ptr.as_mut().buf_addr as *mut u8;
            let slice_ptr: *mut [u8] =
                std::ptr::slice_from_raw_parts_mut(buf_addr, buf_len as usize);
            let _reconstructed_box: Box<[u8]> = Box::from_raw(slice_ptr);
        }

        unsafe {
            let mbuf_addr: *mut ffi::rte_mbuf = self.ptr.as_mut() as *mut ffi::rte_mbuf;
            let _reconstructed_box: Box<ffi::rte_mbuf> = Box::from_raw(mbuf_addr);
        }
    }
}

#[cfg(miri)]
impl Mbuf {
    // A Mbuf allocation method for miri test.
    pub fn new(data_room: u16, head_room: u16) -> Self {
        let vec: Vec<u8> = vec![0; (data_room + head_room) as usize];
        let boxed_array: Box<[u8]> = vec.into_boxed_slice();
        let buf_addr = Box::into_raw(boxed_array) as *mut u8;

        let mbuf: ffi::rte_mbuf = unsafe { std::mem::zeroed() };
        let mut boxed_mbuf = Box::new(mbuf);
        boxed_mbuf.buf_addr = buf_addr as *mut c_void;
        boxed_mbuf.data_off = head_room;
        boxed_mbuf.data_len = 0;
        boxed_mbuf.pkt_len = 0;
        boxed_mbuf.buf_len = data_room + head_room;

        Self {
            ptr: NonNull::new(Box::into_raw(boxed_mbuf)).unwrap(),
        }
    }
}

#[inline]
unsafe fn data_addr(mbuf: &ffi::rte_mbuf) -> *mut u8 {
    let data_off = usize::from(mbuf.data_off);
    (mbuf.buf_addr as *mut u8).add(data_off)
}
