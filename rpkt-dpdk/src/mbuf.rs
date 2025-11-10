#[cfg(miri)]
use std::os::raw::c_void;

use std::marker::PhantomData;
use std::ptr::{null_mut, NonNull};

#[cfg(not(miri))]
use crate::mempool::Mempool;

use crate::ffi;

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

    /// Total bytes available for storing data.
    #[inline]
    pub fn capacity(&self) -> usize {
        unsafe { usize::from(self.ptr.as_ref().buf_len - self.ptr.as_ref().data_off) }
    }

    /// Total bytes available at the front for storing data.
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
        assert!(slice.len() <= self.capacity() - self.data_len());
        let old_len = self.data_len();
        unsafe { self.extend(slice.len()) };
        self.data_mut()[old_len..].copy_from_slice(slice);
    }

    #[inline]
    pub fn extend_front_from_slice(&mut self, slice: &[u8]) {
        assert!(slice.len() <= self.front_capacity());
        unsafe { self.extend_front(slice.len()) };
        self.data_mut()[..slice.len()].copy_from_slice(slice);
    }

    /// Increase buffer length by `cnt` bytes.
    #[inline]
    pub unsafe fn extend(&mut self, cnt: usize) {
        debug_assert!(cnt <= self.capacity() - self.data_len());
        self.ptr.as_mut().data_len += cnt as u16;
        self.ptr.as_mut().pkt_len += cnt as u32;
    }

    /// Decrease buffer length by `cnt` bytes.
    #[inline]
    pub unsafe fn shrink(&mut self, cnt: usize) {
        debug_assert!(cnt <= self.data_len());
        self.ptr.as_mut().data_len -= cnt as u16;
        self.ptr.as_mut().pkt_len -= cnt as u32;
    }

    /// Increase the buffer length at the front.
    ///
    /// This also increases the total capacity.
    #[inline]
    pub unsafe fn extend_front(&mut self, cnt: usize) {
        debug_assert!(cnt <= self.front_capacity());
        self.ptr.as_mut().data_len += cnt as u16;
        self.ptr.as_mut().pkt_len += cnt as u32;
        self.ptr.as_mut().data_off -= cnt as u16;
    }

    /// Decrease the buffer length at the front.
    ///
    /// This also decreases the total capacity.
    #[inline]
    pub unsafe fn shrink_front(&mut self, cnt: usize) {
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

    #[inline]
    pub(crate) const unsafe fn as_mut_ptr(&mut self) -> *mut ffi::rte_mbuf {
        self.ptr.as_ptr()
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

impl Mbuf {
    /// Return the total packet length stored on the mbuf.
    ///
    /// Note this is different from `data_len`, which only indicates the
    /// data length of a single mbuf segment.
    ///
    /// Sincle multiple single-seg mbufs can be concatenated together into
    /// a chained mbuf, `pkt_len` is the sum of all the data length of
    /// all the chained mbufs.
    #[inline]
    pub fn pkt_len(&self) -> usize {
        (unsafe { self.ptr.as_ref().pkt_len }) as usize
    }

    /// The total number of mbuf segments chained together.
    #[inline]
    pub fn num_segs(&self) -> usize {
        usize::from(unsafe { self.ptr.as_ref().nb_segs })
    }

    #[cfg(not(miri))]
    fn from_slice_slow(
        mut source: &[u8],
        mempool: &Mempool,
        mut fst_seg: Mbuf,
        chunk_cap: usize,
    ) -> Option<Self> {
        // Safety: source.len() > 0, chunk_cap is fixed
        let source_len = source.len();
        let total_remaining_segs = (source.len() - 1) / usize::from(chunk_cap) + 1;
        if total_remaining_segs > (ffi::RTE_MBUF_MAX_NB_SEGS - 1) as usize {
            return None;
        }

        let mut cur_seg = fst_seg.ptr;
        for _ in 0..total_remaining_segs - 1 {
            let mut mbuf = mempool.try_alloc()?;
            mbuf.extend_from_slice(&source[..chunk_cap]);
            source = &source[chunk_cap..];

            unsafe {
                cur_seg.as_mut().next = mbuf.into_raw();
                cur_seg = NonNull::new_unchecked(cur_seg.as_ref().next);
            }
        }

        let mut mbuf = mempool.try_alloc()?;
        mbuf.extend_from_slice(source);
        unsafe {
            cur_seg.as_mut().next = mbuf.into_raw();

            fst_seg.ptr.as_mut().pkt_len += source_len as u32;
            fst_seg.ptr.as_mut().nb_segs += total_remaining_segs as u16;
        }

        Some(fst_seg)
    }

    /// Construct a mbuf from a `source` byte slice and a mempool.
    #[cfg(not(miri))]
    #[inline]
    pub fn from_slice(source: &[u8], mempool: &Mempool) -> Option<Self> {
        // create the first segment
        let mut fst_seg = mempool.try_alloc()?;
        let cap = fst_seg.capacity();
        if cap >= source.len() {
            fst_seg.extend_from_slice(source);
            Some(fst_seg)
        } else {
            fst_seg.extend_from_slice(&source[..cap]);
            Self::from_slice_slow(&source[cap..], mempool, fst_seg, cap)
        }
    }

    /// Concatenate the current mbuf with another mbuf.
    #[inline]
    pub fn concat(&mut self, other: Mbuf) {
        assert!(self.num_segs() + other.num_segs() <= (ffi::RTE_MBUF_MAX_NB_SEGS) as usize);

        let mut other_ptr = other.ptr;
        std::mem::forget(other);

        // find out the current linklist tail
        let mut cur_tail = self.ptr;
        unsafe {
            while !cur_tail.as_ref().next.is_null() {
                cur_tail = NonNull::new_unchecked(cur_tail.as_ref().next);
            }
        }

        unsafe {
            // chain 'other' to the old tail
            cur_tail.as_mut().next = other_ptr.as_ptr();

            // accumulate number of segments and total length
            self.ptr.as_mut().nb_segs += other_ptr.as_ref().nb_segs;
            self.ptr.as_mut().pkt_len += other_ptr.as_ref().pkt_len;

            // pkt_len is only set in the head
            other_ptr.as_mut().pkt_len = other_ptr.as_ref().data_len as u32;
            other_ptr.as_mut().nb_segs = 1;
        }
    }

    /// Truncate the packet length of mbuf to `new_size` bytes.
    #[cfg(not(miri))]
    pub fn truncate_to(&mut self, new_size: usize) {
        assert!(new_size <= self.pkt_len());

        let mut cur_seg = self.ptr;
        let mut remaining = new_size;
        let mut nb_segs = 1;

        // SAFETY: safety holds, see comments.
        unsafe {
            // Iterate through the `rte_mbuf` link list.
            // After the iteration, `cur_seg` will point to the last segment after truncating
            // the original `rte_mbuf` to `new_size` bytes.
            while usize::from(cur_seg.as_ref().data_len) < remaining {
                remaining -= usize::from(cur_seg.as_ref().data_len);
                nb_segs += 1;
                cur_seg = NonNull::new_unchecked(cur_seg.as_ref().next);
            }

            if !cur_seg.as_ref().next.is_null() {
                // The trailing segements of `cur_seg` should be deleted.
                // The deletion task is delegated to dpdk library, which
                // can safely free a link list of segments.
                ffi::rte_pktmbuf_free_(cur_seg.as_ref().next);

                // After deleting the trailing segments, `cur_seg` becomes
                // the last segment.
                cur_seg.as_mut().next = null_mut();
                // Adjust the `nb_segs` at the first segment as well.
                self.ptr.as_mut().nb_segs = nb_segs;
            }

            // `remaining` now equals to the length of the last segment.
            cur_seg.as_mut().data_len = remaining as u16;
            // The packet length is truncated to `cnt`.
            self.ptr.as_mut().pkt_len = new_size as u32;
        }
    }

    /// Return a imutable iterator to all the segment data of the mbuf.
    #[inline]
    pub fn seg_iter<'a>(&'a self) -> SegIter<'a> {
        SegIter {
            cur_seg: Some(self.ptr),
            _data: PhantomData,
        }
    }

    /// Return a mutable iterator to all the segment data of the mbuf.
    #[inline]
    pub fn seg_iter_mut<'a>(&'a mut self) -> SegIterMut<'a> {
        SegIterMut {
            cur_seg: Some(self.ptr),
            _data: PhantomData,
        }
    }

    #[inline]
    pub fn appender<'a>(&'a mut self) -> Appender<'a> {
        let mut last_seg = self.ptr;
        unsafe {
            while !last_seg.as_ref().next.is_null() {
                last_seg = NonNull::new_unchecked(last_seg.as_ref().next);
            }
        }
        Appender {
            buf: self,
            last_seg,
        }
    }
}

/// The immutable iterator to all the segment data of the mbuf.
///
/// Each `Item` returned by this iterator corresponds to immutable
/// byte slice covering the active data area of a single mbuf segment.
pub struct SegIter<'a> {
    cur_seg: Option<NonNull<ffi::rte_mbuf>>,
    _data: PhantomData<&'a Mbuf>,
}

impl<'a> Iterator for SegIter<'a> {
    type Item = &'a [u8];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.cur_seg.map(|cur_seg| unsafe {
            let res = std::slice::from_raw_parts(
                data_addr(cur_seg.as_ref()),
                cur_seg.as_ref().data_len as usize,
            );
            self.cur_seg = NonNull::new(cur_seg.as_ref().next);
            res
        })
    }
}

/// The mutable iterator to all the segment data of the mbuf.
///
/// Each `Item` returned by this iterator corresponds to mutable
/// byte slice covering the active data area of a single mbuf segment.
pub struct SegIterMut<'a> {
    cur_seg: Option<NonNull<ffi::rte_mbuf>>,
    _data: PhantomData<&'a mut Mbuf>,
}

impl<'a> Iterator for SegIterMut<'a> {
    type Item = &'a mut [u8];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.cur_seg.map(|cur_seg| unsafe {
            let res = std::slice::from_raw_parts_mut(
                data_addr(cur_seg.as_ref()),
                cur_seg.as_ref().data_len as usize,
            );
            self.cur_seg = NonNull::new(cur_seg.as_ref().next);
            res
        })
    }
}

pub struct Appender<'a> {
    buf: &'a mut Mbuf,
    last_seg: NonNull<ffi::rte_mbuf>,
}

impl<'a> Appender<'a> {
    pub fn append_single_seg(&mut self, other: Mbuf) {
        // Make sure that `other` is a single-segment `Mbuf`.
        assert!(other.num_segs() == 1);
        assert!(self.buf.num_segs() <= (ffi::RTE_MBUF_MAX_NB_SEGS - 1) as usize);

        let other_ptr = other.ptr;
        std::mem::forget(other);

        unsafe {
            // chain 'tail' onto the old tail
            self.last_seg.as_mut().next = other_ptr.as_ptr();

            // accumulate number of segments and total length
            self.buf.ptr.as_mut().nb_segs += 1;
            self.buf.ptr.as_mut().pkt_len += other_ptr.as_ref().pkt_len;

            // update the last_seg
            self.last_seg = other_ptr;
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

#[inline]
pub(crate) unsafe fn data_addr(mbuf: &ffi::rte_mbuf) -> *mut u8 {
    let data_off = usize::from(mbuf.data_off);
    (mbuf.buf_addr as *mut u8).add(data_off)
}

#[cfg(miri)]
unsafe fn deallocate_rte_mbuf(ptr: *mut ffi::rte_mbuf) {
    unsafe {
        let buf_len = (*ptr).buf_len;
        let buf_addr = (*ptr).buf_addr as *mut u8;
        let slice_ptr: *mut [u8] = std::ptr::slice_from_raw_parts_mut(buf_addr, buf_len as usize);
        let _reconstructed_box: Box<[u8]> = Box::from_raw(slice_ptr);
    }

    unsafe {
        let _reconstructed_box: Box<ffi::rte_mbuf> = Box::from_raw(ptr);
    }
}

#[cfg(miri)]
impl Drop for Mbuf {
    fn drop(&mut self) {
        let mut curr = unsafe { self.ptr.as_mut() as *mut ffi::rte_mbuf };

        while !curr.is_null() {
            unsafe {
                let next = (*curr).next;
                deallocate_rte_mbuf(curr);
                curr = next;
            }
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
        boxed_mbuf.next = null_mut();
        boxed_mbuf.nb_segs = 1;

        Self {
            ptr: NonNull::new(Box::into_raw(boxed_mbuf)).unwrap(),
        }
    }

    fn from_slice_slow(
        mut source: &[u8],
        data_room: u16,
        head_room: u16,
        mut fst_seg: Mbuf,
        chunk_cap: usize,
    ) -> Option<Self> {
        // Safety: source.len() > 0, chunk_cap is fixed
        let source_len = source.len();
        let total_remaining_segs = (source.len() - 1) / usize::from(chunk_cap) + 1;
        if total_remaining_segs > (ffi::RTE_MBUF_MAX_NB_SEGS - 1) as usize {
            return None;
        }

        let mut cur_seg = fst_seg.ptr;
        for _ in 0..total_remaining_segs - 1 {
            let mut mbuf = Mbuf::new(data_room, head_room);
            mbuf.extend_from_slice(&source[..chunk_cap]);
            source = &source[chunk_cap..];

            unsafe {
                cur_seg.as_mut().next = mbuf.into_raw();
                cur_seg = NonNull::new_unchecked(cur_seg.as_ref().next);
            }
        }

        let mut mbuf = Mbuf::new(data_room, head_room);
        mbuf.extend_from_slice(source);
        unsafe {
            cur_seg.as_mut().next = mbuf.into_raw();

            fst_seg.ptr.as_mut().pkt_len += source_len as u32;
            fst_seg.ptr.as_mut().nb_segs += total_remaining_segs as u16;
        }

        Some(fst_seg)
    }

    #[inline]
    pub fn from_slice(source: &[u8], data_room: u16, head_room: u16) -> Option<Self> {
        // create the first segment
        let mut fst_seg = Mbuf::new(data_room, head_room);
        let cap = fst_seg.capacity();
        if cap >= source.len() {
            fst_seg.extend_from_slice(source);
            Some(fst_seg)
        } else {
            fst_seg.extend_from_slice(&source[..cap]);
            Self::from_slice_slow(&source[cap..], data_room, head_room, fst_seg, cap)
        }
    }

    pub fn truncate_to(&mut self, new_size: usize) {
        assert!(new_size <= self.pkt_len());

        let mut cur_seg = self.ptr;
        let mut remaining = new_size;
        let mut nb_segs = 1;

        // SAFETY: safety holds, see comments.
        unsafe {
            // Iterate through the `rte_mbuf` link list.
            // After the iteration, `cur_seg` will point to the last segment after truncating
            // the original `rte_mbuf` to `new_size` bytes.
            while usize::from(cur_seg.as_ref().data_len) < remaining {
                remaining -= usize::from(cur_seg.as_ref().data_len);
                nb_segs += 1;
                cur_seg = NonNull::new_unchecked(cur_seg.as_ref().next);
            }

            if !cur_seg.as_ref().next.is_null() {
                // The trailing segements of `cur_seg` should be deleted.
                {
                    let mut curr = cur_seg.as_ref().next;

                    while !curr.is_null() {
                        let next = (*curr).next;
                        deallocate_rte_mbuf(curr);
                        curr = next;
                    }
                }

                // After deleting the trailing segments, `cur_seg` becomes
                // the last segment.
                cur_seg.as_mut().next = null_mut();
                // Adjust the `nb_segs` at the first segment as well.
                self.ptr.as_mut().nb_segs = nb_segs;
            }

            // `remaining` now equals to the length of the last segment.
            cur_seg.as_mut().data_len = remaining as u16;
            // The packet length is truncated to `cnt`.
            self.ptr.as_mut().pkt_len = new_size as u32;
        }
    }
}
