pub use bytes::Buf;

/// A buffer whose readable header survives shared access and field mutation.
///
/// Generated parsers validate lengths once and subsequently index `chunk()`
/// without bounds checks. This is stronger than the safe [`Buf`] contract.
///
/// # Safety
/// Until an explicit cursor/length operation through an exclusive borrow,
/// `chunk()` must retain its length and logical position, and `remaining()`
/// must retain its value. Shared access (including interior mutability and
/// access through other handles) must not shorten or invalidate that region.
/// If `PktBufMut` is implemented, `chunk_mut()` must expose the same region
/// and length as `chunk()`; obtaining it and editing bytes must not change
/// the region's extent. Cloning must preserve these length/position invariants
/// in the clone. All cursor operations must maintain valid initialized slices.
/// Packet wrappers do not expose exclusive access to the buffer until release.
///
/// A safe `Buf` implementation alone cannot opt into unchecked packet access:
/// ```compile_fail
/// use rpkt::{Buf, ether::EtherFrame};
/// struct Custom;
/// impl Buf for Custom {
///     fn remaining(&self) -> usize { 14 }
///     fn chunk(&self) -> &[u8] { &[0; 14] }
///     fn advance(&mut self, _: usize) {}
/// }
/// let _ = EtherFrame::parse(Custom);
/// ```
/// Unchecked construction and structural length changes require an unsafe block:
/// ```compile_fail
/// let _ = rpkt::udp::Udp::parse_unchecked(&[0u8; 8][..]);
/// ```
/// ```compile_fail
/// let mut header = rpkt::ipv4::Ipv4::default_header();
/// rpkt::ipv4::Ipv4::from_header_array_mut(&mut header).set_header_len(20);
/// ```
pub unsafe trait StableBuf: Buf {}

// SAFETY: shared byte slices have immutable length/position until advanced.
unsafe impl StableBuf for &[u8] {}
// SAFETY: these owned byte buffers cannot change extent through shared access;
// their Clone implementations preserve the current readable region.
unsafe impl StableBuf for bytes::Bytes {}
unsafe impl StableBuf for bytes::BytesMut {}
// SAFETY: exclusive forwarding preserves the underlying type's contract.
unsafe impl<T: StableBuf + ?Sized> StableBuf for &mut T {}

/// The PktBuf trait.
pub trait PktBuf: StableBuf {
    /// Move cursor back.
    fn move_back(&mut self, cnt: usize);

    /// Remove trailing bytes.
    fn trim_off(&mut self, cnt: usize);
}

/// The PktBufMut trait.
pub trait PktBufMut: PktBuf {
    /// Size of the chunk headroom.
    fn chunk_headroom(&self) -> usize;

    /// A mutable chunk slice.
    fn chunk_mut(&mut self) -> &mut [u8];
}

impl<T: PktBuf + ?Sized> PktBuf for &mut T {
    #[inline]
    fn move_back(&mut self, cnt: usize) {
        (**self).move_back(cnt)
    }

    #[inline]
    fn trim_off(&mut self, cnt: usize) {
        (**self).trim_off(cnt);
    }
}

impl<T: PktBufMut + ?Sized> PktBufMut for &mut T {
    #[inline]
    fn chunk_mut(&mut self) -> &mut [u8] {
        (**self).chunk_mut()
    }

    #[inline]
    fn chunk_headroom(&self) -> usize {
        (**self).chunk_headroom()
    }
}
