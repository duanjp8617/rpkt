pub use bytes::Buf;

/// The PktBuf trait.
pub trait PktBuf: Buf {
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
