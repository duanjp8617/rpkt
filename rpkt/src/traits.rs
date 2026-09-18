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

/// The PktBufCopy trait.
pub trait PktBufCopy : PktBufMut {
    /// Copy data from a byte slice into the buffer.
    /// 
    /// # Panics
    /// Panics if the source slice is larger than the buffer's remaining space.
    #[inline]
    fn copy_from_slice(&mut self, src: &[u8]) {
        let mut remaining = src.len();
        let mut offset = 0;
        while remaining > 0 {
            let chunk = self.chunk_mut();
            let chunk_len = std::cmp::min(remaining, chunk.len());
            chunk[..chunk_len].copy_from_slice(&src[offset..offset + chunk_len]);
            self.advance(chunk_len);
            offset += chunk_len;
            remaining -= chunk_len;
        }
    }

    /// Prepend data from a byte slice into the buffer.
    /// 
    /// # Panics
    /// Panics if the source slice is larger than the buffer's headroom.
    #[inline]
    fn prepend_from_slice(&mut self, src: &[u8]) {
        let mut remaining = src.len();
        while remaining > 0 {
            let headroom = self.chunk_headroom();
            let chunk_len = std::cmp::min(remaining, headroom);
            self.move_back(chunk_len);
            let chunk = self.chunk_mut();
            chunk[..chunk_len].copy_from_slice(&src[remaining - chunk_len..remaining]);
            remaining -= chunk_len;
        }
    }

    /// Copy almost cnt bytes from another PktBuf into the buffer.
    #[inline]
    fn copy_from_pktbuf<B: PktBuf>(&mut self, src: &mut B, cnt: usize) {
        let remaining = std::cmp::min(cnt, src.remaining());
        let mut copied = 0;
        while copied < remaining {
            let chunk = src.chunk();
            let to_copy = std::cmp::min(remaining - copied, chunk.len());
            self.copy_from_slice(chunk[..to_copy].as_ref());
            src.advance(to_copy);
            copied += to_copy;
        }
        src.move_back(remaining);
    }

    /// Copy all data from another PktBuf into the buffer.
    #[inline]
    fn copy_from_pktbuf_all<B: PktBuf>(&mut self, src: &mut B) {
        let remaining = src.remaining();
        while src.has_remaining() {
            let chunk = src.chunk();
            self.copy_from_slice(chunk);
            src.advance(chunk.len());
        }
        src.move_back(remaining);
    }

    /// Prepend data from another PktBuf into the buffer.
    /// # Panics
    /// Panics if the source buffer has more data than the destination buffer's headroom.
    #[inline]
    fn prepend_from_pktbuf<B: PktBuf>(&mut self, src: &mut B, cnt: usize) {
        let remaining = std::cmp::min(cnt, src.remaining());
        let mut copied = 0;
        while copied < remaining {
            let chunk = src.chunk();
            let to_copy = std::cmp::min(remaining - copied, chunk.len());
            self.prepend_from_slice(&chunk[chunk.len() - to_copy..]);
            src.move_back(to_copy);
            copied += to_copy;
        }
        src.move_back(remaining);
    }

    /// Prepend all data from another PktBuf into the buffer.
    /// # Panics
    /// Panics if the source buffer has more data than the destination buffer's headroom.
    #[inline]
    fn prepend_from_pktbuf_all<B: PktBuf>(&mut self, src: &mut B) {
        let remaining = src.remaining();
        while src.has_remaining() {
            let chunk = src.chunk();
            self.prepend_from_slice(chunk);
            src.move_back(chunk.len());
        }
        src.move_back(remaining);
    }
}

impl <T: PktBufMut + ?Sized> PktBufCopy for T {}
