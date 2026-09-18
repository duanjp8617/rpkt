//! Internet checksum sums (RFC 1071), without the final complement.
use bytes::Buf;

#[cfg(all(feature = "simd", target_arch = "x86_64"))]
mod avx2;

/// Sum the first `len` available bytes of a segmented buffer, preserving odd
/// byte pairing across segment boundaries. Like `Buf::take`, a larger length
/// consumes only the available bytes.
pub fn from_buf<T: Buf>(buf: T, len: usize) -> u16 {
    let mut buf = buf.take(len);
    let mut tail = None;
    let mut sum = 0u32;
    while buf.has_remaining() {
        let chunk = buf.chunk();
        let count = chunk.len();
        assert!(
            count > 0,
            "Buf returned an empty chunk with bytes remaining"
        );
        let mut bytes = chunk;
        if let Some(high) = tail.take() {
            sum += u16::from_be_bytes([high, bytes[0]]) as u32;
            bytes = &bytes[1..];
        }
        let even = bytes.len() & !1;
        sum += from_slice(&bytes[..even]) as u32;
        tail = bytes.get(even).copied();
        sum = fold(sum) as u32;
        buf.advance(count);
    }
    if let Some(high) = tail {
        sum += (high as u32) << 8;
    }
    fold(sum)
}

/// Compute the folded Internet-checksum sum, without complementing it.
///
/// Arbitrary lengths are supported by periodic folding. With the optional
/// `simd` feature, x86-64 inputs of at least 512 bytes use AVX2 when available.
/// With `std`, CPU detection guards dispatch; without it, AVX2 must be enabled
/// in target features. All other builds use the portable implementation.
pub fn from_slice(data: &[u8]) -> u16 {
    #[cfg(all(feature = "simd", target_arch = "x86_64", not(miri)))]
    if data.len() >= 512 {
        #[cfg(feature = "std")]
        let supported = std::is_x86_feature_detected!("avx2");
        #[cfg(not(feature = "std"))]
        let supported = cfg!(target_feature = "avx2");
        if supported {
            // SAFETY: runtime detection or compile-time target features establish
            // CPU support. The kernel accesses only complete blocks of this slice.
            return unsafe { avx2::sum(data) };
        }
    }
    scalar(data)
}

// Keep the established short-input loop; independent accumulators regressed in
// the initial comparison. Fold at 65536 bytes to bound the u32 sum by 2^31.
fn scalar(data: &[u8]) -> u16 {
    if data.len() <= 65536 {
        return scalar_block(data);
    }
    data.chunks(65536).fold(0, |sum, block| {
        fold(sum as u32 + scalar_block(block) as u32)
    })
}

fn scalar_block(mut data: &[u8]) -> u16 {
    let mut sum = 0u32;
    while data.len() >= 32 {
        let mut chunk = &data[..32];
        while chunk.len() >= 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            chunk = &chunk[2..];
        }
        data = &data[32..];
    }
    while data.len() >= 2 {
        sum += u16::from_be_bytes([data[0], data[1]]) as u32;
        data = &data[2..];
    }
    if let Some(&byte) = data.first() {
        sum += (byte as u32) << 8;
    }
    fold(sum)
}

/// Combine folded sums without overflowing for arbitrarily many inputs.
pub fn combine(checksums: &[u16]) -> u16 {
    checksums
        .iter()
        .fold(0, |sum, &word| fold(sum as u32 + word as u32))
}

fn fold(word: u32) -> u16 {
    let sum = (word >> 16) + (word & 0xffff);
    ((sum >> 16) + (sum & 0xffff)) as u16
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reference(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in bytes.chunks(2) {
            sum += (pair[0] as u32) * 256 + pair.get(1).copied().unwrap_or(0) as u32;
            sum = (sum & 0xffff) + (sum >> 16);
        }
        fold(sum)
    }

    #[test]
    fn kernels_alignments_tails_and_long_inputs() {
        let mut data = std::vec![0u8; 262209];
        let mut state = 0x13579bdfu32;
        for byte in &mut data {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        let lengths: std::vec::Vec<_> = (0..260)
            .chain([511, 512, 513, 65535, 65536, 65537, 131073, 262145])
            .collect();
        for &len in &lengths {
            for align in 0..32 {
                let bytes = &data[align..align + len];
                let expected = reference(bytes);
                assert_eq!(scalar(bytes), expected);
                assert_eq!(from_slice(bytes), expected);
                #[cfg(all(feature = "simd", target_arch = "x86_64", not(miri)))]
                if std::is_x86_feature_detected!("avx2") {
                    assert_eq!(unsafe { avx2::sum(bytes) }, expected);
                }
                for split in [0, len.min(1), len / 2, len] {
                    assert_eq!(
                        from_buf((&bytes[..split]).chain(&bytes[split..]), len),
                        expected
                    );
                }
            }
        }
        data.fill(255);
        assert_eq!(from_slice(&data), reference(&data));
        assert_eq!(combine(&std::vec![65535; 131073]), 65535);
    }
}
