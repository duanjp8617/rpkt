use core::arch::x86_64::*;

// SAFETY contract: caller establishes AVX2 support. The entire input is an
// initialized slice; no load touches the tail or a neighboring allocation.
// Split even/odd byte sums before applying the network-order weight of 256.
// Each block is <=65536 bytes, so lane sums and the final u32 reduction fit.
#[target_feature(enable = "avx2")]
pub(super) unsafe fn sum(data: &[u8]) -> u16 {
    let mut result = 0u32;
    for block in data.chunks(65536) {
        let zero = _mm256_setzero_si256();
        let mask = _mm256_set1_epi16(0x00ff);
        let mut high = zero;
        let mut low = zero;
        let mut chunks = block.chunks_exact(32);
        for chunk in &mut chunks {
            let bytes = _mm256_loadu_si256(chunk.as_ptr().cast());
            high = _mm256_add_epi64(high, _mm256_sad_epu8(_mm256_and_si256(bytes, mask), zero));
            low = _mm256_add_epi64(low, _mm256_sad_epu8(_mm256_srli_epi16::<8>(bytes), zero));
        }
        let mut h = [0u64; 4];
        let mut l = [0u64; 4];
        _mm256_storeu_si256(h.as_mut_ptr().cast(), high);
        _mm256_storeu_si256(l.as_mut_ptr().cast(), low);
        let sum = h.iter().sum::<u64>() * 256 + l.iter().sum::<u64>();
        result = super::fold(result + sum as u32 + super::scalar(chunks.remainder()) as u32) as u32;
    }
    result as u16
}
