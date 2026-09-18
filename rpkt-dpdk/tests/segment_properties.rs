#![cfg(miri)]
use rpkt::{checksum, Buf, PktBuf, PktBufMut};
use rpkt_dpdk::{Mbuf, Pbuf};

#[test]
fn segment_boundaries() {
    let bytes: Vec<u8> = (0..67).collect();
    for size in [1, 3, 7, 16, 67] {
        for offset in [0, 1, 15, 66, 67] {
            let mut mbuf = Mbuf::from_slice(&bytes, size, 8).unwrap();
            let mut buf = Pbuf::new(&mut mbuf);
            assert_eq!(
                checksum::from_buf(&mut buf, bytes.len()),
                checksum::from_slice(&bytes)
            );
            buf.move_back(bytes.len());
            buf.advance(offset);
            assert_eq!(buf.cursor(), offset);
            if buf.has_remaining() {
                buf.chunk_mut()[0] ^= 0xff;
            }
            buf.trim_off(buf.remaining());
            assert_eq!(buf.remaining(), 0);
            buf.move_back(offset);
            let mut actual = vec![0; offset];
            buf.copy_to_slice(&mut actual);
            assert_eq!(actual, &bytes[..offset]);
        }
    }
}
