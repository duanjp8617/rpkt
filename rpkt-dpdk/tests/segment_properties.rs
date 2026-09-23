#![cfg(miri)]
use rpkt::{checksum, Buf, PktBuf, PktBufMut};
use rpkt_dpdk::{Mbuf, Pbuf};

#[test]
fn empty_segments_preserve_the_buf_progress_contract() {
    let mut mbuf = Mbuf::new(16, 8);
    mbuf.concat(Mbuf::new(16, 8));
    mbuf.concat(Mbuf::from_slice(&[1, 2, 3], 16, 8).unwrap());
    mbuf.concat(Mbuf::new(16, 8));
    mbuf.concat(Mbuf::from_slice(&[4, 5], 16, 8).unwrap());
    mbuf.concat(Mbuf::new(16, 8));
    let mut buf = Pbuf::new(&mut mbuf);
    assert_eq!(buf.remaining(), 5);
    assert_eq!(buf.chunk(), &[1, 2, 3]);
    buf.advance(3);
    assert_eq!(buf.chunk(), &[4, 5]);
    buf.trim_off(2);
    assert_eq!(buf.remaining(), 0);
    assert!(buf.chunk().is_empty());
    buf.move_back(3);
    assert_eq!(buf.chunk(), &[1, 2, 3]);
    buf.trim_off(3);
    assert_eq!(buf.remaining(), 0);
    assert!(buf.chunk().is_empty());
}

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

#[test]
fn parsed_headers_keep_unchecked_fields_inside_the_first_segment() {
    let mut bytes = vec![0xa5; 68];
    bytes[..20].copy_from_slice(&rpkt::ipv4::Ipv4::default_header());
    bytes[2..4].copy_from_slice(&68u16.to_be_bytes());
    for segment_size in [1, 7, 19, 20, 21, 68] {
        let mut mbuf = Mbuf::from_slice(&bytes, segment_size, 8).unwrap();
        let parsed = rpkt::ipv4::Ipv4::parse(Pbuf::new(&mut mbuf));
        if segment_size < 20 {
            assert!(parsed.is_err());
            continue;
        }
        let mut ip = parsed.unwrap();
        ip.set_src_addr_and_dst_addr([1, 2, 3, 4].into(), [5, 6, 7, 8].into());
        assert_eq!(ip.src_addr_and_dst_addr_bits(), 0x0102030405060708);
        let mut payload = ip.payload();
        let mut actual = [0; 48];
        payload.copy_to_slice(&mut actual);
        assert_eq!(actual, [0xa5; 48]);
    }
}

#[test]
fn buffer_contract_sequences_match_flat_storage() {
    // Runtime evidence for the model/unsafe-implementation boundary. This is
    // intentionally a test, not a claim that the pointer refinement is proved.
    for segment_size in [1, 3, 7, 16] {
        for length in [0, 1, 16, 33] {
            let mut bytes: Vec<u8> = (0..length as u8).collect();
            let mut mbuf = Mbuf::from_slice(&bytes, segment_size, 8).unwrap();
            let mut buf = Pbuf::new(&mut mbuf);
            let mut pos = 0;
            let mut end = length;
            let mut state = 123u32;
            for _ in 0..40 {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                match state % 4 {
                    0 => {
                        let count = (state as usize / 4) % (end - pos + 1);
                        buf.advance(count);
                        pos += count;
                    }
                    1 => {
                        let count = (state as usize / 4) % (pos + 1);
                        buf.move_back(count);
                        pos -= count;
                    }
                    2 => {
                        let count = (state as usize / 4) % (end - pos + 1);
                        buf.trim_off(count);
                        end -= count;
                    }
                    _ if !buf.chunk().is_empty() => {
                        buf.chunk_mut()[0] ^= 0x80;
                        bytes[pos] ^= 0x80;
                    }
                    _ => {}
                }
                assert_eq!(buf.cursor(), pos);
                assert_eq!(buf.remaining(), end - pos);
                assert!(pos + buf.chunk().len() <= end);
                assert_eq!(buf.chunk(), &bytes[pos..pos + buf.chunk().len()]);
            }
        }
    }
}
