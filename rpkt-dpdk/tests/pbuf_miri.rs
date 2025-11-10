#[cfg(test)]
mod tests {
    use rpkt::{Buf, PktBuf, PktBufMut};
    use rpkt_dpdk::*;

    #[test]
    #[cfg(miri)]
    fn read_non_contiguous_packet_data() {
        let mut buf: [u8; 11235] = [0xac; 11235];
        for i in 0..11235 {
            buf[i] = (i % u8::MAX as usize) as u8;
        }

        {
            for i in 0..buf.len() + 1 {
                let mut mbuf = Mbuf::from_slice(&buf[..i], 2048, 128).unwrap();
                let mut pbuf = Pbuf::new(&mut mbuf);

                let mut buf_mut = Vec::new();
                while pbuf.has_remaining() {
                    let chunk = pbuf.chunk();
                    buf_mut.extend_from_slice(chunk);
                    pbuf.advance(chunk.len());
                }

                assert_eq!(&buf[..i], &buf_mut[..]);
                assert_eq!(pbuf.remaining(), 0);
            }
        }
    }

    #[test]
    #[cfg(miri)]
    fn advance_across_non_contiguous_memory_segments() {
        {
            let mut fst_seg = Mbuf::from_slice(&[01; 1000][..], 2048, 128).unwrap();
            let mut appender = fst_seg.appender();

            let snd_seg = Mbuf::from_slice(&[02; 1000][..], 2048, 128).unwrap();
            appender.append_single_seg(snd_seg);
            let snd_seg = Mbuf::from_slice(&[03; 1000][..], 2048, 128).unwrap();
            appender.append_single_seg(snd_seg);

            assert_eq!(fst_seg.pkt_len(), 3000);
            assert_eq!(fst_seg.num_segs(), 3);

            let mut pbuf = Pbuf::new(&mut fst_seg);

            pbuf.advance(500);
            assert_eq!(pbuf.chunk().len(), 500);
            assert_eq!(pbuf.remaining(), 2500);
            pbuf.advance(499);
            assert_eq!(pbuf.chunk().len(), 1);
            assert_eq!(pbuf.remaining(), 2001);
            pbuf.advance(1);
            assert_eq!(pbuf.chunk().len(), 1000);
            assert_eq!(pbuf.remaining(), 2000);

            pbuf.advance(500);
            assert_eq!(pbuf.chunk().len(), 500);
            assert_eq!(pbuf.remaining(), 1500);
            pbuf.advance(499);
            assert_eq!(pbuf.chunk().len(), 1);
            assert_eq!(pbuf.remaining(), 1001);
            pbuf.advance(1);
            assert_eq!(pbuf.chunk().len(), 1000);
            assert_eq!(pbuf.remaining(), 1000);

            pbuf.advance(500);
            assert_eq!(pbuf.chunk().len(), 500);
            assert_eq!(pbuf.remaining(), 500);
            pbuf.advance(499);
            assert_eq!(pbuf.chunk().len(), 1);
            assert_eq!(pbuf.remaining(), 1);
            pbuf.advance(1);
            assert_eq!(pbuf.chunk().len(), 0);
            assert_eq!(pbuf.remaining(), 0);

            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(1500);
            assert_eq!(pbuf.chunk().len(), 500);
            assert_eq!(pbuf.remaining(), 1500);

            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(2500);
            assert_eq!(pbuf.chunk().len(), 500);
            assert_eq!(pbuf.remaining(), 500);

            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(3000);
            assert_eq!(pbuf.chunk().len(), 0);
            assert_eq!(pbuf.remaining(), 0);
            assert_eq!(pbuf.cursor(), 3000);
        }
    }

    #[cfg(miri)]
    fn pbuf_advance_helper(seglen: usize, seg_num: usize, step: usize) {
        assert!(seglen <= 2048 && seg_num >= 1 && step <= seglen * seg_num);

        let mut data = vec![];
        data.extend(std::iter::repeat(0xad).take(seglen));

        let mut mbuf = Mbuf::new(2048, 128);
        mbuf.extend_from_slice(&data);

        let mut app = mbuf.appender();
        for _ in 0..seg_num - 1 {
            let mut seg = Mbuf::new(2048, 128);
            seg.extend_from_slice(&data);
            app.append_single_seg(seg);
        }

        assert_eq!(mbuf.pkt_len(), seglen * seg_num);

        let pkt_len = mbuf.pkt_len();
        let mut pbuf = Pbuf::new(&mut mbuf);
        let mut curr_pos = 0;
        while pbuf.remaining() >= step {
            pbuf.advance(step);

            curr_pos += step;
            assert_eq!(pbuf.cursor(), curr_pos);

            if curr_pos < pkt_len {
                assert_eq!(pbuf.chunk_headroom(), curr_pos % seglen);
                assert_eq!(pbuf.chunk().len(), seglen - curr_pos % seglen);
                assert_eq!(pbuf.chunk_mut().len(), seglen - curr_pos % seglen);
            } else {
                assert_eq!(pbuf.chunk_headroom(), seglen);
                assert_eq!(pbuf.chunk().len(), 0);
                assert_eq!(pbuf.chunk_mut().len(), 0);
            }
        }
    }

    #[test]
    #[cfg(miri)]
    fn pbuf_advance_test() {
        {
            pbuf_advance_helper(1000, 5, 1);
            pbuf_advance_helper(1000, 5, 3);
            pbuf_advance_helper(1000, 5, 1000);
            pbuf_advance_helper(1000, 6, 1200);
            pbuf_advance_helper(1000, 10, 2500);
        }
    }

    #[test]
    #[cfg(miri)]
    fn moveback_across_non_contiguous_memory_segments() {
        {
            let mut fst_seg = Mbuf::from_slice(&[01; 1000][..], 2048, 128).unwrap();
            let mut appender = fst_seg.appender();

            let snd_seg = Mbuf::from_slice(&[02; 1000][..], 2048, 128).unwrap();
            appender.append_single_seg(snd_seg);
            let snd_seg = Mbuf::from_slice(&[03; 1000][..], 2048, 128).unwrap();
            appender.append_single_seg(snd_seg);

            assert_eq!(fst_seg.pkt_len(), 3000);
            assert_eq!(fst_seg.num_segs(), 3);

            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(3000);
            assert_eq!(pbuf.chunk_headroom(), 1000);
            pbuf.move_back(500);
            assert_eq!(pbuf.chunk_headroom(), 500);
            pbuf.move_back(1000);
            assert_eq!(pbuf.chunk_headroom(), 500);
            assert_eq!(pbuf.chunk().len(), 500);
            assert_eq!(pbuf.remaining(), 1500);
            pbuf.move_back(500);
            assert_eq!(pbuf.chunk_headroom(), 0);
            assert_eq!(pbuf.chunk().len(), 1000);
            assert_eq!(pbuf.remaining(), 2000);
            pbuf.move_back(1000);
            assert_eq!(pbuf.chunk_headroom(), 0);
            assert_eq!(pbuf.chunk().len(), 1000);
            assert_eq!(pbuf.remaining(), 3000);

            pbuf.advance(3000);
            pbuf.move_back(2777);
            assert_eq!(pbuf.chunk_headroom(), 223);
            assert_eq!(pbuf.chunk().len(), 1000 - 223);
            assert_eq!(pbuf.remaining(), 2777);
        }
    }

    #[cfg(miri)]
    fn pbuf_moveback_helper(seglen: usize, seg_num: usize, step: usize) {
        assert!(seglen <= 2048 && seg_num >= 1 && step <= seglen * seg_num);

        let mut data = vec![];
        data.extend(std::iter::repeat(0xad).take(seglen));

        let mut mbuf = Mbuf::new(2048, 128);
        mbuf.extend_from_slice(&data);

        let mut app = mbuf.appender();
        for _ in 0..seg_num - 1 {
            let mut seg = Mbuf::new(2048, 128);
            seg.extend_from_slice(&data);
            app.append_single_seg(seg);
        }

        assert_eq!(mbuf.pkt_len(), seglen * seg_num);

        let pkt_len = mbuf.pkt_len();
        let mut pbuf = Pbuf::new(&mut mbuf);
        pbuf.advance(pkt_len);

        assert_eq!(pbuf.remaining(), 0);
        assert_eq!(pbuf.cursor(), pkt_len);

        let mut curr_pos = pkt_len;
        while curr_pos >= step {
            pbuf.move_back(step);

            curr_pos -= step;
            assert_eq!(pbuf.cursor(), curr_pos);

            assert_eq!(pbuf.chunk_headroom(), curr_pos % seglen);
            assert_eq!(pbuf.chunk().len(), seglen - curr_pos % seglen);
            assert_eq!(pbuf.chunk_mut().len(), seglen - curr_pos % seglen);
        }
    }

    #[test]
    #[cfg(miri)]
    fn pbuf_moveback_test() {
        {
            pbuf_moveback_helper(1000, 5, 1);
            pbuf_moveback_helper(1000, 5, 3);
            pbuf_moveback_helper(1000, 5, 1000);
            pbuf_moveback_helper(1000, 6, 1200);
            pbuf_moveback_helper(1000, 10, 2500);
        }
    }

    #[test]
    #[cfg(miri)]
    fn trim_off_test() {
        {
            let mut fst_seg = Mbuf::from_slice(&[01; 1000][..], 2048, 128).unwrap();
            let mut appender = fst_seg.appender();
            let snd_seg = Mbuf::from_slice(&[02; 1000][..], 2048, 128).unwrap();
            appender.append_single_seg(snd_seg);
            let snd_seg = Mbuf::from_slice(&[03; 1000][..], 2048, 128).unwrap();
            appender.append_single_seg(snd_seg);
            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(1500);
            pbuf.trim_off(1000);
            assert_eq!(pbuf.remaining(), 500);
            assert_eq!(pbuf.chunk().len(), 500);
            assert_eq!(pbuf.chunk_headroom(), 500);
            assert_eq!(fst_seg.num_segs(), 2);

            let mut fst_seg = Mbuf::from_slice(&[01; 1000][..], 2048, 128).unwrap();
            let mut appender = fst_seg.appender();
            let snd_seg = Mbuf::from_slice(&[02; 1000][..], 2048, 128).unwrap();
            appender.append_single_seg(snd_seg);
            let snd_seg = Mbuf::from_slice(&[03; 1000][..], 2048, 128).unwrap();
            appender.append_single_seg(snd_seg);
            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(1500);
            pbuf.trim_off(1499);
            assert_eq!(pbuf.remaining(), 1);
            assert_eq!(pbuf.chunk().len(), 1);
            assert_eq!(pbuf.chunk_headroom(), 500);
            assert_eq!(fst_seg.num_segs(), 2);

            let mut fst_seg = Mbuf::from_slice(&[01; 1000][..], 2048, 128).unwrap();
            let mut appender = fst_seg.appender();
            let snd_seg = Mbuf::from_slice(&[02; 1000][..], 2048, 128).unwrap();
            appender.append_single_seg(snd_seg);
            let snd_seg = Mbuf::from_slice(&[03; 1000][..], 2048, 128).unwrap();
            appender.append_single_seg(snd_seg);
            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(1500);
            pbuf.trim_off(1500);
            assert_eq!(pbuf.remaining(), 0);
            assert_eq!(pbuf.chunk().len(), 0);
            assert_eq!(pbuf.chunk_headroom(), 500);
            assert_eq!(fst_seg.num_segs(), 2);

            let mut fst_seg = Mbuf::from_slice(&[01; 1000][..], 2048, 128).unwrap();
            let mut appender = fst_seg.appender();
            let snd_seg = Mbuf::from_slice(&[02; 1000][..], 2048, 128).unwrap();
            appender.append_single_seg(snd_seg);
            let snd_seg = Mbuf::from_slice(&[03; 1000][..], 2048, 128).unwrap();
            appender.append_single_seg(snd_seg);
            let mut pbuf = Pbuf::new(&mut fst_seg);
            pbuf.advance(2000);
            pbuf.trim_off(1000);
            assert_eq!(pbuf.remaining(), 0);
            assert_eq!(pbuf.chunk().len(), 0);
            assert_eq!(pbuf.chunk_headroom(), 1000);
            assert_eq!(fst_seg.num_segs(), 2);
        }
    }

    #[test]
    #[cfg(miri)]
    fn trim_off_test_1() {
        {
            fn build_mbuf() -> Mbuf {
                let mut fst_seg = Mbuf::from_slice(&[01; 1000][..], 2048, 128).unwrap();
                let mut appender = fst_seg.appender();
                let snd_seg = Mbuf::from_slice(&[02; 1000][..], 2048, 128).unwrap();
                appender.append_single_seg(snd_seg);
                let snd_seg = Mbuf::from_slice(&[03; 1000][..], 2048, 128).unwrap();
                appender.append_single_seg(snd_seg);
                fst_seg
            }

            // trim off the last seg
            for cnt in 1..1000 {
                let mut mbuf = build_mbuf();
                let mut pbuf = Pbuf::new(&mut mbuf);
                pbuf.advance(1000);

                pbuf.trim_off(cnt);

                assert_eq!(pbuf.buf().pkt_len(), 3000 - cnt);
                assert_eq!(pbuf.remaining(), 2000 - cnt);
                assert_eq!(pbuf.buf().num_segs(), 3);
                assert_eq!(pbuf.chunk().len(), 1000);
            }

            {
                let mut mbuf = build_mbuf();
                let mut pbuf = Pbuf::new(&mut mbuf);
                pbuf.advance(1000);

                let cnt = 1000;
                pbuf.trim_off(cnt);

                assert_eq!(pbuf.buf().pkt_len(), 3000 - cnt);
                assert_eq!(pbuf.remaining(), 2000 - cnt);
                assert_eq!(pbuf.buf().num_segs(), 2);
                assert_eq!(pbuf.chunk().len(), 1000);
            }

            // trim off the second last seg
            for cnt in 1001..2000 {
                let mut mbuf = build_mbuf();
                let mut pbuf = Pbuf::new(&mut mbuf);
                pbuf.advance(1000);

                pbuf.trim_off(cnt);

                assert_eq!(pbuf.buf().pkt_len(), 3000 - cnt);
                assert_eq!(pbuf.remaining(), 2000 - cnt);
                assert_eq!(pbuf.buf().num_segs(), 2);
                assert_eq!(pbuf.chunk().len(), 2000 - cnt);
                assert_eq!(pbuf.chunk_headroom(), 0);
            }

            {
                let mut mbuf = build_mbuf();
                let mut pbuf = Pbuf::new(&mut mbuf);
                pbuf.advance(1000);

                let cnt = 2000;
                pbuf.trim_off(cnt);

                assert_eq!(pbuf.buf().pkt_len(), 3000 - cnt);
                assert_eq!(pbuf.remaining(), 2000 - cnt);
                assert_eq!(pbuf.buf().num_segs(), 1);
                assert_eq!(pbuf.chunk().len(), 0);
                assert_eq!(pbuf.chunk_headroom(), 1000);
            }
        }
    }
}
