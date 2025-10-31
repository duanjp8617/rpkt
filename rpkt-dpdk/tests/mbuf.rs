#[cfg(test)]
mod tests {
    use rpkt_dpdk::*;

    #[test]
    fn mbuf_data_append_remove() {
        DpdkOption::new()
            .args("--file-prefix mbuf".split(" "))
            .init()
            .unwrap();

        assert_eq!(constant::MBUF_HEADROOM_SIZE, 128);
        {
            let mp = service()
                .mempool_alloc("wtf", 128, 0, 2048 + 128, -1)
                .unwrap();

            let mut mbuf = mp.try_alloc().unwrap();
            assert_eq!(mbuf.capacity(), 2048);
            assert_eq!(mbuf.front_capacity(), 128);

            let mut content: [u8; 1024] = [0; 1024];
            for i in 0..1024 {
                content[i] = (i % u8::MAX as usize) as u8;
            }

            mbuf.extend_from_slice(&content[..512]);
            assert_eq!(mbuf.data(), &content[..512]);
            assert_eq!(mbuf.data_len(), 512);
            assert_eq!(mbuf.capacity() - mbuf.data_len(), 2048 - 512);

            unsafe { mbuf.extend(512) };
            mbuf.data_mut()[512..].copy_from_slice(&content[512..]);
            assert_eq!(mbuf.data(), content);
            assert_eq!(mbuf.data_len(), 1024);
            assert_eq!(mbuf.capacity() - mbuf.data_len(), 2048 - 1024);

            let mut front_content: [u8; 64] = [54; 64];
            (&mut front_content[..32]).copy_from_slice(&[44; 32][..]);
            let mut new_content: [u8; 1088] = [0; 1088];
            new_content[0..64].copy_from_slice(&front_content[..]);
            new_content[64..].copy_from_slice(&content[..]);

            assert_eq!(mbuf.front_capacity(), 128);

            unsafe { mbuf.extend_front(32) };
            mbuf.data_mut()[..32].copy_from_slice(&front_content[32..]);
            assert_eq!(mbuf.data(), &new_content[32..]);
            assert_eq!(mbuf.data_len(), 1024 + 32);
            assert_eq!(mbuf.front_capacity(), 128 - 32);
            assert_eq!(mbuf.capacity() - mbuf.data_len(), 2048 - 1024);

            mbuf.extend_front_from_slice(&front_content[..32]);
            assert_eq!(mbuf.front_capacity(), 128 - 64);
            assert_eq!(mbuf.data(), &new_content[..]);
            assert_eq!(mbuf.data_len(), 1024 + 64);
            assert_eq!(mbuf.capacity() - mbuf.data_len(), 2048 - 1024);

            unsafe { mbuf.shrink(mbuf.data_len() - 512) };
            assert_eq!(mbuf.data_len(), 512);
            assert_eq!(mbuf.data(), &new_content[..512]);
            assert_eq!(
                mbuf.capacity() - mbuf.data_len(),
                2048 - 1024 + (1024 + 64 - 512)
            );

            unsafe { mbuf.shrink_front(44) };
            assert_eq!(mbuf.data_len(), 512 - 44);
            assert_eq!(mbuf.data(), &new_content[44..512]);
            assert_eq!(
                mbuf.capacity() - mbuf.data_len(),
                2048 - 1024 + (1024 + 64 - 512)
            );
            assert_eq!(mbuf.front_capacity(), 128 - 64 + 44);
        }

        service().mempool_free("wtf").unwrap();
        service().graceful_cleanup().unwrap();
    }

    #[test]
    fn create_multiseg_mbuf_from_chainer() {
        DpdkOption::new()
            .args("--file-prefix mbuf".split(" "))
            .init()
            .unwrap();

        assert_eq!(constant::MBUF_HEADROOM_SIZE, 128);
        {
            let mp = service()
                .mempool_alloc("wtf", 128, 0, 2048 + 128, -1)
                .unwrap();
            let mut mbuf = mp.try_alloc().unwrap();

            mbuf.extend_from_slice(&[0; 2048][..]);
            let mut chainer = mbuf.appender();

            let mut new_mbuf = mp.try_alloc().unwrap();
            new_mbuf.extend_from_slice(&[1; 2048][..]);
            chainer.append_single_seg(new_mbuf);

            let mut new_mbuf = mp.try_alloc().unwrap();
            new_mbuf.extend_from_slice(&[2; 2048][..]);
            chainer.append_single_seg(new_mbuf);

            let mut new_mbuf = mp.try_alloc().unwrap();
            new_mbuf.extend_from_slice(&[3; 2048][..]);
            chainer.append_single_seg(new_mbuf);

            for (i, seg) in mbuf.seg_iter().enumerate() {
                let mut v: Vec<u8> = Vec::new();
                for _ in 0..2048 {
                    v.push(i as u8);
                }
                assert_eq!(seg, &v[..]);
            }

            assert_eq!(mbuf.num_segs(), 4);
            assert_eq!(mbuf.pkt_len(), 2048 * 4);
            assert_eq!(mbuf.front_capacity(), 128);
            assert_eq!(mbuf.capacity(), 2048);
        }

        service().mempool_free("wtf").unwrap();
        service().graceful_cleanup().unwrap();
    }

    #[test]
    fn create_multiseg_mbuf_from_slice() {
        DpdkOption::new()
            .args("--file-prefix mbuf".split(" "))
            .init()
            .unwrap();

        let mut buf: [u8; 11235] = [0xac; 11235];
        for i in 0..11235 {
            buf[i] = (i % u8::MAX as usize) as u8;
        }

        assert_eq!(constant::MBUF_HEADROOM_SIZE, 128);
        {
            let mp = service()
                .mempool_alloc("wtf", 128, 0, 2048 + 128, -1)
                .unwrap();

            for i in 0..buf.len() + 1 {
                let mbuf = Mbuf::from_slice(&buf[..i], &mp).unwrap();

                let mut nb_segs = match i % 2048 {
                    0 => i / 2048,
                    _ => i / 2048 + 1,
                };
                if i == 0 {
                    nb_segs = 1;
                }

                assert_eq!(mbuf.num_segs(), nb_segs);

                let mut buf_copy = &buf[..i];
                for seg in mbuf.seg_iter() {
                    assert_eq!(seg, &buf_copy[..seg.len()]);
                    buf_copy = &buf_copy[seg.len()..];
                }
            }
        }

        service().mempool_free("wtf").unwrap();
        service().graceful_cleanup().unwrap();
    }

    #[test]
    fn truncate_multiseg_mbuf() {
        DpdkOption::new()
            .args("--file-prefix mbuf".split(" "))
            .init()
            .unwrap();

        let mut buf: [u8; 11235] = [0xac; 11235];
        for i in 0..11235 {
            buf[i] = (i % u8::MAX as usize) as u8;
        }

        assert_eq!(constant::MBUF_HEADROOM_SIZE, 128);
        {
            let mp = service()
                .mempool_alloc("wtf", 128, 0, 2048 + 128, -1)
                .unwrap();

            for cnt in 0..buf.len() + 1 {
                let mut mbuf = Mbuf::from_slice(&buf[..], &mp).unwrap();

                let mut new_segs = match cnt % 2048 {
                    0 => cnt / 2048,
                    _ => cnt / 2048 + 1,
                };
                if cnt == 0 {
                    new_segs = 1;
                }

                mbuf.truncate_to(cnt);

                assert_eq!(mbuf.pkt_len(), cnt);
                assert_eq!(mbuf.num_segs(), new_segs);

                let mut buf_copy = &buf[..cnt];
                for seg in mbuf.seg_iter() {
                    assert_eq!(seg, &buf_copy[..seg.len()]);
                    buf_copy = &buf_copy[seg.len()..];
                }
            }
        }

        service().mempool_free("wtf").unwrap();
        service().graceful_cleanup().unwrap();
    }

    #[test]
    fn chain_mbuf_into_multiseg_mbuf() {
        DpdkOption::new()
            .args("--file-prefix mbuf".split(" "))
            .init()
            .unwrap();

        let mut buf: [u8; 25465] = [0xac; 25465];
        for i in 0..25465 {
            buf[i] = (i % u8::MAX as usize) as u8;
        }

        assert_eq!(constant::MBUF_HEADROOM_SIZE, 128);
        {
            let mp = service()
                .mempool_alloc("wtf", 128, 0, 2048 + 128, -1)
                .unwrap();

            for fst_mbuf_len in 1..buf.len() {
                let mut fst_mbuf = Mbuf::from_slice(&buf[..fst_mbuf_len], &mp).unwrap();
                let len_fst = fst_mbuf.pkt_len();
                let seg_num_fst = fst_mbuf.num_segs();

                let snd_mbuf = Mbuf::from_slice(&buf[fst_mbuf_len..], &mp).unwrap();
                let len_snd = snd_mbuf.pkt_len();
                let seg_num_snd = snd_mbuf.num_segs();

                fst_mbuf.concat(snd_mbuf);

                assert_eq!(fst_mbuf.pkt_len(), len_fst + len_snd);
                assert_eq!(fst_mbuf.num_segs(), seg_num_fst + seg_num_snd);

                let mut buf_copy = &buf[..];
                for seg in fst_mbuf.seg_iter() {
                    assert_eq!(seg, &buf_copy[..seg.len()]);
                    buf_copy = &buf_copy[seg.len()..];
                }
            }
        }

        service().mempool_free("wtf").unwrap();
        service().graceful_cleanup().unwrap();
    }
}