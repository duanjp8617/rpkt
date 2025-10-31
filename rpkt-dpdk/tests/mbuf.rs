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
    }
}

#[cfg(test)]
mod miri_tests {
    use rpkt_dpdk::*;

    #[test]
    #[cfg(miri)]
    fn mbuf_miri_test() {
        let mut mbuf = Mbuf::new(2048, 128);

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
}
