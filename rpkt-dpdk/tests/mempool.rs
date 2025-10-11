use arrayvec::ArrayVec;
use rpkt_dpdk::constant::*;
use rpkt_dpdk::*;

#[test]
fn create_mempool_with_same_name() {
    DpdkOption::new()
        .args("--file-prefix mempool".split(" "))
        .init()
        .unwrap();

    {
        let res = service().mempool_alloc("wtf", 128, 0, MBUF_DATAROOM_SIZE, -1);
        assert_eq!(res.is_err(), false);

        let res = service().mempool_alloc("wtf", 128, 0, MBUF_DATAROOM_SIZE, -1);
        assert_eq!(res.is_err(), true);
    }

    let res = service().mempool_free("wtf");
    assert_eq!(res.is_err(), false);

    let res = service().mempool_free("wtf");
    assert_eq!(res.is_err(), true);

    let res = service().graceful_cleanup();
    assert_eq!(res.is_ok(), true);
}

#[test]
fn mbuf_alloc_and_size_check() {
    DpdkOption::new()
        .args("--file-prefix mempool".split(" "))
        .init()
        .unwrap();

    {
        let mp = service().mempool_alloc("wtf", 128, 0, 512, -1).unwrap();

        for _ in 0..512 {
            let mut mbuf = mp.try_alloc().unwrap();
            mbuf.extend_from_slice(&[0xff; 265][..]);
        }

        for _ in 0..128 {
            let mbuf = mp.try_alloc().unwrap();
            assert_eq!(mbuf.capacity(), 512 - MBUF_HEADROOM_SIZE as usize);
            assert_eq!(mbuf.front_capacity(), MBUF_HEADROOM_SIZE as usize);
            assert_eq!(mbuf.len(), 0);
        }

        for _ in 0..(128 / 32) {
            let mut batch = ArrayVec::<_, 32>::new();
            mp.alloc_in_batch(&mut batch);
            for mbuf in batch.iter() {
                assert_eq!(mbuf.capacity(), 512 - MBUF_HEADROOM_SIZE as usize);
                assert_eq!(mbuf.front_capacity(), MBUF_HEADROOM_SIZE as usize);
                assert_eq!(mbuf.len(), 0);
            }
        }
    }

    service().mempool_free("wtf").unwrap();
    let res = service().graceful_cleanup();
    assert_eq!(res.is_ok(), true);
}

#[test]
fn mbuf_data_unchanged_after_realloc() {
    DpdkOption::new()
        .args("--file-prefix mempool".split(" "))
        .init()
        .unwrap();

    {
        let mp = service()
            .mempool_alloc("wtf", 128, 0, MBUF_DATAROOM_SIZE, -1)
            .unwrap();
        let mut sb = [0; 2];

        let mut mbufs = vec![];
        for i in 0..128 {
            let mut mbuf = mp.try_alloc().unwrap();
            sb[0] = i + 1;
            mbuf.extend_from_slice(&sb[..]);
            assert_eq!(mbuf.data()[0], i + 1);
            assert_eq!(mbuf.data()[1], 0);
            mbufs.push(mbuf);
        }
        assert_eq!(mp.try_alloc().is_none(), true);

        drop(mbufs);
        for i in 0..128 {
            let mut mbuf = mp.try_alloc().unwrap();
            unsafe { mbuf.extend(1) };
            assert_eq!(mbuf.data()[0], i + 1);
        }
    }

    service().mempool_free("wtf").unwrap();
    let res = service().graceful_cleanup();
    assert_eq!(res.is_ok(), true);
}

#[test]
fn alloc_mbuf_from_multiple_threads() {
    DpdkOption::new()
        .args("--file-prefix mempool".split(" "))
        .init()
        .unwrap();

    assert_eq!(service().available_lcores().len() >= 4, true);

    service()
        .mempool_alloc("wtf", 512, 32, MBUF_DATAROOM_SIZE + MBUF_HEADROOM_SIZE, -1)
        .unwrap();

    let mut jhs = Vec::new();
    for i in 2..4 {
        let jh: std::thread::JoinHandle<()> = std::thread::spawn(move || {
            service().thread_bind_to(i).unwrap();
            service().register_as_rte_thread().unwrap();

            let mp = service().mempool("wtf").unwrap();

            let mut batch = ArrayVec::<_, 32>::new();
            for _ in 0..100 {
                mp.alloc_in_batch(&mut batch);
                for mbuf in batch.drain(..) {
                    assert_eq!(mbuf.capacity(), MBUF_DATAROOM_SIZE as usize);
                    assert_eq!(mbuf.front_capacity(), MBUF_HEADROOM_SIZE as usize);
                }
            }
        });
        jhs.push(jh);
    }

    for jh in jhs {
        jh.join().unwrap();
    }

    service().mempool_free("wtf").unwrap();
    let res = service().graceful_cleanup();
    assert_eq!(res.is_ok(), true);
}

#[test]
fn secondary_process_mempool() {
    // run examples/mempool_primary first
    DpdkOption::new()
        .args("-l 2 -n 4 --file-prefix mempool_primary --proc-type=secondary".split(" "))
        .init()
        .unwrap();
    assert_eq!(service().is_primary_process().unwrap(), false);

    assert_eq!(
        service().mempool_alloc("wtf", 127, 0, 200, -1).is_err(),
        true
    );

    {
        let mp = unsafe { service().assume_mempool("wtf").unwrap() };
        let mut mbufs = vec![];
        for _ in 0..127 {
            let mbuf = mp.try_alloc().unwrap();
            assert_eq!(mbuf.capacity(), 200 - MBUF_HEADROOM_SIZE as usize);
            assert_eq!(mbuf.front_capacity(), MBUF_HEADROOM_SIZE as usize);
            assert_eq!(mbuf.len(), 0);
            mbufs.push(mbuf);
        }
        assert_eq!(mp.try_alloc().is_none(), true);
        assert_eq!(mbufs.len(), 127);
    }

    assert_eq!(service().mempool_free("wtf").is_err(), true);

    let res = service().graceful_cleanup();
    assert_eq!(res.is_ok(), true);
}
