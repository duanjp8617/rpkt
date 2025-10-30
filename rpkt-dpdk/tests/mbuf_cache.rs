use rpkt_dpdk::*;

use arrayvec::ArrayVec;

const BATCH_SIZE: usize = 128;

#[test]
fn cache_enabled_batch() {
    DpdkOption::new()
        .args("--file-prefix mbuf_cache".split(" "))
        .init()
        .unwrap();
    service().thread_bind_to(0).unwrap();
    service().register_as_rte_thread().unwrap();

    println!("Testing mempool cache effect with batch allocation.");

    let nb_mbufs = 4096;
    let per_core_caches = 256;

    service()
        .mempool_alloc(
            "wtf",
            nb_mbufs,
            per_core_caches,
            constant::MBUF_DATAROOM_SIZE + constant::MBUF_HEADROOM_SIZE,
            -1,
        )
        .unwrap();
    println!(
        "mempool wtf created with {} mbufs and {} per-core cache",
        nb_mbufs, per_core_caches
    );
    let mp = service().mempool("wtf").unwrap();

    let mut batch = ArrayVec::<_, BATCH_SIZE>::new();
    assert_eq!(nb_mbufs % BATCH_SIZE as u32, 0);
    assert_eq!(per_core_caches % BATCH_SIZE as u32, 0);

    // On the current rte thread, try to alloc `nb_mbufs / BATCH_SIZE` batches,
    // and fill in test data.
    for _ in 0..(nb_mbufs / BATCH_SIZE as u32) {
        mp.fill_up_batch(&mut batch);
        for mbuf in batch.iter_mut() {
            unsafe { mbuf.extend(1) };
            mbuf.data_mut()[0] = 99;
        }
        batch.drain(..);
    }

    // We can see that the current rte thread gets the allocation
    // from the cache, and all the packets have been correctly set with
    // test data.
    for _ in 0..(nb_mbufs / BATCH_SIZE as u32) {
        mp.fill_up_batch(&mut batch);
        for mbuf in batch.iter_mut() {
            unsafe { mbuf.extend(1) };
            assert_eq!(mbuf.data()[0], 99);
        }
        batch.drain(..);
    }
    println!(
        "lcore {}: all the mbufs from the local cache has been set with test data 99",
        service().current_lcore().unwrap().lcore_id
    );

    let mut jhs = Vec::new();
    for i in 1..3 {
        jhs.push(std::thread::spawn(move || {
            service().thread_bind_to(i).unwrap();
            service().register_as_rte_thread().unwrap();

            let mp = service().mempool("wtf").unwrap();
            let mut batch = ArrayVec::<_, 128>::new();

            // On another rte_thread, we can see that the allocated mbuf
            // does not have the test data.
            for _ in 0..(nb_mbufs / BATCH_SIZE as u32) {
                mp.fill_up_batch(&mut batch);
                for mbuf in batch.iter_mut() {
                    unsafe { mbuf.extend(1) };
                    assert_ne!(mbuf.data()[0], 99);
                }
                batch.drain(..);
            }

            println!(
                "lcore {}: all the mbufs from the local cache are not set with test data 99",
                service().current_lcore().unwrap().lcore_id
            );
        }));
    }

    for jh in jhs {
        jh.join().unwrap();
    }

    drop(mp);
    service().mempool_free("wtf").unwrap();
    service().graceful_cleanup().unwrap();
}

#[test]
fn set_all_mbufs_in_a_pool() {
    DpdkOption::new()
        .args("--file-prefix mbuf_cache".split(" "))
        .init()
        .unwrap();
    service().thread_bind_to(0).unwrap();
    service().register_as_rte_thread().unwrap();
    let nb_mbufs = 4096;
    let per_core_caches = 256;

    service()
        .mempool_alloc(
            "wtf",
            nb_mbufs,
            per_core_caches,
            constant::MBUF_DATAROOM_SIZE + constant::MBUF_HEADROOM_SIZE,
            -1,
        )
        .unwrap();
    println!(
        "mempool wtf created with {} mbufs and {} per-core cache",
        nb_mbufs, per_core_caches
    );

    let mp = service().mempool("wtf").unwrap();
    let mut v = Vec::new();
    // On the current rte thread, try to alloc `nb_mbufs` batches,
    // fill in test data and store all the mbufs in a vector.
    while let Some(mut mbuf) = mp.try_alloc() {
        unsafe { mbuf.extend(1) };
        mbuf.data_mut()[0] = 99;
        v.push(mbuf);
    }
    println!(
        "lcore {}: all the mbufs from current mempool has been set with test data 99",
        service().current_lcore().unwrap().lcore_id
    );
    drop(v);

    let mut jhs = Vec::new();
    for i in 1..3 {
        jhs.push(std::thread::spawn(move || {
            service().thread_bind_to(i).unwrap();
            let mp = service().mempool("wtf").unwrap();
            let mut batch = ArrayVec::<_, BATCH_SIZE>::new();

            // On another rte_thread, we can see that the allocated mbuf have the test data.
            for _ in 0..(nb_mbufs / BATCH_SIZE as u32) {
                mp.fill_up_batch(&mut batch);
                for mbuf in batch.iter_mut() {
                    unsafe { mbuf.extend(1) };
                    assert_eq!(mbuf.data()[0], 99);
                }
                Mempool::free_batch(&mut batch);
            }

            println!(
                "lcore {}: all the mbufs from the local cache are set with test data 99",
                service().current_lcore().unwrap().lcore_id
            );
        }));
    }

    for jh in jhs {
        jh.join().unwrap();
    }

    drop(mp);
    service().mempool_free("wtf").unwrap();
    service().graceful_cleanup().unwrap();
}
