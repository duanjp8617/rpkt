use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;
use rpkt_dpdk::*;

fn cache_enabled_batch(base_idx: u32, nb_threads: u32) {
    let nb_mbufs = 4096;
    let per_core_caches = 256;

    let mut mpconf = MempoolConf::default();
    mpconf.nb_mbufs = nb_mbufs;
    mpconf.per_core_caches = per_core_caches;
    service().mempool_create("wtf", &mpconf).unwrap();
    println!(
        "mempool wtf created with {} mbufs and {} per-core cache",
        nb_mbufs, per_core_caches
    );

    let mp = service().mempool("wtf").unwrap();
    let mut batch = ArrayVec::<_, 128>::new();
    assert_eq!(nb_mbufs % 128, 0);
    // On the current rte thread, try to alloc `nb_mbufs / 128` batches, and
    // fill in test data.
    for _ in 0..(nb_mbufs / 128) {
        mp.fill_batch(&mut batch);
        for mbuf in batch.iter_mut() {
            unsafe { mbuf.extend(1) };
            mbuf.data_mut()[0] = 99;
        }
        batch.drain(..);
    }
    // We can see that the current rte thread gets the allocation
    // from the cache, and all the packets have been correctly set with
    // test data.
    for _ in 0..(nb_mbufs / 128) {
        mp.fill_batch(&mut batch);
        for mbuf in batch.iter_mut() {
            unsafe { mbuf.extend(1) };
            assert_eq!(mbuf.data()[0], 99);
        }
        batch.drain(..);
    }
    println!(
        "lcore {}: all the mbufs from the local cache has been set with test data 99",
        Lcore::current().unwrap().lcore_id
    );

    let mut jhs = Vec::new();
    for i in base_idx..base_idx + nb_threads {
        jhs.push(std::thread::spawn(move || {
            service().lcore_bind(i + 1).unwrap();
            let mp = service().mempool("wtf").unwrap();
            let mut batch = ArrayVec::<_, 128>::new();
            // On another rte_thread, we can see that the allocated mbuf
            // does not have the test data.
            for _ in 0..(nb_mbufs / 128) {
                mp.fill_batch(&mut batch);
                for mbuf in batch.iter_mut() {
                    unsafe { mbuf.extend(1) };
                    assert_ne!(mbuf.data()[0], 99);
                }
                batch.drain(..);
            }
            println!(
                "lcore {}: all the mbufs from the local cache are not set with test data 99",
                Lcore::current().unwrap().lcore_id
            );
        }));
    }

    for jh in jhs {
        jh.join().unwrap();
    }

    drop(mp);
    service().mempool_free("wtf").unwrap();
    println!("mempool wtf freed");
}

fn cache_enabled_single(base_idx: u32, nb_threads: u32) {
    let nb_mbufs = 4096;
    let per_core_caches = 256;

    let mut mpconf = MempoolConf::default();
    mpconf.nb_mbufs = nb_mbufs;
    mpconf.per_core_caches = per_core_caches;
    service().mempool_create("wtf", &mpconf).unwrap();
    println!(
        "mempool wtf created with {} mbufs and {} per-core cache",
        nb_mbufs, per_core_caches
    );

    let mp = service().mempool("wtf").unwrap();
    // On the current rte thread, try to alloc `nb_mbufs` times, and
    // fill in test data.
    for _ in 0..nb_mbufs {
        let mut mbuf = mp.try_alloc().unwrap();
        unsafe { mbuf.extend(1) };

        let data = mbuf.data_mut();
        data[0] = 99;
    }
    // We can see that the current rte thread gets the allocation
    // from the cache, and all the packets have been correctly set with
    // test data.
    for _ in 0..nb_mbufs {
        let mut mbuf = mp.try_alloc().unwrap();
        unsafe { mbuf.extend(1) };

        let data = mbuf.data();
        assert_eq!(data[0], 99);
    }
    println!(
        "lcore {}: all the mbufs from the local cache has been set with test data 99",
        Lcore::current().unwrap().lcore_id
    );

    let mut jhs = Vec::new();
    for i in base_idx..base_idx + nb_threads {
        jhs.push(std::thread::spawn(move || {
            service().lcore_bind(i + 1).unwrap();
            let mp = service().mempool("wtf").unwrap();
            // On another rte_thread, we can see that the allocated mbuf
            // does not have the test data.
            for _ in 0..nb_mbufs {
                let mut mbuf = mp.try_alloc().unwrap();
                unsafe { mbuf.extend(1) };

                let data = mbuf.data();
                assert_ne!(data[0], 99);
            }
            println!(
                "lcore {}: all the mbufs from the local cache are not set with test data 99",
                Lcore::current().unwrap().lcore_id
            );
        }));
    }

    for jh in jhs {
        jh.join().unwrap();
    }

    drop(mp);
    service().mempool_free("wtf").unwrap();
    println!("mempool wtf freed");
}

fn set_all_mbufs_in_a_pool(base_idx: u32, nb_threads: u32) {
    let nb_mbufs = 4096;
    let per_core_caches = 256;

    let run = Arc::new(AtomicBool::new(true));
    let run_clone = run.clone();
    ctrlc::set_handler(move || {
        run_clone.store(false, Ordering::Release);
    })
    .unwrap();

    let mut mpconf = MempoolConf::default();
    mpconf.nb_mbufs = nb_mbufs;
    mpconf.per_core_caches = per_core_caches;
    service().mempool_create("wtf", &mpconf).unwrap();
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
        Lcore::current().unwrap().lcore_id
    );
    drop(v);

    let mut jhs = Vec::new();
    for i in base_idx..base_idx + nb_threads {
        let run = run.clone();
        jhs.push(std::thread::spawn(move || {
            service().lcore_bind(i + 1).unwrap();
            let mp = service().mempool("wtf").unwrap();
            let mut batch = ArrayVec::<_, 128>::new();
            // On another rte_thread, we can see that the allocated mbuf
            // does not have the test data.
            while run.load(Ordering::Acquire) {
                mp.fill_batch(&mut batch);
                for mbuf in batch.iter_mut() {
                    unsafe { mbuf.extend(1) };
                    assert_eq!(mbuf.data()[0], 99);
                }
                Mempool::free_batch(&mut batch);
            }
            println!(
                "lcore {}: all the mbufs from the local cache are set with test data 99",
                Lcore::current().unwrap().lcore_id
            );
        }));
    }

    for jh in jhs {
        jh.join().unwrap();
    }

    drop(mp);
    service().mempool_free("wtf").unwrap();
    println!("mempool wtf freed");
}

fn main() {
    DpdkOption::new().init().unwrap();
    cache_enabled_batch(0, 2);
    cache_enabled_single(2, 2);
    set_all_mbufs_in_a_pool(4, 2);

    service().service_close().unwrap();
    println!("dpdk service shutdown gracefully");
}
