use rpkt_dpdk::*;
use std::sync::{atomic, Arc};

#[test]
fn bind_2_cores() {
    DpdkOption::new()
        .args("--file-prefix lcore_bind".split(" "))
        .init()
        .unwrap();

    // launch 2 threads and bind them to different lores.
    let mut jhs = vec![];
    for i in 0..2 {
        let jh = std::thread::spawn(move || {
            assert_eq!(service().current_lcore().is_none(), true);
            service().thread_bind_to(i).unwrap();
            let lcore = service().current_lcore().unwrap();
            assert_eq!(lcore.lcore_id, i);
        });
        jhs.push(jh);
    }

    for jh in jhs {
        jh.join().unwrap()
    }

    let res = service().graceful_cleanup();
    assert_eq!(res.is_ok(), true);
}

#[test]
fn register_rte_thread() {
    DpdkOption::new()
        .args("--file-prefix lcore_bind".split(" "))
        .init()
        .unwrap();

    // launch 2 threads bind them to different lores, and register them as eal
    // thread.
    let mut jhs = vec![];
    for i in 0..2 {
        let jh = std::thread::spawn(move || {
            service().thread_bind_to(i).unwrap();

            let rte_thread_id = unsafe { sys::rte_lcore_id_() };
            assert_eq!(rte_thread_id, u32::MAX);

            let rte_lcore_id = service().register_as_rte_thread().unwrap();
            assert_eq!(rte_lcore_id, unsafe { sys::rte_lcore_id_() });
        });
        jhs.push(jh);
    }

    for jh in jhs {
        jh.join().unwrap()
    }

    let res = service().graceful_cleanup();
    assert_eq!(res.is_ok(), true);
}

#[test]
fn bind_2_threads_to_the_same_lcore() {
    DpdkOption::new()
        .args("--file-prefix lcore_bind".split(" "))
        .init()
        .unwrap();

    assert_eq!(service().available_lcores().len() >= 2, true);

    let lcore = service().available_lcores()[1];
    assert_ne!(lcore.lcore_id, 0);

    let mut jhs = Vec::new();
    let shared = Arc::new(atomic::AtomicU32::new(0));

    for _ in 0..2 {
        let cloned = shared.clone();
        jhs.push(std::thread::spawn(move || {
            assert_eq!(service().current_lcore().is_none(), true);

            let res = service().thread_bind_to(lcore.lcore_id);
            match res {
                Ok(_) => {
                    cloned.fetch_add(1, atomic::Ordering::SeqCst);
                    let mt_lcore = service().current_lcore().unwrap();
                    assert!(mt_lcore.lcore_id == lcore.lcore_id);
                }
                Err(_) => {
                    assert_eq!(service().current_lcore().is_none(), true);
                }
            }
        }));
    }

    for jh in jhs {
        jh.join().unwrap();
    }

    let num = shared.load(atomic::Ordering::SeqCst);
    assert_eq!(num, 1);

    let res = service().graceful_cleanup();
    assert_eq!(res.is_ok(), true);
}
