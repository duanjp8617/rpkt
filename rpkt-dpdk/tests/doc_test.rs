#[test]
fn dpdkoption_arg() {
    use rpkt_dpdk::{service, DpdkOption};
    // initialize dpdk with 4 memory channels and use "app" as the
    // prefix for the dpdk primary process.
    let res = DpdkOption::new()
        .arg("-n")
        .arg("4")
        .arg("--file-prefix")
        .arg("app")
        .init();
    assert_eq!(res.is_ok(), true);
    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkoption_args() {
    use rpkt_dpdk::{service, DpdkOption};
    // initialize dpdk with 4 memory channels and use "app" as the
    // prefix for the dpdk primary process.
    let res = DpdkOption::new()
        .args("-n 4 --file-prefix app".split(" "))
        .init();
    assert_eq!(res.is_ok(), true);
    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkoption_init() {
    use rpkt_dpdk::{service, DpdkOption};
    // initialize dpdk with 4 memory channels and use "app" as the
    // prefix for the dpdk primary process.
    let res = DpdkOption::new()
        .args("-n 4 --file-prefix app".split(" "))
        .init();
    assert_eq!(res.is_ok(), true);
    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkservice_available_lcores() {
    use rpkt_dpdk::{service, DpdkOption};
    DpdkOption::new()
        .args("-n 4 --file-prefix app".split(" "))
        .init()
        .unwrap();
    let lcores = service().available_lcores();
    println!(
        "The first lcore has lcore_id: {}, cpu_id: {}, socket_id: {}",
        lcores[0].lcore_id, lcores[0].cpu_id, lcores[0].socket_id
    );
    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkservice_thread_bind_to() {
    use rpkt_dpdk::{service, DpdkOption};
    DpdkOption::new()
        .args("-n 4 --file-prefix app".split(" "))
        .init()
        .unwrap();
    let jh = std::thread::spawn(|| {
        // Before thread binding, `current_lcore` returns None.
        assert_eq!(service().current_lcore().is_none(), true);
        service().thread_bind_to(0).unwrap();
        // After thread binding, `current_lcore` records the lcore_id.
        assert_eq!(service().current_lcore().unwrap().lcore_id, 0);
    });
    jh.join().unwrap();
    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkservice_register_as_rte_thread() {
    use rpkt_dpdk::{ffi, service, DpdkOption};
    DpdkOption::new()
        .args("-n 4 --file-prefix app".split(" "))
        .init()
        .unwrap();
    let jh = std::thread::spawn(move || {
        service().thread_bind_to(0).unwrap();
        // Before rte thread registration, rte_thread_id is an invalid
        // value, which is u32::MAX.
        let rte_thread_id = unsafe { ffi::rte_lcore_id_() };
        assert_eq!(rte_thread_id, u32::MAX);
        // After rte thread registration, rte_thread_id is a value that
        // is smaller than u32::MAX.
        let rte_thread_id = service().register_as_rte_thread().unwrap();
        assert_eq!(rte_thread_id, unsafe { ffi::rte_lcore_id_() });
        assert_eq!(rte_thread_id < u32::MAX, true);
    });
    jh.join().unwrap();
    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkservice_mempool_alloc() {
    use rpkt_dpdk::{constant, service, DpdkOption};
    DpdkOption::new()
        .args("-n 4 --file-prefix app".split(" "))
        .init()
        .unwrap();
    {
        let mp = service()
            .mempool_alloc("mp", 128, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
            .unwrap();
        let mbuf = mp.try_alloc().unwrap();
        assert_eq!(mbuf.capacity(), 2048);
        assert_eq!(mbuf.front_capacity(), constant::MBUF_HEADROOM_SIZE as usize);
    }
    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkservice_mempool() {
    use rpkt_dpdk::{constant, service, DpdkOption};
    DpdkOption::new()
        .args("-n 4 --file-prefix app".split(" "))
        .init()
        .unwrap();
    service()
        .mempool_alloc("mp", 128, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
        .unwrap();
    let jh = std::thread::spawn(|| {
        let mp = service().mempool("mp").unwrap();
        let mbuf = mp.try_alloc().unwrap();
        assert_eq!(mbuf.capacity(), 2048);
        assert_eq!(mbuf.front_capacity(), constant::MBUF_HEADROOM_SIZE as usize);
    });
    jh.join().unwrap();
    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkservice_mempool_free() {
    use rpkt_dpdk::{constant, service, DpdkOption};
    DpdkOption::new()
        .args("-n 4 --file-prefix app".split(" "))
        .init()
        .unwrap();
    let mbuf;
    {
        let mp = service()
            .mempool_alloc("mp", 128, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
            .unwrap();
        // Can't deallocate mempool "mp", because the `mp` instance is still alive.
        assert_eq!(service().mempool_free("mp").is_err(), true);
        mbuf = mp.try_alloc().unwrap();
    }
    // Can't deallocate mempool "mp", because `mbuf` is alive, so the mempool is not full.
    assert_eq!(service().mempool_free("mp").is_err(), true);
    drop(mbuf);
    // The mbuf is not in use, we can succefully drop this mempool.
    assert_eq!(service().mempool_free("mp").is_ok(), true);
    service().graceful_cleanup().unwrap();
}
