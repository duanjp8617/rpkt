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
    // Can't deallocate mempool "mp", because `mbuf` is alive, so the mempool is not
    // full.
    assert_eq!(service().mempool_free("mp").is_err(), true);
    drop(mbuf);
    // The mbuf is not in use, we can succefully drop this mempool.
    assert_eq!(service().mempool_free("mp").is_ok(), true);
    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkservice_dev_configure_and_start() {
    use arrayvec::ArrayVec;
    use rpkt_dpdk::{constant, service, DpdkOption, EthConf, RxqConf, TxqConf};

    DpdkOption::new()
        .args("-n 4 --file-prefix app".split(" "))
        .init()
        .unwrap();

    // create a mempool
    service()
        .mempool_alloc("mp", 2048, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
        .unwrap();

    // create the eth conf
    let dev_info = service().dev_info(0).unwrap();
    let mut eth_conf = EthConf::new();
    // enable all rx_offloads
    eth_conf.rx_offloads = dev_info.rx_offload_capa();
    // enable all tx_offloads
    eth_conf.tx_offloads = dev_info.tx_offload_capa();
    // setup the rss hash function
    eth_conf.rss_hf = dev_info.flow_type_rss_offloads();
    // setup rss_hash_key
    if dev_info.hash_key_size() == 40 {
        eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_40B.into();
    } else if dev_info.hash_key_size() == 52 {
        eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_52B.into();
    } else {
        panic!("unsupported hash key size: {}", dev_info.hash_key_size())
    };

    // create rxq conf and txq conf
    let rxq_conf = RxqConf::new(512, 0, "mp");
    let txq_conf = TxqConf::new(512, 0);
    // create 2 rx/tx queues
    let rxq_confs: Vec<RxqConf> = std::iter::repeat_with(|| rxq_conf.clone())
        .take(2 as usize)
        .collect();
    let txq_confs: Vec<TxqConf> = std::iter::repeat_with(|| txq_conf.clone())
        .take(2 as usize)
        .collect();

    // initialize the port
    let res = service().dev_configure_and_start(0, &eth_conf, &rxq_confs, &txq_confs);
    assert_eq!(res.is_ok(), true);

    {
        // receive and send packets
        let mut rxq = service().rx_queue(0, 1).unwrap();
        let mut txq = service().tx_queue(0, 1).unwrap();
        let mut ibatch = ArrayVec::<_, 32>::new();
        rxq.rx(&mut ibatch);
        txq.tx(&mut ibatch);
    }

    // deallocate all the resources and shutdown dpdk
    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkservice_rx_queue() {
    use rpkt_dpdk::{constant, service, DpdkOption, EthConf, RxqConf, TxqConf};

    DpdkOption::new()
        .args("-n 4 --file-prefix app".split(" "))
        .init()
        .unwrap();

    // create a mempool
    service()
        .mempool_alloc("mp", 2048, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
        .unwrap();

    // create the eth conf
    let dev_info = service().dev_info(0).unwrap();
    let mut eth_conf = EthConf::new();
    // enable all rx_offloads
    eth_conf.rx_offloads = dev_info.rx_offload_capa();
    // enable all tx_offloads
    eth_conf.tx_offloads = dev_info.tx_offload_capa();
    // setup the rss hash function
    eth_conf.rss_hf = dev_info.flow_type_rss_offloads();
    // setup rss_hash_key
    if dev_info.hash_key_size() == 40 {
        eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_40B.into();
    } else if dev_info.hash_key_size() == 52 {
        eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_52B.into();
    } else {
        panic!("unsupported hash key size: {}", dev_info.hash_key_size())
    };

    // create rxq conf and txq conf
    let rxq_conf = RxqConf::new(512, 0, "mp");
    let txq_conf = TxqConf::new(512, 0);
    // create 2 rx/tx queues
    let rxq_confs: Vec<RxqConf> = std::iter::repeat_with(|| rxq_conf.clone())
        .take(2 as usize)
        .collect();
    let txq_confs: Vec<TxqConf> = std::iter::repeat_with(|| txq_conf.clone())
        .take(2 as usize)
        .collect();

    // initialize the port
    let res = service().dev_configure_and_start(0, &eth_conf, &rxq_confs, &txq_confs);
    assert_eq!(res.is_ok(), true);

    let jh = std::thread::spawn(|| {
        let res = service().rx_queue(0, 1);
        assert_eq!(res.is_ok(), true);

        // we can only acquire a single rx queue
        let res = service().rx_queue(0, 1);
        assert_eq!(res.is_ok(), false);
    });
    jh.join().unwrap();

    // deallocate all the resources and shutdown dpdk
    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkservice_tx_queue() {
    use rpkt_dpdk::{constant, service, DpdkOption, EthConf, RxqConf, TxqConf};

    DpdkOption::new()
        .args("-n 4 --file-prefix app".split(" "))
        .init()
        .unwrap();

    // create a mempool
    service()
        .mempool_alloc("mp", 2048, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
        .unwrap();

    // create the eth conf
    let dev_info = service().dev_info(0).unwrap();
    let mut eth_conf = EthConf::new();
    // enable all rx_offloads
    eth_conf.rx_offloads = dev_info.rx_offload_capa();
    // enable all tx_offloads
    eth_conf.tx_offloads = dev_info.tx_offload_capa();
    // setup the rss hash function
    eth_conf.rss_hf = dev_info.flow_type_rss_offloads();
    // setup rss_hash_key
    if dev_info.hash_key_size() == 40 {
        eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_40B.into();
    } else if dev_info.hash_key_size() == 52 {
        eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_52B.into();
    } else {
        panic!("unsupported hash key size: {}", dev_info.hash_key_size())
    };

    // create rxq conf and txq conf
    let rxq_conf = RxqConf::new(512, 0, "mp");
    let txq_conf = TxqConf::new(512, 0);
    // create 2 rx/tx queues
    let rxq_confs: Vec<RxqConf> = std::iter::repeat_with(|| rxq_conf.clone())
        .take(2 as usize)
        .collect();
    let txq_confs: Vec<TxqConf> = std::iter::repeat_with(|| txq_conf.clone())
        .take(2 as usize)
        .collect();

    // initialize the port
    let res = service().dev_configure_and_start(0, &eth_conf, &rxq_confs, &txq_confs);
    assert_eq!(res.is_ok(), true);

    let jh = std::thread::spawn(|| {
        let res = service().tx_queue(0, 1);
        assert_eq!(res.is_ok(), true);

        // we can only acquire a single rx queue
        let res = service().tx_queue(0, 1);
        assert_eq!(res.is_ok(), false);
    });
    jh.join().unwrap();

    // deallocate all the resources and shutdown dpdk
    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkservice_stats_query() {
    use rpkt_dpdk::{constant, rdtsc, service, DpdkOption, EthConf, RxqConf, TxqConf};
    DpdkOption::new()
        .args("-n 4 --file-prefix app".split(" "))
        .init()
        .unwrap();

    // create a mempool
    service()
        .mempool_alloc("mp", 2048, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
        .unwrap();

    // create the eth conf
    let dev_info = service().dev_info(0).unwrap();
    let mut eth_conf = EthConf::new();
    // enable all rx_offloads
    eth_conf.rx_offloads = dev_info.rx_offload_capa();
    // enable all tx_offloads
    eth_conf.tx_offloads = dev_info.tx_offload_capa();
    // setup the rss hash function
    eth_conf.rss_hf = dev_info.flow_type_rss_offloads();
    // setup rss_hash_key
    if dev_info.hash_key_size() == 40 {
        eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_40B.into();
    } else if dev_info.hash_key_size() == 52 {
        eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_52B.into();
    } else {
        panic!("unsupported hash key size: {}", dev_info.hash_key_size())
    };

    // create rxq conf and txq conf
    let rxq_conf = RxqConf::new(512, 0, "mp");
    let txq_conf = TxqConf::new(512, 0);
    // create 2 rx/tx queues
    let rxq_confs: Vec<RxqConf> = std::iter::repeat_with(|| rxq_conf.clone())
        .take(2 as usize)
        .collect();
    let txq_confs: Vec<TxqConf> = std::iter::repeat_with(|| txq_conf.clone())
        .take(2 as usize)
        .collect();

    // initialize the port
    let res = service().dev_configure_and_start(0, &eth_conf, &rxq_confs, &txq_confs);
    assert_eq!(res.is_ok(), true);

    {
        let mut stat_query = service().stats_query(0).unwrap();

        // test the basic cpu frequecy for the rdtsc counter
        let base_freq = rdtsc::BaseFreq::new();
        // get the current dpdk port stats
        let curr_stats = stat_query.query();
        // wait for 1s using rdtsc
        let tick_in_1s = rdtsc::rdtsc() + base_freq.sec_to_cycles(1.0);
        while rdtsc::rdtsc() < tick_in_1s {}
        // get the new stats after 1s
        let new_stats = stat_query.query();
        println!("{} pps", new_stats.ipackets() - curr_stats.ipackets());
    }

    // deallocate all the resources and shutdown dpdk
    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkservice_dev_stop_and_close() {
    use rpkt_dpdk::{constant, service, DpdkOption, EthConf, RxqConf, TxqConf};
    DpdkOption::new()
        .args("-n 4 --file-prefix app".split(" "))
        .init()
        .unwrap();

    // create a mempool
    service()
        .mempool_alloc("mp", 2048, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
        .unwrap();

    // create the eth conf
    let dev_info = service().dev_info(0).unwrap();
    let mut eth_conf = EthConf::new();
    // enable all rx_offloads
    eth_conf.rx_offloads = dev_info.rx_offload_capa();
    // enable all tx_offloads
    eth_conf.tx_offloads = dev_info.tx_offload_capa();
    // setup the rss hash function
    eth_conf.rss_hf = dev_info.flow_type_rss_offloads();
    // setup rss_hash_key
    if dev_info.hash_key_size() == 40 {
        eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_40B.into();
    } else if dev_info.hash_key_size() == 52 {
        eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_52B.into();
    } else {
        panic!("unsupported hash key size: {}", dev_info.hash_key_size())
    };

    // create rxq conf and txq conf
    let rxq_conf = RxqConf::new(512, 0, "mp");
    let txq_conf = TxqConf::new(512, 0);
    // create 2 rx/tx queues
    let rxq_confs: Vec<RxqConf> = std::iter::repeat_with(|| rxq_conf.clone())
        .take(2 as usize)
        .collect();
    let txq_confs: Vec<TxqConf> = std::iter::repeat_with(|| txq_conf.clone())
        .take(2 as usize)
        .collect();

    // initialize the port
    let res = service().dev_configure_and_start(0, &eth_conf, &rxq_confs, &txq_confs);
    assert_eq!(res.is_ok(), true);

    {
        let _txq = service().tx_queue(0, 1).unwrap();
        // txq is alive, we can't close the port
        let res = service().dev_stop_and_close(0);
        assert_eq!(res.is_err(), true);
    }

    {
        let _rxq = service().rx_queue(0, 1).unwrap();
        // rxq is alive, we can't close the port
        let res = service().dev_stop_and_close(0);
        assert_eq!(res.is_err(), true);
    }

    {
        let _stats_query = service().stats_query(0).unwrap();
        // rxq is alive, we can't close the port
        let res = service().dev_stop_and_close(0);
        assert_eq!(res.is_err(), true);
    }

    // txq/rxq/stats_query are all dropped, we can successfully shutdown the port.
    let res = service().dev_stop_and_close(0);
    assert_eq!(res.is_ok(), true);

    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkservice_is_primary_process() {
    use rpkt_dpdk::{service, DpdkOption};

    // Launch examples/mempool_primary.rs first.
    // Create a secondary dpdk process and attach to the
    // primary process launched from the example.
    DpdkOption::new()
        .args("-n 4 --file-prefix mempool_primary --proc-type=secondary".split(" "))
        .init()
        .unwrap();

    // This process is a secondary process
    assert_eq!(service().is_primary_process().unwrap(), false);
    {
        // On the secondary process, we can't allocate important resources
        let res = service().mempool_alloc("mp", 127, 0, 200, -1);
        assert_eq!(res.is_err(), true);

        // However, we can obtain the mempool allocated by the primary process
        let res = unsafe { service().assume_mempool("mp_on_primary") };
        assert_eq!(res.is_ok(), true);
    }

    service().graceful_cleanup().unwrap();
}

#[test]
fn dpdkservice_graceful_cleanup() {
    use rpkt_dpdk::{constant, service, DpdkOption, EthConf, RxqConf, TxqConf};
    DpdkOption::new()
        .args("-n 4 --file-prefix app".split(" "))
        .init()
        .unwrap();

    fn entry_function() {
        // create a mempool
        service()
            .mempool_alloc("mp", 2048, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
            .unwrap();

        // create the eth conf
        let dev_info = service().dev_info(0).unwrap();
        let mut eth_conf = EthConf::new();
        // enable all rx_offloads
        eth_conf.rx_offloads = dev_info.rx_offload_capa();
        // enable all tx_offloads
        eth_conf.tx_offloads = dev_info.tx_offload_capa();
        // setup the rss hash function
        eth_conf.rss_hf = dev_info.flow_type_rss_offloads();
        // setup rss_hash_key
        if dev_info.hash_key_size() == 40 {
            eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_40B.into();
        } else if dev_info.hash_key_size() == 52 {
            eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_52B.into();
        } else {
            panic!("unsupported hash key size: {}", dev_info.hash_key_size())
        };

        // create rxq conf and txq conf
        let rxq_conf = RxqConf::new(512, 0, "mp");
        let txq_conf = TxqConf::new(512, 0);
        // create 2 rx/tx queues
        let rxq_confs: Vec<RxqConf> = std::iter::repeat_with(|| rxq_conf.clone())
            .take(2 as usize)
            .collect();
        let txq_confs: Vec<TxqConf> = std::iter::repeat_with(|| txq_conf.clone())
            .take(2 as usize)
            .collect();

        // initialize the port
        let res = service().dev_configure_and_start(0, &eth_conf, &rxq_confs, &txq_confs);
        assert_eq!(res.is_ok(), true);

        let _txq = service().tx_queue(0, 1);
        let _rxq = service().rx_queue(0, 1);
        let _stats_query = service().stats_query(0);
    }

    entry_function();

    let res = service().graceful_cleanup();
    assert_eq!(res.is_ok(), true);

    // after we shutdown the dpdk service, all the public methods of `DpdkService`
    // will fail.
    let res = service().mempool_alloc("mp", 2048, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1);
    assert_eq!(res.is_err(), true);
}
