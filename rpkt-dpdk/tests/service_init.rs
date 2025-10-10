use rpkt_dpdk::*;

#[test]
fn init_fail() {
    // We run mempool_primary first.
    let res = DpdkOption::new()
        .arg("--file-prefix")
        .arg("mempool_primary")
        .init();

    assert_eq!(res.is_err(), true);
}

#[test]
fn init_ok() {
    // We run mempool_primary first.
    let res = DpdkOption::new()
        .args("--file-prefix mempool_primary --proc-type=secondary".split(" "))
        .init();

    assert_eq!(res.is_ok(), true);

    let res = service().graceful_cleanup();
    assert_eq!(res.is_ok(), true);
}
