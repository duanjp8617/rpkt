use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use rpkt_dpdk::{service, DpdkOption};

fn main() {
    DpdkOption::new()
        .args("-l 2 -n 4 --file-prefix mempool_primary --proc-type=primary".split(" "))
        .init()
        .unwrap();
    println!(
        "is primary process: {}",
        service().is_primary_process().unwrap()
    );

    service()
        .mempool_alloc("mp_on_primary", 127, 0, 200, -1)
        .unwrap();

    let run = Arc::new(AtomicBool::new(true));
    let run_clone = run.clone();
    ctrlc::set_handler(move || {
        run_clone.store(false, Ordering::Release);
    })
    .unwrap();

    while run.load(Ordering::Acquire) {}

    service().mempool_free("mp_on_primary").unwrap();
    service().graceful_cleanup().unwrap();
}
