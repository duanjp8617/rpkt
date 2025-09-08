use rpkt_dpdk::{service, DpdkOption};
use std::thread;

fn main() {
    DpdkOption::with_eal_arg("-l 2 -n 4 --file-prefix app1 --proc-type=primary")
        .init()
        .unwrap();
    println!(
        "is primary process: {}",
        service().is_primary_process().unwrap()
    );

    service().mempool_alloc("wtf", 127, 0, 200, -1).unwrap();

    // // launch 2 threads and bind them to different lores.
    // let mut jhs = vec![];
    // for i in 0..2 {
    //     let jh = thread::spawn(move || {
    //         service().lcore_bind(i).unwrap();
    //         let rte_lcore_id = service().rte_thread_register().unwrap();
    //         println!("{rte_lcore_id}");
    //         loop {}
    //     });
    //     jhs.push(jh);
    // }

    // for jh in jhs {
    //     jh.join().unwrap()
    // }

    loop {

    }
}
