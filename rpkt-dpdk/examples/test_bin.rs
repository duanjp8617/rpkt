use rpkt_dpdk::{service, DpdkOption, DpdkService, EthConf, RxqConf, TxqConf};
use std::ffi::CStr;

fn main() {
    DpdkOption::with_eal_arg("-l 2 -n 4 --file-prefix app1 --proc-type=primary")
        .init()
        .unwrap();
    println!(
        "is primary process: {}",
        service().is_primary_process().unwrap()
    );

    {
        let count = service().eth_dev_count_avail().unwrap();
        println!("there are {count} devices on the machine");

        let dev_info = service().dev_info(0).unwrap();

        println!("device driver name: {}", dev_info.driver_name());
        println!(
            "max rx/tx queue: {}:{}",
            dev_info.max_rx_queues(),
            dev_info.max_tx_queues()
        );
        println!("socket_id for port 0 {}", dev_info.socket_id);

        let mac_addr = dev_info.mac_addr;
        println!(
            "mac addr for port 0 0x{:02x}:0x{:02x}:0x{:02x}:0x{:02x}:0x{:02x}:0x{:02x}",
            mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]
        );
    }

    {
        let eth_conf = EthConf::default();
        service().mempool_alloc("wtf", 4096, 32, 2048, 1).unwrap();

        let rxq_conf = RxqConf::new(128, 8, 1, "wtf");
        let rxq_confs: Vec<RxqConf> = std::iter::repeat_with(|| rxq_conf.clone())
            .take(4)
            .collect();

        let txq_conf = TxqConf::new(128, 32, 1);
        let txq_confs: Vec<TxqConf> = std::iter::repeat_with(|| txq_conf.clone())
            .take(4)
            .collect();

        service()
            .dev_configure_and_start(0, &eth_conf, &rxq_confs, &txq_confs)
            .unwrap();
    }

    service().gracefull_cleanup().unwrap();
    println!("Dpdk service has been shutdown gracefully");
}
