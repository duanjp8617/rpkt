use rpkt_dpdk::{service, DpdkOption, DpdkService, EthConf, RxqConf, TxqConf};
use std::ffi::CStr;

fn main() {
    DpdkOption::new()
        .args("-l 2 -n 4 --file-prefix app1 --proc-type=primary".split(" "))
        .init()
        .unwrap();
    println!(
        "is primary process: {}",
        service().is_primary_process().unwrap()
    );

    {
        let count = service().eth_dev_count_avail().unwrap();
        println!("there are {count} devices on the machine");
        let port_id = 1;        
        let dev_info = service().dev_info(port_id).unwrap();

        println!("device driver name: {}", dev_info.driver_name());
        println!(
            "max rx/tx queue: {}:{}",
            dev_info.max_rx_queues(),
            dev_info.max_tx_queues()
        );
        println!("socket_id for port {port_id} {}", dev_info.socket_id);

        let mac_addr = dev_info.mac_addr;
        println!(
            "mac addr for port 0 0x{:02x}:0x{:02x}:0x{:02x}:0x{:02x}:0x{:02x}:0x{:02x}",
            mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]
        );

        println!("min_mtu: {}", dev_info.min_mtu());
        println!("max_mtu: {}", dev_info.max_mtu());
        println!("min_rx_bufsize: {}", dev_info.min_rx_bufsize());
        println!("max_rx_pktlen: {}", dev_info.max_rx_pktlen());
        println!("max_lro_pkt_size: {}", dev_info.max_lro_pkt_size());

        fn show_bit_offset(capa: u64, offload_name: &str) {
            for i in 0..64 {
                let bit_mask: u64 = if i == 0 {1} else {1 << i};
                if bit_mask & capa != 0 {
                    println!("{offload_name}: bit {i}")
                }
            }
        }

        println!("rx_offload_capa: {}", dev_info.rx_offload_capa());
        show_bit_offset(dev_info.rx_offload_capa(), "rx_offload");
        println!("tx_offload_capa: {}", dev_info.tx_offload_capa());
        show_bit_offset(dev_info.tx_offload_capa(), "tx_offload");

        println!("reta_size: {}", dev_info.reta_size());
        println!("hash_key_size: {}", dev_info.hash_key_size());

        println!("flow_type_rss_offloads: {}", dev_info.flow_type_rss_offloads());
        show_bit_offset(dev_info.flow_type_rss_offloads(), "flow_rss");
        
        println!("tx_desc_lim: {:?}", dev_info.tx_desc_lim());
        println!("rx_desc_lim: {:?}", dev_info.rx_desc_lim());
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

    service().graceful_cleanup().unwrap();
    println!("Dpdk service has been shutdown gracefully");
}
