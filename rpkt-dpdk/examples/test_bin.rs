use rpkt_dpdk::{service, DpdkOption, DpdkService};
use std::ffi::CStr;

fn main() {
    DpdkOption::with_eal_arg("-l 2 -n 4 --file-prefix app1 --proc-type=primary")
        .init()
        .unwrap();
    println!(
        "is primary process: {}",
        service().is_primary_process().unwrap()
    );

    let count = service().eth_dev_count_avail().unwrap();
    println!("there are {count} devices on the machine");

    unsafe {
        let dev_info = DpdkService::eth_dev_info_get(0).unwrap();
        let dev_driver_name = CStr::from_ptr(dev_info.driver_name)
            .to_str()
            .unwrap_or("")
            .to_owned();

        println!("device driver name: {dev_driver_name}");
        println!(
            "max rx/tx queue: {}:{}",
            dev_info.max_rx_queues, dev_info.max_tx_queues
        );

        let socket_id_0 = DpdkService::eth_dev_socket_id(0).unwrap();
        println!("socket_id for port 0 {socket_id_0}");

        let socket_id_1 = DpdkService::eth_dev_socket_id(1).unwrap();
        println!("socket_id for port 1 {socket_id_1}");

        let mac_addr = DpdkService::eth_macaddr_get(0).unwrap();
        println!(
            "mac addr for port 0 0x{:02x}:0x{:02x}:0x{:02x}:0x{:02x}:0x{:02x}:0x{:02x}",
            mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]
        );

        let mac_addr = DpdkService::eth_macaddr_get(1).unwrap();
        println!(
            "mac addr for port 1 0x{:02x}:0x{:02x}:0x{:02x}:0x{:02x}:0x{:02x}:0x{:02x}:",
            mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]
        );
    }
}
