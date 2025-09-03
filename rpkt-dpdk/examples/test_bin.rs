use rpkt_dpdk::DpdkOption;

fn main() {
    let res = DpdkOption::with_eal_arg("-l 2 -n 4 --file-prefix app1").init();
    match res {
        Ok(_) => println!("1"),
        Err(e) => println!("{}", e),
    }
}
