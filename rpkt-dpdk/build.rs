use std::env;
use std::iter::FromIterator;
use std::path::PathBuf;
use std::process::Command;
use std::str;

use bindgen::Formatter;
use version_compare::Version;

// Build the dpdk ffi library.
// The library information is acquired through pkg-config.
// The ffi interface is generated with the bindgen.
fn build_dpdk_ffi() {
    // Probe the cflags of the installed DPDK library.
    let output = Command::new("pkg-config")
        .args(&["--cflags", "libdpdk"])
        .output()
        .unwrap();
    assert_eq!(output.status.success(), true);
    let cflags = String::from_utf8(output.stdout).unwrap();

    // Compile the csrc/impl.c file into a static library.
    let cflags_iter = cflags.trim().split(' ');
    let mut cbuild = cc::Build::new();
    cbuild.opt_level(3);
    for cflag in cflags_iter.clone() {
        cbuild.flag(cflag);
    }
    cbuild.file("csrc/impl.c").compile("impl");
    println!("cargo:rerun-if-changed=csrc/impl.c");

    // Generate the dpdk rust bindings.
    let outdir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let mut bgbuilder = bindgen::builder()
        // generate all the wrapper functions defined in csrc/header.h
        .allowlist_function("rte_.*_")
        // generate useful dpdk functions
        .allowlist_function("rte_thread_set_affinity")
        .allowlist_function("rte_thread_register")
        .allowlist_function("rte_pktmbuf_pool_create")
        .allowlist_function("rte_mempool_free")
        .allowlist_function("rte_pktmbuf_free_bulk")
        .allowlist_function("rte_mempool_avail_count") // this can be removed
        .allowlist_function("rte_eth_dev_info_get")
        .allowlist_function("rte_eth_dev_count_avail")
        .allowlist_function("rte_eth_macaddr_get")
        .allowlist_function("rte_eth_stats_get")
        .allowlist_function("rte_eth_dev_socket_id")
        .allowlist_function("rte_eth_dev_configure")
        .allowlist_function("rte_eth_dev_start")
        .allowlist_function("rte_eth_dev_stop")
        .allowlist_function("rte_eth_dev_close")
        .allowlist_function("rte_eth_rx_queue_setup")
        .allowlist_function("rte_eth_tx_queue_setup")
        .allowlist_function("rte_eth_promiscuous_enable")
        .allowlist_function("rte_eth_promiscuous_disable")
        .allowlist_function("rte_eal_init")
        .allowlist_function("rte_eal_cleanup")
        // generate useful dpdk types
        .allowlist_type("rte_eth_conf")
        .allowlist_type("rte_eth_dev_info")
        .allowlist_type("rte_ether_addr")
        .allowlist_type("rte_mempool")
        .allowlist_type("rte_mbuf")
        .allowlist_type("rte_eth_stats")
        // generate useful dpdk macros defined in rte_build_config.h.
        .allowlist_var("RTE_MAX_LCORE")
        .allowlist_var("RTE_MAX_NUMA_NODES")
        .allowlist_var("RTE_MBUF_MAX_NB_SEGS")
        .allowlist_var("RTE_MBUF_DEFAULT_DATAROOM")
        .allowlist_var("RTE_PKTMBUF_HEADROOM")
        .allowlist_var("RTE_ETHDEV_QUEUE_STAT_CNTRS")
        .header("csrc/header.h");
    for cflag in cflags_iter {
        bgbuilder = bgbuilder.clang_arg(cflag);
    }
    bgbuilder
        .formatter(Formatter::Rustfmt)
        .generate()
        .expect("Unable to generate rust bingdings from csrc/header.h.")
        .write_to_file(outdir.join("dpdk.rs"))
        .unwrap();
    println!("cargo:rerun-if-changed=csrc/header.h");

    // Generate linker option hints.
    let output = Command::new("pkg-config")
        .args(&["--libs", "--static", "libdpdk"])
        .output()
        .unwrap();
    assert_eq!(output.status.success(), true);
    let ldflags = String::from_utf8(output.stdout).unwrap();
    for ldflag in ldflags.trim().split(' ') {
        if ldflag.starts_with("-L") {
            println!("cargo:rustc-link-search=native={}", &ldflag[2..]);
        } else if ldflag.starts_with("-l") {
            if ldflag.ends_with(".a") {
                if !ldflag.starts_with("-l:lib") {
                    panic!("Invalid linker option: {}", ldflag);
                }
                let end_range = ldflag.len() - 2;
                println!(
                    "cargo:rustc-link-lib=static:+whole-archive,-bundle={}",
                    &ldflag[6..end_range]
                );
            } else {
                if !ldflag.starts_with("-lrte") {
                    println!("cargo:rustc-link-lib={}", &ldflag[2..]);
                }
            }
        } else {
            if ldflag == "-pthread" {
                println!("cargo:rustc-link-lib={}", &ldflag[1..]);
            } else if ldflag.starts_with("-Wl") {
                // We do nothing with -Wl linker options.
            } else {
                panic!("Invalid linker option: {}.", ldflag);
            }
        }
    }
}

fn main() {
    // Only support recent LTS versions.
    let supported_version = &["21.11.9", "22.11.7", "23.11.3", "24.11.1"];
    let supported_version = Vec::from_iter(supported_version.map(|vs| Version::from(vs).unwrap()));

    // Check DPDK version.
    let output = Command::new("pkg-config")
        .args(&["--modversion", "libdpdk"])
        .output()
        .expect("Cannot find pkg-config. Please install pkg-config.");
    if output.status.success() {
        let s = String::from_utf8(output.stdout).unwrap();
        let version_str = s.trim();
        let version = Version::from(version_str).unwrap();
        if supported_version
            .iter()
            .find(|allowed_version| **allowed_version == version)
            .is_none()
        {
            eprintln!(
                "pkg-config finds DPDK library with version {version_str} which is not matched."
            );
            eprintln!(
                "rpkt only supports DPDK version {}, {}, {} and {}.",
                supported_version[0],
                supported_version[1],
                supported_version[2],
                supported_version[3]
            );
            panic!();
        }
        
        // Found a installed dpdk library.
        build_dpdk_ffi();
        return;
    } else {
        eprintln!("pkg-config can not find installed DPDK library.");
        eprintln!("Please add the pkgconfig path of the installed DPDK library to PKG_CONFIG_PATH and try again.");
        panic!();
    }
}
