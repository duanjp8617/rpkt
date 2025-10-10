use std::env;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use bindgen::Formatter;
use version_compare::Version;

// On Ubuntu server, we need the following packages:
// 1. meson (apt install meson) for meson build
// 2. pyelf-tool (apt install python3-pyelftools) for meson configuration
// 3. clang (apt install clang) for bindgen
// 4. libnuma-dev (apt install libnuma-dev) for NUMA support

// To make rust-analyzer aware of the PKG_CONFIG_PATH environment variable,
// add the following to settings.json:
// "rust-analyzer.cargo.extraEnv": {
//     "PKG_CONFIG_PATH": "<dpdk_installation_path>/lib/<arch>-<os>/pkgconfig"
// }

// Build the dpdk ffi library.
// The library information is acquired through pkg-config.
// The ffi interface is generated with the bindgen.
fn build_dpdk_ffi() {
    // Probe the cflags of the installed DPDK library.
    let output = Command::new("pkg-config")
        .args(&["--cflags", "libdpdk"])
        .output()
        .unwrap();
    assert!(output.status.success());
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
        .allowlist_function("rte_thread_unregister")
        .allowlist_function("rte_pktmbuf_pool_create")
        .allowlist_function("rte_mempool_free")
        .allowlist_function("rte_mempool_lookup")
        .allowlist_function("rte_mp_disable")
        .allowlist_function("rte_eal_process_type")
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
        .allowlist_type("rte_proc_type_t")
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
    let raw_supported_versions = [
        ("21.11.00", "22.00.00"),
        ("22.11.00", "23.00.00"),
        ("23.11.00", "24.00.00"),
        ("24.11.00", "25.00.00"),
    ];

    let supported_versions: Vec<(Version, Version)> = raw_supported_versions
        .iter()
        .map(|(start, end)| (Version::from(start).unwrap(), Version::from(end).unwrap()))
        .collect();

    // Save the absolute path of the root directory.
    let pwd = std::fs::canonicalize(PathBuf::from("./")).unwrap();
    let dest_path = pwd.join(".dpdk_install");

    let input_pkgconfig_env = if let Ok(env_var) = std::env::var("PKG_CONFIG_PATH") {
        Some(env_var)
    } else {
        // Try to retrieve the dpdk installation path from previous build.
        match std::fs::read_to_string(dest_path.clone()) {
            Ok(content) => {
                env::set_var("PKG_CONFIG_PATH", &content);
            }
            _ => {}
        }
        None
    };

    // Check DPDK version.
    let Ok(output) = Command::new("pkg-config")
        .args(&["--modversion", "libdpdk"])
        .output()
    else {
        eprintln!("pkg-config is not available on your system.");
        eprintln!("Please install pkg-config first.");
        std::process::exit(1);
    };

    if output.status.success() {
        let s = String::from_utf8(output.stdout).unwrap();
        let version_str = s.trim();
        let Some(version) = Version::from(version_str) else {
            eprintln!("pkg-config reports an invalid DPDK version: {version_str}");
            std::process::exit(1);
        };

        let matched = supported_versions
            .iter()
            .find(|(start, end)| &version >= start && &version < end);

        if matched.is_none() {
            eprintln!(
                "pkg-config finds DPDK library with version {version_str} which is not supported."
            );
            eprintln!("rpkt only supports the following DPDK version ranges:");
            for (start, end) in &supported_versions {
                eprintln!("  >= {} and < {}", start, end);
            }
            std::process::exit(1);
        }

        // Found a installed dpdk library.
        build_dpdk_ffi();

        if let Some(input_pkgconfig_env) = input_pkgconfig_env {
            let mut f = std::fs::File::create(dest_path).unwrap();
            f.write_all(format!("{input_pkgconfig_env}").as_bytes())
                .unwrap();
        }

        return;
    } else {
        eprintln!("pkg-config can not find installed DPDK library, please build and install DPDK.");
        eprintln!("If you install DPDK locally, you can build this crate by setting the installation path in PKG_CONFIG_PATH: ");
        eprintln!("PKG_CONFIG_PATH=<dpdk_installation_path>/lib/<arch>-<os>/pkgconfig cargo build");
        std::process::exit(1);
    }
}
