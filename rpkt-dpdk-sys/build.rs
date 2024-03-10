use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;
use bindgen::Formatter;

use version_compare::{Version};

const DPDK_PREFERRED_VERSION: &str = "23.11";
const DPDK_GIT_REPO: &str = "https://dpdk.org/git/dpdk";

// On Ubuntu server, we need the following packages:
// 1. meson (apt install meson) for meson build
// 2. pyelf-tool (apt install python3-pyelftools) for meson configuration
// 3. clang (apt install clang) for bindgen
// 4. libnuma-dev (apt install libnuma-dev) for NUMA support

// To rebuild everything, remove dpdk-sys/deps/configure-finish file.

// Build the dpdk ffi library.
// The library information is acquired through pkg-config.
// The ffi interface is generated with the bindgen.
fn build_dpdk_ffi() {
    // Probe the cflags of the installed DPDK library.
    let output = Command::new("pkg-config")
        .args(&["--cflags", "libdpdk"])
        .output()
        .unwrap();
    assert!(output.status.success() == true);
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
    assert!(output.status.success() == true);
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
    // At this moment, rpkt doesn't provide bindings to anything that was changed since 21.11
    // That value should be updated, once those methods/structs would be exposed
    let dpdk_min_version: Version = Version::from("21.11").unwrap();
    // It is not guaranteed that there will be no significant ABI/API changes later
    let dpdk_max_version: Version = Version::from("24.03.9999").unwrap();
    // Check DPDK version.
    let output = Command::new("pkg-config")
        .args(&["--modversion", "libdpdk"])
        .output()
        .expect("Cannot find pkg-config. Please install pkg-config.");
    if output.status.success() {
        let s = String::from_utf8(output.stdout).unwrap();
        let version_str = s.trim();
        let version = Version::from(version_str).unwrap();
        if version < dpdk_min_version {
            panic!(
                "pkg-config finds DPDK library with version {} which is too old.\nPlease install version between {} and {}.\n",
                version_str,
                dpdk_min_version,
                dpdk_max_version
            );
        }
        if version > dpdk_max_version {
            panic!(
                "pkg-config finds DPDK library with version {} which is too new.\nPlease install version between {} and {}.\n",
                version_str,
                dpdk_min_version,
                dpdk_max_version
            );
        }

        // Found a matching dpdk library installed globally.
        build_dpdk_ffi();
        return;
    }

    // Save the absolute path of the root directory.
    let pwd = fs::canonicalize(PathBuf::from("./")).unwrap();

    // Download DPDK source from the official git repo.
    if !Path::new("deps/dpdk").is_dir() {
        let mut tag = "v".to_string();
        tag.push_str(DPDK_PREFERRED_VERSION);
        let res = Command::new("git")
            .args(&["clone", "-b", &tag, DPDK_GIT_REPO, "deps/dpdk"])
            .status()
            .expect("Cannot find git. Please install git.\n");
        if !res.success() {
            panic!("Fail to clone DPDK repo {} at tag {}.", DPDK_GIT_REPO, &tag);
        }
    }

    // Configure DPDK with meson.
    if !Path::new("deps/configure-finish").is_file() {
        // Remove dpdk/build directory if they exist.
        let build_dir = Path::new("deps/dpdk/build");
        if build_dir.is_dir() {
            fs::remove_dir_all(build_dir)
                .expect("Fail to remove existing deps/dpdk/build directory.\n");
        }

        // Configure DPDK for build.
        let mut meson_dprefix = String::from("-Dprefix=");
        meson_dprefix.push_str(pwd.join("deps/dpdk-install").to_str().unwrap());
        let res = Command::new("meson")
            .current_dir("deps/dpdk")
            .args(&[&meson_dprefix[..], "build"])
            .status()
            .expect("Cannot find meson. Please install meson.\n");
        if !res.success() {
            panic!("Fail to configure DPDK source with meson.");
        }

        fs::File::create(Path::new("deps/configure-finish"))
            .expect("Fail to create deps/configure-finish.\n");
        println!("cargo:rerun-if-changed=deps/configure-finish");
    }

    // Build and install DPDK.
    let res = Command::new("ninja")
        .current_dir("deps/dpdk/build")
        .status()
        .expect("Cannot find ninja. Please install ninja.\n");
    if !res.success() {
        panic!("Fail to build DPDK with ninja.");
    }
    let res = Command::new("ninja")
        .current_dir("deps/dpdk/build")
        .args(&["install"])
        .status()
        .unwrap();
    assert!(res.success());

    // Set PKG_CONFIG_PATH environment variable to point to the installed DPDK library.
    env::set_var(
        "PKG_CONFIG_PATH",
        pwd.join("deps/dpdk-install/lib/x86_64-linux-gnu/pkgconfig")
            .to_str()
            .unwrap(),
    );

    build_dpdk_ffi();
}
