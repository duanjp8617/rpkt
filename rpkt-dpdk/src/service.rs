use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::sync::{Mutex, MutexGuard};

use once_cell::sync::OnceCell;

use crate::conf::*;
use crate::ffi;

use super::error::*;
use super::lcore::{self, *};
use super::mempool::*;
use super::port::*;

/// The `DpdkService` singleton.
pub(crate) static SERVICE: OnceCell<DpdkService> = OnceCell::new();

/// Command line arguments that are used to initialize dpdk eal.
///
/// For detailed eal arguments, please refer to https://doc.dpdk.org/guides/linux_gsg/linux_eal_parameters.html.
///
/// # Default
///
/// The [`Default`] implementation of `DpdkOption` contains the following
/// argument string:
///
/// "-n 4 --proc-type primary"
///
/// indicating that eal is initialized with 4 memory channels and as a primary
/// process.
pub struct DpdkOption {
    args: Vec<CString>,
}

impl Default for DpdkOption {
    fn default() -> Self {
        Self {
            args: ["./prefix", "-c", "1", "-n", "4", "--proc-type", "primary"]
                .iter()
                .map(|s| CString::new(*s).unwrap())
                .collect(),
        }
    }
}

impl DpdkOption {
    /// Create a new `DpdkOption` with no eal arguments.
    pub fn new() -> Self {
        Self {
            args: vec![CString::new("./prefix").unwrap()],
        }
    }

    /// Pass a single eal argument to `DpdkOption`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rpkt_dpdk::{service, DpdkOption};
    /// // initialize dpdk with 4 memory channels and use "app" as the
    /// // process prefix.
    /// let res = DpdkOption::new()
    ///     .arg("-n")
    ///     .arg("4")
    ///     .arg("--file-prefix")
    ///     .arg("app")
    ///     .init();
    /// assert_eq!(res.is_ok(), true);
    /// service().graceful_cleanup().unwrap();
    /// ```
    pub fn arg<S: AsRef<str>>(&mut self, arg: S) -> &mut Self {
        self.args.push(CString::new(arg.as_ref()).unwrap());
        self
    }

    /// Pass an iterator containing a list of eal arguments to `DpdkOption`.    
    ///
    /// # Examples
    /// ```rust
    /// use rpkt_dpdk::{service, DpdkOption};
    /// // initialize dpdk with 4 memory channels and use "app" as the
    /// // prefix for the dpdk primary process.
    /// let res = DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init();
    /// assert_eq!(res.is_ok(), true);
    /// service().graceful_cleanup().unwrap();
    /// ```
    pub fn args<S, I>(&mut self, args: I) -> &mut Self
    where
        S: AsRef<str>,
        I: IntoIterator<Item = S>,
    {
        args.into_iter()
            .for_each(|item| self.args.push(CString::new(item.as_ref()).unwrap()));
        self
    }

    /// Initialize dpdk eal using the provided eal arguments.
    ///
    /// After a successful initialization, the global singleton [`DpdkService`]
    /// can be accessed without panicing.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rpkt_dpdk::{service, DpdkOption};
    /// // initialize dpdk with 4 memory channels and use "app" as the
    /// // prefix for the dpdk primary process.
    /// let res = DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init();
    /// assert_eq!(res.is_ok(), true);
    /// service().graceful_cleanup().unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// This function returns [`DpdkError`] if initialization fails due to
    /// various reasons.
    pub fn init(&mut self) -> Result<()> {
        SERVICE.get_or_try_init(|| {
            // initialize dpdk with rte_eal_init
            let c_args: Vec<_> = self
                .args
                .iter()
                .map(|arg| arg.as_bytes_with_nul().as_ptr() as *mut c_char)
                .collect();
            let res = unsafe {
                ffi::rte_eal_init(c_args.len() as c_int, c_args.as_ptr() as *mut *mut c_char)
            };
            if res == -1 {
                return DpdkError::ffi_err(unsafe { ffi::rte_errno_() }, "fail to init eal")
                    .to_err();
            }

            // Detect lcores on the current system
            let lcores = lcore::detect_lcores();

            // rte_eal_init registers the current thread to lcore 0
            // we undo it just like erpc
            unsafe {
                let mut cpu_set: libc::cpu_set_t = std::mem::zeroed();
                libc::CPU_ZERO(&mut cpu_set);
                for lcore in lcores.iter() {
                    libc::CPU_SET(usize::try_from(lcore.lcore_id).unwrap(), &mut cpu_set);
                }
                let res = libc::sched_setaffinity(
                    0,
                    std::mem::size_of::<libc::cpu_set_t>(),
                    &cpu_set as *const libc::cpu_set_t,
                );
                if res != 0 {
                    return DpdkError::service_err(
                        "fail to unset thread affinity for the current process",
                    )
                    .to_err();
                }
                // at last, we unregister the current thread as a rte thread
                ffi::rte_thread_unregister();
            }

            let is_primary = unsafe {
                match ffi::rte_eal_process_type() {
                    ffi::rte_proc_type_t_RTE_PROC_PRIMARY => true,
                    ffi::rte_proc_type_t_RTE_PROC_SECONDARY => false,
                    _ => panic!("invalid dpdk proc type"),
                }
            };

            Ok(DpdkService {
                service: Mutex::new(ServiceInner {
                    started: true,
                    is_primary,
                    lcores: LcoreContext::create(&lcores),
                    mpools: HashMap::new(),
                    ports: HashMap::new(),
                }),
                lcores,
            })
        })?;

        Ok(())
    }
}

/// A global singleton providing public APIs to different dpdk functions.
///
/// The provided APIs include:
///
/// - Check lcores on the CPUs and bind threads to lcores.
///
/// - Create and delete dpdk mempools.
///
/// - Configure, start and close dpdk ports.
///
/// - Miscellaneous APIs, including checking primary process, shuttding down
///   DPDK eal, etc.
///
/// The API calls provided `DpdkService` should be safe wrapper functions for
/// corresponding dpdk ffi APIs. So `DpdkService` uses a mutex to protect all
/// these API calls. In this way, we ensure that there are no multi-thread
/// contentions when invoking important dpdk ffi APIs.
///
/// While this is a little-bit conservative, as some dpdk ffis may tolerate
/// multi-thread contentions, we believe that it is still a worth-while choice.
///
/// The public APIs provided by `DpdkService` are the so-called control-plane
/// APIs, meaning that they are only used to allocate important resources to the
/// library users, including mempools, port tx/rx queues, etc.
///
/// These control-plane APIs are not frequently invoked. They are most-likely to
/// be used during program initiliazation phase.
///
/// After the users acquire the desired resources, like mempools, they are free
/// to use the resources in multi-thread environments. Because dpdk itself
/// provides atomic guarantees for these resources.
pub struct DpdkService {
    service: Mutex<ServiceInner>,
    lcores: Vec<Lcore>,
}

/// Try to acquire a static reference to the [`DpdkService`].
///
/// # Errors
///
/// If [`DpdkService`] is not initialized, this function returns [`DpdkError`].
pub fn try_service() -> Result<&'static DpdkService> {
    SERVICE
        .get()
        .ok_or(DpdkError::service_err("service is not initialized"))
}

/// Return a reference to the [`DpdkService`].
///
/// # Panics
///
/// This function panics if  [`DpdkService`] is not initialized.
pub fn service() -> &'static DpdkService {
    match SERVICE.get() {
        Some(handle) => handle,
        None => panic!("dpdk service is not initialized"),
    }
}

// Lcore related APIs
impl DpdkService {
    /// Get a reference to the [`Lcore`] list of the current machine.
    ///
    /// The lcore list is collected by analyzing the /sys directory of the linux
    /// file system upon dpdk initialization.
    ///
    /// The returned lcore list is sorted by the lcore id in ascending order.
    ///
    /// Under most common cases, the `Lcore` with index `i` from the returned
    /// `Lcore` list corresponds to `Lcore` with `lcore_id` 0.
    ///
    /// # Examples
    /// ```rust
    /// use rpkt_dpdk::{service, DpdkOption};
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init()
    ///     .unwrap();
    /// let lcores = service().available_lcores();
    /// println!(
    ///     "The first lcore has lcore_id: {}, cpu_id: {}, socket_id: {}",
    ///     lcores[0].lcore_id, lcores[0].cpu_id, lcores[0].socket_id
    /// );
    /// service().graceful_cleanup().unwrap();

    /// ```
    pub fn available_lcores(&self) -> &Vec<Lcore> {
        &self.lcores
    }

    /// Bind the current thread to the lcore indicated by `lcore_id`.
    ///
    /// After thread binding, the thread will only be scheduled to run on the
    /// CPU core with `lcore_id`.
    ///
    /// Thread binding is perhaps the most important optimization for all the
    /// user-space packet processing programs.
    ///
    /// [`DpdkService`] manages thread binding in its internal state. It
    /// enforces the following invariants:
    ///
    /// - Each lcore can only be globally bound once.
    ///
    /// - Each thread can only be bound to a single lcore.
    ///
    /// Violating these invariants causes [`DpdkError`] to be returned.
    ///
    /// # Examples
    /// ```rust
    /// use rpkt_dpdk::{service, DpdkOption};
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init()
    ///     .unwrap();
    /// let jh = std::thread::spawn(|| {
    ///     // Before thread binding, `current_lcore` returns None.
    ///     assert_eq!(service().current_lcore().is_none(), true);
    ///     service().thread_bind_to(0).unwrap();
    ///     // After thread binding, `current_lcore` records the lcore_id.
    ///     assert_eq!(service().current_lcore().unwrap().lcore_id, 0);        
    /// });
    /// jh.join().unwrap();
    /// service().graceful_cleanup().unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// It returns [`DpdkError`] if the thread binding fails.
    pub fn thread_bind_to(&self, lcore_id: u32) -> Result<()> {
        let mut inner = self.try_lock()?;

        let lcore = self
            .lcores
            .iter()
            .find(|lcore| lcore.lcore_id == lcore_id)
            .ok_or(DpdkError::service_err("no such lcore"))?;

        inner.lcores.pin(lcore)
    }

    /// Register the current thread as a eal thread.
    ///
    /// After the registration, the thread can access some internal eal states,
    /// like the caches of the memory pool.
    ///
    /// # Examples
    /// ```rust
    /// use rpkt_dpdk::{ffi, service, DpdkOption};
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init()
    ///     .unwrap();
    /// let jh = std::thread::spawn(move || {
    ///     service().thread_bind_to(0).unwrap();
    ///     // Before rte thread registration, rte_thread_id is an invalid
    ///     // value, which is u32::MAX.
    ///     let rte_thread_id = unsafe { ffi::rte_lcore_id_() };
    ///     assert_eq!(rte_thread_id, u32::MAX);
    ///     // After rte thread registration, rte_thread_id is a value that
    ///     // is smaller than u32::MAX.
    ///     let rte_thread_id = service().register_as_rte_thread().unwrap();
    ///     assert_eq!(rte_thread_id, unsafe { ffi::rte_lcore_id_() });
    ///     assert_eq!(rte_thread_id < u32::MAX, true);
    /// });
    /// jh.join().unwrap();
    /// service().graceful_cleanup().unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// It returns [`DpdkError`] if we can't register the thread as a eal
    /// thread.
    pub fn register_as_rte_thread(&self) -> Result<u32> {
        let _inner = self.try_lock()?;

        unsafe {
            let res = ffi::rte_thread_register();
            if res != 0 {
                DpdkError::ffi_err(ffi::rte_errno_(), "fail to register rte thread").to_err()
            } else {
                Ok(ffi::rte_lcore_id_())
            }
        }
    }

    /// Check which [`Lcore`] that the current thread is bound to.
    ///
    /// If the current thread is not bound to a lcore, it returns `None`.
    pub fn current_lcore(&self) -> Option<Lcore> {
        Lcore::current()
    }
}

// Mempool related APIs
impl DpdkService {
    /// Allocate a new dpdk mempool.
    ///
    /// The input parameters are:
    ///
    /// - `name`: name of the mempool, must be unique, duplicated mempool name
    ///   cause allocation failure.
    ///
    /// - `n`: the total number of mbufs that this mempool contains.
    ///
    /// - `cache_size`: the total number of mbufs that the thread-local cache
    ///   contains. To use the thread-local mempool cache, the thread must be
    ///   registered as a eal thread ([`DpdkService::register_as_rte_thread`]).
    ///
    /// - `data_room_size`: the total number of bytes allocated to each mbuf for
    ///   storing data. Note that the initial usable byte length of each
    ///   newly-allocated mbuf will be [`crate::constant::MBUF_HEADROOM_SIZE`]
    ///   bytes shorter than `data_room_size`. Because dpdk mempool
    ///   automatically consumes [`crate::constant::MBUF_HEADROOM_SIZE`] bytes
    ///   at the start of each mbuf upon allocation. These consumed bytes can be
    ///   used to prepend protocol headers to the mbuf.
    ///
    /// - `socket_id`: indicate the socket that the mempool is allocated on. If
    ///   `socket_id` is set to `-1`, it means that numa is ignored and dpdk
    ///   will select a default socket id.
    ///
    /// This method is a safe wrapper for
    /// [`ffi::rte_pktmbuf_pool_create`], which takes an additional
    /// parameter `priv_size`. We just ignore `priv_size` by setting it to 0.
    ///
    /// # Examples
    /// ```rust
    /// use rpkt_dpdk::{constant, service, DpdkOption};
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init()
    ///     .unwrap();
    /// {
    ///     let mp = service()
    ///         .mempool_alloc("mp", 128, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
    ///         .unwrap();
    ///     let mbuf = mp.try_alloc().unwrap();
    ///     assert_eq!(mbuf.capacity(), 2048);
    ///     assert_eq!(mbuf.front_capacity(), constant::MBUF_HEADROOM_SIZE as usize);
    /// }
    /// service().graceful_cleanup().unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// It returns [`DpdkError`] if the mempool allocation fails.
    pub fn mempool_alloc<S: AsRef<str>>(
        &self,
        name: S,
        n: u32,
        cache_size: u32,
        data_room_size: u16,
        socket_id: i32,
    ) -> Result<Mempool> {
        let mut inner = self.try_lock()?;

        // dpdk can only allocate mempool on primary process
        if !inner.is_primary {
            DpdkError::service_err("can not allocate memory pool on secondary process").to_err()?
        }

        // create the mempool with correct name
        if inner.mpools.contains_key(name.as_ref()) {
            DpdkError::service_err(format!("mempool {} already exists", name.as_ref())).to_err()?
        }
        let cname = CString::new(name.as_ref()).map_err(|_| {
            DpdkError::service_err(format!("invalid mempool name {}", name.as_ref()))
        })?;
        let raw = unsafe {
            ffi::rte_pktmbuf_pool_create(
                cname.as_bytes_with_nul().as_ptr() as *const c_char,
                n,
                cache_size,
                0,
                data_room_size,
                socket_id,
            )
        };

        // recorded the created mempool in internal states
        let ptr = std::ptr::NonNull::new(raw).ok_or_else(|| {
            DpdkError::ffi_err(
                unsafe { ffi::rte_errno_() },
                format!(
                    "fail to allocate mempool with {n} items (item size = {data_room_size} bytes)"
                ),
            )
        })?;
        let mempool = Mempool::new(ptr);
        inner
            .mpools
            .insert(name.as_ref().to_string(), mempool.clone());

        Ok(mempool)
    }

    /// Try to acquire an instance of the mempool with name `name`.
    ///
    /// [`Mempool`] is modeled as an atomic shared pointer, so mempool itself
    /// can be copied across different thread. The `DpdkService` always kept
    /// a copy of each allocated mempool. So we can also acquire the mempool
    /// instance from the `DpdkService`.
    ///
    /// # Examples
    /// ```rust
    /// use rpkt_dpdk::{constant, service, DpdkOption};
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init()
    ///     .unwrap();
    /// service()
    ///     .mempool_alloc("mp", 128, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
    ///     .unwrap();
    /// let jh = std::thread::spawn(|| {
    ///     let mp = service().mempool("mp").unwrap();
    ///     let mbuf = mp.try_alloc().unwrap();
    ///     assert_eq!(mbuf.capacity(), 2048);
    ///     assert_eq!(mbuf.front_capacity(), constant::MBUF_HEADROOM_SIZE as usize);
    /// });
    /// jh.join().unwrap();
    /// service().graceful_cleanup().unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// It returns [`DpdkError`] if we can acquire the mempool instance.
    pub fn mempool(&self, name: &str) -> Result<Mempool> {
        let inner = self.try_lock()?;

        // dpdk can only allocate mempool on primary process
        if !inner.is_primary {
            DpdkError::service_err("can not safely get memory pool on secondary process")
                .to_err()?
        }

        let mp = inner
            .mpools
            .get(name)
            .ok_or(DpdkError::service_err(format!("no mempool named {name}")))?;
        Ok(mp.clone())
    }

    /// Deallocate the mempool with name `name`.
    ///
    /// This method is a safe wrapper for [`ffi::rte_mempool_free`].
    ///
    /// However, in order for the deallocation to succeed, the caller must
    /// ensure that the mempool is not in use.
    ///
    /// `rpkt_dpdk` relies on reference counting to track the availability of
    /// different kinds of resources. In terms of mempool, we must ensure
    /// the following 2 conditions are met:
    ///
    /// - All the [`Mempool`] instances have been dropped, leaving the internal
    ///   atomic value to be 1 (`DpdkService` keeps an internal mempool
    ///   instance). Also note that each [`RxQueue`] of the initialized dpdk
    ///   port also holds an internal mempool instance. So make sure to close
    ///   these ports prior to deallocating the mempool.
    ///
    /// - All the mbufs allocated from this mempool have been dropped and
    ///   mempool is full. Dpdk mempool tracks the number of unallocated mbufs,
    ///   we can check this value to determine whether the mempool is full.
    ///
    /// # Examples
    /// ```rust
    /// use rpkt_dpdk::{constant, service, DpdkOption};
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init()
    ///     .unwrap();
    /// let mbuf;
    /// {
    ///     let mp = service()
    ///         .mempool_alloc("mp", 128, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
    ///         .unwrap();
    ///     // Can't deallocate mempool "mp", because the `mp` instance is still alive.
    ///     assert_eq!(service().mempool_free("mp").is_err(), true);
    ///     mbuf = mp.try_alloc().unwrap();
    /// }
    /// // Can't deallocate mempool "mp", because `mbuf` is alive, so the mempool is not full.
    /// assert_eq!(service().mempool_free("mp").is_err(), true);
    /// drop(mbuf);
    /// // The mbuf is not in use, we can succefully drop this mempool.
    /// assert_eq!(service().mempool_free("mp").is_ok(), true);
    /// service().graceful_cleanup().unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// It returns [`DpdkError`] if we can not deallocate the mempool, i.e. the
    /// mempool is still in use.
    pub fn mempool_free(&self, name: &str) -> Result<()> {
        let mut inner = self.try_lock()?;
        inner.do_mempool_free(name)
    }
}

// Port related APIs
impl DpdkService {
    /// Get the total number of available ports on the current machine.
    ///
    /// This is a wrapper for [`ffi::rte_eth_dev_count_avail`].
    ///
    /// # Errors
    ///
    /// It returns [`DpdkError`] if the query fails.
    pub fn eth_dev_count_avail(&self) -> Result<u16> {
        let _inner = self.try_lock()?;
        unsafe { Ok(ffi::rte_eth_dev_count_avail()) }
    }

    /// Get the device info of the corresponding port with `port_id`.
    ///
    /// Dpdk's `rte_eth_dev_info` contains a lot of information, we just extract
    /// useful information and store it in the returned [`DevInfo`].
    ///
    /// # Errors
    ///
    /// It returns [`DpdkError`] if we can't get the device info with `port_id`.
    pub fn dev_info(&self, port_id: u16) -> Result<DevInfo> {
        let inner = self.try_lock()?;

        if !inner.is_primary {
            // For some NIC device, like Huawei's SP670 with hinic3 driver, calling
            // rte_eth_dev_info_get on secondary process results in segfault.
            DpdkError::service_err(
                "dpdk service disallow calling rte_eth_dev_info_get on secondary process",
            )
            .to_err()?
        }

        let mut dev_info: ffi::rte_eth_dev_info = unsafe { std::mem::zeroed() };
        let res = unsafe {
            ffi::rte_eth_dev_info_get(port_id, &mut dev_info as *mut ffi::rte_eth_dev_info)
        };
        if res != 0 {
            return DpdkError::ffi_err(
                res,
                format!("fail to get rte_eth_dev_info for port {port_id}"),
            )
            .to_err();
        }

        let socket_id = unsafe { ffi::rte_eth_dev_socket_id(port_id) };
        if socket_id < 0 {
            return DpdkError::ffi_err(res, format!("fail to get socket id for port {port_id}"))
                .to_err();
        }

        let mut eth_addr: ffi::rte_ether_addr = unsafe { std::mem::zeroed() };
        let res =
            unsafe { ffi::rte_eth_macaddr_get(port_id, &mut eth_addr as *mut ffi::rte_ether_addr) };
        if res != 0 {
            return DpdkError::ffi_err(res, format!("fail to get mac addrress for port {port_id}"))
                .to_err();
        }

        Ok(DevInfo {
            port_id,
            socket_id: socket_id as u32,
            started: false,
            mac_addr: eth_addr.addr_bytes,
            raw: dev_info,
        })
    }

    /// Configure and start the port with `port_id`.
    ///
    /// The input parameters are:
    ///
    /// - `port_id`: the port to initialize
    ///
    /// - `eth_conf`: configuration paramter for the port. [`EthConf`] is a
    ///   simplified version of [`ffi::rte_eth_conf`].
    ///
    /// - `rxq_confs`: configuration parameters for rx queues. Each [`RxqConf`]
    ///   in the list with index `i` is used to initialize rx queue `i`.
    ///
    /// - `txq_confs`: configuration parameters for tx queues. Each [`TxqConf`]
    ///   in the list with index `i` is used to initialize tx queue `i`.
    ///
    /// This method fuses 5 standard steps to initialize the dpdk port into a
    /// single function call:
    ///
    /// - calling [`ffi::rte_eth_dev_configure`] to configure the port. This
    ///   will configure the number of tx/rx queues and apply an initial port
    ///   configuration ([`ffi::rte_eth_conf`]), which contains basic hardware
    ///   offloading functionalities.
    ///
    /// - calling [`ffi::rte_eth_rx_queue_setup`] to setup each rx queue. This
    ///   will setup the descriptor number, socket id and the receiving mempool
    ///   for the rxq.
    ///
    /// - calling [`ffi::rte_eth_tx_queue_setup`] to setup each tx queue. This
    ///   will setup the descriptor number, socket id for the txq.
    ///
    /// - enabling device promiscuous depending on the configuration
    ///
    /// - starting the port with [`ffi::rte_eth_dev_start`].
    ///
    /// # Examples
    /// ```rust
    /// use arrayvec::ArrayVec;
    /// use rpkt_dpdk::{constant, service, DpdkOption, EthConf, RxqConf, TxqConf};
    ///
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init()
    ///     .unwrap();
    ///
    /// // create a mempool
    /// service()
    ///     .mempool_alloc("mp", 2048, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
    ///     .unwrap();
    ///
    /// // create the eth conf
    /// let dev_info = service().dev_info(0).unwrap();
    /// let mut eth_conf = EthConf::new();
    /// // enable all rx_offloads
    /// eth_conf.rx_offloads = dev_info.rx_offload_capa();
    /// // enable all tx_offloads
    /// eth_conf.tx_offloads = dev_info.tx_offload_capa();
    /// // setup the rss hash function
    /// eth_conf.rss_hf = dev_info.flow_type_rss_offloads();
    /// // setup rss_hash_key
    /// if dev_info.hash_key_size() == 40 {
    ///     eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_40B.into();
    /// } else if dev_info.hash_key_size() == 52 {
    ///     eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_52B.into();
    /// } else {
    ///     panic!("unsupported hash key size: {}", dev_info.hash_key_size())
    /// };
    ///
    /// // create rxq conf and txq conf
    /// let rxq_conf = RxqConf::new(512, 0, "mp");
    /// let txq_conf = TxqConf::new(512, 0);
    /// // create 2 rx/tx queues
    /// let rxq_confs: Vec<RxqConf> = std::iter::repeat_with(|| rxq_conf.clone())
    ///     .take(2 as usize)
    ///     .collect();
    /// let txq_confs: Vec<TxqConf> = std::iter::repeat_with(|| txq_conf.clone())
    ///     .take(2 as usize)
    ///     .collect();
    ///
    /// // initialize the port
    /// let res = service().dev_configure_and_start(0, &eth_conf, &rxq_confs, &txq_confs);
    /// assert_eq!(res.is_ok(), true);
    ///
    /// {
    ///     // receive and send packets
    ///     let mut rxq = service().rx_queue(0, 1).unwrap();
    ///     let mut txq = service().tx_queue(0, 1).unwrap();
    ///     let mut ibatch = ArrayVec::<_, 32>::new();
    ///     rxq.rx(&mut ibatch);
    ///     txq.tx(&mut ibatch);
    /// }
    ///
    /// // deallocate all the resources and shutdown dpdk
    /// service().graceful_cleanup().unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// It returns [`DpdkError`] if we can't start port `port_id`.
    pub fn dev_configure_and_start(
        &self,
        port_id: u16,
        eth_conf: &EthConf,
        rxq_confs: &Vec<RxqConf>,
        txq_confs: &Vec<TxqConf>,
    ) -> Result<()> {
        let mut inner = self.try_lock()?;

        if !inner.is_primary {
            // dpdk disallows configurng and starting eth device on secondary process, we
            // manually enforce this in dpdk service api.
            DpdkError::service_err("can not configure and start eth device on secondary process")
                .to_err()?
        }

        // we can only configure and start the port once.
        if inner.ports.get(&port_id).is_some() {
            return DpdkError::service_err(format!(
                "port {port_id} already configured and started"
            ))
            .to_err();
        }

        // queue id is saved in u16, so check the configured queue sizes.
        if rxq_confs.len() > 65535 || txq_confs.len() > 65535 {
            return DpdkError::service_err("too many rx/tx queues").to_err();
        }

        // check the mempool associated with each rxq
        for (rxq_id, rxq_conf) in rxq_confs.iter().enumerate() {
            if inner.mpools.get(rxq_conf.mp_name.as_str()).is_none() {
                return DpdkError::service_err(format!(
                    "mempool {} for rxq {rxq_id} is not allocated",
                    &rxq_conf.mp_name
                ))
                .to_err();
            }
        }

        // configure the device.
        // Safety: The `rte_eth_dev_configure` only copies the payload.
        let rte_eth_conf = unsafe { eth_conf.rte_eth_conf(rxq_confs.len() as u16) };
        let res = unsafe {
            ffi::rte_eth_dev_configure(
                port_id,
                rxq_confs.len() as u16,
                txq_confs.len() as u16,
                &rte_eth_conf as *const ffi::rte_eth_conf,
            )
        };
        if res != 0 {
            return DpdkError::ffi_err(res, format!("fail to configure eth dev {port_id}"))
                .to_err();
        }

        // setup the rx queues
        let rxqs_with_mp = rxq_confs
            .iter()
            .enumerate()
            .map(|(rx_queue_id, rxq_conf)| unsafe {
                let mp = inner.mpools.get(&rxq_conf.mp_name).unwrap();

                // Safety: rxq lives as long as mp
                let res = ffi::rte_eth_rx_queue_setup(
                    port_id,
                    rx_queue_id as u16,
                    rxq_conf.nb_rx_desc,
                    rxq_conf.socket_id,
                    // here, use nullptr for rte_eth_rx_conf
                    // dpdk will apply the default rte_eth_rxconf of
                    // the device.
                    std::ptr::null(),
                    mp.as_ptr() as *mut ffi::rte_mempool,
                );

                if res != 0 {
                    DpdkError::ffi_err(res, format!("fail to setup rx queue {rx_queue_id}"))
                        .to_err()
                } else {
                    Ok((RxQueue::new(port_id, rx_queue_id as u16), mp.clone()))
                }
            })
            .collect::<Result<Vec<(RxQueue, Mempool)>>>()?;

        // setup the tx queues
        let txqs = txq_confs
            .iter()
            .enumerate()
            .map(|(tx_queue_id, txq_conf)| unsafe {
                let res = ffi::rte_eth_tx_queue_setup(
                    port_id,
                    tx_queue_id as u16,
                    txq_conf.nb_tx_desc,
                    txq_conf.socket_id,
                    // same as the rxq, we pass nullptr to let
                    // the dpdk use the default rte_eth_txconf.
                    std::ptr::null(),
                );

                if res != 0 {
                    DpdkError::ffi_err(res, format!("fail to setup tx queue {tx_queue_id}"))
                        .to_err()
                } else {
                    Ok(TxQueue::new(port_id, tx_queue_id as u16))
                }
            })
            .collect::<Result<Vec<TxQueue>>>()?;

        let res = match eth_conf.enable_promiscuous {
            true => unsafe { ffi::rte_eth_promiscuous_enable(port_id) },
            false => unsafe { ffi::rte_eth_promiscuous_disable(port_id) },
        };
        if res != 0 {
            return DpdkError::ffi_err(res, "fail to enable promiscuous").to_err();
        }

        // start the device
        let res = unsafe { ffi::rte_eth_dev_start(port_id) };
        if res != 0 {
            return DpdkError::ffi_err(res, "fail to start eth dev").to_err();
        }

        // save the port in the internal state
        let port = Port::new(rxqs_with_mp, txqs, StatsQuery::new(port_id));
        inner.ports.insert(port_id, port);

        Ok(())
    }

    /// Try to acquire an instance of the rx queue with queue id `qid` for port
    /// `port_id`.
    ///
    /// [`RxQueue`] is modeled as a singleton, indicating that there can only be
    /// one rx queue for a given `qid`. This is because it is highly possible
    /// that dpdk provides no multi-thread concurrency control for accessing the
    /// same rx queue.
    ///
    /// `DpdkService` ensures this using atomic reference counting.
    /// `DpdkService` maintains a atomic shared pointer to the rx queue
    /// instance. Whenever `rx_queue` is called, it checks whether the reference
    /// count of the requested rx queue. If it is larger than 1, then `rx_queue`
    /// returns an error.
    ///
    /// # Examples    
    /// ```rust
    /// use rpkt_dpdk::{constant, service, DpdkOption, EthConf, RxqConf, TxqConf};
    ///
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init()
    ///     .unwrap();
    ///
    /// // create a mempool
    /// service()
    ///     .mempool_alloc("mp", 2048, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
    ///     .unwrap();
    ///
    /// // create the eth conf
    /// let dev_info = service().dev_info(0).unwrap();
    /// let mut eth_conf = EthConf::new();
    /// // enable all rx_offloads
    /// eth_conf.rx_offloads = dev_info.rx_offload_capa();
    /// // enable all tx_offloads
    /// eth_conf.tx_offloads = dev_info.tx_offload_capa();
    /// // setup the rss hash function
    /// eth_conf.rss_hf = dev_info.flow_type_rss_offloads();
    /// // setup rss_hash_key
    /// if dev_info.hash_key_size() == 40 {
    ///     eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_40B.into();
    /// } else if dev_info.hash_key_size() == 52 {
    ///     eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_52B.into();
    /// } else {
    ///     panic!("unsupported hash key size: {}", dev_info.hash_key_size())
    /// };
    ///
    /// // create rxq conf and txq conf
    /// let rxq_conf = RxqConf::new(512, 0, "mp");
    /// let txq_conf = TxqConf::new(512, 0);
    /// // create 2 rx/tx queues
    /// let rxq_confs: Vec<RxqConf> = std::iter::repeat_with(|| rxq_conf.clone())
    ///     .take(2 as usize)
    ///     .collect();
    /// let txq_confs: Vec<TxqConf> = std::iter::repeat_with(|| txq_conf.clone())
    ///     .take(2 as usize)
    ///     .collect();
    ///
    /// // initialize the port
    /// let res = service().dev_configure_and_start(0, &eth_conf, &rxq_confs, &txq_confs);
    /// assert_eq!(res.is_ok(), true);
    ///
    /// let jh = std::thread::spawn(|| {
    ///     let res = service().rx_queue(0, 1);
    ///     assert_eq!(res.is_ok(), true);
    ///
    ///     // we can only acquire a single rx queue
    ///     let res = service().rx_queue(0, 1);
    ///     assert_eq!(res.is_ok(), false);
    /// });
    /// jh.join().unwrap();
    ///
    /// // deallocate all the resources and shutdown dpdk
    /// service().graceful_cleanup().unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// It returns [`DpdkError`] if we can't acquire the rx queue.
    pub fn rx_queue(&self, port_id: u16, qid: u16) -> Result<RxQueue> {
        let inner = self.try_lock()?;

        if !inner.is_primary {
            DpdkError::service_err("can use safe api to create the rx queue on secondary process")
                .to_err()?
        }

        let port = inner
            .ports
            .get(&port_id)
            .ok_or(DpdkError::service_err("invalid port id"))?;
        port.rx_queue(qid)
    }

    /// Try to acquire an instance of the tx queue with queue id `qid` for port
    /// `port_id`.
    ///
    /// [`TxQueue`] is modeled similar as [`RxQueue`]. Refer to the doc of
    /// [`RxQueue`] for details.
    ///
    /// # Examples
    /// ```rust
    /// use rpkt_dpdk::{constant, service, DpdkOption, EthConf, RxqConf, TxqConf};
    ///
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init()
    ///     .unwrap();
    ///
    /// // create a mempool
    /// service()
    ///     .mempool_alloc("mp", 2048, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
    ///     .unwrap();
    ///
    /// // create the eth conf
    /// let dev_info = service().dev_info(0).unwrap();
    /// let mut eth_conf = EthConf::new();
    /// // enable all rx_offloads
    /// eth_conf.rx_offloads = dev_info.rx_offload_capa();
    /// // enable all tx_offloads
    /// eth_conf.tx_offloads = dev_info.tx_offload_capa();
    /// // setup the rss hash function
    /// eth_conf.rss_hf = dev_info.flow_type_rss_offloads();
    /// // setup rss_hash_key
    /// if dev_info.hash_key_size() == 40 {
    ///     eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_40B.into();
    /// } else if dev_info.hash_key_size() == 52 {
    ///     eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_52B.into();
    /// } else {
    ///     panic!("unsupported hash key size: {}", dev_info.hash_key_size())
    /// };
    ///
    /// // create rxq conf and txq conf
    /// let rxq_conf = RxqConf::new(512, 0, "mp");
    /// let txq_conf = TxqConf::new(512, 0);
    /// // create 2 rx/tx queues
    /// let rxq_confs: Vec<RxqConf> = std::iter::repeat_with(|| rxq_conf.clone())
    ///     .take(2 as usize)
    ///     .collect();
    /// let txq_confs: Vec<TxqConf> = std::iter::repeat_with(|| txq_conf.clone())
    ///     .take(2 as usize)
    ///     .collect();
    ///
    /// // initialize the port
    /// let res = service().dev_configure_and_start(0, &eth_conf, &rxq_confs, &txq_confs);
    /// assert_eq!(res.is_ok(), true);
    ///
    /// let jh = std::thread::spawn(|| {
    ///     let res = service().tx_queue(0, 1);
    ///     assert_eq!(res.is_ok(), true);
    ///
    ///     // we can only acquire a single rx queue
    ///     let res = service().tx_queue(0, 1);
    ///     assert_eq!(res.is_ok(), false);
    /// });
    /// jh.join().unwrap();
    ///
    /// // deallocate all the resources and shutdown dpdk
    /// service().graceful_cleanup().unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// It returns [`DpdkError`] if we can't acquire the rx queue.
    pub fn tx_queue(&self, port_id: u16, qid: u16) -> Result<TxQueue> {
        let inner = self.try_lock()?;

        if !inner.is_primary {
            DpdkError::service_err("can use safe api to create the tx queue on secondary process")
                .to_err()?
        }

        let port = inner
            .ports
            .get(&port_id)
            .ok_or(DpdkError::service_err("invalid port id"))?;
        port.tx_queue(qid)
    }

    /// Try to acquire an instance of [`StatsQuery`], with which we can query
    /// the statistics of port `port_id`.
    ///
    /// [`StatsQuery`] is modeled similaly as [`RxQueue`]. Refer to the doc of
    /// [`RxQueue`] for details.
    ///
    /// # Examples
    /// ```rust
    /// use rpkt_dpdk::{constant, rdtsc, service, DpdkOption, EthConf, RxqConf, TxqConf};
    ///
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init()
    ///     .unwrap();
    ///
    /// // create a mempool
    /// service()
    ///     .mempool_alloc("mp", 2048, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
    ///     .unwrap();
    ///
    /// // create the eth conf
    /// let dev_info = service().dev_info(0).unwrap();
    /// let mut eth_conf = EthConf::new();
    /// // enable all rx_offloads
    /// eth_conf.rx_offloads = dev_info.rx_offload_capa();
    /// // enable all tx_offloads
    /// eth_conf.tx_offloads = dev_info.tx_offload_capa();
    /// // setup the rss hash function
    /// eth_conf.rss_hf = dev_info.flow_type_rss_offloads();
    /// // setup rss_hash_key
    /// if dev_info.hash_key_size() == 40 {
    ///     eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_40B.into();
    /// } else if dev_info.hash_key_size() == 52 {
    ///     eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_52B.into();
    /// } else {
    ///     panic!("unsupported hash key size: {}", dev_info.hash_key_size())
    /// };
    ///
    /// // create rxq conf and txq conf
    /// let rxq_conf = RxqConf::new(512, 0, "mp");
    /// let txq_conf = TxqConf::new(512, 0);
    /// // create 2 rx/tx queues
    /// let rxq_confs: Vec<RxqConf> = std::iter::repeat_with(|| rxq_conf.clone())
    ///     .take(2 as usize)
    ///     .collect();
    /// let txq_confs: Vec<TxqConf> = std::iter::repeat_with(|| txq_conf.clone())
    ///     .take(2 as usize)
    ///     .collect();
    ///
    /// // initialize the port
    /// let res = service().dev_configure_and_start(0, &eth_conf, &rxq_confs, &txq_confs);
    /// assert_eq!(res.is_ok(), true);
    ///
    /// {
    ///     let mut stat_query = service().stats_query(0).unwrap();
    ///
    ///     // test the basic cpu frequecy for the rdtsc counter
    ///     let base_freq = rdtsc::BaseFreq::new();
    ///     // get the current dpdk port stats
    ///     let curr_stats = stat_query.query();
    ///     // wait for 1s using rdtsc
    ///     let tick_in_1s = rdtsc::rdtsc() + base_freq.sec_to_cycles(1.0);
    ///     while rdtsc::rdtsc() < tick_in_1s {}
    ///     // get the new stats after 1s
    ///     let new_stats = stat_query.query();
    ///     println!("{} pps", new_stats.ipackets() - curr_stats.ipackets());
    /// }
    ///
    /// // deallocate all the resources and shutdown dpdk
    /// service().graceful_cleanup().unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// It returns [`DpdkError`] if we can't acquire the query instance for port
    /// `port_id`.
    pub fn stats_query(&self, port_id: u16) -> Result<StatsQuery> {
        let inner = self.try_lock()?;

        if !inner.is_primary {
            DpdkError::service_err("can use safe api for port stats query on secondary process")
                .to_err()?
        }

        let port = inner
            .ports
            .get(&port_id)
            .ok_or(DpdkError::service_err("invalid port id"))?;
        port.stats_query()
    }

    /// Stop and close the port with `port_id`.
    ///
    /// This method fuses [`ffi::rte_eth_dev_stop`] and
    /// [`ffi::rte_eth_dev_close`] together, causing a complete shutdown of the
    /// port.
    ///
    /// However, in order to successfully shutdown the port, the caller must
    /// ensure that the port is no longer in use.
    ///
    /// Similar to [`Mempool`], the port is also managed via reference counting.
    /// `DpdkService` keeps reference count for all the rx/tx queues and the
    /// stats query. The caller must ensure that there are no instances of
    /// [`RxQueue`], [`TxQueue`] and [`StatsQuery`] alive.
    ///
    /// # Examples
    /// ```rust
    /// use rpkt_dpdk::{constant, service, DpdkOption, EthConf, RxqConf, TxqConf};
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix app".split(" "))
    ///     .init()
    ///     .unwrap();
    ///
    /// // create a mempool
    /// service()
    ///     .mempool_alloc("mp", 2048, 16, constant::MBUF_HEADROOM_SIZE + 2048, -1)
    ///     .unwrap();
    ///
    /// // create the eth conf
    /// let dev_info = service().dev_info(0).unwrap();
    /// let mut eth_conf = EthConf::new();
    /// // enable all rx_offloads
    /// eth_conf.rx_offloads = dev_info.rx_offload_capa();
    /// // enable all tx_offloads
    /// eth_conf.tx_offloads = dev_info.tx_offload_capa();
    /// // setup the rss hash function
    /// eth_conf.rss_hf = dev_info.flow_type_rss_offloads();
    /// // setup rss_hash_key
    /// if dev_info.hash_key_size() == 40 {
    ///     eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_40B.into();
    /// } else if dev_info.hash_key_size() == 52 {
    ///     eth_conf.rss_hash_key = constant::DEFAULT_RSS_KEY_52B.into();
    /// } else {
    ///     panic!("unsupported hash key size: {}", dev_info.hash_key_size())
    /// };
    ///
    /// // create rxq conf and txq conf
    /// let rxq_conf = RxqConf::new(512, 0, "mp");
    /// let txq_conf = TxqConf::new(512, 0);
    /// // create 2 rx/tx queues
    /// let rxq_confs: Vec<RxqConf> = std::iter::repeat_with(|| rxq_conf.clone())
    ///     .take(2 as usize)
    ///     .collect();
    /// let txq_confs: Vec<TxqConf> = std::iter::repeat_with(|| txq_conf.clone())
    ///     .take(2 as usize)
    ///     .collect();
    ///
    /// // initialize the port
    /// let res = service().dev_configure_and_start(0, &eth_conf, &rxq_confs, &txq_confs);
    /// assert_eq!(res.is_ok(), true);
    ///
    /// {
    ///     let _txq = service().tx_queue(0, 1).unwrap();
    ///     // txq is alive, we can't close the port
    ///     let res = service().dev_stop_and_close(0);
    ///     assert_eq!(res.is_err(), true);
    /// }
    ///
    /// {
    ///     let _rxq = service().rx_queue(0, 1).unwrap();
    ///     // rxq is alive, we can't close the port
    ///     let res = service().dev_stop_and_close(0);
    ///     assert_eq!(res.is_err(), true);
    /// }
    ///
    /// {
    ///     let _stats_query = service().stats_query(0).unwrap();
    ///     // rxq is alive, we can't close the port
    ///     let res = service().dev_stop_and_close(0);
    ///     assert_eq!(res.is_err(), true);
    /// }
    ///
    /// // txq/rxq/stats_query are all dropped, we can successfully shutdown the port.
    /// let res = service().dev_stop_and_close(0);
    /// assert_eq!(res.is_ok(), true);
    ///
    /// service().graceful_cleanup().unwrap();

    /// ```
    /// 
    /// # Errors
    ///
    /// It returns [`DpdkError`] if we fail to shutdown port `port_id`.
    pub fn dev_stop_and_close(&self, port_id: u16) -> Result<()> {
        let mut inner = self.try_lock()?;
        inner.do_dev_stop_and_close(port_id)
    }
}

impl DpdkService {
    /// Check whether the current process is a dpdk primary process.
    ///
    /// Dpdk has primary process and secondary process. The primary process
    /// allocates and maintains all the resources on the shared memory.
    /// The secondary process will be attached to a primary process, and uses
    /// the fd descriptor exposed by the primary process to acquire important
    /// memory addresses that the primary process allocates on the shared
    /// memory.
    ///
    /// In theory, the secondary process can not allocate any resources, it can
    /// only acquire the resources pre-allocated from the primary process.
    ///
    /// Users can configure any eal arguments using [`DpdkOption`]. So they can
    /// create a secondary dpdk processs using `rpkt_dpdk`. However, most of
    /// the public methods of `DpdkService` will fail on the secondary dpdk
    /// process.
    ///
    /// `is_primary_process` provides a way for the user to query whether the
    /// current process is a secondary dpdk process.
    ///
    /// # Examples
    /// ```rust
    /// use rpkt_dpdk::{service, DpdkOption};
    ///
    /// // Launch examples/mempool_primary.rs first.
    /// // Create a secondary dpdk process and attach to the
    /// // primary process launched from the example.
    /// DpdkOption::new()
    ///     .args("-n 4 --file-prefix mempool_primary --proc-type=secondary".split(" "))
    ///     .init()
    ///     .unwrap();
    ///
    /// // This process is a secondary process
    /// assert_eq!(service().is_primary_process().unwrap(), false);
    /// {
    ///     // On the secondary process, we can't allocate important resources
    ///     let res = service().mempool_alloc("mp", 127, 0, 200, -1);
    ///     assert_eq!(res.is_err(), true);
    ///
    ///     // However, we can obtain the mempool allocated by the primary process
    ///     let res = unsafe { service().assume_mempool("mp_on_primary") };
    ///     assert_eq!(res.is_ok(), true);
    /// }
    ///
    /// service().graceful_cleanup().unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// It returns [`DpdkError`] if the `DpdkService` has been shutdown by
    /// [`DpdkService::graceful_cleanup`].
    pub fn is_primary_process(&self) -> Result<bool> {
        Ok(self.try_lock()?.is_primary)
    }

    pub fn graceful_cleanup(&self) -> Result<()> {
        let mut inner = self.try_lock()?;

        // we only do graceful cleanup for primary process
        if inner.is_primary {
            // first, deallocate the ports
            let port_ids: Vec<u16> = inner.ports.keys().map(|id| *id).collect();
            for port_id in port_ids {
                inner.do_dev_stop_and_close(port_id)?;
            }

            // then check the mpools
            let names: Vec<String> = inner.mpools.keys().map(|s| s.clone()).collect();
            for name in names {
                inner.do_mempool_free(&name)?;
            }
        }

        unsafe { ffi::rte_eal_cleanup() };
        inner.started = false;

        Ok(())
    }

    pub unsafe fn assume_mempool(&self, name: &str) -> Result<Mempool> {
        let _inner = self.try_lock()?;

        let cname = CString::new(name)
            .map_err(|_| DpdkError::service_err(format!("invalid mempool name {name}")))?;

        // secondary process queries mempool from dpdk
        let raw =
            unsafe { ffi::rte_mempool_lookup(cname.as_bytes_with_nul().as_ptr() as *const c_char) };
        let ptr = std::ptr::NonNull::new(raw).ok_or_else(|| {
            DpdkError::ffi_err(
                unsafe { ffi::rte_errno_() },
                format!("fail to lookup mempool {name}, make sure that it has been allocated"),
            )
        })?;
        Ok(Mempool::new(ptr))
    }

    pub unsafe fn assume_rx_queue(&self, port_id: u16, qid: u16) -> Result<RxQueue> {
        let _inner = self.try_lock()?;
        Ok(RxQueue::new(port_id, qid))
    }

    pub unsafe fn assume_tx_queue(&self, port_id: u16, qid: u16) -> Result<TxQueue> {
        let _inner = self.try_lock()?;
        Ok(TxQueue::new(port_id, qid))
    }

    pub unsafe fn assume_stats_query(&self, port_id: u16) -> Result<StatsQuery> {
        let _inner = self.try_lock()?;
        Ok(StatsQuery::new(port_id))
    }

    fn try_lock(&self) -> Result<MutexGuard<'_, ServiceInner>> {
        let inner = self.service.lock().unwrap();
        if !inner.started {
            DpdkError::service_err("service is shutdown").to_err()
        } else {
            Ok(inner)
        }
    }
}

// Holds all the internal states of dpdk
struct ServiceInner {
    started: bool,
    is_primary: bool,
    lcores: LcoreContext,
    mpools: HashMap<String, Mempool>,
    ports: HashMap<u16, Port>,
}

impl ServiceInner {
    fn do_mempool_free(&mut self, name: &str) -> Result<()> {
        // dpdk can only deallocate mempool on primary process
        if !self.is_primary {
            DpdkError::service_err("can not deallocate memory pool on secondary process")
                .to_err()?
        }

        let mp = self
            .mpools
            .get_mut(name)
            .ok_or(DpdkError::service_err(format!("no mempool named {name}")))?;

        if !mp.in_use() && mp.full() {
            // We are the sole owner of the mempool and here are no allocated mbufs.
            // We are safe to delete the mempool.
            let mp = self.mpools.remove(name).unwrap();
            unsafe {
                ffi::rte_mempool_free(mp.as_ptr() as *mut ffi::rte_mempool);
            }
            Ok(())
        } else {
            DpdkError::service_err(format!("mempool {name} is in use")).to_err()
        }
    }

    fn do_dev_stop_and_close(&mut self, port_id: u16) -> Result<()> {
        if !self.is_primary {
            DpdkError::service_err("can not stop and close device on secondary process").to_err()?
        }

        let port = self
            .ports
            .get(&port_id)
            .ok_or(DpdkError::service_err(format!("invalid port id {port_id}")))?;

        if !port.can_shutdown() {
            return DpdkError::service_err(format!("port {port_id} is in use")).to_err();
        }

        self.ports.remove(&port_id).unwrap();

        if unsafe { ffi::rte_eth_dev_stop(port_id) } != 0 {
            return Err(DpdkError::service_err(format!(
                "fail to stop the port {port_id}",
            )));
        }

        if unsafe { ffi::rte_eth_dev_close(port_id) } != 0 {
            return Err(DpdkError::service_err(format!(
                "fail to close the port {port_id}",
            )));
        }

        Ok(())
    }
}
