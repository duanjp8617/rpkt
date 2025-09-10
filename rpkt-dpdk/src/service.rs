use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::sync::{Mutex, MutexGuard};

use once_cell::sync::OnceCell;

use crate::conf::*;
use crate::sys as ffi;

use super::error::*;
use super::lcore::{self, *};
use super::mempool::*;
use super::port::*;

pub(crate) static SERVICE: OnceCell<DpdkService> = OnceCell::new();

/// `DpdkOption` contains an eal argument string for initializing dpdk.
///
/// # Default
///
/// By default, `DpdkOption` contains the following argument string:
///
/// "-n 4 --proc-type primary"
///
/// indicating that eal is initialized with 4 memory channels and as a primary
/// process.
pub struct DpdkOption {
    arg_string: String,
}

impl Default for DpdkOption {
    fn default() -> Self {
        Self {
            arg_string: "-c 1 -n 4 --proc-type primary".into(),
        }
    }
}

impl DpdkOption {
    /// Create a new `DpdkOption` with use-defined eal argument string.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rpkt_dpdk::DpdkOption;
    ///
    /// let res = DpdkOption::with_eal_arg("-l 2 -n 4 --file-prefix app1").init();
    /// assert_eq!(res.is_ok(), true);
    /// ```
    pub fn with_eal_arg<S: Into<String>>(arg: S) -> Self {
        Self {
            arg_string: arg.into(),
        }
    }

    /// Initialize dpdk eal using the provided eal argument string.
    ///
    /// After initialization, the global singleton [`DpdkService`] can be
    /// accessed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rpkt_dpdk::DpdkOption;
    ///
    /// let res = DpdkOption::default().init();
    /// assert_eq!(res.is_ok(), true);
    /// ```
    ///
    /// # Errors
    ///
    /// This function returns [`DpdkError`] if initialization fails due to
    /// various reasons.
    pub fn init(self) -> Result<()> {
        SERVICE.get_or_try_init(|| {
            // eal argument requires a prefix
            let mut args: Vec<CString> = vec![CString::new("./prefix").unwrap()];
            // extend `args` with other arguments
            args.extend(
                self.arg_string
                    .split(" ")
                    .map(|arg| CString::new(arg).unwrap()),
            );

            // initialize dpdk with rte_eal_init
            let c_args: Vec<_> = args
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

/// A global singleton providing all the dpdk services.
///
/// The provided dpdk services include:
/// -
pub struct DpdkService {
    service: Mutex<ServiceInner>,
    lcores: Vec<Lcore>,
}

/// Try to acquire a reference to the [`DpdkService`].
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
/// This function panics if  [`DpdkService`] is not correctly initialized.
pub fn service() -> &'static DpdkService {
    match SERVICE.get() {
        Some(handle) => handle,
        None => panic!("dpdk service is not initialized"),
    }
}

impl DpdkService {
    /// Check whether the current process is a dpdk primary process.
    pub fn is_primary_process(&self) -> Result<bool> {
        Ok(self.try_lock()?.is_primary)
    }

    /// Get a list of [`Lcore`] on the current machine.
    ///
    /// The lcore list is collected by analyzing the /sys directory of the linux
    /// file system upon dpdk initialization.
    ///
    /// The returned lcore list is sorted by the lcore id in ascending order.
    pub fn lcores(&self) -> &Vec<Lcore> {
        &self.lcores
    }

    /// Bind the current thread to the lcore indicated by `lcore_id`].
    ///
    /// [`DpdkService`] manages thread binding in its internal state. It
    /// enforces the following invariants:
    /// - Each lcore can only be globally bound once.
    /// - Each thread can only be bound to a single lcore.
    ///
    /// # Errors
    ///
    /// It returns [`DpdkError`] if the thread binding fails.
    pub fn lcore_bind(&self, lcore_id: u32) -> Result<()> {
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
    /// # Errors
    ///
    /// It returns [`DpdkError`] if we can't register the thread as a eal
    /// thread.
    pub fn rte_thread_register(&self) -> Result<u32> {
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

    pub fn mempool_free(&self, name: &str) -> Result<()> {
        let mut inner = self.try_lock()?;
        inner.do_mempool_free(name)
    }

    pub fn mempool(&self, name: &str) -> Result<Mempool> {
        let inner = self.try_lock()?;

        if inner.is_primary {
            // primary process retrieves mempool from internal state
            let mp = inner
                .mpools
                .get(name)
                .ok_or(DpdkError::service_err(format!("no mempool named {name}")))?;
            Ok(mp.clone())
        } else {
            let cname = CString::new(name)
                .map_err(|_| DpdkError::service_err(format!("invalid mempool name {name}")))?;

            // secondary process queries mempool from dpdk
            let raw = unsafe {
                ffi::rte_mempool_lookup(cname.as_bytes_with_nul().as_ptr() as *const c_char)
            };
            let ptr = std::ptr::NonNull::new(raw).ok_or_else(|| {
                DpdkError::ffi_err(
                    unsafe { ffi::rte_errno_() },
                    format!(
                        "fail to lookup mempool {name}, make sure that primary process has allocated this mempool"
                    ),
                )
            })?;
            Ok(Mempool::new(ptr))
        }
    }

    pub fn eth_dev_count_avail(&self) -> Result<u16> {
        let _inner = self.try_lock()?;

        unsafe { Ok(ffi::rte_eth_dev_count_avail()) }
    }

    pub fn dev_info(&self, port_id: u16) -> Result<DevInfo> {
        let inner = self.try_lock()?;

        if !inner.is_primary {
            // For some NIC device, like Huawei's SP670 with hinic3 driver, callilng
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
            eth_addr: eth_addr.addr_bytes,
            raw: dev_info,
        })
    }

    // rte_eth_dev_configure
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
                let mut rxconf: ffi::rte_eth_rxconf = std::mem::zeroed();
                rxconf.rx_thresh.pthresh = rxq_conf.pthresh;

                let mp = inner.mpools.get(&rxq_conf.mp_name).unwrap();

                // Safety: rxq lives as long as mp
                let res = ffi::rte_eth_rx_queue_setup(
                    port_id,
                    rx_queue_id as u16,
                    rxq_conf.nb_rx_desc,
                    rxq_conf.socket_id,
                    &mut rxconf as *mut ffi::rte_eth_rxconf,
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
                let mut txconf: ffi::rte_eth_txconf = std::mem::zeroed();
                txconf.tx_thresh.pthresh = txq_conf.pthresh;

                let res = ffi::rte_eth_tx_queue_setup(
                    port_id,
                    tx_queue_id as u16,
                    txq_conf.nb_tx_desc,
                    txq_conf.socket_id,
                    &mut txconf as *mut ffi::rte_eth_txconf,
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
        let port = Port::new(port_id, rxqs_with_mp, txqs, StatsQuery::new(port_id));
        inner.ports.insert(port_id, port);

        Ok(())
    }

    pub fn dev_stop_and_close(&self, port_id: u16) -> Result<()> {
        let mut inner = self.try_lock()?;
        inner.do_dev_stop_and_close(port_id)
    }

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

    pub fn gracefull_cleanup(&self) -> Result<()> {
        let mut inner = self.try_lock()?;

        if !inner.is_primary {
            // secondary process owns no resources, we can directly shutdown
            unsafe { ffi::rte_eal_cleanup() };
            inner.started = false;
        } else {
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

            unsafe { ffi::rte_eal_cleanup() };
            inner.started = false;
        }

        Ok(())
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

#[cfg(test)]
mod tests {
    #[test]
    fn lcores_doc() {
        use crate::{service, DpdkOption};

        DpdkOption::default().init().unwrap();
        let sorted = service()
            .lcores()
            .iter()
            .map(|lcore| lcore.lcore_id)
            .is_sorted();
        assert_eq!(sorted, true);
    }

    #[test]
    fn lcore_bind_test() {
        use crate::{service, DpdkOption};
        use std::thread;

        DpdkOption::default().init().unwrap();

        // launch 2 threads and bind them to different lores.
        let mut jhs = vec![];
        for i in 0..2 {
            let jh = thread::spawn(move || {
                assert_eq!(service().current_lcore().is_none(), true);
                service().lcore_bind(i).unwrap();
                let lcore = service().current_lcore().unwrap();
                assert_eq!(lcore.lcore_id, i);
            });
            jhs.push(jh);
        }

        for jh in jhs {
            jh.join().unwrap()
        }
    }

    #[test]
    fn rte_thread_register_test() {
        use crate::{service, DpdkOption};
        use std::thread;

        DpdkOption::default().init().unwrap();

        // launch 2 threads bind them to different lores, and register them as eal
        // thread.
        let mut jhs = vec![];
        for i in 0..2 {
            let jh = thread::spawn(move || {
                service().lcore_bind(i).unwrap();
                let rte_lcore_id = service().rte_thread_register().unwrap();
                println!("{rte_lcore_id}");
            });
            jhs.push(jh);
        }

        for jh in jhs {
            jh.join().unwrap()
        }
    }
}
