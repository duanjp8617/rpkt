use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::sync::{Mutex, MutexGuard};

use crate::sys as ffi;
use once_cell::sync::OnceCell;

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

    pub fn mempool_create<S: AsRef<str>>(&self, name: S, conf: &MempoolConf) -> Result<Mempool> {
        let mut inner = self.try_lock()?;

        if inner.mpools.contains_key(name.as_ref()) {
            return DpdkError::service_err("mempool already exists").to_err();
        }

        let mp = Mempool::try_create(name.as_ref().to_string(), conf)?;
        inner.mpools.insert(name.as_ref().to_string(), mp.clone());

        Ok(mp)
    }

    pub fn mempool_free(&self, name: &str) -> Result<()> {
        let mut inner = self.try_lock()?;

        let mp = inner
            .mpools
            .get_mut(name)
            .ok_or(DpdkError::service_err("no such mempool"))?;

        if !mp.in_use() && mp.full() {
            // We are the sole owner of the counter, this also means that
            // we are the sole owner of the PtrWrapper, and we are safe to deallocate it.
            // The mempool to be removed is also full, this means that there are no
            // out-going mbuf pointers.
            let mp = inner.mpools.remove(name).unwrap();
            unsafe { Mempool::delete(mp) }
            Ok(())
        } else {
            DpdkError::service_err("mempool is in use").to_err()
        }
    }

    pub fn mempool(&self, name: &str) -> Result<Mempool> {
        let inner = self.try_lock()?;

        let mp = inner
            .mpools
            .get(name)
            .ok_or(DpdkError::service_err("no such mempool"))?;
        Ok(mp.clone())
    }

    pub fn port_num(&self) -> Result<u16> {
        let _inner = self.try_lock()?;
        unsafe { Ok(ffi::rte_eth_dev_count_avail()) }
    }

    pub fn port_info(&self, port_id: u16) -> Result<PortInfo> {
        let _inner = self.try_lock()?;

        if port_id >= unsafe { ffi::rte_eth_dev_count_avail() } {
            return Err(DpdkError::service_err("invalid port id"));
        }
        unsafe { PortInfo::try_get(port_id) }
    }

    // rte_eth_dev_configure
    pub fn port_configure(
        &self,
        port_id: u16,
        port_conf: &PortConf,
        rxq_confs: &Vec<RxQueueConf>,
        txq_confs: &Vec<TxQueueConf>,
    ) -> Result<()> {
        let mut inner = self.try_lock()?;

        if inner.ports.get(&port_id).is_some() {
            return DpdkError::service_err("port already configured").to_err();
        }

        let rxq_confs = rxq_confs
            .iter()
            .map(|rxq_conf| {
                inner
                    .mpools
                    .get(rxq_conf.mp_name.as_str())
                    .ok_or(DpdkError::service_err("no such mempool"))
                    .map(|mp| (rxq_conf.nb_rx_desc, rxq_conf.socket_id, mp.clone()))
            })
            .collect::<Result<Vec<(u16, u32, Mempool)>>>()?;

        let txq_confs = txq_confs
            .iter()
            .map(|txq_conf| (txq_conf.nb_tx_desc, txq_conf.socket_id))
            .collect::<Vec<(u16, u32)>>();

        let port = Port::try_create(port_id, port_conf, &rxq_confs, &txq_confs)?;
        inner.ports.insert(port_id, port);

        Ok(())
    }

    pub fn port_close(&self, port_id: u16) -> Result<()> {
        let mut inner = self.try_lock()?;

        let port = inner
            .ports
            .get(&port_id)
            .ok_or(DpdkError::service_err("invalid port id"))?;

        if !port.can_shutdown() {
            return DpdkError::service_err("port is in use").to_err();
        }

        port.stop_port()?;

        inner.ports.remove(&port_id).unwrap();
        Ok(())
    }

    pub fn rx_queue(&self, port_id: u16, qid: u16) -> Result<RxQueue> {
        let inner = self.service.lock().unwrap();
        let port = inner
            .ports
            .get(&port_id)
            .ok_or(DpdkError::service_err("invalid port id"))?;
        port.rx_queue(qid)
    }

    pub fn tx_queue(&self, port_id: u16, qid: u16) -> Result<TxQueue> {
        let inner = self.service.lock().unwrap();
        let port = inner
            .ports
            .get(&port_id)
            .ok_or(DpdkError::service_err("invalid port id"))?;
        port.tx_queue(qid)
    }

    pub fn stats_query(&self, port_id: u16) -> Result<StatsQueryContext> {
        let inner = self.try_lock()?;
        let port = inner
            .ports
            .get(&port_id)
            .ok_or(DpdkError::service_err("invalid port id"))?;
        port.stats_query()
    }

    pub fn service_close(&self) -> Result<()> {
        let mut inner = self.service.lock().unwrap();
        if inner.started {
            if inner.ports.len() == 0 && inner.mpools.len() == 0 {
                // ignore the returned error value
                unsafe { ffi::rte_eal_cleanup() };
                inner.started = false;
            } else {
                return DpdkError::service_err("service is in use").to_err();
            }
        }

        Ok(())
    }

    fn try_lock(&self) -> Result<MutexGuard<ServiceInner>> {
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
