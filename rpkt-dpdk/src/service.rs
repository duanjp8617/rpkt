use std::collections::HashMap;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::sync::{Mutex, MutexGuard};

use once_cell::sync::OnceCell;
use rpkt_dpdk_sys as ffi;

use super::error::*;
use super::lcore::{self, *};
use super::mempool::*;
use super::port::*;

pub(crate) static SERVICE: OnceCell<DpdkService> = OnceCell::new();

pub struct DpdkOption {}

impl DpdkOption {
    /// Create a new EalOption.
    pub fn new() -> Self {
        DpdkOption {}
    }

    pub fn init(self) -> Result<()> {
        SERVICE.get_or_try_init(|| {
            // prepare the eal paramters, "-c 1 -n 4 --proc-type primary"
            let mut args: Vec<CString> = vec![CString::new("./prefix").unwrap()];
            args.push(CString::new("-c").unwrap());
            args.push(CString::new("1").unwrap());
            args.push(CString::new("-n").unwrap());
            args.push(CString::new("4").unwrap());
            args.push(CString::new("--proc-type").unwrap());
            args.push(CString::new("primary").unwrap());

            // let potential errors panic early
            let lcores = lcore::detect_lcores();

            // initialize dpdk with rte_eal_init
            let c_args: Vec<_> = args
                .iter()
                .map(|arg| arg.as_bytes_with_nul().as_ptr() as *mut c_char)
                .collect();
            let res = unsafe {
                ffi::rte_eal_init(c_args.len() as c_int, c_args.as_ptr() as *mut *mut c_char)
            };
            if res == -1 {
                return Error::ffi_err(unsafe { ffi::rte_errno_() }, "fail to init eal").to_err();
            }

            Ok(DpdkService {
                service: Mutex::new(ServiceInner {
                    started: true,
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
    lcores: LcoreContext,
    mpools: HashMap<String, Mempool>,
    ports: HashMap<u16, Port>,
}

// Eal is just a wrapper that provides some public interfaces.
pub struct DpdkService {
    service: Mutex<ServiceInner>,
    lcores: Vec<Lcore>,
}

impl DpdkService {
    /// Return a static reference to a list of `Lcore` on the current machine.
    /// 
    /// Each `Lcore` contains the lcore id, cpu id and the socket id of the corresponding
    /// physical CPU core. 
    /// 
    /// We obtain the list of `Lcore` by reading the `/sys/` folder under the 
    /// Linux file system.
    pub fn lcores(&self) -> &Vec<Lcore> {
        &self.lcores
    }

    /// Bind the current thread to the lcore indicated by `lcore_id`.
    /// 
    /// This function will fail and return an `Err` if the following conditions happen:
    /// 1. The DPDK service has been shutdown.
    /// 2. The lcore id is invalid on the current machine.
    /// 3. The thread has already been bind to an lcore.
    /// 4. The lcore has already been bind to another thread.
    /// 5. The DPDK FFI fails with lcore binding.    
    pub fn lcore_bind(&self, lcore_id: u32) -> Result<()> {
        let mut inner = self.try_lock()?;

        let lcore = self
            .lcores
            .iter()
            .find(|lcore| lcore.lcore_id == lcore_id)
            .ok_or(Error::service_err("no such lcore"))?;

        inner.lcores.pin(lcore)
    }

    pub fn mempool_create<S: AsRef<str>>(&self, name: S, conf: &MempoolConf) -> Result<Mempool> {
        let mut inner = self.try_lock()?;

        if inner.mpools.contains_key(name.as_ref()) {
            return Error::service_err("mempool already exists").to_err();
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
            .ok_or(Error::service_err("no such mempool"))?;

        if !mp.in_use() && mp.full() {
            // We are the sole owner of the counter, this also means that
            // we are the sole owner of the PtrWrapper, and we are safe to deallocate it.
            // The mempool to be removed is also full, this means that there are no out-going
            // mbuf pointers.
            let mp = inner.mpools.remove(name).unwrap();
            unsafe { Mempool::delete(mp) }
            Ok(())
        } else {
            Error::service_err("mempool is in use").to_err()
        }
    }

    pub fn mempool(&self, name: &str) -> Result<Mempool> {
        let inner = self.try_lock()?;

        let mp = inner
            .mpools
            .get(name)
            .ok_or(Error::service_err("no such mempool"))?;
        Ok(mp.clone())
    }

    pub fn port_num(&self) -> Result<u16> {
        let _inner = self.try_lock()?;
        unsafe { Ok(ffi::rte_eth_dev_count_avail()) }
    }

    pub fn port_info(&self, port_id: u16) -> Result<PortInfo> {
        let _inner = self.try_lock()?;

        if port_id >= unsafe { ffi::rte_eth_dev_count_avail() } {
            return Err(Error::service_err("invalid port id"));
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
            return Error::service_err("port already configured").to_err();
        }

        let rxq_confs = rxq_confs
            .iter()
            .map(|rxq_conf| {
                inner
                    .mpools
                    .get(rxq_conf.mp_name.as_str())
                    .ok_or(Error::service_err("no such mempool"))
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
            .ok_or(Error::service_err("invalid port id"))?;

        if !port.can_shutdown() {
            return Error::service_err("port is in use").to_err();
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
            .ok_or(Error::service_err("invalid port id"))?;
        port.rx_queue(qid)
    }

    pub fn tx_queue(&self, port_id: u16, qid: u16) -> Result<TxQueue> {
        let inner = self.service.lock().unwrap();
        let port = inner
            .ports
            .get(&port_id)
            .ok_or(Error::service_err("invalid port id"))?;
        port.tx_queue(qid)
    }

    pub fn stats_query(&self, port_id: u16) -> Result<StatsQueryContext> {
        let inner = self.try_lock()?;
        let port = inner
            .ports
            .get(&port_id)
            .ok_or(Error::service_err("invalid port id"))?;
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
                return Error::service_err("service is in use").to_err();
            }
        }

        Ok(())
    }

    fn try_lock(&self) -> Result<MutexGuard<ServiceInner>> {
        let inner = self.service.lock().unwrap();
        if !inner.started {
            Error::service_err("service is shutdown").to_err()
        } else {
            Ok(inner)
        }
    }
}

pub fn try_service() -> Result<&'static DpdkService> {
    SERVICE
        .get()
        .ok_or(Error::service_err("service is not initialized"))
}

/// Return a static reference to the `DpdkService` instance.
/// 
/// The `DpdkService` instance will only be initialized once, and all
/// subsequent access to the public methods are protected by a global lock. 
pub fn service() -> &'static DpdkService {
    match SERVICE.get() {
        Some(handle) => handle,
        None => panic!("dpdk service is not initialized"),
    }
}
