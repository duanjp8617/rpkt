use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use rpkt_dpdk_sys as ffi;

use crate::error::*;

thread_local! {
    pub(crate) static LCORE: RefCell<Option<Lcore>> = RefCell::new(None);
}

#[derive(Copy, Clone)]
pub struct Lcore {
    pub lcore_id: u32,
    pub cpu_id: u32,
    pub socket_id: u32,
}

impl Lcore {
    pub fn current() -> Option<Lcore> {
        LCORE.with(|tl| tl.borrow().as_ref().map(|lcore| *lcore))
    }
}

pub(crate) struct LcoreContext(HashMap<u32, bool>);

impl LcoreContext {
    pub(crate) fn create(lcores: &Vec<Lcore>) -> Self {
        Self(
            lcores
                .iter()
                .map(|lcore| {
                    if lcore.lcore_id == unsafe { ffi::rte_lcore_id_() } {
                        LCORE.with(|local| {
                            *local.borrow_mut() = Some(*lcore);
                        });
                        (lcore.lcore_id, true)
                    } else {
                        (lcore.lcore_id, false)
                    }
                })
                .collect(),
        )
    }

    pub(crate) fn pin(&mut self, lcore: &Lcore) -> Result<()> {
        if LCORE.with(|tl| tl.borrow().is_some()) {
            return Error::service_err("thread is pinned").to_err();
        };

        let occupied = self.0.get_mut(&lcore.lcore_id).unwrap();
        if *occupied {
            return Error::service_err("lcore is in use").to_err();
        }
        *occupied = true;

        unsafe {
            let mut cpu_set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(usize::try_from(lcore.lcore_id).unwrap(), &mut cpu_set);
            let res = ffi::rte_thread_set_affinity(&mut std::mem::transmute(cpu_set));
            if res != 0 {
                return Error::ffi_err(res, "fail to set thread affinity").to_err();
            }
            let res = ffi::rte_thread_register();
            if res != 0 {
                return Error::ffi_err(ffi::rte_errno_(), "fail to register rte thread").to_err();
            }
        }

        LCORE.with(|tl| {
            *tl.borrow_mut() = Some(*lcore);
        });

        Ok(())
    }
}

pub(crate) fn detect_lcores() -> Vec<Lcore> {
    let mut lcores: Vec<Lcore> = (0..ffi::RTE_MAX_LCORE)
        .filter(|id| cpu_detected(*id))
        .map(|lcore_id| {
            let socket_id = cpu_socket_id(lcore_id).unwrap();
            let cpu_id = cpu_core_id(lcore_id).unwrap();
            Lcore {
                lcore_id,
                cpu_id,
                socket_id,
            }
        })
        .collect();
    lcores.sort_by(|a, b| a.lcore_id.cmp(&b.lcore_id));
    lcores
}

fn cpu_detected(lcore_id: u32) -> bool {
    let sys_file = PathBuf::from("/sys/devices/system/cpu")
        .join(&format!("cpu{}", lcore_id))
        .join("topology/core_id");

    sys_file.exists()
}

fn cpu_socket_id(lcore_id: u32) -> Option<u32> {
    for socket_id in 0..ffi::RTE_MAX_NUMA_NODES {
        let sys_file = PathBuf::from("/sys/devices/system/node")
            .join(&format!("node{}", socket_id))
            .join(&format!("cpu{}", lcore_id));

        if sys_file.exists() {
            return Some(socket_id);
        }
    }
    None
}

fn cpu_core_id(lcore_id: u32) -> Option<u32> {
    let sys_file = PathBuf::from("/sys/devices/system/cpu")
        .join(&format!("cpu{}", lcore_id))
        .join("topology/core_id");

    let mut file = File::open(sys_file).ok()?;
    let mut contents = String::new();
    file.read_to_string(&mut contents).ok()?;
    contents.trim().parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use crate::*;
    use std::sync::atomic;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn bind_lcore_to_thread_0() {
        // Dpdk will only be initialized once
        DpdkOption::new().init().unwrap();

        let res = service().lcore_bind(0);
        assert_eq!(res.is_err(), true);
    }

    #[test]
    fn bind_2_cores_to_the_same_lcore() {
        DpdkOption::new().init().unwrap();

        assert_eq!(service().lcores().len() >= 2, true);

        let lcore = service().lcores()[1];
        assert_ne!(lcore.lcore_id, 0);

        let mut jhs = Vec::new();
        let shared = Arc::new(atomic::AtomicU32::new(0));

        for _ in 0..2 {
            let cloned = shared.clone();
            jhs.push(thread::spawn(move || {
                assert_eq!(Lcore::current().is_none(), true);
                let res = service().lcore_bind(lcore.lcore_id);
                match res {
                    Ok(_) => {
                        cloned.fetch_add(1, atomic::Ordering::SeqCst);
                        let mt_lcore = Lcore::current().unwrap();
                        assert!(mt_lcore.lcore_id == lcore.lcore_id);
                    }
                    Err(_) => {
                        assert_eq!(Lcore::current().is_none(), true);
                    }
                }
            }));
        }

        for jh in jhs {
            jh.join().unwrap();
        }

        let num = shared.load(atomic::Ordering::SeqCst);
        assert_eq!(num, 1);
    }
}
