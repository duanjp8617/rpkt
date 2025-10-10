use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use crate::sys as ffi;

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
    pub(crate) fn current() -> Option<Lcore> {
        LCORE.with(|tl| tl.borrow().as_ref().map(|lcore| *lcore))
    }
}

pub(crate) struct LcoreContext(HashMap<u32, bool>);

impl LcoreContext {
    pub(crate) fn create(lcores: &Vec<Lcore>) -> Self {
        Self(lcores.iter().map(|lcore| (lcore.lcore_id, false)).collect())
    }

    pub(crate) fn pin(&mut self, lcore: &Lcore) -> Result<()> {
        if LCORE.with(|tl| tl.borrow().is_some()) {
            return DpdkError::service_err("thread is pinned").to_err();
        };

        let occupied = self.0.get_mut(&lcore.lcore_id).unwrap();
        if *occupied {
            return DpdkError::service_err("lcore is in use").to_err();
        }
        *occupied = true;

        unsafe {
            let mut cpu_set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_SET(usize::try_from(lcore.lcore_id).unwrap(), &mut cpu_set);
            let res = ffi::rte_thread_set_affinity(&mut std::mem::transmute(cpu_set));
            if res != 0 {
                return DpdkError::ffi_err(res, "fail to set thread affinity").to_err();
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
