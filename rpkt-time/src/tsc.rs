use core::arch::x86_64::_rdtsc;
use std::cell::UnsafeCell;
use std::fs::read_to_string;
use std::mem::{size_of, zeroed, MaybeUninit};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use ctor::ctor;
use libc::{cpu_set_t, sched_setaffinity, CPU_SET};

type Error = Box<dyn std::error::Error>;

struct TimeState {
    nanos_per_cycle: UnsafeCell<f64>,
    cycles_per_sec: UnsafeCell<u64>,
    ref_time: UnsafeCell<MaybeUninit<Instant>>,
    ref_tsc: UnsafeCell<u64>,
    tsc_stable: UnsafeCell<bool>,
}

unsafe impl Sync for TimeState {}

static TS: TimeState = TimeState {
    nanos_per_cycle: UnsafeCell::new(0.0),
    cycles_per_sec: UnsafeCell::new(0),
    ref_time: UnsafeCell::new(MaybeUninit::uninit()),
    ref_tsc: UnsafeCell::new(0),
    tsc_stable: UnsafeCell::new(false),
};

static PRECISION: f64 = 0.00001;

#[inline]
fn tsc() -> u64 {
    #[cfg(target_arch = "x86")]
    use core::arch::x86::_rdtsc;

    #[cfg(target_arc = "x86_64")]
    use core::arch::x86_64::_rdtsc;

    unsafe { _rdtsc() }
}

#[inline]
pub(crate) fn nanos_per_cycle() -> f64 {
    unsafe { *TS.nanos_per_cycle.get() }
}

#[inline]
pub(crate) fn cycles_per_sec() -> u64 {
    unsafe { *TS.cycles_per_sec.get() }
}

#[inline]
pub(crate) fn tsc_from_ref() -> u64 {
    tsc().wrapping_sub(unsafe { *TS.ref_tsc.get() })
}

pub(crate) fn tsc_stable() -> bool {
    unsafe { *TS.tsc_stable.get() }
}

// Return value:
// Ok((nanos_per_cycle, cycles_per_sec, ref_time, ref_tsc))
// None: no stable measurement
#[allow(unused_assignments)]
fn measure_fraq(precision: f64, repeat: u64) -> Option<(f64, u64, Instant, u64)> {
    let mut t1 = Instant::now();
    let mut tsc1 = tsc();

    let mut t2 = t1;
    let mut tsc2 = tsc1;

    let mut last_interval = 0;
    for _ in 0..repeat {
        loop {
            t2 = Instant::now();
            tsc2 = tsc();

            if (t2 - t1).as_nanos() >= 10_000_000 {
                break;
            }
        }

        let diff = ((tsc2 - tsc1) as f64 - last_interval as f64).abs();
        if diff / (tsc2 - tsc1) as f64 <= precision {
            // we get a stable measurement
            let nanos_per_cycle = (t2 - t1).as_nanos() as f64 / (tsc2 - tsc1) as f64;
            let cycles_per_sec = (1_000_000_000 as f64 / nanos_per_cycle) as u64;
            return Some((nanos_per_cycle, cycles_per_sec, t2, tsc2));
        }

        // continue measure for the next interval
        last_interval = tsc2 - tsc1;
        t1 = t2;
        tsc1 = tsc2;
    }

    None
}

#[ctor]
unsafe fn module_init() {
    // According to http://oliveryang.net/2015/09/pitfalls-of-TSC-usage/
    // Linux kernel will check whether tsc is stable during boot time.
    // If the check is passed, Linux will export tsc as the current clocksource
    // in the following sysfs: /sys/devices/system/clocksource/clocksource0/current_clocksource
    // So we first check the sysfs to determine whether the tsc is stable.
    let tsc_stable =
        read_to_string("/sys/devices/system/clocksource/clocksource0/current_clocksource")
            .map(|s| {
                s.trim()
                    .split(" ")
                    .find(|s| *s == "tsc")
                    .map(|_| true)
                    .unwrap_or(false)
            })
            .unwrap_or(false);

    let measured_fraq = if tsc_stable {
        Some(measure_fraq(PRECISION, 50).unwrap())
    } else {
        // If we can't determine whether tsc is stable from the sysfs, we will
        // perform a manual check by meausing the CPU fraquency at each core and comparing
        // the measurement results to see whether they are all synchronized.
        measure_fraq(PRECISION, 50).and_then(
            |(nanos_per_cycle, cycles_per_sec, ref_time, ref_tsc)| {
                let cpus = available_cpus().unwrap();

                let mut tls = Vec::new();
                for _ in 0..cpus.len() {
                    tls.push(Arc::new(RwLock::new((0.0, Instant::now(), 0))));
                }

                let mut jhs = Vec::new();
                for (idx, cpu) in cpus.iter().enumerate() {
                    let cpu = *cpu;
                    let rwl = tls[idx].clone();
                    jhs.push(std::thread::spawn(move || {
                        set_affinity(cpu).unwrap();
                        let (tl_nanos_per_cycle, _, tl_ref_time, tl_ref_tsc) =
                            measure_fraq(PRECISION, 50).unwrap_or((0.0, 0, Instant::now(), tsc()));
                        *rwl.write().unwrap() = (tl_nanos_per_cycle, tl_ref_time, tl_ref_tsc);
                    }));
                }
                for jh in jhs {
                    jh.join().unwrap();
                }

                tls.iter()
                    .map(|rwl| {
                        let (tl_nanos_per_cycle, tl_ref_time, tl_ref_tsc) = *rwl.read().unwrap();
                        let t1 = (tl_ref_tsc - ref_tsc) as f64 * tl_nanos_per_cycle;
                        let t2 = (tl_ref_time - ref_time).as_nanos() as f64;
                        if (t2 - t1).abs() / t2 <= PRECISION * 10.0 {
                            Some(())
                        } else {
                            None
                        }
                    })
                    .collect::<Option<Vec<()>>>()
                    .map(|_| (nanos_per_cycle, cycles_per_sec, ref_time, ref_tsc))
            },
        )
    };

    match measured_fraq {
        Some((nanos_per_cycle, cycles_per_sec, ref_time, ref_tsc)) => {
            *TS.nanos_per_cycle.get() = nanos_per_cycle;
            *TS.cycles_per_sec.get() = cycles_per_sec;
            (*TS.ref_time.get()).write(ref_time);
            (*TS.ref_time.get()).assume_init();
            *TS.ref_tsc.get() = ref_tsc;
            *TS.tsc_stable.get() = true;
        }
        None => {
            (*TS.ref_time.get()).write(Instant::now());
            (*TS.ref_time.get()).assume_init();
            *TS.ref_tsc.get() = tsc();
            *TS.tsc_stable.get() = false;
        }
    }

    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
}

//--------------------------------------------------------------------------------------------------//
// The following code is taken from minstant at https://github.com/tikv/minstant

// Retrieve available CPUs from `/sys` filesystem.
fn available_cpus() -> Result<Vec<usize>, Error> {
    let s = read_to_string("/sys/devices/system/cpu/online")?;
    parse_cpu_list_format(&s)
}

/// A wrapper function of sched_setaffinity(2)
fn set_affinity(cpuid: usize) -> Result<(), Error> {
    let mut set = unsafe { zeroed::<cpu_set_t>() };

    unsafe { CPU_SET(cpuid, &mut set) };

    // Set the current thread's core affinity.
    if unsafe {
        sched_setaffinity(
            0, // Defaults to current thread
            size_of::<cpu_set_t>(),
            &set as *const _,
        )
    } != 0
    {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

/// List format
/// The  List  Format for cpus and mems is a comma-separated list of CPU or
/// memory-node numbers and ranges of numbers, in ASCII decimal.
///
/// Examples of the List Format:
///   0-4,9           # bits 0, 1, 2, 3, 4, and 9 set
///   0-2,7,12-14     # bits 0, 1, 2, 7, 12, 13, and 14 set
fn parse_cpu_list_format(list: &str) -> Result<Vec<usize>, Error> {
    let mut res = vec![];
    let list = list.trim();
    for set in list.split(',') {
        if set.contains('-') {
            let mut ft = set.splitn(2, '-');
            let from = ft.next().ok_or("expected from")?.parse::<usize>()?;
            let to = ft.next().ok_or("expected to")?.parse::<usize>()?;
            for i in from..=to {
                res.push(i);
            }
        } else {
            res.push(set.parse()?)
        }
    }

    Ok(res)
}
