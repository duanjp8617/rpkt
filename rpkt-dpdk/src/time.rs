
use std::fs::read_to_string;
use std::marker::PhantomData;
use std::ops::{AddAssign, Sub, SubAssign};
use std::sync::OnceLock;
use std::{ops::Add, time::{self, Duration, SystemTime, UNIX_EPOCH}};

/// Return the current TSC (Time Stamp Counter) value read from the CPU.
///
/// Both x86_64 and aarch64 can store a constantly-increasing counter to the CPU
/// registers. The counter increases at a constant frequency, triggered by an
/// internal clock of the CPU.
///
/// Therefore, `rdtsc` can be used for high-resolution timer at negligible cost,
/// and is critical for high-performance user-space packet processing programs.
///
/// # aarch64
///
/// This implementation provies `rdtsc` through the `pmccntr_el0` (Performance
/// Monitors Cycle Counter Register). According to DPDK, it uses the PMU cycle
/// counter from the the ARMv8 PMU subsystem. However, accessing the PMU cycle
/// counter from the user space is not enabled by default in the arm64 linux
/// kernel. To enable the sucesss, we must configure the PMU from the privileged
/// mode (kernel space).
///
/// According to DPDK, we can use the following kernel module to configure PMU:
/// ```shell
/// git clone https://github.com/jerinjacobk/armv8_pmu_cycle_counter_el0
/// cd armv8_pmu_cycle_counter_el0
/// make
/// sudo insmod pmu_el0_cycle_counter.ko
/// ```
#[cfg(target_arch = "aarch64")]
#[inline]
fn rdtsc() -> u64 {
    let tsc: u64;
    unsafe {
        std::arch::asm!(
            "mrs {}, pmccntr_el0",
            out(reg) tsc,
            options(nomem, nostack, preserves_flags)
        );
    }
    tsc
}

/// Return the current TSC (Time Stamp Counter) value read from the CPU.
///
/// Both x86_64 and aarch64 can store a constantly-increasing counter to the CPU
/// registers. The counter increases at a constant frequency, triggered by an
/// internal clock of the CPU.
///
/// Therefore, `rdtsc` can be used for high-resolution timer at negligible cost,
/// and is critical for high-performance user-space packet processing programs.
#[cfg(target_arch = "x86_64")]
#[inline]
fn rdtsc() -> u64 {
    let mut rax: u64;
    let mut rdx: u64;
    unsafe {
        std::arch::asm!(
            "rdtsc",
            out("rax") rax,
            out("rdx") rdx,
            options(nomem, nostack, preserves_flags)
        );
    }
    (rdx << 32) | rax
}

// measure the rdtsc counter frequency.
//
// We copy this implementation from erpc, which performs a complex algorithmic
// calculation first and then calcualates the frequency by dividing the rdtsc
// difference with the time difference measured by `std::time::Instant`.

fn measure_rdtsc_in_hz_once() -> u64 {
    loop {
        let start = time::Instant::now();
        let rdtsc_start = rdtsc();

        let mut sum: u64 = 5;
        for i in 0u64..1000000 {
            sum = sum.wrapping_add(i.wrapping_add((sum.wrapping_add(i)).wrapping_mul(i % sum)));
        }
        assert!(
            sum == 13580802877818827968,
            "error in rdtsc freq measurement"
        );

        let duration = time::Instant::now() - start;
        let rdtsc_cycles = rdtsc().checked_sub(rdtsc_start).unwrap_or(10);

        let freq_hz = (rdtsc_cycles as f64) / duration.as_secs_f64();
        if freq_hz <= 10000000.0 || freq_hz >= 10000000000.0 {
            // if the measured frequency does not fall between 10MHz to 10GHz,
            // we just measure again
            continue;
        }

        return freq_hz.round() as u64;
    }
}

// The final base frequency is obtained by calculating the frequency from
// `10000000` consecutive times and making sure the the difference between
// consecutive measurements is smaller than 5%.

fn base_freq_in_hz() -> u64 {
    let mut consecutive_successful_measure = 0;
    let delta = 0.05;

    let mut prev_freq_hz = measure_rdtsc_in_hz_once();
    for _ in 0..10000000 {
        let curr_freq_hz = measure_rdtsc_in_hz_once();
        let diff = ((curr_freq_hz as f64) - (prev_freq_hz as f64)).abs() / (prev_freq_hz as f64);
        if diff <= delta {
            consecutive_successful_measure += 1;
            if consecutive_successful_measure > 50 {
                return curr_freq_hz;
            }
            prev_freq_hz = curr_freq_hz;
        } else {
            consecutive_successful_measure = 0;
            prev_freq_hz = curr_freq_hz;
        }
    }

    panic!("fail to measure a stable rdtsc after trying for 10 million times")
}

/// The base frequency of the rdtsc counter.
///
/// We can use `BaseFreq` to convert rdtsc cycles to actual time duration and
/// vice-versa.
///
/// `BaseFreq` is provided as a standalone instance. It can be used even without
/// initializing dpdk.
///
/// # Examples
/// ```rust
/// use rpkt_dpdk::rdtsc;
/// use std::time;
///
/// // prepare the base frequency
/// let base_freq = rdtsc::BaseFreq::new();
/// // prepare the current time value using std
/// let curr_time = time::Instant::now();
/// // calculate the current rdtsc value.
/// let curr_rdtsc = rdtsc::rdtsc();
/// // wait for 1s.
/// let tick_in_1s = curr_rdtsc + base_freq.sec_to_cycles(1.0);
/// while rdtsc::rdtsc() < tick_in_1s {}
/// // calculate the ending rdtsc value
/// let end_rdtsc = rdtsc::rdtsc();
/// // calculate the ending time instant.
/// let end_time = time::Instant::now();
///
/// let measured_time_in_std = (end_time - curr_time).as_secs() as f64;
/// let mesured_time_in_rdtsc = base_freq.cycles_to_sec(end_rdtsc.checked_sub(curr_rdtsc).unwrap());
///
/// assert_eq!(
///     measured_time_in_std.sub(mesured_time_in_rdtsc).abs() / measured_time_in_std < 0.005,
///     true
/// );
/// ```

#[derive(Clone, Copy, Debug)]
pub struct BaseFreq {
    freq_in_ghz: f64,
    can_not_send: PhantomData<*const ()>,
}


impl BaseFreq {
    /// Construct a new `BaseFreq` instance.
    pub fn new() -> Self {
        let base_freq = base_freq_in_hz();
        Self {
            freq_in_ghz: (base_freq as f64) / 1000_000_000.0,
            can_not_send: PhantomData,
        }
    }

    /// Return the measured rdtsc counter frequency in Hz.
    #[inline]
    pub fn freq_in_hz(&self) -> u64 {
        (self.freq_in_ghz * 1000_000_000.0) as u64
    }

    /// Return the measured rdtsc counter frequency in GHz.
    #[inline]
    pub fn freq_in_ghz(&self) -> f64 {
        self.freq_in_ghz
    }

    /// Convert rdtsc cycles to seconds.
    #[inline]
    pub fn cycles_to_sec(&self, cycles: u64) -> f64 {
        (cycles as f64) / (self.freq_in_ghz as f64 * 1000_000_000.0)
    }

    /// Convert rdtsc cycles to milliseconds.
    #[inline]
    pub fn cycles_to_ms(&self, cycles: u64) -> f64 {
        (cycles as f64) / (self.freq_in_ghz as f64 * 1000_000.0)
    }

    /// Convert rdtsc cycles to microseconds.
    #[inline]
    pub fn cycles_to_us(&self, cycles: u64) -> f64 {
        (cycles as f64) / (self.freq_in_ghz as f64 * 1000.0)
    }

    /// Convert rdtsc cycles to nanoseconds.
    #[inline]
    pub fn cycles_to_ns(&self, cycles: u64) -> f64 {
        (cycles as f64) / self.freq_in_ghz
    }

    /// Convert seconds to rdtsc cycles.
    #[inline]
    pub fn sec_to_cycles(&self, sec: f64) -> u64 {
        (sec * self.freq_in_ghz * 1000_000_000.0) as u64
    }

    /// Convert milliseconds to rdtsc cycles.
    #[inline]
    pub fn ms_to_cycles(&self, ms: f64) -> u64 {
        (ms * self.freq_in_ghz * 1000_000.0) as u64
    }

    /// Convert microseconds to rdtsc cycles.
    #[inline]
    pub fn us_to_cycles(&self, us: f64) -> u64 {
        (us * self.freq_in_ghz * 1000.0) as u64
    }

    /// Convert nanoseconds to rdtsc cycles.
    #[inline]
    pub fn ns_to_cycles(&self, ns: f64) -> u64 {
        (ns * self.freq_in_ghz) as u64
    }
}


impl PartialEq for BaseFreq {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.freq_in_hz() == other.freq_in_hz()
    }
}


impl Eq for BaseFreq {}


impl PartialOrd for BaseFreq {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.freq_in_hz().cmp(&other.freq_in_hz()))
    }
}


impl Ord for BaseFreq {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.freq_in_hz().cmp(&other.freq_in_hz())
    }
}


impl std::hash::Hash for BaseFreq {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.freq_in_hz(), state);
    }
}

/// A TSC-based clock source.
/// 
/// We can use `TscClockSource` to get the current monotonic time and system time. `TscClockSource` depends on the `invariant TSC` feature of modern CPUs.
/// If the CPU does not support invariant TSC, `TscClockSource::create()` will return `None`.
/// 
/// # Examples
/// ```rust
/// use rpkt-dpdk::time::time::{ TscClockSource };
/// 
/// // Create a TscClockSource
/// let tsc_time_source = TscClockSource::create().expect("TSC is not stable on this system");
/// 
/// let mono_time = tsc_time_source.get_mono_time();
/// let system_time = tsc_time_source.get_system_time();
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]

pub struct TscClockSource {
    freq: BaseFreq,
    ns_from_epoch: u64,
    ref_cycle: u64,
}


impl TscClockSource {
    pub fn create() -> Option<Self> {
        if !tsc_stable() {
            return None;
        }

        Some(TscClockSource {
            freq: BaseFreq::new(),
            ns_from_epoch: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_nanos() as u64,
            ref_cycle: rdtsc(),
        })
    }

    #[inline]
    pub fn freq(&self) -> BaseFreq {
        self.freq
    }

    #[inline]
    pub fn get_mono_time(&self) -> TscMonoTime {
        TscMonoTime {
            freq: self.freq,
            tsc: rdtsc(),
        }
    }

    #[inline]
    pub fn get_system_time(&self) -> SystemTime {
        use std::time::Duration;

        let tsc = rdtsc();
        let elapsed_ns = self.freq.cycles_to_ns(tsc - self.ref_cycle as u64) as u64;
        UNIX_EPOCH + Duration::from_nanos(self.ns_from_epoch + elapsed_ns)
    }

    #[inline]
    pub fn get_tsc(&self) -> u64 {
        rdtsc()
    }
}

/// A monotonic time point based on TSC counter.
/// 
/// We can use `TscMonoTime` to represent a point in monotonic time,
/// and do arithmetic operations on it.
/// 
/// # Notes
/// Same as `BaseFreq`, `TscMonoTime` can not be sent across threads. You
/// can find more details at [`BaseFreq`](`BaseFreq`).
/// 
/// # Examples
/// ```rust
/// use rpkt-dpdk::time::time::{ TscClockSource, TscMonoTime };
/// use std::time::Duration;
/// 
/// // Create a TscClockSource
/// let tsc_time_source = TscClockSource::create().expect("TSC is not stable on this system");
/// 
/// let start_time = tsc_time_source.get_mono_time();
/// std::thread::sleep(Duration::from_millis(10));
/// let end_time = tsc_time_source.get_mono_time();
/// let duration = end_time.duration_since(start_time);
/// println!("Elapsed time: {} ms", duration.as_millis());
/// ```

#[derive(Clone, Copy)]
pub struct TscMonoTime {
    freq: BaseFreq,
    tsc: u64,
}


impl TscMonoTime {
    /// Returns the raw value of the tsc counter.
    #[inline]
    pub fn as_tsc(&self) -> u64 {
      self.tsc
    }

    #[inline]
    pub fn freq(&self) -> BaseFreq {
        self.freq
    }

    /// Returns the amount of time elapsed from another instant to this one,
    /// or zero duration if that instant is later than this one.
    #[inline]
    pub fn duration_since(&self, earlier: TscMonoTime) -> Duration {
      self.checked_duration_since(earlier).unwrap_or_default()
    }

    /// Returns the amount of time elapsed from another instant to this one,
    /// or None if that instant is later than this one.
    #[inline]
    pub fn checked_duration_since(&self, earlier: TscMonoTime) -> Option<Duration> {
        Some(Duration::from_nanos(self.freq.cycles_to_ns(self.tsc.checked_sub(earlier.tsc)? as u64) as u64))
    }

    /// Returns the amount of time elapsed from another instant to this one,
    /// or zero duration if that instant is later than this one.
    #[inline]
    pub fn saturating_duration_since(&self, earlier: TscMonoTime) -> Duration {
        self.checked_duration_since(earlier).unwrap_or_default()
    }

    /// Returns `Some(t)` where `t` is the time `self + duration` if `t` can be represented as
    /// `Instant` (which means it's inside the bounds of the underlying data structure), `None`
    /// otherwise.
    #[inline]
    pub fn checked_add(&self, duration: Duration) -> Option<TscMonoTime> {
        self.tsc
            .checked_add(self.freq.ns_to_cycles(duration.as_nanos() as f64))
            .map(|tsc| TscMonoTime {
                freq: self.freq,
                tsc,
            })
    }

    /// Returns `Some(t)` where `t` is the time `self - duration` if `t` can be represented as
    /// `Instant` (which means it's inside the bounds of the underlying data structure), `None`
    /// otherwise.
    #[inline]
    pub fn checked_sub(&self, duration: Duration) -> Option<TscMonoTime> {
        self.tsc
            .checked_sub(self.freq.ns_to_cycles(duration.as_nanos() as f64))
            .map(|tsc| TscMonoTime {
                freq: self.freq,
                tsc,
            })
    }

    #[inline]
    pub fn as_nanos(&self) -> f64 {
        self.freq.cycles_to_ns(self.tsc)
    }

    #[inline]
    pub fn as_micros(&self) -> f64 {
        self.freq.cycles_to_ms(self.tsc) 
    }

    #[inline]
    pub fn as_millis(&self) -> f64 {
        self.freq.cycles_to_ms(self.tsc) 
    }

    #[inline]
    pub fn as_secs(&self) -> f64 {
        self.freq.cycles_to_sec(self.tsc) 
    }
}

impl Add<Duration> for TscMonoTime {
    type Output = TscMonoTime;

    #[inline]
    fn add(self, other: Duration) -> TscMonoTime {
        self.checked_add(other)
            .expect("overflow when adding duration to TscMonoTime")
    }
}

impl AddAssign<Duration> for TscMonoTime {
    #[inline]
    fn add_assign(&mut self, other: Duration) {
        *self = *self + other;
    }
}

impl Sub<Duration> for TscMonoTime {
    type Output = TscMonoTime;

    #[inline]
    fn sub(self, other: Duration) -> TscMonoTime {
        self.checked_sub(other)
            .expect("overflow when subtracting duration from TscMonoTime")
    }
}

impl SubAssign<Duration> for TscMonoTime {
    #[inline]
    fn sub_assign(&mut self, other: Duration) {
        *self = *self - other;
    }
}

impl Sub<TscMonoTime> for TscMonoTime {
    type Output = Duration;

    /// Returns the amount of time elapsed from another instant to this one,
    /// or zero duration if that instant is later than this one.
    ///
    /// # Panics
    ///
    /// Previously we panicked if `other` was later than `self`. Currently, this method saturates
    /// to follow the behavior of the standard library. Future versions may reintroduce the panic
    /// in some circumstances.
    #[inline]
    fn sub(self, other: TscMonoTime) -> Duration {
        self.duration_since(other)
    }
}

impl PartialEq for TscMonoTime {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.tsc == other.tsc
    }
}

impl Eq for TscMonoTime {}

impl PartialOrd for TscMonoTime {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TscMonoTime {
    #[inline]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.tsc.cmp(&other.tsc)
    }
}

impl std::hash::Hash for TscMonoTime {
    /// Only the tsc value is hashed. If you want to 
    /// also hash the frequency, please hash it separately.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(&self.tsc, state);
    }
}

impl std::fmt::Debug for TscMonoTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.tsc.fmt(f)
    }
}

fn tsc_stable() -> bool {
    // According to http://oliveryang.net/2015/09/pitfalls-of-TSC-usage/
    // Linux kernel will check whether tsc is stable during boot time.
    // If the check is passed, Linux will export tsc as the current clocksource
    // in the following sysfs: /sys/devices/system/clocksource/clocksource0/current_clocksource
    // So we first check the sysfs to determine whether the tsc is stable.
    static TSC_STABLE: OnceLock<bool> = OnceLock::new();
    TSC_STABLE.get_or_init( || -> bool {
        let tsc_stable = read_to_string("/sys/devices/system/clocksource/clocksource0/current_clocksource")
        .map(|s| {
                s.trim()
                    .split(" ")
                    .find(|s| *s == "tsc")
                    .map(|_| true)
                    .unwrap_or(false)
            })
            .unwrap_or(false);    
        tsc_stable
    }).to_owned()
}