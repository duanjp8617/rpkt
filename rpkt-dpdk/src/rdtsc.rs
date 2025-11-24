use std::time;

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
pub fn rdtsc() -> u64 {
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
pub fn rdtsc() -> u64 {
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
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
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
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
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
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[derive(Clone, Copy, Debug)]
pub struct BaseFreq {
    freq_in_ghz: f64,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl BaseFreq {
    /// Construct a new `BaseFreq` instance.
    pub fn new() -> Self {
        let base_freq = base_freq_in_hz();
        Self {
            freq_in_ghz: (base_freq as f64) / 1000_000_000.0,
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
