use std::time;

#[cfg(target_arch = "aarch64")]
/// Return the TSC (Time Stamp Counter) or equivalent
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
    ((rdx << 32) | rax)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
pub fn rdtsc() -> u64 {
    0
}

fn measure_rdtsc_in_hz_once() -> u64 {
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
    let rdtsc_cycles = rdtsc() - rdtsc_start;

    let freq_hz = (rdtsc_cycles as f64) / duration.as_secs_f64();
    assert!(
        freq_hz > 10000000.0 && freq_hz < 10000000000.0,
        "rdtsc frequency {freq_hz} does not fall between 10MHz to 10GHz"
    );

    freq_hz.round() as u64
}

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

#[derive(Clone, Copy, Debug)]
pub struct BaseFreq {
    freq_in_ghz: f64,
}

impl BaseFreq {
    pub fn new() -> Self {
        let base_freq = base_freq_in_hz();
        Self {
            freq_in_ghz: (base_freq as f64) / 1000_000_000.0,
        }
    }

    #[inline]
    pub fn freq_in_hz(&self) -> u64 {
        (self.freq_in_ghz * 1000_000_000.0) as u64
    }

    #[inline]
    pub fn freq_in_ghz(&self) -> f64 {
        self.freq_in_ghz
    }

    #[inline]
    pub fn cycles_to_sec(&self, cycles: u64) -> f64 {
        (cycles as f64) / (self.freq_in_ghz as f64 * 1000_000_000.0)
    }

    #[inline]
    pub fn cycles_to_ms(&self, cycles: u64) -> f64 {
        (cycles as f64) / (self.freq_in_ghz as f64 * 1000_000.0)
    }

    #[inline]
    pub fn cycles_to_us(&self, cycles: u64) -> f64 {
        (cycles as f64) / (self.freq_in_ghz as f64 * 1000.0)
    }

    #[inline]
    pub fn cycles_to_ns(&self, cycles: u64) -> f64 {
        (cycles as f64) / self.freq_in_ghz
    }

    #[inline]
    pub fn sec_to_cycles(&self, sec: f64) -> u64 {
        (sec * self.freq_in_ghz * 1000_000_000.0) as u64
    }

    #[inline]
    pub fn ms_to_cycles(&self, ms: f64) -> u64 {
        (ms * self.freq_in_ghz * 1000_000.0) as u64
    }

    #[inline]
    pub fn us_to_cycles(&self, us: f64) -> u64 {
        (us * self.freq_in_ghz * 1000.0) as u64
    }

    #[inline]
    pub fn ns_to_cycles(&self, ns: f64) -> u64 {
        (ns * self.freq_in_ghz) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        let base_freq = BaseFreq::new();
        println!("ghz: {}", base_freq.freq_in_ghz());
        println!("hz: {}", base_freq.freq_in_hz());

        println!("1s: {}", base_freq.sec_to_cycles(1.0));
        println!("1ms: {}", base_freq.ms_to_cycles(1.0));
        println!("1us: {}", base_freq.us_to_cycles(1.0));
        println!("1ns: {}", base_freq.ns_to_cycles(1.0));

        println!("1000000 cycles: {}s", base_freq.cycles_to_sec(1000000));
        println!("1000000 cycles: {}ms", base_freq.cycles_to_ms(1000000));
        println!("1000000 cycles: {}us", base_freq.cycles_to_us(1000000));
        println!("1000000 cycles: {}ns", base_freq.cycles_to_ns(1000000));
    }
}
