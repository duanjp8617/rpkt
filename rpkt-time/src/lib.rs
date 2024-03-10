/// This crate provides an alternative approach to the time crate of the stardard library.
/// It relies on the tsc registers to get the current time instant in a faster and more accurate
/// fasihon.
///
/// Note that this library does has the following limitations:
///
/// 1. It only works on 32/64 bits Linux systems with stable tsc (see this blog post for more information
/// about stable tsc: http://oliveryang.net/2015/09/pitfalls-of-TSC-usage/).
///
/// 2. When this crate is loaded, it will check whether the system has stable tsc.
/// If it does not detect tsc, it will report `false` through the `tsc_stable()` method.
/// Any usage of this crate is strictly forbidended without stable tsc, as the APIs of this
/// crate may report errorneous time result.
///
/// 3. When initializing this library, it may cause a panic if it fails to read the sysfs file or
/// parse the file read result.
///
/// Some of the code is taken from minstant library, but remove some unncessary
/// code path for performance.

#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
mod instant;

#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
pub use instant::{Anchor, Instant};

#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
mod tsc;

#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
/// Return whether tsc is stable on the current system.
///
/// Note that if this method returns `false`, the whole library should not be used,
/// as the library may report erroneous time result.
///
/// # Examples
/// ```
/// use rpkt_time;
///
/// assert!(rpkt_time::tsc_stable());
/// ```
pub fn tsc_stable() -> bool {
    tsc::tsc_stable()
}

#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
/// Return the number of CPU cycles of 1 second. It can be used to caclculate future tsc
/// counter value after a fixed time interval.
/// 
/// Note that this method may return 0 if it is not running on systems with stable tsc.
/// 
/// # Examples
/// ```
/// use rpkt_time::Instant;
///
/// let ddl = Instant::now().raw().checked_add(rpkt_time::cycles_per_sec()).unwrap();
/// while Instant::now().raw() <= ddl {}
///
/// println!("1s has passed");
/// ```
#[inline]
pub fn cycles_per_sec() -> u64 {
    tsc::cycles_per_sec()
}
