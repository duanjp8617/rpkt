// This file is taken from minstant at https://github.com/tikv/minstant and modified
// for compatibility with the code in lib.rs.

// Copyright 2021 TiKV Project Authors. Licensed under Apache-2.0.

use crate::tsc;

use std::{
    ops::{Add, AddAssign, Sub, SubAssign},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// A measurement of a monotonically non-decreasing clock. Similar to
/// [`std::time::Instant`](std::time::Instant) but is faster and more
/// accurate with stable TSC.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

impl Instant {
    /// Returns the raw value of the tsc counter.
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
    pub fn raw(&self) -> u64 {
        self.0
    }

    /// Returns an instant corresponding to "now".
    ///
    /// # Examples
    ///
    /// ```
    /// use minstant::Instant;
    ///
    /// let now = Instant::now();
    /// ```
    #[inline]
    pub fn now() -> Instant {
        Instant(tsc::tsc_from_ref())
    }

    /// Returns the amount of time elapsed from another instant to this one,
    /// or zero duration if that instant is later than this one.
    ///
    /// # Panics
    ///
    /// Previously we panicked if `earlier` was later than `self`. Currently, this method saturates
    /// to follow the behavior of the standard library. Future versions may reintroduce the panic
    /// in some circumstances.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use std::thread::sleep;
    ///
    /// use minstant::Instant;
    ///
    /// let now = Instant::now();
    /// sleep(Duration::new(1, 0));
    /// let new_now = Instant::now();
    /// println!("{:?}", new_now.duration_since(now));
    /// println!("{:?}", now.duration_since(new_now)); // 0ns
    /// ```
    #[inline]
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        self.checked_duration_since(earlier).unwrap_or_default()
    }

    /// Returns the amount of time elapsed from another instant to this one,
    /// or None if that instant is later than this one.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use std::thread::sleep;
    ///
    /// use minstant::Instant;
    ///
    /// let now = Instant::now();
    /// sleep(Duration::new(1, 0));
    /// let new_now = Instant::now();
    /// println!("{:?}", new_now.checked_duration_since(now));
    /// println!("{:?}", now.checked_duration_since(new_now)); // None
    /// ```
    #[inline]
    pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        Some(Duration::from_nanos(
            (self.0.checked_sub(earlier.0)? as f64 * tsc::nanos_per_cycle()) as u64,
        ))
    }

    /// Returns the amount of time elapsed from another instant to this one,
    /// or zero duration if that instant is later than this one.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use std::thread::sleep;
    ///
    /// use minstant::Instant;
    ///
    /// let now = Instant::now();
    /// sleep(Duration::new(1, 0));
    /// let new_now = Instant::now();
    /// println!("{:?}", new_now.saturating_duration_since(now));
    /// println!("{:?}", now.saturating_duration_since(new_now)); // 0ns
    /// ```
    #[inline]
    pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
        self.checked_duration_since(earlier).unwrap_or_default()
    }

    /// Returns the amount of time elapsed since this instant was created.
    ///
    /// # Panics
    ///
    /// This function may panic if the current time is earlier than this
    /// instant, which is something that can happen if an `Instant` is
    /// produced synthetically.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use std::thread::sleep;
    ///
    /// use minstant::Instant;
    ///
    /// let instant = Instant::now();
    /// let three_secs = Duration::from_secs(3);
    /// sleep(three_secs);
    /// assert!(instant.elapsed() >= three_secs);
    /// ```
    #[inline]
    pub fn elapsed(&self) -> Duration {
        Instant::now() - *self
    }

    /// Returns `Some(t)` where `t` is the time `self + duration` if `t` can be represented as
    /// `Instant` (which means it's inside the bounds of the underlying data structure), `None`
    /// otherwise.
    #[inline]
    pub fn checked_add(&self, duration: Duration) -> Option<Instant> {
        self.0
            .checked_add((duration.as_nanos() as u64 as f64 / tsc::nanos_per_cycle()) as u64)
            .map(Instant)
    }

    /// Returns `Some(t)` where `t` is the time `self - duration` if `t` can be represented as
    /// `Instant` (which means it's inside the bounds of the underlying data structure), `None`
    /// otherwise.
    #[inline]
    pub fn checked_sub(&self, duration: Duration) -> Option<Instant> {
        self.0
            .checked_sub((duration.as_nanos() as u64 as f64 / tsc::nanos_per_cycle()) as u64)
            .map(Instant)
    }

    /// Convert internal clocking counter into a UNIX timestamp represented as the
    /// nanoseconds elapsed from [UNIX_EPOCH](UNIX_EPOCH).
    ///
    /// [`Anchor`](Anchor) contains the necessary calibration data for conversion.
    /// Typically, initializing an [`Anchor`](Anchor) takes about 50 nanoseconds, so
    /// try to reuse it for a batch of `Instant`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::UNIX_EPOCH;
    /// use minstant::{Instant, Anchor};
    ///
    /// let anchor = Anchor::new();
    /// let instant = Instant::now();
    ///
    /// let expected = UNIX_EPOCH.elapsed().unwrap().as_nanos();
    /// assert!((instant.as_unix_nanos(&anchor) as i64 - expected as i64).abs() < 1_000_000);
    /// ```
    pub fn as_unix_nanos(&self, anchor: &Anchor) -> u64 {
        if self.0 > anchor.cycle {
            let forward_ns = ((self.0 - anchor.cycle) as f64 * tsc::nanos_per_cycle()) as u64;
            anchor.unix_time_ns + forward_ns
        } else {
            let backward_ns = ((anchor.cycle - self.0) as f64 * tsc::nanos_per_cycle()) as u64;
            anchor.unix_time_ns - backward_ns
        }
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    #[inline]
    fn add(self, other: Duration) -> Instant {
        self.checked_add(other)
            .expect("overflow when adding duration to instant")
    }
}

impl AddAssign<Duration> for Instant {
    #[inline]
    fn add_assign(&mut self, other: Duration) {
        *self = *self + other;
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;

    #[inline]
    fn sub(self, other: Duration) -> Instant {
        self.checked_sub(other)
            .expect("overflow when subtracting duration from instant")
    }
}

impl SubAssign<Duration> for Instant {
    #[inline]
    fn sub_assign(&mut self, other: Duration) {
        *self = *self - other;
    }
}

impl Sub<Instant> for Instant {
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
    fn sub(self, other: Instant) -> Duration {
        self.duration_since(other)
    }
}

impl std::fmt::Debug for Instant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// An anchor which can be used to convert internal clocking counter into system timestamp.
///
/// *[See also the `Instant::as_unix_nanos()`](Instant::as_unix_nanos).*
#[derive(Copy, Clone)]
pub struct Anchor {
    unix_time_ns: u64,
    cycle: u64,
}

impl Default for Anchor {
    fn default() -> Self {
        Self::new()
    }
}

impl Anchor {
    pub fn new() -> Anchor {
        let unix_time_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("unexpected time drift")
            .as_nanos() as u64;
        Anchor {
            unix_time_ns,
            cycle: tsc::tsc_from_ref(),
        }
    }
}
