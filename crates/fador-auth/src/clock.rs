//! Time sources.
//!
//! Every expiry check in this crate takes an explicit `now` value instead of
//! reading the clock. That keeps the logic pure and testable. A server that
//! wants the convenience wrappers uses [`Clock`], which has a production
//! implementation ([`SystemClock`]) and a deterministic one ([`ManualClock`]).

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of Unix time in seconds.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch.
    fn now(&self) -> i64;
}

/// The operating system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        unix_now()
    }
}

/// Seconds since the Unix epoch, or `0` when the system clock is before 1970.
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

/// A clock a test can advance by hand.
///
/// The value is shared through an atomic, so the clock can be handed to a
/// thread while the test keeps a handle to move time forward.
#[derive(Debug)]
pub struct ManualClock {
    now: AtomicI64,
}

impl ManualClock {
    /// Create a clock frozen at `now`.
    pub fn new(now: i64) -> Self {
        Self {
            now: AtomicI64::new(now),
        }
    }

    /// Move the clock forward (or back, for a negative value) and return the
    /// new time.
    pub fn advance(&self, seconds: i64) -> i64 {
        self.now.fetch_add(seconds, Ordering::SeqCst) + seconds
    }

    /// Set the clock to an absolute time.
    pub fn set(&self, now: i64) {
        self.now.store(now, Ordering::SeqCst);
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Clock for ManualClock {
    fn now(&self) -> i64 {
        self.now.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_after_2020() {
        assert!(SystemClock.now() > 1_577_836_800);
    }

    #[test]
    fn manual_clock_moves_only_when_told() {
        let clock = ManualClock::new(1_000);
        assert_eq!(clock.now(), 1_000);
        assert_eq!(clock.advance(60), 1_060);
        assert_eq!(clock.now(), 1_060);
        clock.set(42);
        assert_eq!(clock.now(), 42);
    }
}
