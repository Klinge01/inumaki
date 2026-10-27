//! Injected time source so rotation and expiry are testable.

use std::time::{SystemTime, UNIX_EPOCH};

/// Unix seconds.
pub trait Clock: Send + Sync {
    /// Current time in seconds since the Unix epoch.
    fn now(&self) -> i64;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }
}
