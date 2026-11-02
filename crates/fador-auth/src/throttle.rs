//! Bounded rate limiting and login flood counters.
//!
//! Two different problems are solved here:
//!
//! - [`FixedWindowLimiter`] is a general per-key request limiter with a fixed
//!   window, a hard entry bound and sharded locks. It is what an anonymous
//!   request rate limit is built from.
//! - [`FloodCounter`] is SMF's `passwd_flood` format: one small string per
//!   account that counts recent failures without a table.
//! - [`LoginThrottle`] combines a per-account and a per-address failure limit
//!   on top of a [`LoginAttemptStore`].
//!
//! # Bounds
//!
//! The limiter never stores the key itself: it stores a hash, so an address or
//! an email cannot leak out of a memory dump and an attacker cannot grow the
//! table with long keys. The table is capped per shard; when a shard is full,
//! expired buckets are dropped first and the oldest bucket after that. A key
//! collision merges two counters, which is acceptable for a rate limit and is
//! the price of not keeping the key.

use crate::error::StoreResult;
use std::collections::HashMap;
use std::fmt;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::Mutex;

const SHARDS: usize = 16;
/// The default number of tracked keys in a [`FixedWindowLimiter`].
pub const DEFAULT_CAPACITY: usize = 4_096;
/// The longest username kept in a login-attempt record.
pub const MAX_ATTEMPT_USERNAME: usize = 255;

/// The answer of a rate limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleDecision {
    /// The request may proceed; `remaining` requests are left in the window.
    Allowed {
        /// Requests left in the current window.
        remaining: u32,
    },
    /// The request must be refused.
    Limited {
        /// Seconds until the window resets.
        retry_after: i64,
    },
}

impl ThrottleDecision {
    /// Whether the request may proceed.
    pub fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    /// The `Retry-After` value when the request is limited.
    pub fn retry_after(self) -> Option<i64> {
        match self {
            Self::Limited { retry_after } => Some(retry_after),
            Self::Allowed { .. } => None,
        }
    }
}

#[derive(Debug)]
struct Bucket {
    window_start: i64,
    count: u32,
}

#[derive(Debug)]
struct Shard {
    map: Mutex<HashMap<u64, Bucket>>,
    capacity: usize,
}

impl Shard {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Bucket>> {
        // A panic in another thread must not take the limiter down with it.
        self.map.lock().unwrap_or_else(|error| error.into_inner())
    }
}

/// A fixed-window rate limiter with a hard entry bound.
///
/// ```
/// use fador_auth::throttle::FixedWindowLimiter;
///
/// let limiter = FixedWindowLimiter::new(2, 60);
/// assert!(limiter.check("203.0.113.7", 0).is_allowed());
/// assert!(limiter.check("203.0.113.7", 1).is_allowed());
/// let limited = limiter.check("203.0.113.7", 2);
/// assert_eq!(limited.retry_after(), Some(58));
/// ```
#[derive(Debug)]
pub struct FixedWindowLimiter {
    limit: u32,
    window: i64,
    hasher: std::collections::hash_map::RandomState,
    shards: [Shard; SHARDS],
}

impl FixedWindowLimiter {
    /// Create a limiter that allows `limit` requests per `window` seconds.
    ///
    /// `limit == 0` disables the limiter (every request is allowed with
    /// `u32::MAX` remaining). A `window` below one second is raised to one.
    pub fn new(limit: u32, window: i64) -> Self {
        Self::with_capacity(limit, window, DEFAULT_CAPACITY)
    }

    /// Create a limiter with an explicit entry bound.
    pub fn with_capacity(limit: u32, window: i64, capacity: usize) -> Self {
        let capacity_per_shard = capacity.div_ceil(SHARDS).max(1);
        Self {
            limit,
            window: window.max(1),
            hasher: std::collections::hash_map::RandomState::new(),
            shards: std::array::from_fn(|_| Shard {
                map: Mutex::new(HashMap::new()),
                capacity: capacity_per_shard,
            }),
        }
    }

    /// The configured limit.
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// The window length in seconds.
    pub fn window(&self) -> i64 {
        self.window
    }

    /// The nominal entry bound, rounded up to a whole number of shards.
    pub fn capacity(&self) -> usize {
        self.shards[0].capacity * SHARDS
    }

    /// Count one request for `key`.
    pub fn check(&self, key: &str, now: i64) -> ThrottleDecision {
        if self.limit == 0 {
            return ThrottleDecision::Allowed {
                remaining: u32::MAX,
            };
        }
        let hash = self.hasher.hash_one(key);
        let shard = &self.shards[(hash as usize) % SHARDS];
        let mut map = shard.lock();
        let elapsed = now.rem_euclid(self.window);
        let window_start = now.saturating_sub(elapsed);
        if !map.contains_key(&hash) && map.len() >= shard.capacity {
            map.retain(|_, bucket| bucket.window_start == window_start);
            while map.len() >= shard.capacity {
                let Some(oldest) = map
                    .iter()
                    .min_by_key(|(_, bucket)| (bucket.window_start, bucket.count))
                    .map(|(key, _)| *key)
                else {
                    break;
                };
                map.remove(&oldest);
            }
        }
        let bucket = map.entry(hash).or_insert(Bucket {
            window_start,
            count: 0,
        });
        if bucket.window_start != window_start {
            bucket.window_start = window_start;
            bucket.count = 0;
        }
        if bucket.count >= self.limit {
            return ThrottleDecision::Limited {
                retry_after: (self.window - elapsed).max(1),
            };
        }
        bucket.count += 1;
        ThrottleDecision::Allowed {
            remaining: self.limit - bucket.count,
        }
    }

    /// Read the current state for `key` without counting a request.
    pub fn peek(&self, key: &str, now: i64) -> ThrottleDecision {
        if self.limit == 0 {
            return ThrottleDecision::Allowed {
                remaining: u32::MAX,
            };
        }
        let hash = self.hasher.hash_one(key);
        let shard = &self.shards[(hash as usize) % SHARDS];
        let map = shard.lock();
        let elapsed = now.rem_euclid(self.window);
        let window_start = now.saturating_sub(elapsed);
        match map.get(&hash) {
            Some(bucket) if bucket.window_start == window_start && bucket.count >= self.limit => {
                ThrottleDecision::Limited {
                    retry_after: (self.window - elapsed).max(1),
                }
            }
            Some(bucket) if bucket.window_start == window_start => ThrottleDecision::Allowed {
                remaining: self.limit - bucket.count,
            },
            _ => ThrottleDecision::Allowed {
                remaining: self.limit,
            },
        }
    }

    /// Forget one key.
    pub fn reset(&self, key: &str) {
        let hash = self.hasher.hash_one(key);
        let shard = &self.shards[(hash as usize) % SHARDS];
        shard.lock().remove(&hash);
    }

    /// Forget every key.
    pub fn clear(&self) {
        for shard in &self.shards {
            shard.lock().clear();
        }
    }

    /// Number of tracked keys.
    pub fn len(&self) -> usize {
        self.shards.iter().map(|shard| shard.lock().len()).sum()
    }

    /// Whether no key is tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A login flood counter that does not fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloodError {
    /// The account has too many recent failures.
    BruteForce,
}

impl fmt::Display for FloodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BruteForce => write!(f, "too many failed login attempts"),
        }
    }
}

impl std::error::Error for FloodError {}

/// SMF's per-account password flood counter.
///
/// The stored value is `<timestamp>|<tries>`. A failure increments the count;
/// after [`FloodCounter::window`] seconds the count restarts at two, and after
/// [`FloodCounter::reset_after`] seconds the timestamp is refreshed, so an
/// attacker cannot keep an account locked forever by continuing to fail.
///
/// ```
/// use fador_auth::throttle::FloodCounter;
///
/// let flood = FloodCounter::default();
/// assert_eq!(flood.validate("", 1_000, false).unwrap(), "1000|1");
/// assert_eq!(flood.validate("1000|1", 1_001, false).unwrap(), "1000|2");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloodCounter {
    /// The number of failures after which every attempt is refused.
    pub max_attempts: i64,
    /// After this many seconds the count restarts at two.
    pub window: i64,
    /// After this many seconds the timestamp is refreshed.
    pub reset_after: i64,
}

impl Default for FloodCounter {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            window: 20,
            reset_after: 10,
        }
    }
}

impl FloodCounter {
    /// Update the counter after one login attempt.
    ///
    /// `was_correct` clears the counter when this was the first attempt in the
    /// window, matching SMF's `validatePasswordFlood($value, $time, true)`.
    ///
    /// # Errors
    ///
    /// Returns [`FloodError::BruteForce`] when the account is over the limit.
    pub fn validate(&self, value: &str, now: i64, was_correct: bool) -> Result<String, FloodError> {
        if self.max_attempts <= 0 {
            return Ok(String::new());
        }
        let (mut timestamp, mut tries) = match value.split_once('|') {
            Some((timestamp, tries)) => match (timestamp.parse::<i64>(), tries.parse::<i64>()) {
                (Ok(timestamp), Ok(tries)) if timestamp > 0 && tries > 0 => (timestamp, tries),
                _ => (now, 0),
            },
            None => (now, 0),
        };
        if tries > 0 {
            if timestamp < now.saturating_sub(self.window) {
                if was_correct {
                    return Ok(String::new());
                }
                tries = 2;
            }
            if timestamp < now.saturating_sub(self.reset_after) {
                timestamp = now;
            }
        }
        tries = tries.saturating_add(1);
        if tries > self.max_attempts {
            return Err(FloodError::BruteForce);
        }
        Ok(if was_correct && tries == 1 {
            String::new()
        } else {
            format!("{timestamp}|{tries}")
        })
    }
}

/// One recorded login attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginAttempt<'a> {
    /// The account, when the submitted name resolved to one.
    pub user_id: Option<u64>,
    /// The client address.
    pub ip: Option<IpAddr>,
    /// The submitted login name, bounded by the store.
    pub username: &'a str,
    /// The attempt time.
    pub now: i64,
    /// Whether the attempt succeeded.
    pub success: bool,
}

/// Storage for login attempts.
pub trait LoginAttemptStore {
    /// Record one attempt.
    fn record(&self, attempt: &LoginAttempt<'_>) -> StoreResult<()>;
    /// Failed attempts for one account since `since`.
    fn user_failures(&self, user_id: u64, since: i64) -> StoreResult<u32>;
    /// Failed attempts from one address since `since`.
    fn ip_failures(&self, ip: IpAddr, since: i64) -> StoreResult<u32>;
    /// Forget an account's failures after a successful login.
    fn clear_user(&self, user_id: u64) -> StoreResult<()>;
}

/// A per-account and per-address login throttle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginThrottle {
    /// Failures allowed per account inside the window. `0` disables the check.
    pub user_limit: u32,
    /// Failures allowed per address inside the window. `0` disables the check.
    pub ip_limit: u32,
    /// The look-back window in seconds.
    pub window: i64,
}

impl Default for LoginThrottle {
    fn default() -> Self {
        Self {
            user_limit: 5,
            ip_limit: 20,
            window: 900,
        }
    }
}

impl LoginThrottle {
    /// Check whether another attempt may start.
    ///
    /// The `retry_after` value is the whole window: the store counts failures
    /// since a timestamp and does not report the oldest one.
    pub fn check(
        &self,
        store: &dyn LoginAttemptStore,
        user_id: Option<u64>,
        ip: Option<IpAddr>,
        now: i64,
    ) -> StoreResult<ThrottleDecision> {
        let since = now.saturating_sub(self.window);
        let mut remaining = u32::MAX;
        if let Some(user_id) = user_id.filter(|_| self.user_limit > 0) {
            let failures = store.user_failures(user_id, since)?;
            if failures >= self.user_limit {
                return Ok(ThrottleDecision::Limited {
                    retry_after: self.window,
                });
            }
            remaining = remaining.min(self.user_limit - failures);
        }
        if let Some(ip) = ip.filter(|_| self.ip_limit > 0) {
            let failures = store.ip_failures(ip, since)?;
            if failures >= self.ip_limit {
                return Ok(ThrottleDecision::Limited {
                    retry_after: self.window,
                });
            }
            remaining = remaining.min(self.ip_limit - failures);
        }
        Ok(ThrottleDecision::Allowed { remaining })
    }

    /// Record an attempt. A successful attempt clears the account counter.
    pub fn record(
        &self,
        store: &dyn LoginAttemptStore,
        attempt: &LoginAttempt<'_>,
    ) -> StoreResult<()> {
        store.record(attempt)?;
        if attempt.success {
            if let Some(user_id) = attempt.user_id {
                store.clear_user(user_id)?;
            }
        }
        Ok(())
    }
}

/// A recorded login attempt, as returned by
/// [`MemoryLoginAttemptStore::attempts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginAttemptRecord {
    /// The account, when the submitted name resolved to one.
    pub user_id: Option<u64>,
    /// The client address.
    pub ip: Option<IpAddr>,
    /// The submitted login name, bounded to [`MAX_ATTEMPT_USERNAME`].
    pub username: String,
    /// The attempt time.
    pub at: i64,
    /// Whether the attempt succeeded.
    pub success: bool,
}

/// A bounded in-memory [`LoginAttemptStore`].
#[derive(Debug)]
pub struct MemoryLoginAttemptStore {
    rows: Mutex<Vec<LoginAttemptRecord>>,
    capacity: usize,
}

impl MemoryLoginAttemptStore {
    /// Create a store holding at most `capacity` attempts.
    pub fn new(capacity: usize) -> Self {
        Self {
            rows: Mutex::new(Vec::new()),
            capacity: capacity.max(1),
        }
    }

    /// Number of recorded attempts.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether no attempt is recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The recorded attempts, oldest first.
    pub fn attempts(&self) -> Vec<LoginAttemptRecord> {
        self.lock().clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<LoginAttemptRecord>> {
        self.rows.lock().unwrap_or_else(|error| error.into_inner())
    }
}

impl Default for MemoryLoginAttemptStore {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl LoginAttemptStore for MemoryLoginAttemptStore {
    fn record(&self, attempt: &LoginAttempt<'_>) -> StoreResult<()> {
        let mut rows = self.lock();
        if rows.len() >= self.capacity {
            let cutoff = attempt.now.saturating_sub(86_400);
            rows.retain(|row| row.at >= cutoff);
            if rows.len() >= self.capacity {
                let index = rows.iter().position(|row| row.user_id.is_none()).unwrap_or(0);
                rows.remove(index);
            }
        }
        rows.push(LoginAttemptRecord {
            user_id: attempt.user_id,
            ip: attempt.ip,
            username: attempt
                .username
                .chars()
                .take(MAX_ATTEMPT_USERNAME)
                .collect(),
            at: attempt.now,
            success: attempt.success,
        });
        Ok(())
    }

    fn user_failures(&self, user_id: u64, since: i64) -> StoreResult<u32> {
        Ok(self
            .lock()
            .iter()
            .filter(|row| !row.success && row.user_id == Some(user_id) && row.at >= since)
            .count() as u32)
    }

    fn ip_failures(&self, ip: IpAddr, since: i64) -> StoreResult<u32> {
        Ok(self
            .lock()
            .iter()
            .filter(|row| !row.success && row.ip == Some(ip) && row.at >= since)
            .count() as u32)
    }

    fn clear_user(&self, user_id: u64) -> StoreResult<()> {
        self.lock().retain(|row| row.user_id != Some(user_id));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn limiter_allows_the_limit_and_reports_retry_after() {
        let limiter = FixedWindowLimiter::new(3, 60);
        assert_eq!(
            limiter.check("key", 0),
            ThrottleDecision::Allowed { remaining: 2 }
        );
        assert_eq!(
            limiter.check("key", 1),
            ThrottleDecision::Allowed { remaining: 1 }
        );
        assert_eq!(
            limiter.check("key", 2),
            ThrottleDecision::Allowed { remaining: 0 }
        );
        assert_eq!(
            limiter.check("key", 3),
            ThrottleDecision::Limited { retry_after: 57 }
        );
        // Another key has its own window.
        assert!(limiter.check("other", 3).is_allowed());
        // The next epoch-aligned window starts fresh.
        assert_eq!(
            limiter.check("key", 60),
            ThrottleDecision::Allowed { remaining: 2 }
        );
        for extreme in [i64::MIN, i64::MAX] {
            let _ = limiter.check("extreme", extreme);
            let _ = limiter.peek("extreme", extreme);
        }
    }

    #[test]
    fn limit_zero_disables_the_limiter() {
        let limiter = FixedWindowLimiter::new(0, 60);
        for now in 0..100 {
            assert_eq!(
                limiter.check("key", now),
                ThrottleDecision::Allowed {
                    remaining: u32::MAX
                }
            );
        }
        assert!(limiter.is_empty());
    }

    #[test]
    fn peek_does_not_consume_and_reset_forgets() {
        let limiter = FixedWindowLimiter::new(1, 60);
        assert_eq!(
            limiter.peek("key", 0),
            ThrottleDecision::Allowed { remaining: 1 }
        );
        assert!(limiter.check("key", 0).is_allowed());
        assert_eq!(
            limiter.peek("key", 1),
            ThrottleDecision::Limited { retry_after: 59 }
        );
        limiter.reset("key");
        assert_eq!(limiter.len(), 0);
        assert!(limiter.check("key", 2).is_allowed());
        limiter.clear();
        assert!(limiter.is_empty());
    }

    #[test]
    fn the_table_is_bounded() {
        let limiter = FixedWindowLimiter::with_capacity(1, 60, 64);
        for index in 0..10_000 {
            let _ = limiter.check(&format!("key-{index}"), 0);
            assert!(
                limiter.len() <= limiter.capacity(),
                "{} > {}",
                limiter.len(),
                limiter.capacity()
            );
        }
        assert!(limiter.capacity() >= 64);
    }

    #[test]
    fn stale_buckets_are_dropped_first() {
        let limiter = FixedWindowLimiter::with_capacity(1, 60, 16);
        for index in 0..16 {
            let _ = limiter.check(&format!("old-{index}"), 0);
        }
        // A new window lets the limiter reuse the table instead of evicting a
        // current bucket.
        let _ = limiter.check("new", 60);
        assert!(limiter.len() <= limiter.capacity());
    }

    #[test]
    fn flood_counter_matches_the_smf_behaviour() {
        let flood = FloodCounter::default();
        assert_eq!(flood.validate("", 1_000, true).unwrap(), "");
        assert_eq!(flood.validate("", 1_000, false).unwrap(), "1000|1");
        assert_eq!(flood.validate("1000|1", 1_001, false).unwrap(), "1000|2");
        assert_eq!(flood.validate("1000|1", 1_030, false).unwrap(), "1030|3");
        assert_eq!(
            flood.validate("1000|5", 1_001, true),
            Err(FloodError::BruteForce)
        );
        assert_eq!(flood.validate("1000|5", 1_030, true).unwrap(), "");
        assert_eq!(
            flood.validate("1000|6", 1_001, false),
            Err(FloodError::BruteForce)
        );
        assert_eq!(flood.validate("garbage", 1_000, false).unwrap(), "1000|1");
        assert_eq!(flood.validate("0|0", 1_000, false).unwrap(), "1000|1");
        assert_eq!(flood.validate("-1|3", 1_000, false).unwrap(), "1000|1");
        assert_eq!(flood.validate("1|2|3", 1_000, false).unwrap(), "1000|1");
        assert_eq!(flood.validate("1000|1", i64::MIN, false).unwrap(), "1000|2");
    }

    #[test]
    fn a_zero_flood_limit_disables_the_counter() {
        let flood = FloodCounter {
            max_attempts: 0,
            ..FloodCounter::default()
        };
        assert_eq!(flood.validate("1000|99", 1_000, false).unwrap(), "");
    }

    fn store() -> MemoryLoginAttemptStore {
        MemoryLoginAttemptStore::new(100)
    }

    fn attempt(user_id: Option<u64>, ip: &str, now: i64, success: bool) -> LoginAttempt<'_> {
        LoginAttempt {
            user_id,
            ip: Some(ip.parse().unwrap()),
            username: "Test",
            now,
            success,
        }
    }

    #[test]
    fn login_throttle_counts_per_user_and_per_address() {
        let store = store();
        let throttle = LoginThrottle {
            user_limit: 2,
            ip_limit: 3,
            window: 60,
        };
        let ip = Ipv4Addr::new(192, 0, 2, 7);
        assert!(throttle
            .check(&store, Some(7), Some(IpAddr::V4(ip)), 1_000)
            .unwrap()
            .is_allowed());
        throttle
            .record(&store, &attempt(Some(7), "192.0.2.7", 1_000, false))
            .unwrap();
        throttle
            .record(&store, &attempt(Some(7), "192.0.2.7", 1_001, false))
            .unwrap();
        assert_eq!(
            throttle
                .check(&store, Some(7), Some(IpAddr::V4(ip)), 1_002)
                .unwrap(),
            ThrottleDecision::Limited { retry_after: 60 }
        );
        // Another account from the same address still has the address budget.
        assert!(throttle
            .check(&store, Some(8), Some(IpAddr::V4(ip)), 1_002)
            .unwrap()
            .is_allowed());

        throttle
            .record(&store, &attempt(Some(8), "192.0.2.7", 1_003, false))
            .unwrap();
        assert_eq!(
            throttle
                .check(&store, Some(9), Some(IpAddr::V4(ip)), 1_004)
                .unwrap(),
            ThrottleDecision::Limited { retry_after: 60 }
        );
        // Outside the window the failures are forgotten.
        assert!(throttle
            .check(&store, Some(7), Some(IpAddr::V4(ip)), 2_000)
            .unwrap()
            .is_allowed());
    }

    #[test]
    fn a_successful_login_clears_the_account_counter() {
        let store = store();
        let throttle = LoginThrottle::default();
        for now in 0..4 {
            throttle
                .record(&store, &attempt(Some(7), "192.0.2.7", now, false))
                .unwrap();
        }
        assert_eq!(store.user_failures(7, 0).unwrap(), 4);
        throttle
            .record(&store, &attempt(Some(7), "192.0.2.7", 5, true))
            .unwrap();
        assert_eq!(store.user_failures(7, 0).unwrap(), 0);
        assert_eq!(
            store.ip_failures("192.0.2.7".parse().unwrap(), 0).unwrap(),
            0
        );
    }

    #[test]
    fn disabled_limits_allow_everything() {
        let store = store();
        let throttle = LoginThrottle {
            user_limit: 0,
            ip_limit: 0,
            window: 60,
        };
        for now in 0..100 {
            throttle
                .record(&store, &attempt(Some(7), "192.0.2.7", now, false))
                .unwrap();
        }
        assert!(throttle
            .check(&store, Some(7), Some("192.0.2.7".parse().unwrap()), 100)
            .unwrap()
            .is_allowed());
    }

    #[test]
    fn the_attempt_store_is_bounded_and_bounds_names() {
        let store = MemoryLoginAttemptStore::new(3);
        for now in 0..10 {
            let name = "ä".repeat(MAX_ATTEMPT_USERNAME + 10);
            let attempt = LoginAttempt {
                user_id: Some(7),
                ip: None,
                username: &name,
                now,
                success: false,
            };
            store.record(&attempt).unwrap();
        }
        assert_eq!(store.len(), 3);
        {
            let rows = store.lock();
            assert_eq!(rows[0].username.chars().count(), MAX_ATTEMPT_USERNAME);
        }

        // Prefers evicting unknown-user attempts over known-user attempts.
        let store = MemoryLoginAttemptStore::new(2);
        store.record(&attempt(Some(7), "192.0.2.1", 1_000, false)).unwrap();
        store.record(&attempt(None, "192.0.2.2", 1_001, false)).unwrap();
        store.record(&attempt(None, "192.0.2.3", 1_002, false)).unwrap();
        assert_eq!(store.user_failures(7, 0).unwrap(), 1);
    }
}
