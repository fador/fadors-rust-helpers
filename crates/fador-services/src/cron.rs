//! Cron leader election, execution locking and status reporting.
//!
//! A long-running server runs one scheduler thread. The thread holds a
//! heartbeat *leader* lock so that several server processes elect exactly one
//! scheduler, and every execution additionally takes a short *run* lock so an
//! internal tick and a manual or web trigger can never run the same task twice
//! at the same time.
//!
//! Both locks are files containing `<token> <unix-time>`. A lock whose
//! timestamp is older than the caller's stale window is removed and re-created,
//! so a crashed process cannot block the scheduler forever. The status file is
//! written next to the leader lock as `<lock>.status` with an atomic
//! temporary-file rename.
//!
//! The crate owns no clock beyond [`unix_now`] and no task: the caller passes
//! the work as a closure that returns the number of delivered items.
//!
//! ```no_run
//! use fador_services::cron::{run_once, RunOutcome, RunSource};
//! use std::path::Path;
//!
//! let outcome = run_once(Path::new("temp/cron.lock"), RunSource::Manual, 1_000, || 3);
//! match outcome {
//!     RunOutcome::Done(run) => assert_eq!(run.sent, 3),
//!     RunOutcome::Locked => { /* another trigger is running */ }
//!     RunOutcome::Panicked => { /* the status file records `panic` */ }
//! }
//! ```
//!
//! # Bounds
//!
//! | item | limit |
//! | --- | --- |
//! | scheduler interval | 5-3,600 seconds (clamped by [`clamp_interval`]) |
//! | leader stale window | at least 120 seconds, or three intervals |
//! | run lock stale window | 900 seconds |
//! | status file | 8 KiB |

use fador_core::random::random_hex;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Shortest scheduler interval accepted by [`clamp_interval`], in seconds.
pub const MIN_INTERVAL_SECONDS: u64 = 5;
/// Longest scheduler interval accepted by [`clamp_interval`], in seconds.
pub const MAX_INTERVAL_SECONDS: u64 = 3_600;
/// A leader heartbeat older than this is stolen even with a short interval.
pub const LEADER_STALE_MIN_SECONDS: i64 = 120;
/// A run lock older than this is considered abandoned.
pub const RUN_STALE_SECONDS: i64 = 900;
/// Largest status file this crate reads, in bytes.
pub const STATUS_MAX_BYTES: u64 = 8 * 1024;

/// Current Unix time in seconds.
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// Clamp a configured interval to [`MIN_INTERVAL_SECONDS`]..=[`MAX_INTERVAL_SECONDS`].
pub fn clamp_interval(seconds: u64) -> Duration {
    Duration::from_secs(seconds.clamp(MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS))
}

/// Result of one bounded run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CronRun {
    /// Items the task reported as delivered.
    pub sent: usize,
    /// Wall time of the task, in milliseconds.
    pub duration_ms: u64,
}

/// The outcome recorded in the status file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusResult {
    /// The task finished.
    Ok,
    /// The task reported an error.
    Error,
    /// The task panicked; the scheduler keeps running.
    Panic,
}

impl StatusResult {
    /// The token stored in the status file.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Panic => "panic",
        }
    }

    /// Parse a status token.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ok" => Some(Self::Ok),
            "error" => Some(Self::Error),
            "panic" => Some(Self::Panic),
            _ => None,
        }
    }
}

/// Who triggered a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunSource {
    /// The internal scheduler thread.
    Scheduler,
    /// An administrator's manual trigger.
    Manual,
    /// An HTTP cron endpoint.
    Web,
}

impl RunSource {
    /// The token stored in the status file.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scheduler => "scheduler",
            Self::Manual => "manual",
            Self::Web => "web",
        }
    }

    /// Parse a source token.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "scheduler" => Some(Self::Scheduler),
            "manual" => Some(Self::Manual),
            "web" => Some(Self::Web),
            _ => None,
        }
    }
}

/// Persisted state of the last run.
///
/// ```text
/// # fador-services cron status
/// last_run=<unix time>
/// duration_ms=<milliseconds>
/// result=ok|error|panic
/// sent=<items delivered>
/// source=scheduler|manual|web
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CronStatus {
    /// When the run started, as a Unix timestamp.
    pub last_run: i64,
    /// Wall time of the task, in milliseconds.
    pub duration_ms: u64,
    /// How the task ended.
    pub result: StatusResult,
    /// Items the task reported as delivered.
    pub sent: u64,
    /// Who triggered the run.
    pub source: RunSource,
}

impl CronStatus {
    /// The status of a run that finished.
    pub const fn ok(run: CronRun, source: RunSource, now: i64) -> Self {
        Self {
            last_run: now,
            duration_ms: run.duration_ms,
            result: StatusResult::Ok,
            sent: run.sent as u64,
            source,
        }
    }

    /// The status of a run that failed or panicked.
    pub const fn failed(
        result: StatusResult,
        duration_ms: u64,
        source: RunSource,
        now: i64,
    ) -> Self {
        Self {
            last_run: now,
            duration_ms,
            result,
            sent: 0,
            source,
        }
    }
}

/// Render the status file format.
pub fn format_status(status: &CronStatus) -> String {
    format!(
        "# fador-services cron status\nlast_run={}\nduration_ms={}\nresult={}\nsent={}\nsource={}\n",
        status.last_run,
        status.duration_ms,
        status.result.as_str(),
        status.sent,
        status.source.as_str()
    )
}

/// Parse a status file.
///
/// Unknown keys, comments and blank lines are ignored. A missing or
/// non-numeric `last_run` makes the whole file unusable; an unknown `result`
/// or `source` falls back to `ok` and `scheduler`.
pub fn parse_status(text: &str) -> Option<CronStatus> {
    let mut last_run = None;
    let mut duration_ms = 0u64;
    let mut result = StatusResult::Ok;
    let mut sent = 0u64;
    let mut source = RunSource::Scheduler;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "last_run" => last_run = value.parse::<i64>().ok(),
            "duration_ms" => duration_ms = value.parse().unwrap_or(0),
            "result" => {
                if let Some(parsed) = StatusResult::parse(value) {
                    result = parsed;
                }
            }
            "sent" => sent = value.parse().unwrap_or(0),
            "source" => {
                if let Some(parsed) = RunSource::parse(value) {
                    source = parsed;
                }
            }
            _ => {}
        }
    }
    Some(CronStatus {
        last_run: last_run?,
        duration_ms,
        result,
        sent,
        source,
    })
}

/// `<leader_lock>.status`
pub fn status_path(leader_lock: &Path) -> PathBuf {
    append_suffix(leader_lock, ".status")
}

/// `<leader_lock>.run`
pub fn run_lock_path(leader_lock: &Path) -> PathBuf {
    append_suffix(leader_lock, ".run")
}

/// Read the last status, or `None` when the file is missing, too large or
/// unusable.
pub fn read_status(leader_lock: &Path) -> Option<CronStatus> {
    let file = fs::File::open(status_path(leader_lock)).ok()?;
    let mut text = String::new();
    file.take(STATUS_MAX_BYTES + 1)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() as u64 > STATUS_MAX_BYTES {
        return None;
    }
    parse_status(&text)
}

/// Write the status file atomically.
pub fn write_status(leader_lock: &Path, status: &CronStatus) -> std::io::Result<()> {
    write_atomic(&status_path(leader_lock), format_status(status).as_bytes())
}

/// Outcome of [`run_once`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunOutcome {
    /// Another trigger holds the run lock.
    Locked,
    /// The task finished; the status file has been updated.
    Done(CronRun),
    /// The task panicked; the status file records `panic`.
    Panicked,
}

/// Run one task under the run lock.
///
/// The lock lives at [`run_lock_path`] and is released when the task returns.
/// A task that panics is caught, recorded as `panic` and reported as
/// [`RunOutcome::Panicked`]; the caller's process keeps running.
pub fn run_once<F>(leader_lock: &Path, source: RunSource, now: i64, task: F) -> RunOutcome
where
    F: FnOnce() -> usize,
{
    let Some(_guard) = RunLock::acquire(run_lock_path(leader_lock), now, RUN_STALE_SECONDS) else {
        return RunOutcome::Locked;
    };
    let started = Instant::now();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(task)) {
        Ok(sent) => {
            let run = CronRun {
                sent,
                duration_ms: started.elapsed().as_millis() as u64,
            };
            let _ = write_status(leader_lock, &CronStatus::ok(run, source, now));
            RunOutcome::Done(run)
        }
        Err(_) => {
            let duration_ms = started.elapsed().as_millis() as u64;
            let _ = write_status(
                leader_lock,
                &CronStatus::failed(StatusResult::Panic, duration_ms, source, now),
            );
            RunOutcome::Panicked
        }
    }
}

/// Scheduler thread settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerConfig {
    /// Leader lock path. The run lock and the status file are derived from it.
    pub lock_path: PathBuf,
    /// Time between ticks. [`SchedulerConfig::new`] clamps it; a caller that
    /// builds the struct directly is responsible for a sane value.
    pub interval: Duration,
}

impl SchedulerConfig {
    /// A configuration with a clamped interval.
    pub fn new(lock_path: impl Into<PathBuf>, interval_seconds: u64) -> Self {
        Self {
            lock_path: lock_path.into(),
            interval: clamp_interval(interval_seconds),
        }
    }
}

/// A running scheduler thread.
pub struct SchedulerHandle {
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl SchedulerHandle {
    /// Ask the thread to stop after the current tick. This does not block.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Whether [`SchedulerHandle::stop`] has been called.
    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Stop and wait for the thread to finish.
    pub fn join(mut self) {
        self.stop();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for SchedulerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start the scheduler thread.
///
/// Each tick refreshes the leader lock and, when this process is the leader,
/// runs the task through [`run_once`]. The task is called on the scheduler
/// thread, so it must not block forever; a panic is caught and recorded.
pub fn spawn<F>(config: SchedulerConfig, task: F) -> std::io::Result<SchedulerHandle>
where
    F: FnMut() -> usize + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let join = thread::Builder::new()
        .name("fador-cron".into())
        .spawn(move || scheduler_loop(config, task, stop_flag))?;
    Ok(SchedulerHandle {
        stop,
        join: Some(join),
    })
}

fn scheduler_loop<F>(config: SchedulerConfig, mut task: F, stop: Arc<AtomicBool>)
where
    F: FnMut() -> usize,
{
    let interval = config.interval.max(Duration::from_millis(10));
    let stale_after = (interval.as_secs() as i64)
        .saturating_mul(3)
        .max(LEADER_STALE_MIN_SECONDS);
    let mut leader = LeaderLock::new(config.lock_path.clone());
    while !stop.load(Ordering::Relaxed) {
        let now = unix_now();
        if leader.refresh(now, stale_after) {
            let _ = run_once(&config.lock_path, RunSource::Scheduler, now, &mut task);
        }
        sleep_until(&stop, interval);
    }
}

fn sleep_until(stop: &AtomicBool, interval: Duration) {
    let deadline = Instant::now() + interval;
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        let remaining = deadline - now;
        thread::sleep(remaining.min(Duration::from_millis(25)));
    }
}

// ---------------------------------------------------------------------------
// Locks
// ---------------------------------------------------------------------------

/// Heartbeat leader-election lock.
///
/// The file contains `<token> <unix-time>` and is refreshed every scheduler
/// tick. A process that finds a fresh file owned by another token stays a
/// follower; a stale file is removed and re-created with its own token. The run
/// lock still serialises the actual work, so a brief takeover race cannot
/// duplicate deliveries.
#[derive(Debug)]
pub struct LeaderLock {
    path: PathBuf,
    token: String,
    held: bool,
}

impl LeaderLock {
    /// Create a lock with a fresh random token. Nothing is written until
    /// [`LeaderLock::refresh`] is called.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            token: random_hex(8),
            held: false,
        }
    }

    /// Refresh the heartbeat and report whether this instance is the leader.
    ///
    /// `stale_after` is the age in seconds after which another process's
    /// heartbeat may be stolen; a negative value is treated as zero.
    pub fn refresh(&mut self, now: i64, stale_after: i64) -> bool {
        let stale_after = stale_after.max(0);
        match fs::read_to_string(&self.path) {
            Ok(content) if content.starts_with(&self.token) => {
                if write_atomic(&self.path, lock_contents(&self.token, now).as_bytes()).is_ok() {
                    self.held = true;
                    return true;
                }
            }
            Ok(content) => {
                let fresh = lock_timestamp(&content)
                    .map(|timestamp| now.saturating_sub(timestamp) <= stale_after)
                    .unwrap_or(false);
                if fresh {
                    self.held = false;
                    return false;
                }
                let _ = fs::remove_file(&self.path);
            }
            Err(_) => {}
        }
        self.held = false;
        if write_lock_new(&self.path, &self.token, now).is_ok() {
            self.held = true;
            true
        } else {
            false
        }
    }

    /// Whether the last [`LeaderLock::refresh`] acquired or kept the lock.
    pub fn is_held(&self) -> bool {
        self.held
    }

    /// The lock file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// This instance's random token.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Remove the lock file when this instance still owns it.
    pub fn release(&mut self) {
        if !self.held {
            return;
        }
        if let Ok(content) = fs::read_to_string(&self.path) {
            if content.starts_with(&self.token) {
                let _ = fs::remove_file(&self.path);
            }
        }
        self.held = false;
    }
}

impl Drop for LeaderLock {
    fn drop(&mut self) {
        self.release();
    }
}

/// Short-lived execution lock taken by every trigger.
#[derive(Debug)]
pub struct RunLock {
    path: PathBuf,
    token: String,
}

impl RunLock {
    /// Take the run lock, or `None` when a fresh lock is already held.
    ///
    /// A lock file older than `stale_after` seconds is removed first, so a
    /// process that died mid-run cannot block every later trigger.
    pub fn acquire(path: impl Into<PathBuf>, now: i64, stale_after: i64) -> Option<Self> {
        let path = path.into();
        if let Ok(content) = fs::read_to_string(&path) {
            let fresh = lock_timestamp(&content)
                .map(|timestamp| now.saturating_sub(timestamp) <= stale_after.max(0))
                .unwrap_or(false);
            if fresh {
                return None;
            }
            let _ = fs::remove_file(&path);
        }
        let token = random_hex(8);
        write_lock_new(&path, &token, now).ok()?;
        Some(Self { path, token })
    }

    /// The lock file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// This instance's random token.
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl Drop for RunLock {
    fn drop(&mut self) {
        if let Ok(content) = fs::read_to_string(&self.path) {
            if content.starts_with(&self.token) {
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn lock_timestamp(content: &str) -> Option<i64> {
    content.split_whitespace().nth(1)?.parse().ok()
}

fn lock_contents(token: &str, timestamp: i64) -> String {
    format!("{token} {timestamp}\n")
}

fn write_lock_new(path: &Path, token: &str, timestamp: i64) -> std::io::Result<()> {
    ensure_parent(path)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(lock_contents(token, timestamp).as_bytes())?;
    file.sync_all()
}

fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    ensure_parent(path)?;
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(format!(".tmp-{}", random_hex(4)));
    let temporary = PathBuf::from(temporary);
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    match fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error)
        }
    }
}

fn ensure_parent(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => fs::create_dir_all(parent),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn temp_dir(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "fador-services-cron-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn leader_lock_is_exclusive_and_refreshes() {
        let dir = temp_dir("leader");
        let path = dir.join("cron.lock");
        let mut first = LeaderLock::new(path.clone());
        let mut second = LeaderLock::new(path.clone());

        assert!(first.refresh(1_000, 300));
        assert!(!second.refresh(1_000, 300));
        assert!(first.is_held());
        assert!(!second.is_held());
        assert!(first.refresh(1_100, 300));
        assert!(!second.refresh(1_100, 300));
        first.release();
        assert!(!first.is_held());
        assert!(second.refresh(1_200, 300));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn stale_leader_is_stolen_but_a_fresh_owner_is_not() {
        let dir = temp_dir("stale");
        let path = dir.join("cron.lock");
        fs::create_dir_all(&dir).expect("dir");
        write_lock_new(&path, "other", 1_000).expect("lock");

        let mut lock = LeaderLock::new(path.clone());
        assert!(!lock.refresh(1_200, 300));
        assert!(lock.refresh(1_301, 300));
        let content = fs::read_to_string(&path).expect("content");
        assert!(content.starts_with(lock.token()));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn run_lock_serialises_execution_and_recovers_stale_files() {
        let dir = temp_dir("run");
        let path = dir.join("cron.lock.run");
        let first = RunLock::acquire(path.clone(), 1_000, 900).expect("first run lock");
        assert!(RunLock::acquire(path.clone(), 1_000, 900).is_none());
        drop(first);
        assert!(RunLock::acquire(path.clone(), 1_000, 900).is_some());

        write_lock_new(&path, "stale", 1_000).expect("stale lock");
        assert!(RunLock::acquire(path.clone(), 1_901, 900).is_some());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn status_round_trips_through_the_file() {
        let dir = temp_dir("status");
        let lock = dir.join("cron.lock");
        let status = CronStatus {
            last_run: 1_792_842_548,
            duration_ms: 42,
            result: StatusResult::Ok,
            sent: 3,
            source: RunSource::Manual,
        };
        assert_eq!(status_path(&lock), dir.join("cron.lock.status"));
        assert_eq!(run_lock_path(&lock), dir.join("cron.lock.run"));
        write_status(&lock, &status).expect("write status");
        assert_eq!(read_status(&lock), Some(status));
        assert_eq!(parse_status(&format_status(&status)), Some(status));

        // Unknown keys, comments and blank lines are ignored.
        let tolerant = parse_status(
            "# comment\n\nlast_run=100\nunknown=1\nresult=bogus\nsent=notanumber\nsource=other\n",
        )
        .expect("parse");
        assert_eq!(tolerant.last_run, 100);
        assert_eq!(tolerant.result, StatusResult::Ok);
        assert_eq!(tolerant.sent, 0);
        assert_eq!(tolerant.source, RunSource::Scheduler);
        assert!(parse_status("result=ok\n").is_none());
        assert!(parse_status("").is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_status_keeps_the_documented_shape() {
        let failed = CronStatus::failed(StatusResult::Panic, 5, RunSource::Scheduler, 900);
        assert_eq!(failed.result, StatusResult::Panic);
        assert_eq!(failed.sent, 0);
        assert_eq!(failed.duration_ms, 5);
        assert_eq!(parse_status(&format_status(&failed)), Some(failed));
        assert_eq!(StatusResult::Error.as_str(), "error");
        assert_eq!(StatusResult::parse("panic"), Some(StatusResult::Panic));
        assert_eq!(RunSource::parse("web"), Some(RunSource::Web));
        assert_eq!(RunSource::parse("cron"), None);
    }

    #[test]
    fn run_once_records_the_result() {
        let dir = temp_dir("once");
        let lock = dir.join("cron.lock");
        let outcome = run_once(&lock, RunSource::Manual, 1_000, || 3);
        match outcome {
            RunOutcome::Done(run) => assert_eq!(run.sent, 3),
            other => panic!("unexpected outcome: {other:?}"),
        }
        let status = read_status(&lock).expect("status");
        assert_eq!(status.last_run, 1_000);
        assert_eq!(status.sent, 3);
        assert_eq!(status.source, RunSource::Manual);
        assert_eq!(status.result, StatusResult::Ok);
        assert!(!run_lock_path(&lock).exists(), "the run lock is released");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn run_once_reports_a_locked_trigger() {
        let dir = temp_dir("locked");
        let lock = dir.join("cron.lock");
        let held = RunLock::acquire(run_lock_path(&lock), 1_000, RUN_STALE_SECONDS).expect("lock");
        assert_eq!(
            run_once(&lock, RunSource::Web, 1_000, || 1),
            RunOutcome::Locked
        );
        drop(held);
        assert!(matches!(
            run_once(&lock, RunSource::Web, 1_000, || 1),
            RunOutcome::Done(_)
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn run_once_catches_a_panic() {
        let dir = temp_dir("panic");
        let lock = dir.join("cron.lock");
        let outcome = run_once(&lock, RunSource::Scheduler, 5, || {
            panic!("cron task panicked");
        });
        assert_eq!(outcome, RunOutcome::Panicked);
        let status = read_status(&lock).expect("status");
        assert_eq!(status.result, StatusResult::Panic);
        assert_eq!(status.sent, 0);
        assert_eq!(status.last_run, 5);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn interval_is_clamped() {
        assert_eq!(clamp_interval(0), Duration::from_secs(MIN_INTERVAL_SECONDS));
        assert_eq!(clamp_interval(10), Duration::from_secs(10));
        assert_eq!(
            clamp_interval(99_999),
            Duration::from_secs(MAX_INTERVAL_SECONDS)
        );
        let config = SchedulerConfig::new("temp/cron.lock", 0);
        assert_eq!(config.interval, Duration::from_secs(MIN_INTERVAL_SECONDS));
    }

    #[test]
    fn scheduler_runs_the_task_and_stops() {
        let dir = temp_dir("scheduler");
        let lock = dir.join("cron.lock");
        let counter = Arc::new(AtomicUsize::new(0));
        let task_counter = Arc::clone(&counter);
        let config = SchedulerConfig {
            lock_path: lock.clone(),
            interval: Duration::from_millis(20),
        };
        let handle = spawn(config, move || {
            task_counter.fetch_add(1, Ordering::SeqCst);
            1
        })
        .expect("spawn");
        let deadline = Instant::now() + Duration::from_secs(5);
        while counter.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        handle.stop();
        assert!(handle.is_stopped());
        handle.join();
        assert!(
            counter.load(Ordering::SeqCst) >= 2,
            "the scheduler did not run"
        );
        let status = read_status(&lock).expect("status");
        assert_eq!(status.source, RunSource::Scheduler);
        assert_eq!(status.result, StatusResult::Ok);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn status_parser_never_panics_on_hostile_input() {
        let mut rng = fador_testutil::Rng::new(0xc0de);
        for text in fador_testutil::MALICIOUS_STRINGS {
            let _ = parse_status(text);
        }
        for _ in 0..fador_testutil::iterations(2_000) {
            let length = 1 + rng.below(200);
            let text = rng.text(length);
            if let Some(status) = parse_status(&text) {
                assert!(!format_status(&status).contains('\0'));
            }
        }
    }
}
