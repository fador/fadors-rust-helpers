//! Session identifiers, session records, expiry policy and remember-me keys.
//!
//! A session is a server-side record identified by an unguessable id. This
//! module keeps the record and its policy, not the storage: an application
//! implements [`SessionStore`] over its own table or a cache.
//!
//! # Rotation
//!
//! [`SessionManager::login`] always destroys the presented id and writes a
//! fresh one, even when the presented id was already valid. Keeping the id
//! across a login would let an attacker who planted a session id stay logged in
//! as the victim (session fixation). [`SessionManager::rotate`] does the same
//! for a password change or an administrator re-authentication.
//!
//! # Remember me
//!
//! A remember-me cookie carries a user id and a random token. Only the SHA-256
//! of the token is stored, so a database leak does not hand out login cookies.
//! [`RememberMeKey::rotate`] revokes the presented key and issues a new one.

use crate::error::{StoreError, StoreResult};
use fador_core::crypto::{hex, sha256};
use fador_core::random::{random_hex, try_random_bytes};
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Mutex;

/// Length of a session id in hexadecimal characters.
pub const SESSION_ID_LEN: usize = 32;
/// Longest user-agent string kept in a session record, in characters.
pub const MAX_USER_AGENT: usize = 255;

/// A validated session identifier: exactly 32 lowercase hexadecimal
/// characters.
///
/// The shape is checked before a store is asked for the row, so a hostile
/// cookie cannot turn into an arbitrary database key. Only the generated shape
/// is accepted: uppercase hex, a shorter SMF-style id or a URL-safe id is
/// rejected. That is deliberate, because a stored session id is always the one
/// this crate generated.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(String);

impl SessionId {
    /// Generate a session id from the operating system entropy source.
    ///
    /// Falls back to the mixed process seed of [`fador_core::random`] when the
    /// OS source is unavailable. Use [`SessionId::try_generate`] on a security
    /// boundary where a failure must abort the request.
    pub fn generate() -> Self {
        Self(random_hex(16))
    }

    /// Generate a session id, returning an error when the OS entropy source is
    /// unavailable.
    pub fn try_generate() -> Result<Self, StoreError> {
        let bytes = try_random_bytes(16).map_err(|error| StoreError::new(error.to_string()))?;
        Ok(Self(hex(&bytes)))
    }

    /// Validate a presented session id.
    pub fn parse(value: &str) -> Option<Self> {
        if Self::is_valid(value) {
            Some(Self(value.to_string()))
        } else {
            None
        }
    }

    /// Whether `value` has the generated shape.
    pub fn is_valid(value: &str) -> bool {
        value.len() == SESSION_ID_LEN
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }

    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the id and return its string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for SessionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for SessionId {
    type Err = StoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or_else(|| StoreError::new("invalid session id"))
    }
}

/// The connection attributes a session is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionBinding {
    /// The client address, after any trusted proxy handling.
    pub ip: Option<IpAddr>,
    /// The user agent string.
    pub user_agent: String,
}

impl SessionBinding {
    /// Create a binding from a client address and a user agent.
    pub fn new(ip: Option<IpAddr>, user_agent: impl Into<String>) -> Self {
        Self {
            ip,
            user_agent: bound_user_agent(&user_agent.into()),
        }
    }

    /// A binding with no address and an empty user agent.
    pub fn anonymous() -> Self {
        Self::default()
    }
}

/// Truncate a user agent to [`MAX_USER_AGENT`] characters on a character
/// boundary.
pub fn bound_user_agent(value: &str) -> String {
    value.chars().take(MAX_USER_AGENT).collect()
}

/// One stored session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// The session id.
    pub id: SessionId,
    /// The authenticated user, or `None` for a guest.
    pub user_id: Option<u64>,
    /// Creation time, used for the absolute expiry.
    pub created: i64,
    /// Last time the session was seen, used for the idle expiry.
    pub last_seen: i64,
    /// The address the session was created for, when known.
    pub ip: Option<IpAddr>,
    /// The user agent the session was created for, bounded to
    /// [`MAX_USER_AGENT`].
    pub user_agent: String,
    /// Whether the session was restored from a remember-me cookie.
    pub remember_me: bool,
    /// Whether the visitor re-authenticated as an administrator.
    pub admin: bool,
}

impl SessionRecord {
    /// Create a record for a user or a guest.
    pub fn new(id: SessionId, user_id: Option<u64>, now: i64, binding: &SessionBinding) -> Self {
        Self {
            id,
            user_id,
            created: now,
            last_seen: now,
            ip: binding.ip,
            user_agent: bound_user_agent(&binding.user_agent),
            remember_me: false,
            admin: false,
        }
    }

    /// Create a guest record.
    pub fn guest(id: SessionId, now: i64, binding: &SessionBinding) -> Self {
        Self::new(id, None, now, binding)
    }

    /// Create a record for an authenticated user.
    pub fn for_user(id: SessionId, user_id: u64, now: i64, binding: &SessionBinding) -> Self {
        Self::new(id, Some(user_id), now, binding)
    }

    /// Whether this is a guest session.
    pub fn is_guest(&self) -> bool {
        self.user_id.is_none()
    }
}

/// Why a session record is not usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionValidity {
    /// The record is current and matches its binding.
    Valid,
    /// The record has not been seen within the idle timeout.
    IdleExpired,
    /// The record was created longer ago than the absolute timeout.
    AbsoluteExpired,
    /// The request comes from another address.
    IpMismatch,
    /// The request comes from another user agent.
    UserAgentMismatch,
}

impl SessionValidity {
    /// Whether the record can be used.
    pub fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// The idle and absolute expiry rules, and the binding rules, of a session.
///
/// ```
/// use fador_auth::session::SessionPolicy;
///
/// let policy = SessionPolicy::default();
/// assert_eq!(policy.idle_timeout, 3_600);
/// assert_eq!(policy.absolute_timeout, 30 * 86_400);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPolicy {
    /// Seconds of inactivity after which a session is dead.
    pub idle_timeout: i64,
    /// Seconds after creation after which a session is dead regardless of
    /// activity.
    pub absolute_timeout: i64,
    /// Minimum number of seconds between two persisted `last_seen` updates.
    /// `0` persists on every request.
    pub touch_interval: i64,
    /// Whether the record is bound to its client address.
    pub bind_ip: bool,
    /// Whether the record is bound to its user agent.
    pub bind_user_agent: bool,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            idle_timeout: 3_600,
            absolute_timeout: 30 * 86_400,
            touch_interval: 60,
            bind_ip: true,
            bind_user_agent: true,
        }
    }
}

impl SessionPolicy {
    /// Reject a policy that cannot be satisfied.
    ///
    /// # Errors
    ///
    /// Returns an error when a timeout is not positive or when the touch
    /// interval is negative.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.idle_timeout <= 0 {
            return Err(StoreError::new("idle_timeout must be positive"));
        }
        if self.absolute_timeout <= 0 {
            return Err(StoreError::new("absolute_timeout must be positive"));
        }
        if self.touch_interval < 0 {
            return Err(StoreError::new("touch_interval must not be negative"));
        }
        Ok(())
    }

    /// Whether the record has reached either expiry.
    pub fn is_expired(&self, record: &SessionRecord, now: i64) -> bool {
        now.saturating_sub(record.created) > self.absolute_timeout
            || now.saturating_sub(record.last_seen) > self.idle_timeout
    }

    /// Evaluate a record against the policy and a request binding.
    pub fn check(
        &self,
        record: &SessionRecord,
        now: i64,
        binding: &SessionBinding,
    ) -> SessionValidity {
        if now.saturating_sub(record.created) > self.absolute_timeout {
            return SessionValidity::AbsoluteExpired;
        }
        if now.saturating_sub(record.last_seen) > self.idle_timeout {
            return SessionValidity::IdleExpired;
        }
        if self.bind_ip && record.ip != binding.ip {
            return SessionValidity::IpMismatch;
        }
        if self.bind_user_agent
            && bound_user_agent(&record.user_agent) != bound_user_agent(&binding.user_agent)
        {
            return SessionValidity::UserAgentMismatch;
        }
        SessionValidity::Valid
    }

    /// Whether the stored `last_seen` is old enough to be written again.
    ///
    /// Persisting a session row on every request turns a read-mostly board into
    /// a write-heavy one. The request still sees the current time in memory;
    /// only the stored row lags by at most `touch_interval` seconds.
    pub fn should_touch(&self, stored_last_seen: i64, now: i64) -> bool {
        self.touch_interval == 0 || now.saturating_sub(stored_last_seen) >= self.touch_interval
    }
}

/// Storage for session records.
///
/// `load` takes `&self` so an implementation can hold a connection pool or a
/// `Mutex` behind a shared reference.
pub trait SessionStore {
    /// Read one record by id.
    fn load(&self, id: &SessionId) -> StoreResult<Option<SessionRecord>>;
    /// Insert or replace one record.
    fn save(&self, record: &SessionRecord) -> StoreResult<()>;
    /// Delete one record. Deleting a missing record is not an error.
    fn destroy(&self, id: &SessionId) -> StoreResult<()>;
    /// Delete every record the policy considers expired and return the count.
    ///
    /// The default does nothing, for a store whose backend runs its own expiry
    /// job.
    fn gc(&self, now: i64, policy: &SessionPolicy) -> StoreResult<usize> {
        let _ = (now, policy);
        Ok(0)
    }
}

/// A bounded in-memory [`SessionStore`] for tests and single-process servers.
#[derive(Debug)]
pub struct MemorySessionStore {
    rows: Mutex<HashMap<String, SessionRecord>>,
    capacity: usize,
}

impl MemorySessionStore {
    /// Create a store holding at most `capacity` records. A capacity of `0` is
    /// raised to `1`.
    pub fn new(capacity: usize) -> Self {
        Self {
            rows: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Number of stored records.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, SessionRecord>> {
        self.rows.lock().unwrap_or_else(|error| error.into_inner())
    }
}

impl Default for MemorySessionStore {
    fn default() -> Self {
        Self::new(1_024)
    }
}

impl SessionStore for MemorySessionStore {
    fn load(&self, id: &SessionId) -> StoreResult<Option<SessionRecord>> {
        Ok(self.lock().get(id.as_str()).cloned())
    }

    fn save(&self, record: &SessionRecord) -> StoreResult<()> {
        let mut rows = self.lock();
        if !rows.contains_key(record.id.as_str()) && rows.len() >= self.capacity {
            if let Some(oldest) = rows
                .iter()
                .min_by_key(|(_, row)| row.last_seen)
                .map(|(id, _)| id.clone())
            {
                rows.remove(&oldest);
            }
        }
        rows.insert(record.id.as_str().to_string(), record.clone());
        Ok(())
    }

    fn destroy(&self, id: &SessionId) -> StoreResult<()> {
        self.lock().remove(id.as_str());
        Ok(())
    }

    fn gc(&self, now: i64, policy: &SessionPolicy) -> StoreResult<usize> {
        let mut rows = self.lock();
        let before = rows.len();
        rows.retain(|_, record| !policy.is_expired(record, now));
        Ok(before - rows.len())
    }
}

/// Loads, creates and rotates sessions in a [`SessionStore`].
#[derive(Debug)]
pub struct SessionManager<S> {
    store: S,
    policy: SessionPolicy,
}

impl<S: SessionStore> SessionManager<S> {
    /// Create a manager. The policy is validated by [`SessionManager::validate`]
    /// or by the caller; an invalid policy simply expires everything at once.
    pub fn new(store: S, policy: SessionPolicy) -> Self {
        Self { store, policy }
    }

    /// The backing store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The policy.
    pub fn policy(&self) -> &SessionPolicy {
        &self.policy
    }

    /// Validate the policy.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.policy.validate()
    }

    /// Load and validate a presented session id.
    ///
    /// An expired record is deleted. A record that fails the address or user
    /// agent binding is ignored but *not* deleted: a hostile request with a
    /// stolen id must not be able to log the real owner out.
    pub fn load(
        &self,
        id: &SessionId,
        now: i64,
        binding: &SessionBinding,
    ) -> StoreResult<Option<SessionRecord>> {
        let Some(mut record) = self.store.load(id)? else {
            return Ok(None);
        };
        match self.policy.check(&record, now, binding) {
            SessionValidity::Valid => {}
            SessionValidity::IdleExpired | SessionValidity::AbsoluteExpired => {
                self.store.destroy(id)?;
                return Ok(None);
            }
            SessionValidity::IpMismatch | SessionValidity::UserAgentMismatch => {
                return Ok(None);
            }
        }
        self.touch(&mut record, now)?;
        Ok(Some(record))
    }

    /// Create a fresh guest session.
    pub fn start_guest(&self, now: i64, binding: &SessionBinding) -> StoreResult<SessionRecord> {
        let record = SessionRecord::guest(SessionId::try_generate()?, now, binding);
        self.store.save(&record)?;
        Ok(record)
    }

    /// Create a session for an authenticated user, destroying the session id
    /// the request presented.
    ///
    /// The returned record always carries a new id. See the module
    /// documentation for why this is mandatory.
    pub fn login(
        &self,
        presented: Option<&SessionId>,
        user_id: u64,
        now: i64,
        binding: &SessionBinding,
    ) -> StoreResult<SessionRecord> {
        if let Some(presented) = presented {
            self.store.destroy(presented)?;
        }
        let record = SessionRecord::for_user(SessionId::try_generate()?, user_id, now, binding);
        self.store.save(&record)?;
        Ok(record)
    }

    /// Replace a record with a fresh id and the same user, for a privilege
    /// change (a password change or an administrator re-authentication).
    pub fn rotate(
        &self,
        record: &SessionRecord,
        now: i64,
        binding: &SessionBinding,
    ) -> StoreResult<SessionRecord> {
        self.store.destroy(&record.id)?;
        let mut rotated = record.clone();
        rotated.id = SessionId::try_generate()?;
        rotated.created = now;
        rotated.last_seen = now;
        rotated.ip = binding.ip;
        rotated.user_agent = bound_user_agent(&binding.user_agent);
        self.store.save(&rotated)?;
        Ok(rotated)
    }

    /// Update the in-memory `last_seen` and persist it when the touch interval
    /// has passed. Returns whether the store was written.
    pub fn touch(&self, record: &mut SessionRecord, now: i64) -> StoreResult<bool> {
        let due = self.policy.should_touch(record.last_seen, now);
        record.last_seen = now;
        if due {
            self.store.save(record)?;
        }
        Ok(due)
    }

    /// Destroy one session.
    pub fn logout(&self, id: &SessionId) -> StoreResult<()> {
        self.store.destroy(id)
    }

    /// Delete expired records.
    pub fn gc(&self, now: i64) -> StoreResult<usize> {
        self.store.gc(now, &self.policy)
    }
}

/// A remember-me cookie value: the user id plus an unguessable token.
///
/// The token is 32 hexadecimal characters (16 random bytes). Only
/// [`RememberMeKey::token_hash`] is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RememberMeKey {
    /// The user the key was issued to.
    pub user_id: u64,
    /// The raw token from the cookie.
    pub token: String,
}

impl RememberMeKey {
    /// Generate a key for `user_id`.
    pub fn generate(user_id: u64) -> Self {
        Self {
            user_id,
            token: random_hex(16),
        }
    }

    /// Generate a key, returning an error when the OS entropy source is
    /// unavailable.
    pub fn try_generate(user_id: u64) -> Result<Self, StoreError> {
        let bytes = try_random_bytes(16).map_err(|error| StoreError::new(error.to_string()))?;
        Ok(Self {
            user_id,
            token: hex(&bytes),
        })
    }

    /// Whether the token has the generated shape.
    pub fn is_valid(&self) -> bool {
        self.token.len() == 32 && self.token.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    /// The SHA-256 of the token, which is what a store keeps.
    pub fn token_hash(&self) -> [u8; 32] {
        sha256(self.token.as_bytes())
    }

    /// Build the record to store for this key.
    pub fn record(&self, now: i64, lifetime: i64, ip: Option<IpAddr>) -> RememberMeRecord {
        RememberMeRecord {
            user_id: self.user_id,
            token_hash: self.token_hash(),
            created: now,
            expires: now.saturating_add(lifetime.max(0)),
            ip,
        }
    }

    /// Store this key.
    pub fn issue(
        &self,
        store: &impl RememberMeStore,
        now: i64,
        lifetime: i64,
        ip: Option<IpAddr>,
    ) -> StoreResult<()> {
        store.insert(&self.record(now, lifetime, ip))
    }

    /// Look the key up and return its record when it is current.
    ///
    /// An expired record is revoked on the way out.
    pub fn verify(
        &self,
        store: &impl RememberMeStore,
        now: i64,
    ) -> StoreResult<Option<RememberMeRecord>> {
        if !self.is_valid() {
            return Ok(None);
        }
        let hash = self.token_hash();
        let Some(record) = store.find(self.user_id, &hash)? else {
            return Ok(None);
        };
        if record.is_expired(now) {
            store.revoke(self.user_id, &hash)?;
            return Ok(None);
        }
        Ok(Some(record))
    }

    /// Revoke this key and issue a new one, the single-use remember-me rule.
    pub fn rotate(
        &self,
        store: &impl RememberMeStore,
        now: i64,
        lifetime: i64,
        ip: Option<IpAddr>,
    ) -> StoreResult<Self> {
        store.revoke(self.user_id, &self.token_hash())?;
        let rotated = Self::try_generate(self.user_id)?;
        rotated.issue(store, now, lifetime, ip)?;
        Ok(rotated)
    }
}

/// One stored remember-me key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RememberMeRecord {
    /// The user the key belongs to.
    pub user_id: u64,
    /// SHA-256 of the raw token.
    pub token_hash: [u8; 32],
    /// Issue time.
    pub created: i64,
    /// Expiry time.
    pub expires: i64,
    /// The address the key was issued to, when known.
    pub ip: Option<IpAddr>,
}

impl RememberMeRecord {
    /// Whether the record has expired at `now`.
    pub fn is_expired(&self, now: i64) -> bool {
        self.expires <= now
    }
}

/// Storage for remember-me keys.
pub trait RememberMeStore {
    /// Store one key.
    fn insert(&self, record: &RememberMeRecord) -> StoreResult<()>;
    /// Look up a key by user and token hash.
    fn find(&self, user_id: u64, token_hash: &[u8; 32]) -> StoreResult<Option<RememberMeRecord>>;
    /// Delete one key.
    fn revoke(&self, user_id: u64, token_hash: &[u8; 32]) -> StoreResult<()>;
    /// Delete every key of one user, for a password change.
    fn revoke_all(&self, user_id: u64) -> StoreResult<()>;
    /// Delete expired keys and return the count.
    fn gc(&self, now: i64) -> StoreResult<usize> {
        let _ = now;
        Ok(0)
    }
}

/// A bounded in-memory [`RememberMeStore`] for tests and small servers.
#[derive(Debug)]
pub struct MemoryRememberMeStore {
    rows: Mutex<HashMap<(u64, [u8; 32]), RememberMeRecord>>,
    capacity: usize,
}

impl MemoryRememberMeStore {
    /// Create a store holding at most `capacity` keys.
    pub fn new(capacity: usize) -> Self {
        Self {
            rows: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Number of stored keys.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(u64, [u8; 32]), RememberMeRecord>> {
        self.rows.lock().unwrap_or_else(|error| error.into_inner())
    }
}

impl Default for MemoryRememberMeStore {
    fn default() -> Self {
        Self::new(1_024)
    }
}

impl RememberMeStore for MemoryRememberMeStore {
    fn insert(&self, record: &RememberMeRecord) -> StoreResult<()> {
        let mut rows = self.lock();
        let key = (record.user_id, record.token_hash);
        if !rows.contains_key(&key) && rows.len() >= self.capacity {
            if let Some(oldest) = rows
                .iter()
                .min_by_key(|(_, row)| row.created)
                .map(|(key, _)| *key)
            {
                rows.remove(&oldest);
            }
        }
        rows.insert(key, record.clone());
        Ok(())
    }

    fn find(&self, user_id: u64, token_hash: &[u8; 32]) -> StoreResult<Option<RememberMeRecord>> {
        Ok(self.lock().get(&(user_id, *token_hash)).cloned())
    }

    fn revoke(&self, user_id: u64, token_hash: &[u8; 32]) -> StoreResult<()> {
        self.lock().remove(&(user_id, *token_hash));
        Ok(())
    }

    fn revoke_all(&self, user_id: u64) -> StoreResult<()> {
        self.lock().retain(|(owner, _), _| *owner != user_id);
        Ok(())
    }

    fn gc(&self, now: i64) -> StoreResult<usize> {
        let mut rows = self.lock();
        let before = rows.len();
        rows.retain(|_, record| !record.is_expired(now));
        Ok(before - rows.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn binding() -> SessionBinding {
        SessionBinding::new(
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))),
            "TestAgent/1.0",
        )
    }

    #[test]
    fn session_ids_have_the_generated_shape() {
        let id = SessionId::generate();
        assert_eq!(id.as_str().len(), SESSION_ID_LEN);
        assert!(SessionId::is_valid(id.as_str()));
        assert_eq!(SessionId::parse(id.as_str()), Some(id.clone()));
        assert_ne!(SessionId::generate(), id);
        for value in [
            "",
            "x",
            "0123",
            &"a".repeat(31),
            &"a".repeat(33),
            &"g".repeat(32),
            &"A".repeat(32),
            "0123456789abcdef0123456789abcde-",
        ] {
            assert!(!SessionId::is_valid(value), "accepted session id {value:?}");
        }
        assert!(SessionId::parse("bad/id").is_none());
        assert_eq!(
            "bad/id".parse::<SessionId>().unwrap_err().message(),
            "invalid session id"
        );
    }

    #[test]
    fn try_generate_uses_the_os_source() {
        let id = SessionId::try_generate().unwrap();
        assert!(SessionId::is_valid(id.as_str()));
    }

    #[test]
    fn policy_rejects_impossible_settings() {
        assert!(SessionPolicy::default().validate().is_ok());
        let policy = SessionPolicy {
            idle_timeout: 0,
            ..SessionPolicy::default()
        };
        assert!(policy.validate().is_err());
        let policy = SessionPolicy {
            absolute_timeout: -1,
            ..SessionPolicy::default()
        };
        assert!(policy.validate().is_err());
        let policy = SessionPolicy {
            touch_interval: -1,
            ..SessionPolicy::default()
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn policy_separates_idle_and_absolute_expiry() {
        let policy = SessionPolicy {
            idle_timeout: 100,
            absolute_timeout: 1_000,
            ..SessionPolicy::default()
        };
        let record = SessionRecord::for_user(SessionId::generate(), 7, 0, &binding());
        assert_eq!(
            policy.check(&record, 100, &binding()),
            SessionValidity::Valid
        );
        assert_eq!(
            policy.check(&record, 101, &binding()),
            SessionValidity::IdleExpired
        );
        let mut active = record.clone();
        active.last_seen = 999;
        assert_eq!(
            policy.check(&active, 1_001, &binding()),
            SessionValidity::AbsoluteExpired
        );
        assert_eq!(
            policy.check(&active, 1_000, &binding()),
            SessionValidity::Valid
        );
    }

    #[test]
    fn policy_binds_address_and_user_agent() {
        let policy = SessionPolicy::default();
        let record = SessionRecord::for_user(SessionId::generate(), 7, 0, &binding());
        assert_eq!(policy.check(&record, 0, &binding()), SessionValidity::Valid);

        let other_ip = SessionBinding::new(
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8))),
            "TestAgent/1.0",
        );
        assert_eq!(
            policy.check(&record, 0, &other_ip),
            SessionValidity::IpMismatch
        );
        let other_agent = SessionBinding::new(binding().ip, "Other/2.0");
        assert_eq!(
            policy.check(&record, 0, &other_agent),
            SessionValidity::UserAgentMismatch
        );
        let unbound = SessionPolicy {
            bind_ip: false,
            bind_user_agent: false,
            ..SessionPolicy::default()
        };
        assert_eq!(unbound.check(&record, 0, &other_ip), SessionValidity::Valid);
        assert_eq!(
            unbound.check(&record, 0, &other_agent),
            SessionValidity::Valid
        );
    }

    #[test]
    fn touches_are_coalesced_to_the_interval() {
        let policy = SessionPolicy::default();
        assert!(!policy.should_touch(1_000, 1_000));
        assert!(!policy.should_touch(1_000, 1_059));
        assert!(policy.should_touch(1_000, 1_060));
        assert!(policy.should_touch(1_000, 2_000));
        let every_request = SessionPolicy {
            touch_interval: 0,
            ..SessionPolicy::default()
        };
        assert!(every_request.should_touch(1_000, 1_000));
    }

    #[test]
    fn manager_creates_loads_and_destroys_sessions() {
        let manager = SessionManager::new(MemorySessionStore::default(), SessionPolicy::default());
        let record = manager.start_guest(1_000, &binding()).unwrap();
        assert!(record.is_guest());
        let loaded = manager
            .load(&record.id, 1_001, &binding())
            .unwrap()
            .unwrap();
        assert_eq!(loaded.id, record.id);
        assert_eq!(loaded.user_id, None);
        assert_eq!(loaded.created, record.created);
        // The request sees the current time even when the write is coalesced.
        assert_eq!(loaded.last_seen, 1_001);
        manager.logout(&record.id).unwrap();
        assert_eq!(manager.load(&record.id, 1_002, &binding()).unwrap(), None);
    }

    #[test]
    fn manager_deletes_an_expired_record_but_keeps_a_mismatched_one() {
        let manager = SessionManager::new(
            MemorySessionStore::default(),
            SessionPolicy {
                idle_timeout: 100,
                ..SessionPolicy::default()
            },
        );
        let record = manager.start_guest(0, &binding()).unwrap();
        assert_eq!(manager.load(&record.id, 200, &binding()).unwrap(), None);
        assert!(manager.store().load(&record.id).unwrap().is_none());

        let record = manager.start_guest(0, &binding()).unwrap();
        let other = SessionBinding::new(Some(IpAddr::V4(Ipv4Addr::LOCALHOST)), "Other/1.0");
        assert_eq!(manager.load(&record.id, 1, &other).unwrap(), None);
        assert!(
            manager.store().load(&record.id).unwrap().is_some(),
            "a mismatched binding must not let a stranger end the session"
        );
    }

    #[test]
    fn login_always_rotates_the_presented_session_id() {
        let manager = SessionManager::new(MemorySessionStore::default(), SessionPolicy::default());
        let presented = manager.start_guest(1_000, &binding()).unwrap();
        let logged_in = manager
            .login(Some(&presented.id), 7, 1_001, &binding())
            .unwrap();
        assert_ne!(logged_in.id, presented.id, "login reused the presented id");
        assert_eq!(logged_in.user_id, Some(7));
        assert!(manager.store().load(&presented.id).unwrap().is_none());
        assert!(manager.store().load(&logged_in.id).unwrap().is_some());

        let second = manager
            .login(Some(&logged_in.id), 7, 1_002, &binding())
            .unwrap();
        assert_ne!(second.id, logged_in.id);
    }

    #[test]
    fn rotate_keeps_the_user_and_issues_a_new_id() {
        let manager = SessionManager::new(MemorySessionStore::default(), SessionPolicy::default());
        let record = manager.login(None, 9, 1_000, &binding()).unwrap();
        let rotated = manager.rotate(&record, 2_000, &binding()).unwrap();
        assert_ne!(rotated.id, record.id);
        assert_eq!(rotated.user_id, Some(9));
        assert_eq!(rotated.created, 2_000);
        assert!(manager.store().load(&record.id).unwrap().is_none());
        assert!(manager.store().load(&rotated.id).unwrap().is_some());
    }

    #[test]
    fn touch_persists_only_when_due() {
        let manager = SessionManager::new(
            MemorySessionStore::default(),
            SessionPolicy {
                touch_interval: 60,
                ..SessionPolicy::default()
            },
        );
        let mut record = manager.start_guest(1_000, &binding()).unwrap();
        // A call inside the interval updates memory but not the store.
        assert!(!manager.touch(&mut record, 1_001).unwrap());
        assert_eq!(record.last_seen, 1_001);
        assert_eq!(
            manager.store().load(&record.id).unwrap().unwrap().last_seen,
            1_000
        );
        // A call one interval after the last in-memory touch persists.
        assert!(manager.touch(&mut record, 1_061).unwrap());
        assert_eq!(
            manager.store().load(&record.id).unwrap().unwrap().last_seen,
            1_061
        );
    }

    #[test]
    fn memory_store_evicts_the_oldest_record_at_capacity() {
        let store = MemorySessionStore::new(2);
        let manager = SessionManager::new(store, SessionPolicy::default());
        let first = manager.start_guest(1, &binding()).unwrap();
        let second = manager.start_guest(2, &binding()).unwrap();
        let third = manager.start_guest(3, &binding()).unwrap();
        assert_eq!(manager.store().len(), 2);
        assert!(manager.store().load(&first.id).unwrap().is_none());
        assert!(manager.store().load(&second.id).unwrap().is_some());
        assert!(manager.store().load(&third.id).unwrap().is_some());
    }

    #[test]
    fn gc_removes_expired_records() {
        let manager = SessionManager::new(
            MemorySessionStore::default(),
            SessionPolicy {
                idle_timeout: 100,
                ..SessionPolicy::default()
            },
        );
        manager.start_guest(0, &binding()).unwrap();
        manager.start_guest(500, &binding()).unwrap();
        assert_eq!(manager.gc(550).unwrap(), 1);
        assert_eq!(manager.store().len(), 1);
    }

    #[test]
    fn remember_me_keys_store_only_a_hash() {
        let store = MemoryRememberMeStore::default();
        let key = RememberMeKey::generate(7);
        assert!(key.is_valid());
        key.issue(&store, 1_000, 3_600, binding().ip).unwrap();
        let record = key.verify(&store, 1_001).unwrap().unwrap();
        assert_eq!(record.user_id, 7);
        assert_ne!(record.token_hash, key.token.as_bytes());
        assert_eq!(record.token_hash, key.token_hash());

        let mut wrong = key.clone();
        wrong.token = "0".repeat(32);
        assert!(wrong.verify(&store, 1_001).unwrap().is_none());
        let mut malformed = key.clone();
        malformed.token = "x".into();
        assert!(malformed.verify(&store, 1_001).unwrap().is_none());
    }

    #[test]
    fn remember_me_keys_expire_and_rotate() {
        let store = MemoryRememberMeStore::default();
        let key = RememberMeKey::generate(7);
        key.issue(&store, 1_000, 100, None).unwrap();
        assert!(key.verify(&store, 1_100).unwrap().is_none());
        assert!(store.is_empty(), "an expired key must be revoked");

        key.issue(&store, 1_000, 1_000, None).unwrap();
        let rotated = key.rotate(&store, 1_010, 1_000, None).unwrap();
        assert_ne!(rotated.token, key.token);
        assert!(key.verify(&store, 1_011).unwrap().is_none());
        assert!(rotated.verify(&store, 1_011).unwrap().is_some());
    }

    #[test]
    fn revoke_all_ends_every_remembered_device() {
        let store = MemoryRememberMeStore::default();
        let first = RememberMeKey::generate(7);
        let second = RememberMeKey::generate(7);
        let other = RememberMeKey::generate(8);
        for key in [&first, &second, &other] {
            key.issue(&store, 0, 1_000, None).unwrap();
        }
        store.revoke_all(7).unwrap();
        assert!(first.verify(&store, 1).unwrap().is_none());
        assert!(second.verify(&store, 1).unwrap().is_none());
        assert!(other.verify(&store, 1).unwrap().is_some());
    }

    #[test]
    fn user_agents_are_bounded_on_a_character_boundary() {
        let long = "ä".repeat(MAX_USER_AGENT + 50);
        let bounded = bound_user_agent(&long);
        assert_eq!(bounded.chars().count(), MAX_USER_AGENT);
        assert!(bounded.is_char_boundary(bounded.len()));
        let record = SessionRecord::new(
            SessionId::generate(),
            None,
            0,
            &SessionBinding::new(None, long),
        );
        assert_eq!(record.user_agent.chars().count(), MAX_USER_AGENT);
    }
}
