//! User records, login-name normalisation and a password-checking login
//! helper.
//!
//! [`UserStore`] is the only account-shaped trait in this crate: it returns a
//! [`UserRecord`] with the fields a password check needs, and nothing else. A
//! server implements it over its own table.
//!
//! [`authenticate`] composes a [`UserStore`] with a [`PasswordVerifier`]. It
//! checks the account status before the password, performs a dummy verification
//! for an unknown account so the response time does not reveal whether a name
//! exists, and reports whether the stored hash should be replaced.

use crate::error::StoreResult;
use crate::password::{PasswordCheck, PasswordContext, PasswordVerifier};
use fador_core::util::repair_mojibake;
use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

/// A dummy hash of a value no visitor knows. It is verified when the submitted
/// login name does not resolve or names an inactive account, so an unknown or
/// inactive account costs the same as a known active one.
#[cfg(any(
    feature = "bcrypt",
    all(not(feature = "bcrypt"), not(feature = "mediawiki-pbkdf2"))
))]
const DUMMY_HASH: &str = "$2y$10$u/a4ZTIgnxqS1ATR8n2wNunuxzZ5uhjnw9GmxNqStOompVzhBJwye";

/// A PBKDF2 dummy hash used when `bcrypt` is disabled and `mediawiki-pbkdf2` is
/// enabled.
#[cfg(all(not(feature = "bcrypt"), feature = "mediawiki-pbkdf2"))]
const DUMMY_HASH: &str = ":pbkdf2:sha256:120000:32:MDEyMzQ1Njc4OWFiY2RlZg==:tiKWHy4FAGCWE8gn6GtKhaxD2OeeAUUWXFT/p1aaNl8=";

/// The lifecycle state of an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatus {
    /// The account may log in.
    Active,
    /// The account exists but has not been activated.
    Inactive,
    /// The account is suspended by an administrator or a ban.
    Suspended,
    /// The account is a bot account; it does not log in through the form.
    Bot,
}

impl UserStatus {
    /// Whether the account may authenticate.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// The state name used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Suspended => "suspended",
            Self::Bot => "bot",
        }
    }
}

impl fmt::Display for UserStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The account fields a password check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    /// The account id.
    pub id: u64,
    /// The login name as stored.
    pub username: String,
    /// The stored password hash.
    pub password_hash: String,
    /// The account email address.
    pub email: String,
    /// The lifecycle state.
    pub status: UserStatus,
    /// Whether the account is an administrator.
    pub is_admin: bool,
    /// Whether the account is a bot.
    pub is_bot: bool,
}

impl UserRecord {
    /// Create an active account with an empty email.
    pub fn new(id: u64, username: impl Into<String>, password_hash: impl Into<String>) -> Self {
        Self {
            id,
            username: username.into(),
            password_hash: password_hash.into(),
            email: String::new(),
            status: UserStatus::Active,
            is_admin: false,
            is_bot: false,
        }
    }

    /// Set the email address.
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = email.into();
        self
    }

    /// Set the lifecycle state.
    pub fn with_status(mut self, status: UserStatus) -> Self {
        self.status = status;
        self
    }

    /// Mark the account as an administrator.
    pub fn admin(mut self) -> Self {
        self.is_admin = true;
        self
    }

    /// Mark the account as a bot.
    pub fn bot(mut self) -> Self {
        self.is_bot = true;
        self
    }

    /// Whether the account may authenticate.
    pub fn is_active(&self) -> bool {
        self.status.is_active()
    }
}

/// Storage for account records.
pub trait UserStore {
    /// Find an account by its normalised login name.
    fn find_by_login(&self, login: &str) -> StoreResult<Option<UserRecord>>;
    /// Find an account by id.
    fn find_by_id(&self, id: u64) -> StoreResult<Option<UserRecord>>;
    /// Replace the stored password hash.
    fn update_password_hash(&self, id: u64, hash: &str) -> StoreResult<()>;
}

/// Normalise a submitted login name.
///
/// The board stores a cleaned name: HTML entities are decoded, mojibake is
/// repaired and the result is lowercased. The same transformation is applied to
/// a submitted name so a user can type the name they see.
///
/// ```
/// use fador_auth::user::normalize_login;
///
/// assert_eq!(normalize_login("  Teuvo "), "teuvo");
/// assert_eq!(normalize_login("Lee&lt;3"), "lee<3");
/// ```
pub fn normalize_login(value: &str) -> String {
    repair_mojibake(value)
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#039;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
        .trim()
        .to_lowercase()
}

/// The result of a password login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    /// The password matched.
    Success {
        /// The account.
        user: UserRecord,
        /// Whether the stored hash should be replaced.
        needs_rehash: bool,
    },
    /// The submitted name did not resolve to an account.
    UnknownUser,
    /// The account exists but is not active.
    Inactive,
    /// The password did not match, or it was empty.
    WrongPassword,
}

impl LoginOutcome {
    /// Whether the login succeeded.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success { .. })
    }

    /// The authenticated account.
    pub fn user(&self) -> Option<&UserRecord> {
        match self {
            Self::Success { user, .. } => Some(user),
            _ => None,
        }
    }

    /// Whether the stored hash should be replaced.
    pub fn needs_rehash(&self) -> bool {
        matches!(
            self,
            Self::Success {
                needs_rehash: true,
                ..
            }
        )
    }
}

/// Check a submitted name and password against a store.
///
/// The store is asked for the normalised name. An empty name or password is
/// refused without touching the store. An inactive account is refused before
/// the password is checked, so an inactive account cannot be used as a
/// password-testing oracle. An unknown account still costs one hash check.
///
/// The caller must render [`LoginOutcome::UnknownUser`],
/// [`LoginOutcome::Inactive`] and [`LoginOutcome::WrongPassword`] with the same
/// visitor-facing message; the distinction is for logs and metrics only.
pub fn authenticate(
    users: &dyn UserStore,
    verifier: &PasswordVerifier,
    login: &str,
    password: &str,
) -> StoreResult<LoginOutcome> {
    let login = normalize_login(login);
    if login.is_empty() {
        return Ok(LoginOutcome::UnknownUser);
    }
    if password.is_empty() || password.len() > crate::password::MAX_PASSWORD_LEN {
        return Ok(LoginOutcome::WrongPassword);
    }
    let Some(user) = users.find_by_login(&login)? else {
        let _ = verifier.verify(DUMMY_HASH, password);
        return Ok(LoginOutcome::UnknownUser);
    };
    if !user.is_active() {
        let _ = verifier.verify(DUMMY_HASH, password);
        return Ok(LoginOutcome::Inactive);
    }
    let context = PasswordContext::new(&user.username, user.id);
    let check = verifier.verify_with(&user.password_hash, password, &context);
    if !check.valid {
        return Ok(LoginOutcome::WrongPassword);
    }
    Ok(LoginOutcome::Success {
        needs_rehash: check.needs_rehash,
        user,
    })
}

/// The password check of an account, without a store round trip.
///
/// This is the pure part of [`authenticate`], exposed for a caller that has
/// already loaded the row.
pub fn check_password(
    verifier: &PasswordVerifier,
    user: &UserRecord,
    password: &str,
) -> PasswordCheck {
    let context = PasswordContext::new(&user.username, user.id);
    verifier.verify_with(&user.password_hash, password, &context)
}

/// A small in-memory [`UserStore`] for tests and examples.
#[derive(Debug, Default)]
pub struct MemoryUserStore {
    rows: Mutex<HashMap<u64, UserRecord>>,
}

impl MemoryUserStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace an account.
    pub fn insert(&self, user: UserRecord) {
        self.lock().insert(user.id, user);
    }

    /// Number of accounts.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, UserRecord>> {
        self.rows.lock().unwrap_or_else(|error| error.into_inner())
    }
}

impl UserStore for MemoryUserStore {
    fn find_by_login(&self, login: &str) -> StoreResult<Option<UserRecord>> {
        let login = normalize_login(login);
        Ok(self
            .lock()
            .values()
            .find(|user| normalize_login(&user.username) == login)
            .cloned())
    }

    fn find_by_id(&self, id: u64) -> StoreResult<Option<UserRecord>> {
        Ok(self.lock().get(&id).cloned())
    }

    fn update_password_hash(&self, id: u64, hash: &str) -> StoreResult<()> {
        if let Some(user) = self.lock().get_mut(&id) {
            user.password_hash = hash.to_string();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::password::PasswordVerifier;

    fn store_with(hash: String) -> MemoryUserStore {
        let store = MemoryUserStore::new();
        store.insert(
            UserRecord::new(7, "Test", hash)
                .with_email("test@example.test")
                .admin(),
        );
        store
    }

    #[test]
    fn normalises_login_names_like_the_board() {
        assert_eq!(normalize_login("  Teuvo "), "teuvo");
        assert_eq!(normalize_login("Lee&lt;3"), "lee<3");
        assert_eq!(normalize_login("Matti&amp;Maija"), "matti&maija");
        assert_eq!(normalize_login("&quot;Quoted&quot;"), "\"quoted\"");
        assert_eq!(normalize_login("O&#039;Neil"), "o'neil");
        assert_eq!(normalize_login("O&#39;Neil"), "o'neil");
        assert_eq!(normalize_login("&amp;lt;"), "&lt;");
        assert_eq!(normalize_login(""), "");
    }

    #[test]
    #[cfg(any(feature = "bcrypt", feature = "mediawiki-pbkdf2"))]
    fn authenticates_an_active_account() {
        let verifier = PasswordVerifier::new();
        let hash = verifier.hash("secret").unwrap();
        let store = store_with(hash);
        let outcome = authenticate(&store, &verifier, " TEST ", "secret").unwrap();
        assert!(outcome.is_success());
        assert_eq!(outcome.user().map(|user| user.id), Some(7));
        assert!(!outcome.needs_rehash());

        assert_eq!(
            authenticate(&store, &verifier, "Test", "wrong").unwrap(),
            LoginOutcome::WrongPassword
        );
        assert_eq!(
            authenticate(&store, &verifier, "Nobody", "secret").unwrap(),
            LoginOutcome::UnknownUser
        );
        assert_eq!(
            authenticate(&store, &verifier, "Test", "").unwrap(),
            LoginOutcome::WrongPassword
        );
        assert_eq!(
            authenticate(
                &store,
                &verifier,
                "Test",
                &"a".repeat(crate::password::MAX_PASSWORD_LEN + 1)
            )
            .unwrap(),
            LoginOutcome::WrongPassword
        );
        assert_eq!(
            authenticate(&store, &verifier, "", "secret").unwrap(),
            LoginOutcome::UnknownUser
        );
    }

    #[test]
    #[cfg(any(feature = "bcrypt", feature = "mediawiki-pbkdf2"))]
    fn refuses_inactive_accounts_before_checking_the_password() {
        let verifier = PasswordVerifier::new();
        let hash = verifier.hash("secret").unwrap();
        let store = MemoryUserStore::new();
        store.insert(UserRecord::new(7, "Test", hash).with_status(UserStatus::Inactive));
        assert_eq!(
            authenticate(&store, &verifier, "Test", "secret").unwrap(),
            LoginOutcome::Inactive
        );
        assert_eq!(
            authenticate(&store, &verifier, "Test", "wrong").unwrap(),
            LoginOutcome::Inactive
        );
    }

    #[test]
    fn reports_legacy_hashes_for_rehashing() {
        let verifier = PasswordVerifier::new();
        let store = store_with("5ebe2294ecd0e0f08eab7690d2a6ee69".into());
        let outcome = authenticate(&store, &verifier, "Test", "secret").unwrap();
        assert!(outcome.is_success());
        assert!(outcome.needs_rehash());
    }

    #[test]
    fn updates_and_looks_up_by_id() {
        let store = MemoryUserStore::new();
        store.insert(UserRecord::new(7, "Test", "hash"));
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
        assert_eq!(
            store.find_by_id(7).unwrap().map(|user| user.username),
            Some("Test".into())
        );
        assert!(store.find_by_id(8).unwrap().is_none());
        store.update_password_hash(7, "new-hash").unwrap();
        assert_eq!(
            store.find_by_login("test").unwrap().unwrap().password_hash,
            "new-hash"
        );
        // Updating a missing account is a no-op, not an error.
        store.update_password_hash(8, "x").unwrap();
    }

    #[test]
    #[cfg(any(feature = "bcrypt", feature = "mediawiki-pbkdf2"))]
    fn check_password_is_the_pure_part_of_authenticate() {
        let verifier = PasswordVerifier::new();
        let hash = verifier.hash("secret").unwrap();
        let user = UserRecord::new(7, "Test", hash);
        assert!(check_password(&verifier, &user, "secret").valid);
        assert!(!check_password(&verifier, &user, "wrong").valid);
    }

    #[test]
    fn user_status_and_flags_are_reported() {
        let user = UserRecord::new(1, "Bot", "x")
            .bot()
            .with_status(UserStatus::Bot);
        assert!(user.is_bot);
        assert!(!user.is_active());
        assert_eq!(user.status.to_string(), "bot");
        assert!(UserStatus::Active.is_active());
        assert!(!UserStatus::Suspended.is_active());
        assert_eq!(UserStatus::Inactive.as_str(), "inactive");
    }
}
