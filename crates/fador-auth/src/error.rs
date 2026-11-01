//! The error type shared by every store trait.
//!
//! A store implementation owns its own error type (a database driver error, an
//! I/O error, a test failure). It converts that error into [`StoreError`] at
//! the trait boundary, so this crate stays independent of any schema or driver.

use std::fmt;

/// A store implementation failed.
///
/// The message is for logs and tests; it is never shown to a visitor, because a
/// store error can contain a table name, an SQL fragment or a connection
/// string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    message: String,
}

impl StoreError {
    /// Create a store error with a human-readable message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "auth store: {}", self.message)
    }
}

impl std::error::Error for StoreError {}

impl From<&str> for StoreError {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for StoreError {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

/// Result alias used by every store trait in this crate.
pub type StoreResult<T> = Result<T, StoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_error_carries_its_message() {
        let error = StoreError::from("connection reset");
        assert_eq!(error.message(), "connection reset");
        assert_eq!(error.to_string(), "auth store: connection reset");
        assert_eq!(
            StoreError::from(String::from("x")).to_string(),
            "auth store: x"
        );
    }
}
