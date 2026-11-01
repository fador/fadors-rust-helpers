//! A generic allow/deny permission set.
//!
//! The schema-coupled ACLs of phpBB and SMF are not part of this crate: they
//! need forum ids, group ids, roles, permission masks and a board setting for
//! deny permissions. What remains is the part every implementation needs and
//! gets wrong: how an allow and a deny for the same name combine.
//!
//! # Precedence
//!
//! A deny always wins over an allow, regardless of insertion order, and a
//! merged set keeps that property. A permission that appears in neither set is
//! denied.
//!
//! Three precedence bugs from the source applications are deliberately not
//! reproduced:
//!
//! 1. **phpBB ORs a global permission with a forum-local one.** A forum-local
//!    "never" cannot override a global "yes", so a global `f_read` leaks into
//!    every forum. This set has no scopes; an application resolves the scope
//!    first, then asks the set, and a deny in the resolved scope wins.
//! 2. **phpBB grants a parent flag when a child is allowed.** Allowing
//!    `u_viewprofile` also sets `u_`, so a later `can("u_")` succeeds even
//!    though no `u_` row exists. This set grants exactly the names it is given;
//!    a wildcard or a parent flag must be an explicit row.
//! 3. **SMF's group merge depends on row order.** Its `apply_group_setting`
//!    refuses to overwrite a stored `0`, so a user-level deny blocks a later
//!    group allow while the same group allow before the user deny is
//!    overwritten. Here the sets are merged as sets and the answer does not
//!    depend on the order.
//!
//! One more SMF shortcut is designed out: `allowedTo([])` returns true, so a
//! caller that passes an empty list is allowed. [`PermissionSet::any`] with an
//! empty list returns false, the fail-closed answer.

use std::collections::BTreeSet;
use std::fmt;

/// Whether a row grants or removes a permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Grant the permission.
    Allow,
    /// Remove the permission.
    Deny,
}

impl Effect {
    /// The effect name used in logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

impl fmt::Display for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One permission row.
///
/// A database implementation maps its own rows (a role, a group, a user, a
/// forum) into this shape after resolving the scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionRow {
    /// The permission name, for example `post_new` or `f_read`.
    pub permission: String,
    /// Whether the row grants or removes it.
    pub effect: Effect,
}

impl PermissionRow {
    /// A row that grants `permission`.
    pub fn allow(permission: impl Into<String>) -> Self {
        Self {
            permission: permission.into(),
            effect: Effect::Allow,
        }
    }

    /// A row that removes `permission`.
    pub fn deny(permission: impl Into<String>) -> Self {
        Self {
            permission: permission.into(),
            effect: Effect::Deny,
        }
    }
}

/// The resolved permissions of one request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PermissionSet {
    allowed: BTreeSet<String>,
    denied: BTreeSet<String>,
}

impl PermissionSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a set from rows.
    ///
    /// `deny_enabled` mirrors the board setting that turns deny rows on. When
    /// it is false, deny rows are ignored instead of being treated as allows.
    pub fn from_rows(rows: &[PermissionRow], deny_enabled: bool) -> Self {
        let mut set = Self::new();
        set.apply_rows(rows, deny_enabled);
        set
    }

    /// Apply one row.
    pub fn apply(&mut self, row: &PermissionRow, deny_enabled: bool) {
        if row.permission.is_empty() {
            return;
        }
        match row.effect {
            Effect::Allow => {
                self.allowed.insert(row.permission.clone());
            }
            Effect::Deny if deny_enabled => {
                self.denied.insert(row.permission.clone());
            }
            Effect::Deny => {}
        }
    }

    /// Apply several rows in order. The result does not depend on the order.
    pub fn apply_rows(&mut self, rows: &[PermissionRow], deny_enabled: bool) {
        for row in rows {
            self.apply(row, deny_enabled);
        }
    }

    /// Grant a permission.
    pub fn allow(&mut self, permission: &str) {
        if !permission.is_empty() {
            self.allowed.insert(permission.to_string());
        }
    }

    /// Remove a permission. It stays removed even if it is also granted.
    pub fn deny(&mut self, permission: &str) {
        if !permission.is_empty() {
            self.denied.insert(permission.to_string());
        }
    }

    /// Merge another set into this one. Allows and denials are both unioned, so
    /// the merge is commutative.
    pub fn merge(&mut self, other: &Self) {
        self.allowed.extend(other.allowed.iter().cloned());
        self.denied.extend(other.denied.iter().cloned());
    }

    /// Whether `permission` is granted.
    pub fn is_allowed(&self, permission: &str) -> bool {
        self.allowed.contains(permission) && !self.denied.contains(permission)
    }

    /// Whether `permission` is explicitly denied.
    pub fn is_denied(&self, permission: &str) -> bool {
        self.denied.contains(permission)
    }

    /// Whether any of the names is granted. An empty list is false: a caller
    /// with no requirement must say so explicitly.
    pub fn any(&self, any_of: &[&str]) -> bool {
        any_of.iter().any(|permission| self.is_allowed(permission))
    }

    /// Whether every name is granted. An empty list is true, because there is
    /// nothing to fail.
    pub fn all(&self, all_of: &[&str]) -> bool {
        all_of.iter().all(|permission| self.is_allowed(permission))
    }

    /// The effective permission names, in sorted order.
    pub fn allowed_names(&self) -> impl Iterator<Item = &str> {
        self.allowed
            .iter()
            .filter(|permission| !self.denied.contains(*permission))
            .map(String::as_str)
    }

    /// The number of effective permissions.
    pub fn len(&self) -> usize {
        self.allowed_names().count()
    }

    /// Whether no permission is granted.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(name: &str) -> PermissionRow {
        PermissionRow::allow(name)
    }

    fn deny(name: &str) -> PermissionRow {
        PermissionRow::deny(name)
    }

    #[test]
    fn deny_wins_regardless_of_row_order() {
        for rows in [
            vec![allow("post_new"), deny("post_new")],
            vec![deny("post_new"), allow("post_new")],
            vec![allow("post_new"), allow("post_new"), deny("post_new")],
        ] {
            let set = PermissionSet::from_rows(&rows, true);
            assert!(!set.is_allowed("post_new"));
            assert!(set.is_denied("post_new"));
            assert_eq!(set.len(), 0);
        }
        // Applying to an existing set has the same property.
        let mut set = PermissionSet::from_rows(&[allow("post_new")], true);
        set.apply(&deny("post_new"), true);
        assert!(!set.is_allowed("post_new"));
        set.apply(&allow("post_new"), true);
        assert!(!set.is_allowed("post_new"));
    }

    #[test]
    fn deny_rows_are_ignored_when_the_setting_is_off() {
        let rows = [allow("post_new"), deny("post_new")];
        assert!(!PermissionSet::from_rows(&rows, true).is_allowed("post_new"));
        assert!(PermissionSet::from_rows(&rows, false).is_allowed("post_new"));
        let mut set = PermissionSet::new();
        set.apply(&deny("post_new"), false);
        assert!(!set.is_denied("post_new"));
    }

    #[test]
    fn merging_user_and_group_sets_is_commutative() {
        // The SMF bug: a user deny followed by a group allow could be
        // overwritten. A deny must survive either order.
        let user = PermissionSet::from_rows(&[allow("poll_vote"), deny("poll_post")], true);
        let group = PermissionSet::from_rows(&[allow("poll_post"), allow("poll_vote")], true);
        let mut first = user.clone();
        first.merge(&group);
        let mut second = group.clone();
        second.merge(&user);
        assert_eq!(first, second);
        assert!(first.is_allowed("poll_vote"));
        assert!(!first.is_allowed("poll_post"));
    }

    #[test]
    fn no_parent_flag_is_granted_implicitly() {
        // phpBB would set `u_` when `u_viewprofile` is allowed.
        let set = PermissionSet::from_rows(&[allow("u_viewprofile")], true);
        assert!(set.is_allowed("u_viewprofile"));
        assert!(!set.is_allowed("u_"));
        assert!(!set.is_allowed("u_sendpm"));
    }

    #[test]
    fn unknown_and_empty_names_are_denied() {
        let set = PermissionSet::from_rows(&[allow("known"), allow("")], true);
        assert!(set.is_allowed("known"));
        assert!(!set.is_allowed(""));
        assert!(!set.is_allowed("unknown"));
        assert!(!set.any(&[]));
        assert!(set.all(&[]));
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
        assert!(PermissionSet::new().is_empty());
    }

    #[test]
    fn any_and_all_require_the_named_permissions() {
        let set = PermissionSet::from_rows(&[allow("a"), allow("b")], true);
        assert!(set.any(&["a", "c"]));
        assert!(!set.any(&["c", "d"]));
        assert!(set.all(&["a", "b"]));
        assert!(!set.all(&["a", "c"]));
        assert_eq!(set.allowed_names().collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn names_are_case_sensitive_and_exact() {
        let set = PermissionSet::from_rows(&[allow("post_new")], true);
        assert!(set.is_allowed("post_new"));
        assert!(!set.is_allowed("Post_New"));
        assert!(!set.is_allowed("post_new "));
        assert!(!set.is_allowed("post"));
    }

    #[test]
    fn effects_are_named() {
        assert_eq!(Effect::Allow.to_string(), "allow");
        assert_eq!(Effect::Deny.as_str(), "deny");
    }
}
