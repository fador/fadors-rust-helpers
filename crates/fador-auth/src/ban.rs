//! Ban rules, ban patterns, a cached ban store and IP safety.
//!
//! A ban rule names a user, a username pattern, an email pattern and IP
//! patterns. A subject matches when every constraint the rule names matches.
//! A rule that names no constraint never matches: an empty row must not ban the
//! whole board.
//!
//! # Precedence
//!
//! - An exemption rule (`exempt = true`) wins over any number of denying rules,
//!   regardless of the order the store returned them in. phpBB's `ban.exclude`
//!   also wins, but only because its loop returns early; a reordered row set
//!   could change the answer. Here the answer is order-independent.
//! - When several rules deny, the one with the lowest id is reported, so the
//!   reason and expiry a visitor sees do not depend on database row order.
//!
//! # Patterns
//!
//! | kind | example | semantics |
//! | --- | --- | --- |
//! | exact | `spam@example.test` | the whole value, case-insensitively |
//! | wildcard | `*@example.test` | the whole value, `*` matches any run |
//! | prefix | `192.168.` | the beginning, with a label boundary for IPs |
//! | CIDR | `192.168.0.0/16`, `2001:db8::/32` | address range |
//!
//! A wildcard is anchored: `*.ru` does not match `a.ru.evil`. The old board
//! matched a wildcard by looking for its pieces anywhere in the value, so a
//! crafted address could slip past a `*.ru` ban; that behaviour is deliberately
//! not reproduced. An IP prefix must end on a dot boundary, so `1.2.3.4` does
//! not match `1.2.3.40`.

use crate::error::StoreResult;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// The longest accepted ban pattern in bytes.
pub const MAX_PATTERN_LEN: usize = 255;
/// The longest accepted ban reason in characters.
pub const MAX_REASON_LEN: usize = 255;
/// The longest value a pattern is matched against.
///
/// An email address is at most 254 bytes and a hostname at most 253, so a longer
/// value cannot be a real subject. The bound also keeps the glob matcher from
/// running over an attacker-supplied megabyte.
pub const MAX_MATCH_VALUE: usize = 1_024;

/// A ban pattern that cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    /// The pattern is empty or only whitespace.
    Empty,
    /// The pattern is longer than [`MAX_PATTERN_LEN`] bytes.
    TooLong(usize),
    /// The pattern contains a control character.
    ControlCharacter,
    /// The text after `/` is not a valid CIDR network.
    InvalidCidr(String),
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "ban pattern is empty"),
            Self::TooLong(length) => {
                write!(f, "ban pattern is {length} bytes, limit {MAX_PATTERN_LEN}")
            }
            Self::ControlCharacter => write!(f, "ban pattern contains a control character"),
            Self::InvalidCidr(value) => write!(f, "invalid CIDR network: {value:?}"),
        }
    }
}

impl std::error::Error for PatternError {}

/// An IPv4 or IPv6 network.
///
/// The stored address is masked to the prefix, so `192.168.1.7/24` and
/// `192.168.1.0/24` are the same network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNetwork {
    addr: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    /// Create a network from an address and a prefix length.
    ///
    /// Returns `None` when the prefix is longer than the address family allows.
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        let maximum = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > maximum {
            return None;
        }
        Some(Self {
            addr: mask_ip(addr, prefix),
            prefix,
        })
    }

    /// Parse `address/prefix`.
    pub fn parse(text: &str) -> Option<Self> {
        let (addr, prefix) = text.trim().split_once('/')?;
        let addr: IpAddr = addr.trim().parse().ok()?;
        let prefix: u8 = prefix.trim().parse().ok()?;
        Self::new(addr, prefix)
    }

    /// The masked network address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `ip` is inside the network.
    ///
    /// An IPv4-mapped IPv6 address is compared as its IPv4 form.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                masked_v4(network, self.prefix) == masked_v4(ip, self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                masked_v6(network, self.prefix) == masked_v6(ip, self.prefix)
            }
            (IpAddr::V4(network), IpAddr::V6(ip)) => ip
                .to_ipv4_mapped()
                .is_some_and(|ip| masked_v4(network, self.prefix) == masked_v4(ip, self.prefix)),
            (IpAddr::V6(network), IpAddr::V4(ip)) => {
                network.to_ipv4_mapped().is_some_and(|network| {
                    self.prefix >= 96
                        && masked_v4(network, self.prefix - 96) == masked_v4(ip, self.prefix - 96)
                })
            }
        }
    }
}

fn masked_v4(addr: Ipv4Addr, prefix: u8) -> u32 {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    u32::from(addr) & mask
}

fn masked_v6(addr: Ipv6Addr, prefix: u8) -> u128 {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    u128::from(addr) & mask
}

fn mask_ip(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(addr) => IpAddr::V4(Ipv4Addr::from(masked_v4(addr, prefix))),
        IpAddr::V6(addr) => IpAddr::V6(Ipv6Addr::from(masked_v6(addr, prefix))),
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(addr) => addr
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(addr)),
        IpAddr::V4(addr) => IpAddr::V4(addr),
    }
}

/// One ban pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanPattern {
    /// The whole value, compared case-insensitively.
    Exact(String),
    /// A glob with `*`, anchored at both ends.
    Wildcard(String),
    /// The beginning of the value; for an IP, the beginning must end on a dot
    /// boundary.
    Prefix(String),
    /// An address range.
    Cidr(IpNetwork),
}

impl BanPattern {
    /// Parse a pattern.
    ///
    /// Text containing `/` is a CIDR network, text containing `*` is a
    /// wildcard, and everything else is exact. A plain prefix has no syntax:
    /// use [`BanPattern::prefix`] explicitly, so a legacy first-octet ban is
    /// never mistaken for an exact address.
    pub fn parse(text: &str) -> Result<Self, PatternError> {
        let text = text.trim();
        if text.is_empty() {
            return Err(PatternError::Empty);
        }
        if text.len() > MAX_PATTERN_LEN {
            return Err(PatternError::TooLong(text.len()));
        }
        if text.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(PatternError::ControlCharacter);
        }
        if text.contains('/') {
            return IpNetwork::parse(text)
                .map(Self::Cidr)
                .ok_or_else(|| PatternError::InvalidCidr(text.to_string()));
        }
        if text.contains('*') {
            return Ok(Self::Wildcard(text.to_string()));
        }
        Ok(Self::Exact(text.to_string()))
    }

    /// An exact pattern.
    pub fn exact(text: impl Into<String>) -> Self {
        Self::Exact(text.into())
    }

    /// A wildcard pattern.
    pub fn wildcard(text: impl Into<String>) -> Self {
        Self::Wildcard(text.into())
    }

    /// A prefix pattern.
    pub fn prefix(text: impl Into<String>) -> Self {
        Self::Prefix(text.into())
    }

    /// A CIDR pattern.
    pub fn cidr(network: IpNetwork) -> Self {
        Self::Cidr(network)
    }

    /// Match a text value (an email address, a username or an address in
    /// textual form).
    ///
    /// A value longer than [`MAX_MATCH_VALUE`] never matches.
    pub fn matches(&self, value: &str) -> bool {
        if value.len() > MAX_MATCH_VALUE {
            return false;
        }
        match self {
            Self::Exact(pattern) => value.eq_ignore_ascii_case(pattern),
            Self::Wildcard(pattern) => glob_match(pattern, value),
            Self::Prefix(pattern) => value
                .get(..pattern.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(pattern)),
            Self::Cidr(network) => value
                .trim()
                .parse::<IpAddr>()
                .ok()
                .is_some_and(|ip| network.contains(normalize_ip(ip))),
        }
    }

    /// Match an IP address.
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        let ip = normalize_ip(ip);
        match self {
            Self::Cidr(network) => network.contains(ip),
            Self::Exact(pattern) => pattern
                .trim()
                .parse::<IpAddr>()
                .ok()
                .is_some_and(|pattern| normalize_ip(pattern) == ip),
            Self::Wildcard(pattern) => glob_match(pattern, &ip.to_string()),
            Self::Prefix(pattern) => {
                let value = ip.to_string();
                let Some(prefix) = value.get(..pattern.len()) else {
                    return false;
                };
                prefix.eq_ignore_ascii_case(pattern)
                    && (pattern.ends_with('.')
                        || pattern.ends_with(':')
                        || value
                            .as_bytes()
                            .get(pattern.len())
                            .is_none_or(|byte| matches!(*byte, b'.' | b':')))
            }
        }
    }
}

/// Match `*` against any run of characters, anchored at both ends.
fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let value: Vec<char> = value.to_ascii_lowercase().chars().collect();
    let (mut pattern_index, mut value_index) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut resume = 0usize;
    while value_index < value.len() {
        if pattern_index < pattern.len() && pattern[pattern_index] == value[value_index] {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            star = Some(pattern_index);
            pattern_index += 1;
            resume = value_index;
        } else if let Some(position) = star {
            pattern_index = position + 1;
            resume += 1;
            value_index = resume;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

/// The restrictions a ban imposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BanFlags {
    /// Block every request.
    pub access: bool,
    /// Block registration.
    pub register: bool,
    /// Block posting.
    pub post: bool,
    /// Block login.
    pub login: bool,
}

impl BanFlags {
    /// No restriction.
    pub const NONE: Self = Self {
        access: false,
        register: false,
        post: false,
        login: false,
    };

    /// Every restriction.
    pub const ALL: Self = Self {
        access: true,
        register: true,
        post: true,
        login: true,
    };

    /// Whether at least one restriction is set.
    pub fn any(self) -> bool {
        self.access || self.register || self.post || self.login
    }
}

/// One stored ban rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRule {
    /// The row id, used to report a stable rule.
    pub id: u64,
    /// Match this account id.
    pub user_id: Option<u64>,
    /// Match any of these username patterns.
    pub usernames: Vec<BanPattern>,
    /// Match any of these email patterns.
    pub emails: Vec<BanPattern>,
    /// Match any of these address patterns.
    pub ips: Vec<BanPattern>,
    /// The reason shown to the visitor.
    pub reason: String,
    /// Expiry as a Unix timestamp; `0` is permanent.
    pub expires: i64,
    /// Whether this rule exempts the subject instead of banning it.
    pub exempt: bool,
    /// The restrictions the rule imposes.
    pub flags: BanFlags,
}

impl BanRule {
    /// Start a permanent, non-exempt rule that imposes every restriction.
    pub fn new(id: u64) -> Self {
        Self {
            id,
            user_id: None,
            usernames: Vec::new(),
            emails: Vec::new(),
            ips: Vec::new(),
            reason: String::new(),
            expires: 0,
            exempt: false,
            flags: BanFlags::ALL,
        }
    }

    /// Ban one account id.
    pub fn for_user(mut self, user_id: u64) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Add a username pattern.
    pub fn with_username(mut self, pattern: BanPattern) -> Self {
        self.usernames.push(pattern);
        self
    }

    /// Add an email pattern.
    pub fn with_email(mut self, pattern: BanPattern) -> Self {
        self.emails.push(pattern);
        self
    }

    /// Add an address pattern.
    pub fn with_ip(mut self, pattern: BanPattern) -> Self {
        self.ips.push(pattern);
        self
    }

    /// Set the reason, bounded to [`MAX_REASON_LEN`] characters.
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into().chars().take(MAX_REASON_LEN).collect();
        self
    }

    /// Set the expiry.
    pub fn expires(mut self, unix_seconds: i64) -> Self {
        self.expires = unix_seconds;
        self
    }

    /// Turn this rule into an exemption.
    pub fn exempt(mut self) -> Self {
        self.exempt = true;
        self
    }

    /// Replace the restrictions.
    pub fn with_flags(mut self, flags: BanFlags) -> Self {
        self.flags = flags;
        self
    }

    /// Whether the rule has not expired at `now`.
    pub fn is_active(&self, now: i64) -> bool {
        self.expires == 0 || self.expires > now
    }

    /// Whether the rule names at least one constraint.
    pub fn is_constrained(&self) -> bool {
        self.user_id.is_some()
            || !self.usernames.is_empty()
            || !self.emails.is_empty()
            || !self.ips.is_empty()
    }

    /// Whether every constraint the rule names matches the subject.
    pub fn matches(&self, subject: &BanSubject<'_>) -> bool {
        if !self.is_constrained() {
            return false;
        }
        if let Some(user_id) = self.user_id {
            if subject.user_id != Some(user_id) {
                return false;
            }
        }
        if !self.usernames.is_empty() {
            let Some(username) = subject.username else {
                return false;
            };
            if !self
                .usernames
                .iter()
                .any(|pattern| pattern.matches(username))
            {
                return false;
            }
        }
        if !self.emails.is_empty() {
            let Some(email) = subject.email else {
                return false;
            };
            if !self.emails.iter().any(|pattern| pattern.matches(email)) {
                return false;
            }
        }
        if !self.ips.is_empty() {
            let Some(ip) = subject.ip else {
                return false;
            };
            if !self.ips.iter().any(|pattern| pattern.matches_ip(ip)) {
                return false;
            }
        }
        true
    }

    /// Build the hit reported for this rule.
    pub fn hit(&self) -> BanHit {
        BanHit {
            rule_id: self.id,
            reason: self.reason.clone(),
            expires: self.expires,
            flags: self.flags,
        }
    }
}

/// The visitor attributes a ban rule is checked against.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BanSubject<'a> {
    /// The account id, when the visitor is logged in.
    pub user_id: Option<u64>,
    /// The client address, after trusted-proxy handling.
    pub ip: Option<IpAddr>,
    /// The account email address.
    pub email: Option<&'a str>,
    /// The account username.
    pub username: Option<&'a str>,
}

impl<'a> BanSubject<'a> {
    /// An empty subject.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the account id.
    pub fn with_user(mut self, user_id: u64) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// Set the address.
    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.ip = Some(ip);
        self
    }

    /// Set the email address.
    pub fn with_email(mut self, email: &'a str) -> Self {
        self.email = Some(email);
        self
    }

    /// Set the username.
    pub fn with_username(mut self, username: &'a str) -> Self {
        self.username = Some(username);
        self
    }
}

/// The rule that decided a check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanHit {
    /// The rule id.
    pub rule_id: u64,
    /// The rule reason.
    pub reason: String,
    /// The rule expiry; `0` is permanent.
    pub expires: i64,
    /// The restrictions the rule imposes.
    pub flags: BanFlags,
}

/// The result of checking one subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanDecision {
    /// No rule matched.
    Allow,
    /// An exemption rule matched; the subject is allowed even if a denying rule
    /// also matches.
    Exempt(BanHit),
    /// A denying rule matched.
    Deny(BanHit),
}

impl BanDecision {
    /// Whether the subject is banned.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny(_))
    }

    /// Whether the decision is an exemption.
    pub fn is_exempt(&self) -> bool {
        matches!(self, Self::Exempt(_))
    }

    /// The rule behind the decision.
    pub fn hit(&self) -> Option<&BanHit> {
        match self {
            Self::Allow => None,
            Self::Exempt(hit) | Self::Deny(hit) => Some(hit),
        }
    }

    /// The reason behind the decision.
    pub fn reason(&self) -> Option<&str> {
        self.hit().map(|hit| hit.reason.as_str())
    }

    /// The restrictions behind the decision.
    pub fn flags(&self) -> BanFlags {
        self.hit().map(|hit| hit.flags).unwrap_or(BanFlags::NONE)
    }
}

/// Storage for ban rules.
pub trait BanStore {
    /// Every rule the store wants evaluated, including expired rows if the
    /// backend does not filter them. [`BanCache`] checks expiry itself.
    fn active_bans(&self, now: i64) -> StoreResult<Vec<BanRule>>;
}

#[derive(Debug)]
struct CachedBans {
    rules: Vec<BanRule>,
    loaded_at: i64,
    generation: u64,
}

/// A [`BanStore`] wrapper that caches the rule list for a short time.
///
/// The ban list is read on almost every request, so a cache is the difference
/// between one query per request and one query per interval. The cache is
/// invalidated explicitly by [`BanCache::invalidate`] (an ACP ban change) and
/// by the TTL.
#[derive(Debug)]
pub struct BanCache<S> {
    store: S,
    ttl: i64,
    state: Mutex<Option<CachedBans>>,
    generation: AtomicU64,
}

impl<S: BanStore> BanCache<S> {
    /// Wrap a store. A `ttl` of `0` disables the cache.
    pub fn new(store: S, ttl: i64) -> Self {
        Self {
            store,
            ttl,
            state: Mutex::new(None),
            generation: AtomicU64::new(0),
        }
    }

    /// The backing store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// The current cache generation.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Drop the cached list and bump the generation.
    pub fn invalidate(&self) -> u64 {
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        *self.state.lock().unwrap_or_else(|error| error.into_inner()) = None;
        generation
    }

    /// Evaluate a subject against the cached rules.
    ///
    /// A store error is returned to the caller instead of being turned into an
    /// allow or a deny; the application decides whether an unavailable ban list
    /// should fail open or closed.
    pub fn check(&self, subject: &BanSubject<'_>, now: i64) -> StoreResult<BanDecision> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        let generation = self.generation.load(Ordering::SeqCst);
        let fresh = state.as_ref().is_some_and(|cached| {
            cached.generation == generation
                && self.ttl > 0
                && now >= cached.loaded_at
                && now.saturating_sub(cached.loaded_at) < self.ttl
        });
        if !fresh {
            let rules = self.store.active_bans(now)?;
            *state = Some(CachedBans {
                rules,
                loaded_at: now,
                generation,
            });
        }
        let rules: &[BanRule] = state
            .as_ref()
            .map(|cached| cached.rules.as_slice())
            .unwrap_or(&[]);
        Ok(evaluate(rules, subject, now))
    }
}

fn evaluate(rules: &[BanRule], subject: &BanSubject<'_>, now: i64) -> BanDecision {
    let mut exempt: Option<&BanRule> = None;
    let mut deny: Option<&BanRule> = None;
    for rule in rules {
        if !rule.is_active(now) || !rule.matches(subject) {
            continue;
        }
        if rule.exempt {
            if exempt.is_none_or(|current| rule.id < current.id) {
                exempt = Some(rule);
            }
        } else if deny.is_none_or(|current| rule.id < current.id) {
            deny = Some(rule);
        }
    }
    if let Some(rule) = exempt {
        BanDecision::Exempt(rule.hit())
    } else if let Some(rule) = deny {
        BanDecision::Deny(rule.hit())
    } else {
        BanDecision::Allow
    }
}

/// Where an address lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpScope {
    /// A globally routable unicast address.
    Public,
    /// `127.0.0.0/8` or `::1`.
    Loopback,
    /// `10/8`, `172.16/12` or `192.168/16`.
    Private,
    /// `169.254/16` or `fe80::/10`.
    LinkLocal,
    /// `100.64.0.0/10`, the carrier-grade NAT range.
    Cgnat,
    /// `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` or `2001:db8::/32`.
    Documentation,
    /// `198.18.0.0/15`, the benchmarking range.
    Shared,
    /// `224/4` or `ff00::/8`.
    Multicast,
    /// `0.0.0.0` or `::`.
    Unspecified,
    /// A reserved or special-purpose range that is not public.
    Reserved,
    /// `255.255.255.255`.
    Broadcast,
    /// `fc00::/7`.
    UniqueLocal,
}

impl IpScope {
    /// Whether the address is globally routable.
    pub fn is_public(self) -> bool {
        matches!(self, Self::Public)
    }
}

/// Classify an address.
pub fn ip_scope(ip: IpAddr) -> IpScope {
    match ip {
        IpAddr::V4(ip) => ipv4_scope(ip),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => ipv4_scope(ip),
            None => ipv6_scope(ip),
        },
    }
}

/// Whether an automatically created ban may name `ip`.
///
/// An automatic ban (a cron abuser, a login flood) must never name a loopback,
/// private, link-local, CGNAT, documentation or otherwise special address: the
/// proxy would ban itself, or the board would lock out its own network. The
/// rule is the same one the keskustelu server applies to its cron ban.
pub fn automatic_ban_allowed(ip: IpAddr) -> bool {
    ip_scope(ip).is_public()
}

fn ipv4_scope(ip: Ipv4Addr) -> IpScope {
    let octets = ip.octets();
    if ip.is_unspecified() {
        IpScope::Unspecified
    } else if ip.is_loopback() {
        IpScope::Loopback
    } else if ip.is_private() {
        IpScope::Private
    } else if ip.is_link_local() {
        IpScope::LinkLocal
    } else if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        IpScope::Cgnat
    } else if ip.is_documentation() {
        IpScope::Documentation
    } else if ip.is_multicast() {
        IpScope::Multicast
    } else if ip.is_broadcast() {
        IpScope::Broadcast
    } else if octets[0] == 198 && matches!(octets[1], 18 | 19) {
        IpScope::Shared
    } else if octets[0] >= 240
        || octets[0] == 0
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
    {
        IpScope::Reserved
    } else {
        IpScope::Public
    }
}

fn ipv6_scope(ip: Ipv6Addr) -> IpScope {
    if ip.is_unspecified() {
        IpScope::Unspecified
    } else if ip.is_loopback() {
        IpScope::Loopback
    } else if ip.is_unique_local() {
        IpScope::UniqueLocal
    } else if ip.is_unicast_link_local() {
        IpScope::LinkLocal
    } else if ip.is_multicast() {
        IpScope::Multicast
    } else if v6_in_network(ip, [0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32) {
        IpScope::Documentation
    } else if v6_in_network(ip, [0x2001, 0x0002, 0, 0, 0, 0, 0, 0], 48) {
        IpScope::Shared
    } else if v6_in_network(ip, [0x2001, 0, 0, 0, 0, 0, 0, 0], 23) {
        IpScope::Reserved
    } else if v6_in_network(ip, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16) {
        let v4 = Ipv4Addr::from((u128::from(ip) >> 80) as u32);
        ipv4_scope(v4)
    } else if v6_in_network(ip, [0x2000, 0, 0, 0, 0, 0, 0, 0], 3) {
        IpScope::Public
    } else {
        IpScope::Reserved
    }
}

fn v6_in_network(ip: Ipv6Addr, base: [u16; 8], prefix: u8) -> bool {
    let base = u128::from(Ipv6Addr::from(base));
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    (u128::from(ip) & mask) == (base & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn parses_patterns_by_shape() {
        assert_eq!(
            BanPattern::parse("exact@example.test").unwrap(),
            BanPattern::Exact("exact@example.test".into())
        );
        assert_eq!(
            BanPattern::parse("*.ru").unwrap(),
            BanPattern::Wildcard("*.ru".into())
        );
        assert_eq!(
            BanPattern::parse("192.168.0.0/16").unwrap(),
            BanPattern::Cidr(IpNetwork::parse("192.168.0.0/16").unwrap())
        );
        assert!(matches!(BanPattern::parse(""), Err(PatternError::Empty)));
        assert!(matches!(BanPattern::parse("  "), Err(PatternError::Empty)));
        assert!(matches!(
            BanPattern::parse(&"a".repeat(MAX_PATTERN_LEN + 1)),
            Err(PatternError::TooLong(_))
        ));
        assert!(matches!(
            BanPattern::parse("a\r\nb"),
            Err(PatternError::ControlCharacter)
        ));
        assert!(matches!(
            BanPattern::parse("10.0.0.0/33"),
            Err(PatternError::InvalidCidr(_))
        ));
        assert!(matches!(
            BanPattern::parse("not-an-address/24"),
            Err(PatternError::InvalidCidr(_))
        ));
    }

    #[test]
    fn exact_and_wildcard_are_anchored_and_case_insensitive() {
        let exact = BanPattern::exact("Spam@Example.test");
        assert!(exact.matches("spam@example.TEST"));
        assert!(!exact.matches("xspam@example.test"));
        assert!(!exact.matches("spam@example.test.evil"));

        let wildcard = BanPattern::wildcard("*.ru");
        assert!(wildcard.matches("user@example.ru"));
        assert!(wildcard.matches("USER@EXAMPLE.RU"));
        assert!(!wildcard.matches("user@example.com"));
        assert!(
            !wildcard.matches("a.ru.evil"),
            "a wildcard must be anchored"
        );
        assert!(!wildcard.matches("ru"));
        assert!(BanPattern::wildcard("*@example.test").matches("a@example.test"));
        assert!(BanPattern::wildcard("a*b*c").matches("aXXbYYc"));
        assert!(!BanPattern::wildcard("a*b*c").matches("aXXbYY"));
        assert!(BanPattern::wildcard("*").matches("anything"));
        assert!(BanPattern::wildcard("").matches(""));
        assert!(!BanPattern::wildcard("").matches("x"));
    }

    #[test]
    fn prefixes_do_not_cross_a_label_boundary_for_addresses() {
        let prefix = BanPattern::prefix("1.2.3.4");
        assert!(prefix.matches_ip(ip("1.2.3.4")));
        assert!(
            !prefix.matches_ip(ip("1.2.3.40")),
            "prefix matched a longer octet"
        );
        assert!(BanPattern::prefix("192.168.").matches_ip(ip("192.168.1.7")));
        assert!(!BanPattern::prefix("192.168.").matches_ip(ip("192.169.1.7")));
        assert!(BanPattern::prefix("2001:db8:").matches_ip(ip("2001:db8::1")));
        assert!(BanPattern::prefix("2001:db8").matches_ip(ip("2001:db8::1")));
        assert!(!BanPattern::prefix("2001:db").matches_ip(ip("2001:db8::1")));
        // For a non-address value a prefix is a plain prefix.
        assert!(BanPattern::prefix("spam@").matches("spam@example.test"));
    }

    #[test]
    fn cidr_matches_both_families_and_mapped_addresses() {
        let network = IpNetwork::parse("192.168.0.0/16").unwrap();
        assert!(network.contains(ip("192.168.0.1")));
        assert!(network.contains(ip("192.168.255.255")));
        assert!(!network.contains(ip("192.169.0.1")));
        assert!(network.contains(ip("::ffff:192.168.1.1")));
        assert_eq!(network.addr(), ip("192.168.0.0"));
        assert_eq!(network.prefix(), 16);

        let v6 = IpNetwork::parse("2001:db8::/32").unwrap();
        assert!(v6.contains(ip("2001:db8::1")));
        assert!(v6.contains(ip("2001:db8:ffff::1")));
        assert!(!v6.contains(ip("2001:db9::1")));
        assert!(!v6.contains(ip("::ffff:192.0.2.1")));

        assert!(IpNetwork::parse("0.0.0.0/0")
            .unwrap()
            .contains(ip("8.8.8.8")));
        assert!(IpNetwork::parse("::/0")
            .unwrap()
            .contains(ip("2606:4700::1111")));
        assert!(IpNetwork::parse("10.0.0.0/8").is_some());
        assert!(IpNetwork::parse("10.0.0.0/33").is_none());
        assert!(IpNetwork::parse("::/129").is_none());
        assert!(IpNetwork::parse("10.0.0.0").is_none());
        assert!(IpNetwork::parse("10.0.0.0/8/9").is_none());
        assert_eq!(
            IpNetwork::new(ip("192.168.1.7"), 24).unwrap().addr(),
            ip("192.168.1.0")
        );
    }

    #[test]
    fn rule_requires_every_named_constraint() {
        let rule = BanRule::new(1)
            .for_user(7)
            .with_email(BanPattern::wildcard("*@spam.test"))
            .with_ip(BanPattern::cidr(IpNetwork::parse("10.0.0.0/8").unwrap()));
        let subject = BanSubject::new()
            .with_user(7)
            .with_email("a@spam.test")
            .with_ip(ip("10.1.2.3"));
        assert!(rule.matches(&subject));
        assert!(!rule.matches(
            &BanSubject::new()
                .with_user(8)
                .with_email("a@spam.test")
                .with_ip(ip("10.1.2.3"))
        ));
        assert!(!rule.matches(
            &BanSubject::new()
                .with_user(7)
                .with_email("a@ok.test")
                .with_ip(ip("10.1.2.3"))
        ));
        assert!(!rule.matches(
            &BanSubject::new()
                .with_user(7)
                .with_email("a@spam.test")
                .with_ip(ip("11.0.0.1"))
        ));
        assert!(!rule.matches(&BanSubject::new().with_user(7).with_email("a@spam.test")));
    }

    #[test]
    fn an_unconstrained_rule_never_matches() {
        let rule = BanRule::new(1);
        assert!(!rule.is_constrained());
        assert!(!rule.matches(&BanSubject::new().with_user(1).with_email("a@b.test")));
        assert!(!rule.matches(&BanSubject::new()));
    }

    #[test]
    fn username_patterns_and_expiry_are_honoured() {
        let rule = BanRule::new(1)
            .with_username(BanPattern::wildcard("spam*"))
            .expires(2_000);
        assert!(rule.is_active(1_999));
        assert!(!rule.is_active(2_000));
        assert!(!rule.is_active(2_001));
        assert!(rule.matches(&BanSubject::new().with_username("SpamBot")));
        assert!(!rule.matches(&BanSubject::new().with_username("human")));
        assert!(!rule.matches(&BanSubject::new()));
    }

    #[test]
    fn reasons_and_flags_are_bounded_and_copied() {
        let rule = BanRule::new(3)
            .for_user(1)
            .reason("x".repeat(MAX_REASON_LEN + 50))
            .with_flags(BanFlags::NONE);
        assert_eq!(rule.reason.chars().count(), MAX_REASON_LEN);
        let hit = rule.hit();
        assert_eq!(hit.rule_id, 3);
        assert!(!hit.flags.any());
        assert!(BanFlags::ALL.any());
    }

    struct FakeStore {
        rules: Vec<BanRule>,
        loads: std::sync::atomic::AtomicUsize,
    }

    impl FakeStore {
        fn new(rules: Vec<BanRule>) -> Self {
            Self {
                rules,
                loads: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    impl BanStore for FakeStore {
        fn active_bans(&self, _now: i64) -> StoreResult<Vec<BanRule>> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            Ok(self.rules.clone())
        }
    }

    #[test]
    fn cache_loads_once_per_ttl_and_can_be_invalidated() {
        let cache = BanCache::new(
            FakeStore::new(vec![BanRule::new(1)
                .with_ip(BanPattern::cidr(IpNetwork::parse("10.0.0.0/8").unwrap()))
                .reason("blocked")]),
            60,
        );
        let subject = BanSubject::new().with_ip(ip("10.1.2.3"));
        assert!(cache.check(&subject, 1_000).unwrap().is_denied());
        assert!(cache.check(&subject, 1_001).unwrap().is_denied());
        assert_eq!(cache.store().loads.load(Ordering::SeqCst), 1);
        assert!(cache.check(&subject, 1_060).unwrap().is_denied());
        assert_eq!(cache.store().loads.load(Ordering::SeqCst), 2);

        let generation = cache.generation();
        assert_eq!(cache.invalidate(), generation + 1);
        assert!(cache.check(&subject, 1_061).unwrap().is_denied());
        assert_eq!(cache.store().loads.load(Ordering::SeqCst), 3);
        // A clock rollback reloads the cache instead of treating it as fresh.
        assert!(cache.check(&subject, 1_000).unwrap().is_denied());
        assert_eq!(cache.store().loads.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn exemptions_win_regardless_of_row_order() {
        let denying = BanRule::new(5)
            .with_email(BanPattern::exact("user@example.test"))
            .reason("denied");
        let exempt = BanRule::new(9)
            .with_email(BanPattern::exact("user@example.test"))
            .reason("staff")
            .exempt();
        let subject = BanSubject::new().with_email("user@example.test");
        for rules in [
            vec![denying.clone(), exempt.clone()],
            vec![exempt.clone(), denying.clone()],
        ] {
            let cache = BanCache::new(FakeStore::new(rules), 60);
            let decision = cache.check(&subject, 1).unwrap();
            assert!(decision.is_exempt());
            assert!(!decision.is_denied());
            assert_eq!(decision.reason(), Some("staff"));
        }
    }

    #[test]
    fn the_lowest_rule_id_is_reported_deterministically() {
        let subject = BanSubject::new().with_ip(ip("10.1.2.3"));
        let high = BanRule::new(9)
            .with_ip(BanPattern::cidr(IpNetwork::parse("10.0.0.0/8").unwrap()))
            .reason("high");
        let low = BanRule::new(3)
            .with_ip(BanPattern::cidr(IpNetwork::parse("10.0.0.0/8").unwrap()))
            .reason("low");
        for rules in [
            vec![high.clone(), low.clone()],
            vec![low.clone(), high.clone()],
        ] {
            let cache = BanCache::new(FakeStore::new(rules), 60);
            let decision = cache.check(&subject, 1).unwrap();
            assert_eq!(decision.reason(), Some("low"));
        }
    }

    #[test]
    fn expired_rules_are_ignored() {
        let cache = BanCache::new(
            FakeStore::new(vec![BanRule::new(1)
                .with_ip(BanPattern::exact("10.1.2.3"))
                .expires(100)]),
            60,
        );
        let subject = BanSubject::new().with_ip(ip("10.1.2.3"));
        assert!(cache.check(&subject, 99).unwrap().is_denied());
        assert!(!cache.check(&subject, 100).unwrap().is_denied());
        assert!(!cache.check(&subject, 101).unwrap().is_denied());
    }

    #[test]
    fn classifies_every_special_range() {
        let cases = [
            ("127.0.0.1", IpScope::Loopback),
            ("10.1.2.3", IpScope::Private),
            ("172.16.0.1", IpScope::Private),
            ("172.31.255.255", IpScope::Private),
            ("172.32.0.1", IpScope::Public),
            ("192.168.1.1", IpScope::Private),
            ("169.254.1.1", IpScope::LinkLocal),
            ("100.64.0.1", IpScope::Cgnat),
            ("100.127.255.255", IpScope::Cgnat),
            ("100.128.0.1", IpScope::Public),
            ("192.0.2.1", IpScope::Documentation),
            ("198.51.100.1", IpScope::Documentation),
            ("203.0.113.1", IpScope::Documentation),
            ("198.18.0.1", IpScope::Shared),
            ("198.19.255.255", IpScope::Shared),
            ("224.0.0.1", IpScope::Multicast),
            ("255.255.255.255", IpScope::Broadcast),
            ("0.0.0.0", IpScope::Unspecified),
            ("0.1.2.3", IpScope::Reserved),
            ("240.0.0.1", IpScope::Reserved),
            ("192.0.0.1", IpScope::Reserved),
            ("192.88.99.1", IpScope::Reserved),
            ("8.8.8.8", IpScope::Public),
            ("1.1.1.1", IpScope::Public),
            ("::1", IpScope::Loopback),
            ("::", IpScope::Unspecified),
            ("fc00::1", IpScope::UniqueLocal),
            ("fdff::1", IpScope::UniqueLocal),
            ("fe80::1", IpScope::LinkLocal),
            ("ff02::1", IpScope::Multicast),
            ("2001:db8::1", IpScope::Documentation),
            ("2001:2::1", IpScope::Shared),
            ("2001::1", IpScope::Reserved),
            ("2001:20::1", IpScope::Reserved),
            ("2002:7f00:1::1", IpScope::Loopback),
            ("2002:0a00:1::1", IpScope::Private),
            ("2606:4700::1111", IpScope::Public),
            ("::ffff:10.0.0.1", IpScope::Private),
            ("::ffff:8.8.8.8", IpScope::Public),
            ("64:ff9b::1", IpScope::Reserved),
            ("100::1", IpScope::Reserved),
        ];
        for (text, expected) in cases {
            assert_eq!(ip_scope(ip(text)), expected, "{text}");
        }
    }

    #[test]
    fn automatic_bans_only_name_public_addresses() {
        for text in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "192.0.2.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
        ] {
            assert!(!automatic_ban_allowed(ip(text)), "{text}");
        }
        for text in ["8.8.8.8", "1.1.1.1", "2606:4700::1111"] {
            assert!(automatic_ban_allowed(ip(text)), "{text}");
        }
    }

    #[test]
    fn decision_accessors_are_consistent() {
        let allow = BanDecision::Allow;
        assert!(!allow.is_denied());
        assert!(!allow.is_exempt());
        assert!(allow.hit().is_none());
        assert_eq!(allow.flags(), BanFlags::NONE);
        let hit = BanRule::new(1).reason("x").hit();
        let deny = BanDecision::Deny(hit.clone());
        assert!(deny.is_denied());
        assert_eq!(deny.reason(), Some("x"));
        assert_eq!(deny.flags(), BanFlags::ALL);
        assert_eq!(BanDecision::Exempt(hit).reason(), Some("x"));
    }
}
