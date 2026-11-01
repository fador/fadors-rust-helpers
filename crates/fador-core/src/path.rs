//! Shared path-safety helpers.
//!
//! Every filesystem write, read and unlink in the server goes through one of
//! these checks. They are deliberately strict and platform aware: the shipped
//! server runs on Linux, but the tests run on Windows, where a trailing dot or
//! space, a device name or an alternate data stream changes which file a path
//! actually names.
//!
//! Rules:
//!
//! - a relative path is a `/`-separated list of non-empty components;
//! - a component may not be `.` or `..`, may not contain `\`, NUL, `:` or any
//!   control character, may not end with a dot or a space (Windows strips
//!   them, so `....` names the parent directory), and may not be a reserved
//!   device name (`CON`, `NUL`, `COM1`, …);
//! - a resolved path must canonicalise inside its root. A missing file is
//!   accepted only when its parent canonicalises inside the root, so a caller
//!   can create a new file but never write through a symlink that leaves the
//!   root.

use std::path::{Component, Path, PathBuf};

/// The device names Windows resolves before looking at the directory entry.
const RESERVED_DEVICES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Whether a single name (without an extension) is a reserved device name.
pub fn is_reserved_device_name(name: &str) -> bool {
    let stem = name.split_once('.').map(|(stem, _)| stem).unwrap_or(name);
    RESERVED_DEVICES
        .iter()
        .any(|device| stem.eq_ignore_ascii_case(device))
}

/// Whether one `/`-separated path component is safe on every platform we run
/// on.
pub fn component_is_safe(component: &str) -> bool {
    if component.is_empty() || component.len() > 255 {
        return false;
    }
    if component == "." || component == ".." {
        return false;
    }
    if component.chars().any(|ch| {
        ch.is_control() || matches!(ch, '\\' | '/' | ':' | '"' | '<' | '>' | '|' | '?' | '*')
    }) {
        return false;
    }
    // Windows silently drops trailing dots and spaces, so `....` and `.. ` would
    // address the parent directory instead of a directory with that name.
    if component.ends_with('.') || component.ends_with(' ') {
        return false;
    }
    if is_reserved_device_name(component) {
        return false;
    }
    // Reject the Windows component forms `Path` would treat specially.
    !Path::new(component)
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
}

/// A `/`-separated relative path whose every component is safe.
pub fn relative_is_safe(path: &str) -> bool {
    if path.is_empty() || path.len() > 4096 {
        return false;
    }
    if path.starts_with('/') || path.starts_with('~') {
        return false;
    }
    path.split('/').all(component_is_safe)
}

/// Validate a stored database value that becomes part of an on-disk file name
/// (`attachments.filename`, `attachments.file_hash`).
///
/// Returns the value unchanged when it is a single safe component.
pub fn stored_component(value: &str) -> Option<&str> {
    if component_is_safe(value) {
        Some(value)
    } else {
        None
    }
}

/// Build the `<id>_<hash>` (or `<id>_<filename>`) name of an attachment file.
///
/// The id is fixed by the row; the suffix comes from the database, so it is
/// validated instead of trusted.
pub fn attachment_file_name(id: i64, hash: &str, filename: &str) -> Option<String> {
    if id <= 0 {
        return None;
    }
    let suffix = if hash.is_empty() { filename } else { hash };
    let suffix = stored_component(suffix)?;
    let name = format!("{id}_{suffix}");
    if name.len() > 255 {
        return None;
    }
    Some(name)
}

/// Whether a resolved path stays inside `root`.
///
/// Both sides are canonicalised. A missing target is accepted when its parent
/// canonicalises inside the root, so callers can create new files without
/// allowing a write through a symlinked directory.
pub fn is_inside(root: &Path, path: &Path) -> bool {
    let Ok(root) = std::fs::canonicalize(root) else {
        return false;
    };
    match std::fs::canonicalize(path) {
        Ok(path) => path.starts_with(root),
        Err(_) => path
            .parent()
            .and_then(|parent| std::fs::canonicalize(parent).ok())
            .is_some_and(|parent| parent.starts_with(&root)),
    }
}

/// Resolve a relative path against a canonical root, rejecting traversal and
/// symlink escapes. The target must already exist.
///
/// `root` must already be canonical (the application canonicalises the content
/// root at startup); a non-canonical root makes the containment check fail,
/// never succeed. Only the candidate is canonicalised, so the static file
/// handler does not pay for a second `realpath` on every request.
pub fn resolve_under(root: &Path, relative: &str) -> Option<PathBuf> {
    if !relative_is_safe(relative) {
        return None;
    }
    let candidate = root.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
    let canonical = std::fs::canonicalize(candidate).ok()?;
    canonical.starts_with(root).then_some(canonical)
}

/// Remove `path` only when it stays inside `root`.
pub fn remove_file_inside(root: &Path, path: &Path) -> bool {
    if !is_inside(root, path) {
        return false;
    }
    std::fs::remove_file(path).is_ok()
}

/// A file name that is safe to embed in `Content-Disposition`.
///
/// Strips control characters (so no header can be split), quotes and
/// backslashes (so the quoted form cannot be closed), and bounds the length.
/// SMF prints the stored name raw; this is the only intentional difference and
/// it is invisible for ordinary names.
pub fn disposition_filename(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_control() || matches!(ch, '"' | '\\' | '/') {
            continue;
        }
        out.push(ch);
        if out.chars().count() >= 200 {
            break;
        }
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        "attachment".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU32, Ordering};

    static NEXT: AtomicU32 = AtomicU32::new(1);

    struct Temp(PathBuf);

    impl Temp {
        fn new() -> Self {
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("fador-path-{}-{id}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(path.join("root/sub")).unwrap();
            fs::write(path.join("root/sub/file.txt"), b"x").unwrap();
            fs::write(path.join("outside.txt"), b"secret").unwrap();
            Self(fs::canonicalize(&path).unwrap())
        }

        fn root(&self) -> PathBuf {
            self.0.join("root")
        }
    }

    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rejects_windows_path_quirks() {
        assert!(!component_is_safe(".."));
        assert!(!component_is_safe("."));
        assert!(!component_is_safe("...."));
        assert!(!component_is_safe("file."));
        assert!(!component_is_safe("file "));
        assert!(!component_is_safe("CON"));
        assert!(!component_is_safe("con.txt"));
        assert!(!component_is_safe("NUL.csv"));
        assert!(!component_is_safe("COM1"));
        assert!(!component_is_safe("lpt9.log"));
        assert!(!component_is_safe("file.txt:stream"));
        assert!(!component_is_safe("a\\b"));
        assert!(!component_is_safe("a\u{0}b"));
        assert!(!component_is_safe("a/b"));
        assert!(!component_is_safe(""));
        assert!(component_is_safe("index.css"));
        assert!(component_is_safe("My File.png"));
        assert!(component_is_safe("com10.txt"));
    }

    #[test]
    fn relative_paths_need_safe_components() {
        assert!(relative_is_safe("Themes/default/css/index.css"));
        assert!(!relative_is_safe(""));
        assert!(!relative_is_safe("/etc/passwd"));
        assert!(!relative_is_safe("../Settings.php"));
        assert!(!relative_is_safe("Themes/../../Settings.php"));
        assert!(!relative_is_safe("Themes//default"));
        assert!(!relative_is_safe("Themes/..../default"));
        assert!(!relative_is_safe("C:/Windows/win.ini"));
        assert!(!relative_is_safe("\\\\server\\share"));
    }

    #[test]
    fn attachment_names_never_contain_a_separator() {
        assert_eq!(
            attachment_file_name(5, "abcdef", "ignored.png").as_deref(),
            Some("5_abcdef")
        );
        assert_eq!(
            attachment_file_name(5, "", "photo.png").as_deref(),
            Some("5_photo.png")
        );
        assert_eq!(attachment_file_name(5, "../x", "y"), None);
        assert_eq!(attachment_file_name(5, "", "../../x"), None);
        assert_eq!(attachment_file_name(0, "abc", "x"), None);
    }

    #[test]
    fn resolves_only_inside_the_root() {
        let temp = Temp::new();
        let root = temp.root();
        assert!(resolve_under(&root, "sub/file.txt").is_some());
        assert!(resolve_under(&root, "../outside.txt").is_none());
        assert!(resolve_under(&root, "sub/../../outside.txt").is_none());
        assert!(resolve_under(&root, "missing.txt").is_none());
        assert!(!is_inside(&root, &temp.0.join("outside.txt")));
        assert!(is_inside(&root, &root.join("sub/file.txt")));
        // A missing file is accepted when its parent is inside the root.
        assert!(is_inside(&root, &root.join("sub/new.txt")));
        assert!(!is_inside(&root, &temp.0.join("new.txt")));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escapes_are_rejected() {
        let temp = Temp::new();
        let root = temp.root();
        std::os::unix::fs::symlink(temp.0.join("outside.txt"), root.join("link.txt")).unwrap();
        std::os::unix::fs::symlink(&temp.0, root.join("linkdir")).unwrap();
        assert!(!is_inside(&root, &root.join("link.txt")));
        assert!(!is_inside(&root, &root.join("linkdir/new.txt")));
        assert!(resolve_under(&root, "link.txt").is_none());
    }

    #[test]
    fn disposition_names_cannot_break_the_header() {
        assert_eq!(disposition_filename("photo.png"), "photo.png");
        assert_eq!(
            disposition_filename("a\"b\r\nInjected: 1.png"),
            "abInjected: 1.png"
        );
        assert_eq!(disposition_filename("a\\b"), "ab");
        assert_eq!(disposition_filename("\r\n"), "attachment");
        assert_eq!(disposition_filename(""), "attachment");
        let long = disposition_filename(&"x".repeat(400));
        assert_eq!(long.chars().count(), 200);
    }
}
