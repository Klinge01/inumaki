//! The OS user's identity (M8 spec decision 13, §5.4): the full name from
//! the account database's real-name field, the login name, the distinctive
//! part of the home directory, and `user.name`/`user.email` from the user's
//! global git configuration. Seeded into the chat dictionary so a harness's
//! system prompt, which carries them (a working directory, a git author),
//! is tokenized. Read once when the proxy host is built; the values stay in
//! memory (`Zeroizing`), never in a log line or a `Debug` output.
//!
//! Every read is best effort: a missing passwd entry, an unreadable or
//! non-UTF-8 file, or an absent home directory yields fewer values, never
//! an error and never a panic.

use std::path::{Path, PathBuf};

use inumaki_core::span::EntityKind;
use zeroize::Zeroizing;

/// A git configuration file larger than this is not read (a real one is a
/// few KiB; this bounds what a hostile file can make the daemon hold).
const MAX_GIT_CONFIG: u64 = 1024 * 1024;

/// Account names that identify nobody (shared, service, and CI accounts).
const GENERIC_LOGINS: &[&str] = &[
    "admin",
    "administrator",
    "build",
    "builder",
    "default",
    "developer",
    "docker",
    "guest",
    "local",
    "nobody",
    "operator",
    "owner",
    "root",
    "runner",
    "server",
    "shared",
    "staff",
    "test",
    "tester",
    "ubuntu",
    "user",
    "users",
    "vagrant",
    "work",
];

/// What was found, split by use. `Debug` prints counts only.
#[derive(Default)]
pub struct Identity {
    /// Full names and emails: tokenized in chat and refused in tool
    /// definitions (decision 24).
    pub names: Vec<(EntityKind, Zeroizing<String>)>,
    /// The login name and the home directory's last component: tokenized
    /// in chat only (a tool definition naming a path under the home
    /// directory is not refused for it).
    pub accounts: Vec<(EntityKind, Zeroizing<String>)>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("names", &self.names.len())
            .field("accounts", &self.accounts.len())
            .finish()
    }
}

impl Identity {
    /// Every value, names first.
    pub fn all(&self) -> Vec<(EntityKind, Zeroizing<String>)> {
        self.names
            .iter()
            .chain(&self.accounts)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

/// The full-name part of a passwd GECOS field (`Full Name,room,…`): at
/// least three letters and two words, else `None`.
pub fn gecos_full_name(g: &str) -> Option<&str> {
    let n = g.split(',').next()?.trim();
    (n.chars().filter(|c| c.is_alphabetic()).count() >= 3 && n.contains(' ')).then_some(n)
}

/// `(name, email)` from a git configuration file's `[user]` section.
pub fn git_user(text: &str) -> (Option<String>, Option<String>) {
    let (mut in_user, mut name, mut email) = (false, None, None);
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_user = l.eq_ignore_ascii_case("[user]");
            continue;
        }
        if !in_user {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            let v = git_value(v);
            if v.is_empty() {
                continue;
            }
            match k.trim().to_ascii_lowercase().as_str() {
                "name" => name = Some(v),
                "email" => email = Some(v),
                _ => {}
            }
        }
    }
    (name, email)
}

/// A git configuration value as git reads it: an unquoted `#` or `;`
/// starts a comment, double quotes are removed, `\"` and `\\` are
/// unescaped, and surrounding whitespace is trimmed.
fn git_value(raw: &str) -> String {
    let (mut out, mut quoted, mut chars) = (String::new(), false, raw.chars());
    while let Some(c) = chars.next() {
        match c {
            '"' => quoted = !quoted,
            '\\' => {
                if let Some(n) = chars.next() {
                    out.push(match n {
                        'n' => '\n',
                        't' => '\t',
                        other => other,
                    });
                }
            }
            '#' | ';' if !quoted => break,
            c => out.push(c),
        }
    }
    out.trim().to_string()
}

/// A login-like word that names someone: four or more characters, a
/// letter among them, not a generic account, not an ordinary word.
fn distinctive_login(s: &str) -> bool {
    let s = s.trim();
    s.chars().count() >= 4
        && s.chars().any(char::is_alphabetic)
        && !s.chars().any(char::is_whitespace)
        && !GENERIC_LOGINS.iter().any(|g| g.eq_ignore_ascii_case(s))
        && !inumaki_core::stoplist::is_common_word(s)
}

/// The passwd entry's `(gecos, login, home)`, each when present and UTF-8.
fn passwd() -> (Option<String>, Option<String>, Option<String>) {
    // SAFETY: `getpwuid_r` writes only into the caller-owned `pw` and
    // `buf`; on success `out` points at `pw`, whose string fields point
    // into `buf`, which outlives every read below. A non-zero return or a
    // null `out` means no entry, and nothing is read.
    unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut out: *mut libc::passwd = std::ptr::null_mut();
        let mut buf = vec![0 as libc::c_char; 16 * 1024];
        let rc = libc::getpwuid_r(
            libc::getuid(),
            &mut pw,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out,
        );
        if rc != 0 || out.is_null() {
            return (None, None, None);
        }
        let field = |p: *const libc::c_char| {
            if p.is_null() {
                None
            } else {
                std::ffi::CStr::from_ptr(p)
                    .to_str()
                    .ok()
                    .map(str::to_string)
            }
        };
        (field(pw.pw_gecos), field(pw.pw_name), field(pw.pw_dir))
    }
}

fn read_small(p: &Path) -> Option<Zeroizing<String>> {
    let meta = std::fs::metadata(p).ok()?;
    if !meta.is_file() || meta.len() > MAX_GIT_CONFIG {
        return None;
    }
    std::fs::read_to_string(p).ok().map(Zeroizing::new)
}

/// Build the identity from what was read. Pure (tests): `git_texts` are
/// the global git configuration files' contents.
pub fn collect(
    gecos: Option<&str>,
    login: Option<&str>,
    home: Option<&Path>,
    git_texts: &[Zeroizing<String>],
) -> Identity {
    let mut id = Identity::default();
    if let Some(n) = gecos.and_then(gecos_full_name) {
        id.names
            .push((EntityKind::Person, Zeroizing::new(n.to_string())));
    }
    for t in git_texts {
        let (n, e) = git_user(t);
        if let Some(n) =
            n.filter(|n| n.contains(' ') && n.chars().filter(|c| c.is_alphabetic()).count() >= 3)
        {
            id.names.push((EntityKind::Person, Zeroizing::new(n)));
        }
        if let Some(e) = e.filter(|e| {
            e.split_once('@')
                .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty())
        }) {
            id.names.push((EntityKind::Email, Zeroizing::new(e)));
        }
    }
    let login = login.map(str::trim).filter(|l| distinctive_login(l));
    if let Some(l) = login {
        id.accounts
            .push((EntityKind::Person, Zeroizing::new(l.to_string())));
    }
    // The home directory's own name, when it differs from the login (a
    // path under the home carries it in every working directory).
    if let Some(dir) = home
        .and_then(Path::file_name)
        .and_then(|n| n.to_str())
        .filter(|d| distinctive_login(d))
        .filter(|d| !login.is_some_and(|l| l.eq_ignore_ascii_case(d)))
    {
        id.accounts
            .push((EntityKind::Person, Zeroizing::new(dir.to_string())));
    }
    // The chat text is NFC (`normalize_input`); so are the values.
    for (_, v) in id.names.iter_mut().chain(id.accounts.iter_mut()) {
        use unicode_normalization::UnicodeNormalization;
        *v = Zeroizing::new(v.nfc().collect());
    }
    dedup(&mut id.names);
    dedup(&mut id.accounts);
    id.accounts.retain(|(k, v)| {
        !id.names
            .iter()
            .any(|(nk, nv)| nk == k && nv.eq_ignore_ascii_case(v))
    });
    id
}

fn dedup(v: &mut Vec<(EntityKind, Zeroizing<String>)>) {
    let mut i = 0;
    while i < v.len() {
        let dup = v[..i]
            .iter()
            .any(|(k, x)| *k == v[i].0 && x.eq_ignore_ascii_case(&v[i].1));
        if dup {
            v.remove(i);
        } else {
            i += 1;
        }
    }
}

/// Read the identity of the user running the daemon. Never fails: what
/// cannot be read is left out.
pub fn read_parts() -> Identity {
    let (gecos, login, pw_home) = passwd();
    let home: Option<PathBuf> = pw_home
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(::dirs::home_dir);
    let login = login.or_else(|| std::env::var("USER").ok());
    let xdg = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| home.as_ref().map(|h| h.join(".config")));
    let texts: Vec<Zeroizing<String>> = [
        home.as_ref().map(|h| h.join(".gitconfig")),
        xdg.map(|x| x.join("git").join("config")),
    ]
    .into_iter()
    .flatten()
    .filter_map(|p| read_small(&p))
    .collect();
    collect(gecos.as_deref(), login.as_deref(), home.as_deref(), &texts)
}

/// [`read_parts`], every value.
pub fn read() -> Vec<(EntityKind, Zeroizing<String>)> {
    read_parts().all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(v: &[(EntityKind, Zeroizing<String>)]) -> Vec<(EntityKind, String)> {
        v.iter().map(|(k, s)| (k.clone(), s.to_string())).collect()
    }

    #[test]
    fn parses_gecos_and_git_config() {
        assert_eq!(
            gecos_full_name("Pellqwyn Yrsabel,,,"),
            Some("Pellqwyn Yrsabel")
        );
        assert_eq!(gecos_full_name("root"), None);
        assert_eq!(gecos_full_name(""), None);
        assert_eq!(gecos_full_name(",,,"), None);
        let (n, e) = git_user(
            "[core]\n editor = vi\n[user]\n\tname = Pellqwyn Yrsabel\n\temail = p@example.invalid\n",
        );
        assert_eq!(n.as_deref(), Some("Pellqwyn Yrsabel"));
        assert_eq!(e.as_deref(), Some("p@example.invalid"));
        // Inline comments end a value unless quoted; quotes are removed.
        let (n, e) = git_user(
            "[user]\n name = Pellqwyn Yrsabel # work\n email = \"p;q@example.invalid\" ; old\n",
        );
        assert_eq!(n.as_deref(), Some("Pellqwyn Yrsabel"));
        assert_eq!(e.as_deref(), Some("p;q@example.invalid"));
        // A name outside `[user]` is not the user's.
        assert_eq!(git_user("[author]\nname = A B\n"), (None, None));
    }

    /// Spec decision 13 robustness: hostile or missing inputs give fewer
    /// values, never a panic.
    #[test]
    fn hostile_and_missing_inputs_yield_fewer_values() {
        let id = collect(None, None, None, &[]);
        assert!(id.all().is_empty());
        let junk =
            Zeroizing::new("\u{0}[user\n=\n==\nname\n[user]\nname =\nemail = nobody\n".into());
        let id = collect(Some(""), Some("root"), Some(Path::new("/")), &[junk]);
        assert!(id.all().is_empty(), "{id:?}");
        // The common accounts and short logins identify nobody.
        for l in ["admin", "ubuntu", "ab", "1234", "user"] {
            assert!(collect(None, Some(l), None, &[]).all().is_empty(), "{l}");
        }
        assert!(read_small(Path::new("/nonexistent/inumaki/gitconfig")).is_none());
        // The real read never fails.
        let _ = read_parts();
    }

    #[test]
    fn collects_names_logins_and_the_home_directory() {
        let git = Zeroizing::new(
            "[user]\n name = \"Pellqwyn Yrsabel\"\n email = pyrsabel@example.invalid\n".into(),
        );
        let id = collect(
            Some("Pellqwyn Yrsabel,,,"),
            Some("pyrsabel"),
            Some(Path::new("/Users/qwelmarx")),
            &[git],
        );
        assert_eq!(
            values(&id.names),
            vec![
                (EntityKind::Person, "Pellqwyn Yrsabel".into()),
                (EntityKind::Email, "pyrsabel@example.invalid".into()),
            ]
        );
        assert_eq!(
            values(&id.accounts),
            vec![
                (EntityKind::Person, "pyrsabel".into()),
                (EntityKind::Person, "qwelmarx".into()),
            ]
        );
        // Values are NFC, like the text they are matched against.
        let nfd = "Ange\u{301}lique Yrsabel,,,";
        let id = collect(Some(nfd), None, None, &[]);
        assert_eq!(id.names[0].1.as_str(), "Ang\u{e9}lique Yrsabel");
        // The home directory named like the login adds nothing.
        let id = collect(
            None,
            Some("pyrsabel"),
            Some(Path::new("/home/pyrsabel")),
            &[],
        );
        assert_eq!(id.accounts.len(), 1);
        let dbg = format!("{id:?}");
        assert!(!dbg.contains("pyrsabel"), "{dbg}");
    }
}
