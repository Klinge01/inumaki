//! Directory-handle file operations (M5 spec §6.3, §6.4). Every path below
//! a root is walked one component at a time with `O_NOFOLLOW`, so no
//! symlink is ever followed; names are single components, checked; writes
//! go to a temporary file that is renamed into place. Errors are plain
//! `io::Error`s whose messages carry no path (rustix's `Errno` has none).

use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat, Timespec, Timestamps};

/// Marker file in each mirror directory; holds the label.
pub const MARKER: &str = ".inumaki-mirror";
/// Marker file in the mirror root; its presence says the root is ours.
pub const ROOT_MARKER: &str = ".inumaki-root";
/// The root marker's fixed content.
pub const ROOT_MARKER_BODY: &[u8] = b"inumaki mirror root\n";
/// Temporary file prefix.
pub const TMP_PREFIX: &str = ".inumaki-tmp-";

const DIR_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

const NEW_FILE_FLAGS: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

/// What an entry is (from `lstat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Regular file.
    File,
    /// Directory.
    Dir,
    /// Symbolic link (never followed).
    Symlink,
    /// Anything else (fifo, socket, device).
    Other,
}

/// `lstat`/`fstat` facts the mirror compares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    /// Entry kind.
    pub kind: Kind,
    /// Size in bytes.
    pub size: u64,
    /// Modification time (seconds, nanoseconds).
    pub mtime: (i64, i64),
    /// Status change time.
    pub ctime: (i64, i64),
    /// Device.
    pub dev: u64,
    /// Inode.
    pub ino: u64,
    /// Link count.
    pub nlink: u64,
    /// macOS `SF_DATALESS`: the content is only in the cloud.
    pub dataless: bool,
}

/// `<sys/stat.h>`: the file is a dataless (cloud-only) object.
#[cfg(target_os = "macos")]
const SF_DATALESS: u32 = 0x4000_0000;

impl Meta {
    #[allow(clippy::unnecessary_cast)]
    fn of(st: &Stat) -> Meta {
        let kind = match FileType::from_raw_mode(st.st_mode as _) {
            FileType::RegularFile => Kind::File,
            FileType::Directory => Kind::Dir,
            FileType::Symlink => Kind::Symlink,
            _ => Kind::Other,
        };
        #[cfg(target_os = "macos")]
        let dataless = st.st_flags & SF_DATALESS != 0;
        #[cfg(not(target_os = "macos"))]
        let dataless = false;
        Meta {
            kind,
            size: st.st_size as u64,
            mtime: (st.st_mtime as i64, st.st_mtime_nsec as i64),
            ctime: (st.st_ctime as i64, st.st_ctime_nsec as i64),
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            nlink: st.st_nlink as u64,
            dataless,
        }
    }

    /// Same file, same content version (spec §5.1 step 8).
    pub fn same_version(&self, other: &Meta) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.size == other.size
            && self.mtime == other.mtime
            && self.ctime == other.ctime
    }
}

/// `fstat` of an open file (spec §5.1 step 8).
pub fn fstat_file(f: &std::fs::File) -> io::Result<Meta> {
    Ok(Meta::of(&rustix::fs::fstat(f)?))
}

/// Error classes the mirror maps to folder errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoClass {
    /// `ENOENT`, `ENOTDIR`.
    NotFound,
    /// `EPERM` (macOS privacy protection).
    NotPermitted,
    /// `EACCES`.
    AccessDenied,
    /// `ELOOP` and friends: a symlink where a directory or file was expected.
    Symlink,
    /// `ENOSPC`, `EDQUOT`, `EROFS`.
    NoSpace,
    /// Anything else.
    Other,
}

/// Classify an `io::Error` without formatting it.
pub fn map_errno(e: &io::Error) -> IoClass {
    match e.raw_os_error() {
        Some(libc::ENOENT) | Some(libc::ENOTDIR) => IoClass::NotFound,
        Some(libc::EPERM) => IoClass::NotPermitted,
        Some(libc::EACCES) => IoClass::AccessDenied,
        // FreeBSD reports `O_NOFOLLOW` on a symlink as `EMLINK`.
        Some(libc::ELOOP) | Some(libc::EMLINK) => IoClass::Symlink,
        Some(libc::ENOSPC) | Some(libc::EDQUOT) | Some(libc::EROFS) => IoClass::NoSpace,
        _ => IoClass::Other,
    }
}

/// Refuse anything that is not one plain component. Length is left to the
/// kernel (`ENAMETOOLONG`): APFS allows 255 UTF-16 units, far more than 255
/// UTF-8 bytes for non-ASCII names.
pub fn check_name(name: &OsStr) -> io::Result<()> {
    let b = name.as_bytes();
    if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') || b.contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    Ok(())
}

fn cname(name: &OsStr) -> io::Result<CString> {
    check_name(name)?;
    CString::new(name.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn tmp_name() -> io::Result<OsString> {
    let mut r = [0u8; 8];
    getrandom::fill(&mut r).map_err(|_| io::Error::other("random"))?;
    let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
    Ok(OsString::from(format!("{TMP_PREFIX}{hex}")))
}

fn mode(m: u32) -> Mode {
    Mode::from_raw_mode(m as _)
}

/// An open directory; every operation is relative to it.
pub struct Dir {
    fd: OwnedFd,
}

impl std::fmt::Debug for Dir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dir")
    }
}

impl Dir {
    /// Open a configured root; the last component must not be a symlink.
    pub fn open_root(path: &Path) -> io::Result<Dir> {
        Ok(Dir {
            fd: rustix::fs::open(path, DIR_FLAGS, Mode::empty())?,
        })
    }

    /// `fstat` of this directory.
    pub fn meta(&self) -> io::Result<Meta> {
        Ok(Meta::of(&rustix::fs::fstat(&self.fd)?))
    }

    /// Open a child directory (never a symlink).
    pub fn child(&self, name: &OsStr) -> io::Result<Dir> {
        let c = cname(name)?;
        Ok(Dir {
            fd: rustix::fs::openat(&self.fd, c.as_c_str(), DIR_FLAGS, Mode::empty())?,
        })
    }

    /// A second handle to this directory.
    fn dup(&self) -> io::Result<Dir> {
        Ok(Dir {
            fd: rustix::fs::openat(&self.fd, c".", DIR_FLAGS, Mode::empty())?,
        })
    }

    /// Open a descendant directory by a `/`-separated relative path.
    pub fn walk(&self, rel: &[u8]) -> io::Result<Dir> {
        let mut d = self.dup()?;
        for comp in rel.split(|b| *b == b'/').filter(|c| !c.is_empty()) {
            d = d.child(OsStr::from_bytes(comp))?;
        }
        Ok(d)
    }

    /// `lstat` of a child.
    pub fn stat(&self, name: &OsStr) -> io::Result<Meta> {
        let c = cname(name)?;
        Ok(Meta::of(&rustix::fs::statat(
            &self.fd,
            c.as_c_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )?))
    }

    /// Child names with their kinds (`.` and `..` omitted).
    pub fn entries(&self) -> io::Result<Vec<(OsString, Kind)>> {
        let mut out = Vec::new();
        // A separate descriptor: reading a directory moves its offset.
        let dup = self.dup()?;
        for e in rustix::fs::Dir::read_from(&dup.fd)? {
            let e = e?;
            let name = OsStr::from_bytes(e.file_name().to_bytes()).to_os_string();
            if name == "." || name == ".." {
                continue;
            }
            let kind = match e.file_type() {
                FileType::RegularFile => Kind::File,
                FileType::Directory => Kind::Dir,
                FileType::Symlink => Kind::Symlink,
                FileType::Unknown => self.stat(&name)?.kind,
                _ => Kind::Other,
            };
            out.push((name, kind));
        }
        Ok(out)
    }

    /// Read a regular file (never a symlink) up to `max` bytes. Returns the
    /// bytes and the `fstat` of the open descriptor, and the open file so
    /// the caller can `fstat` it again before committing (spec §5.1 step 8).
    pub fn read_file(&self, name: &OsStr, max: u64) -> io::Result<(Vec<u8>, Meta, std::fs::File)> {
        let c = cname(name)?;
        // `O_NONBLOCK`: opening a fifo must not hang; it is refused below.
        let fd = rustix::fs::openat(
            &self.fd,
            c.as_c_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?;
        let meta = Meta::of(&rustix::fs::fstat(&fd)?);
        if meta.kind != Kind::File {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let mut file = std::fs::File::from(fd);
        let mut buf = Vec::new();
        (&mut file)
            .take(max.saturating_add(1))
            .read_to_end(&mut buf)?;
        if buf.len() as u64 > max {
            return Err(io::Error::from(io::ErrorKind::FileTooLarge));
        }
        Ok((buf, meta, file))
    }

    /// `fchmod` this directory (the mirror root, spec §4.1).
    pub fn set_mode(&self, m: u32) -> io::Result<()> {
        Ok(rustix::fs::fchmod(&self.fd, mode(m))?)
    }

    /// Create a child directory with `mode`. `Ok(true)` when this call
    /// created it, `Ok(false)` when something is already there (not
    /// inspected). Never removes or changes anything.
    pub fn mkdir_new(&self, name: &OsStr, m: u32) -> io::Result<bool> {
        let c = cname(name)?;
        match rustix::fs::mkdirat(&self.fd, c.as_c_str(), mode(m)) {
            Ok(()) => Ok(true),
            Err(rustix::io::Errno::EXIST) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// A child directory, created with `mode` if missing. Never removes
    /// anything: a file or symlink in its place is `AlreadyExists` (the
    /// user's outbox destination, review I6).
    pub fn open_or_create(&self, name: &OsStr, m: u32) -> io::Result<Dir> {
        let c = cname(name)?;
        match rustix::fs::mkdirat(&self.fd, c.as_c_str(), mode(m)) {
            Ok(()) | Err(rustix::io::Errno::EXIST) => {}
            Err(e) => return Err(e.into()),
        }
        match self.child(name) {
            Ok(d) => Ok(d),
            // A symlink (`ELOOP`) or a file (`ENOTDIR`) where the directory
            // belongs: refused, left alone. A vanished directory (`ENOENT`)
            // stays `NotFound`.
            Err(e)
                if map_errno(&e) == IoClass::Symlink || e.raw_os_error() == Some(libc::ENOTDIR) =>
            {
                Err(io::Error::from(io::ErrorKind::AlreadyExists))
            }
            Err(e) => Err(e),
        }
    }

    /// A child directory, created with `mode` if missing. In a mirror, a
    /// symlink or file in its place is removed first. Never used outside the
    /// mirror tree.
    pub fn ensure_dir(&self, name: &OsStr, m: u32) -> io::Result<Dir> {
        let c = cname(name)?;
        match self.stat(name) {
            Ok(meta) if meta.kind == Kind::Dir => {}
            Ok(_) => {
                rustix::fs::unlinkat(&self.fd, c.as_c_str(), AtFlags::empty())?;
                rustix::fs::mkdirat(&self.fd, c.as_c_str(), mode(m))?;
            }
            Err(e) if map_errno(&e) == IoClass::NotFound => {
                rustix::fs::mkdirat(&self.fd, c.as_c_str(), mode(m))?;
            }
            Err(e) => return Err(e),
        }
        self.child(name)
    }

    fn write_tmp(&self, bytes: &[u8], m: u32, mtime: Option<(i64, i64)>) -> io::Result<CString> {
        let tmp = cname(&tmp_name()?)?;
        let fd = rustix::fs::openat(&self.fd, tmp.as_c_str(), NEW_FILE_FLAGS, mode(0o600))?;
        let mut f = std::fs::File::from(fd);
        let r = (|| {
            f.write_all(bytes)?;
            if let Some((s, ns)) = mtime {
                let ts = Timespec {
                    tv_sec: s,
                    tv_nsec: ns as _,
                };
                rustix::fs::futimens(
                    &f,
                    &Timestamps {
                        last_access: ts,
                        last_modification: ts,
                    },
                )?;
            }
            rustix::fs::fchmod(&f, mode(m))?;
            rustix::fs::fsync(&f)?;
            Ok::<(), io::Error>(())
        })();
        if let Err(e) = r {
            let _ = rustix::fs::unlinkat(&self.fd, tmp.as_c_str(), AtFlags::empty());
            return Err(e);
        }
        Ok(tmp)
    }

    /// Write `name` atomically (temporary file, rename over, directory
    /// `fsync`). A symlink at `name` is replaced, never followed.
    pub fn write_atomic(
        &self,
        name: &OsStr,
        bytes: &[u8],
        m: u32,
        mtime: Option<(i64, i64)>,
    ) -> io::Result<()> {
        let target = cname(name)?;
        let tmp = self.write_tmp(bytes, m, mtime)?;
        if CRASH_BEFORE_RENAME.with(std::cell::Cell::get) {
            // Test seam: a kill between the temporary write and the rename
            // (spec §16.1 item 3). The temporary file stays, as after a crash.
            return Err(io::Error::other("injected crash"));
        }
        if let Err(e) = rustix::fs::renameat(&self.fd, tmp.as_c_str(), &self.fd, target.as_c_str())
        {
            let _ = rustix::fs::unlinkat(&self.fd, tmp.as_c_str(), AtFlags::empty());
            return Err(e.into());
        }
        rustix::fs::fsync(&self.fd)?;
        Ok(())
    }

    /// Write a new file `name`; `AlreadyExists` if it exists. No-replace
    /// rename where the file system supports it, else `O_CREAT | O_EXCL`
    /// and a direct write (spec §8 step 7). Never a plain rename. A name the
    /// file system refuses (too long, an illegal character) is an error for
    /// which [`is_name_rejected`] holds; a failed write or `fsync` never is.
    pub fn write_new(&self, name: &OsStr, bytes: &[u8], m: u32) -> io::Result<()> {
        let target = cname(name)?;
        let tmp = self.write_tmp(bytes, m, None)?;
        let e = match rename_noreplace(self, &tmp, self, &target) {
            Ok(()) => return Ok(rustix::fs::fsync(&self.fd)?),
            Err(e) => e,
        };
        let _ = rustix::fs::unlinkat(&self.fd, tmp.as_c_str(), AtFlags::empty());
        if matches!(
            e.raw_os_error(),
            Some(libc::ENAMETOOLONG) | Some(libc::EILSEQ)
        ) {
            return Err(name_rejected());
        }
        if !matches!(
            e.raw_os_error(),
            Some(libc::EINVAL) | Some(libc::ENOTSUP) | Some(libc::ENOSYS)
        ) {
            // `EEXIST` arrives as `ErrorKind::AlreadyExists`.
            return Err(e);
        }
        let fd = match rustix::fs::openat(&self.fd, target.as_c_str(), NEW_FILE_FLAGS, mode(m)) {
            Ok(fd) => fd,
            // Only the open of the final name: its `EINVAL` is the name.
            Err(
                rustix::io::Errno::INVAL
                | rustix::io::Errno::ILSEQ
                | rustix::io::Errno::NAMETOOLONG,
            ) => return Err(name_rejected()),
            Err(e) => return Err(e.into()),
        };
        let mut f = std::fs::File::from(fd);
        if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
            // Leave no partial file, but only remove the one this call made.
            let ours = rustix::fs::fstat(&f).map(|st| Meta::of(&st));
            if let (Ok(ours), Ok(there)) = (ours, self.stat(name)) {
                if ours.dev == there.dev && ours.ino == there.ino {
                    let _ = rustix::fs::unlinkat(&self.fd, target.as_c_str(), AtFlags::empty());
                }
            }
            return Err(e);
        }
        rustix::fs::fsync(&self.fd)?;
        Ok(())
    }

    /// Remove a child: a file or symlink is unlinked, a directory removed
    /// with its tree. Absent is fine.
    pub fn remove(&self, name: &OsStr) -> io::Result<()> {
        let c = cname(name)?;
        match self.stat(name) {
            Ok(meta) if meta.kind == Kind::Dir => self.remove_tree(name),
            Ok(_) => Ok(rustix::fs::unlinkat(
                &self.fd,
                c.as_c_str(),
                AtFlags::empty(),
            )?),
            Err(e) if map_errno(&e) == IoClass::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Unlink a child that is not a directory (a file, or a symlink, never
    /// followed). A directory is refused, never removed. Absent is fine.
    pub fn unlink(&self, name: &OsStr) -> io::Result<()> {
        let c = cname(name)?;
        match rustix::fs::unlinkat(&self.fd, c.as_c_str(), AtFlags::empty()) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Remove a child directory only if it is empty: one `REMOVEDIR`, never
    /// recursive, never through a symlink (`ENOTDIR`). Absent is fine; a
    /// directory that is not empty is an error and stays.
    pub fn remove_empty_dir(&self, name: &OsStr) -> io::Result<()> {
        let c = cname(name)?;
        match rustix::fs::unlinkat(&self.fd, c.as_c_str(), AtFlags::REMOVEDIR) {
            Ok(()) | Err(rustix::io::Errno::NOENT) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Remove a child directory and everything below it, through handles.
    pub fn remove_tree(&self, name: &OsStr) -> io::Result<()> {
        let c = cname(name)?;
        self.child(name)?.remove_contents(None)?;
        rustix::fs::unlinkat(&self.fd, c.as_c_str(), AtFlags::REMOVEDIR)?;
        Ok(())
    }

    /// Remove everything in this directory except `keep`.
    fn remove_contents(&self, keep: Option<&OsStr>) -> io::Result<()> {
        for (n, _) in self.entries()? {
            if Some(n.as_os_str()) != keep {
                self.remove(&n)?;
            }
        }
        Ok(())
    }

    /// Rename a child of this directory to `to` in `to_dir` (replaces).
    pub fn rename(&self, from: &OsStr, to_dir: &Dir, to: &OsStr) -> io::Result<()> {
        let (f, t) = (cname(from)?, cname(to)?);
        rustix::fs::renameat(&self.fd, f.as_c_str(), &to_dir.fd, t.as_c_str())?;
        Ok(())
    }

    /// `fsync` the directory.
    pub fn sync(&self) -> io::Result<()> {
        Ok(rustix::fs::fsync(&self.fd)?)
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn raw(&self) -> std::os::fd::RawFd {
        self.fd.as_raw_fd()
    }
}

/// The payload of [`name_rejected`] errors; prints no name.
#[derive(Debug)]
struct NameRejected;

impl std::fmt::Display for NameRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("name rejected by the file system")
    }
}

impl std::error::Error for NameRejected {}

fn name_rejected() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, NameRejected)
}

/// The file system refused the name itself ([`Dir::write_new`]).
pub fn is_name_rejected(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|x| x.is::<NameRejected>())
}

/// Rename without replacing: `renameatx_np(RENAME_EXCL)` on macOS,
/// `renameat2(RENAME_NOREPLACE)` on Linux, `ENOTSUP` elsewhere (the caller
/// falls back to `O_EXCL`). `AlreadyExists` on a clash. Both names must be
/// single components ([`check_name`]).
pub fn rename_noreplace(from_dir: &Dir, from: &CStr, to_dir: &Dir, to: &CStr) -> io::Result<()> {
    check_name(OsStr::from_bytes(from.to_bytes()))?;
    check_name(OsStr::from_bytes(to.to_bytes()))?;
    if NOREPLACE_UNSUPPORTED.with(std::cell::Cell::get) {
        return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
    }
    #[cfg(target_os = "macos")]
    // SAFETY: both descriptors are open for the call and both names are
    // NUL-terminated C strings that outlive it.
    let r = unsafe {
        libc::renameatx_np(
            from_dir.raw(),
            from.as_ptr(),
            to_dir.raw(),
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    #[cfg(target_os = "linux")]
    // SAFETY: as above.
    let r = unsafe {
        libc::renameat2(
            from_dir.raw(),
            from.as_ptr(),
            to_dir.raw(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let r = {
        let _ = (from_dir, from, to_dir, to);
        return Err(io::Error::from_raw_os_error(libc::ENOTSUP));
    };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

thread_local! {
    static CRASH_BEFORE_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static NOREPLACE_UNSUPPORTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static DELETE_FAULT: std::cell::Cell<Option<DeleteFault>> = const { std::cell::Cell::new(None) };
}

/// Where [`inject_delete_fault`] makes [`delete_mirror_tree`] fail.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteFault {
    /// After the contents are gone, before the marker is unlinked.
    BeforeMarker,
    /// The final `REMOVEDIR`, as `ENOTEMPTY` (a file created meanwhile).
    FinalRmdir,
}

/// Test seam (this thread only): `delete_mirror_tree` fails at `fault`.
#[doc(hidden)]
pub fn inject_delete_fault(fault: Option<DeleteFault>) {
    DELETE_FAULT.with(|c| c.set(fault));
}

/// Test seam (this thread only): `write_atomic` stops after the temporary
/// file is written, as a kill would.
#[doc(hidden)]
pub fn inject_crash_before_rename(on: bool) {
    CRASH_BEFORE_RENAME.with(|c| c.set(on));
}

/// Test seam (this thread only): `rename_noreplace` fails with `ENOTSUP`,
/// as on a file system without it, so `write_new` takes the `O_EXCL` path.
#[doc(hidden)]
pub fn inject_noreplace_unsupported(on: bool) {
    NOREPLACE_UNSUPPORTED.with(|c| c.set(on));
}

/// Write the marker (the label) into a fresh mirror directory.
pub fn write_marker(dir: &Dir, label: &str) -> io::Result<()> {
    dir.write_atomic(OsStr::new(MARKER), label.as_bytes(), 0o444, None)
}

/// Delete `root/<label>` only if its marker holds `label`. `Ok(false)` when
/// absent, when present without a marker and with content, or when the
/// marker is a plain file holding another label (left untouched in both
/// cases); an empty directory without a marker is removed.
/// `PermissionDenied` when the marker is not a plain file (a symlink) or
/// unreadable, or the directory was replaced during the delete.
///
/// The contents are removed through the handle whose marker was checked,
/// never by reopening the name, and the marker goes last: a delete that
/// fails halfway leaves a marked tree that the next call can finish. If the
/// final `REMOVEDIR` fails, the marker is written again for the same reason.
///
/// Precondition: the caller has stopped the watcher and every writer for
/// this tree first. A file created after the marker is unlinked makes the
/// final `REMOVEDIR` fail (`ENOTEMPTY`); the marker is then re-created on a
/// best-effort basis, so a crash at exactly that point can still leave an
/// unmarked tree.
pub fn delete_mirror_tree(root: &Dir, label: &str) -> io::Result<bool> {
    let name = OsStr::new(label);
    let c = cname(name)?;
    let d = match root.child(name) {
        Ok(d) => d,
        Err(e) if map_errno(&e) == IoClass::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    match d.read_file(OsStr::new(MARKER), 64) {
        Ok((b, _, _)) if b == label.as_bytes() => {}
        // A plain marker file that holds another label: not our tree, so
        // nothing is deleted. Like an unmarked directory with content it is
        // left as it is and the caller drops its records; an error here
        // would let an agent keep a folder in `stopped` for good.
        Ok(_) => return Ok(false),
        // No marker (a crash between `mkdir` and the marker, or an agent
        // deleted it): an empty directory is removed; one with content is
        // not ours to delete and is left untouched (`Ok(false)`: nothing
        // deleted, the caller drops its records).
        Err(e) if map_errno(&e) == IoClass::NotFound => {
            if !d.entries()?.is_empty() {
                return Ok(false);
            }
            match rustix::fs::unlinkat(&root.fd, c.as_c_str(), AtFlags::REMOVEDIR) {
                Ok(()) => {}
                // Filled meanwhile: leave it.
                Err(rustix::io::Errno::NOTEMPTY) => return Ok(false),
                Err(e) => return Err(e.into()),
            }
            root.sync()?;
            return Ok(true);
        }
        // A different marker, a symlink, or anything unreadable.
        _ => return Err(io::Error::from(io::ErrorKind::PermissionDenied)),
    }
    let ours = d.meta()?;
    d.remove_contents(Some(OsStr::new(MARKER)))?;
    let fault = DELETE_FAULT.with(std::cell::Cell::get);
    if fault == Some(DeleteFault::BeforeMarker) {
        return Err(io::Error::other("injected fault"));
    }
    d.remove(OsStr::new(MARKER))?;
    let rmdir = || -> io::Result<()> {
        // The name must still be the directory we emptied.
        let there = root.stat(name)?;
        if there.kind != Kind::Dir || there.dev != ours.dev || there.ino != ours.ino {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        if fault == Some(DeleteFault::FinalRmdir) {
            return Err(io::Error::from_raw_os_error(libc::ENOTEMPTY));
        }
        // `REMOVEDIR` removes only an empty directory.
        Ok(rustix::fs::unlinkat(
            &root.fd,
            c.as_c_str(),
            AtFlags::REMOVEDIR,
        )?)
    };
    if let Err(e) = rmdir() {
        let _ = write_marker(&d, label);
        return Err(e);
    }
    root.sync()?;
    Ok(true)
}

/// macOS: reads on this thread fail fast on dataless (cloud-only) files
/// instead of downloading them (spec §5.1 step 3). An error means reads on
/// this thread may download. No-op elsewhere.
pub fn no_dataless_materialization() -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        // <sys/resource.h>: IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES = 3,
        // IOPOL_SCOPE_THREAD = 1, IOPOL_MATERIALIZE_DATALESS_FILES_OFF = 1.
        unsafe extern "C" {
            fn setiopolicy_np(
                iotype: libc::c_int,
                scope: libc::c_int,
                policy: libc::c_int,
            ) -> libc::c_int;
        }
        // SAFETY: a plain syscall wrapper with integer arguments.
        if unsafe { setiopolicy_np(3, 1, 1) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
