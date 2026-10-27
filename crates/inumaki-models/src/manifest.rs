//! Pinned model manifest, download with SHA-256 verification, and model paths.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Default download host.
pub const HF_BASE: &str = "https://huggingface.co";

const EMBEDDED: &str = include_str!("../../../models/manifest.toml");

/// Errors while reading the manifest or fetching models.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// HTTP failure; carries the URL or status, never file content.
    #[error("download failed: {0}")]
    Http(String),
    /// File system failure; carries the path.
    #[error("file error: {0}")]
    Io(String),
    /// Downloaded file did not match its pinned SHA-256; carries the file path.
    #[error("checksum mismatch for {0}")]
    Checksum(String),
    /// Manifest could not be parsed.
    #[error("invalid manifest: {0}")]
    Manifest(String),
}

/// All pinned models.
#[derive(Debug, Clone, Deserialize)]
pub struct Manifest {
    /// Model entries.
    pub models: Vec<ModelEntry>,
}

/// One model: where it comes from and which files it needs.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelEntry {
    /// Short name used in configs and on the command line.
    pub name: String,
    /// `gliner` or `token_classifier`.
    pub kind: String,
    /// Hugging Face repository.
    pub repo: String,
    /// Pinned revision (commit SHA).
    pub revision: String,
    /// SPDX license id.
    pub license: String,
    /// License reference.
    pub license_url: String,
    /// Pulled by `inumaki models pull` without arguments.
    #[serde(default)]
    pub default: bool,
    /// Files to download.
    pub files: Vec<ModelFile>,
}

/// One file of a model.
#[derive(Debug, Clone, Deserialize)]
pub struct ModelFile {
    /// Path inside the repository (and inside the local model directory).
    pub path: String,
    /// `model`, `tokenizer` or `config`.
    pub role: String,
    /// Lower-case hex SHA-256.
    pub sha256: String,
    /// Size in bytes.
    pub size: u64,
}

/// State of one local file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    /// Present and matches its checksum.
    Ok,
    /// Not present.
    Missing,
    /// Present but different size or checksum.
    Corrupt,
}

impl Manifest {
    /// The manifest compiled into the binary.
    pub fn embedded() -> Manifest {
        Manifest::parse(EMBEDDED).expect("embedded manifest is valid")
    }

    /// Parse a manifest. Every model must list the roles `model`, `tokenizer`
    /// and `config`, so the loaders in `assemble` can rely on them. Every
    /// file `path` must be relative and stay inside the model's directory:
    /// an absolute path or a `..` segment is rejected, since `path` is
    /// joined onto the local models directory unchanged when downloading
    /// and verifying (`ModelEntry::path`).
    pub fn parse(s: &str) -> Result<Manifest, FetchError> {
        let m: Manifest =
            toml::from_str(s).map_err(|e| FetchError::Manifest(e.message().to_string()))?;
        for entry in &m.models {
            for role in ["model", "tokenizer", "config"] {
                if !entry.files.iter().any(|f| f.role == role) {
                    return Err(FetchError::Manifest(format!(
                        "{}: missing role {role}",
                        entry.name
                    )));
                }
            }
            for file in &entry.files {
                if file.path.starts_with('/') || file.path.split('/').any(|seg| seg == "..") {
                    return Err(FetchError::Manifest(format!(
                        "{}: unsafe file path {}",
                        entry.name, file.path
                    )));
                }
            }
        }
        Ok(m)
    }

    /// Entry by name.
    pub fn get(&self, name: &str) -> Option<&ModelEntry> {
        self.models.iter().find(|m| m.name == name)
    }

    /// Entries marked `default = true`, in manifest order.
    pub fn defaults(&self) -> Vec<&ModelEntry> {
        self.models.iter().filter(|m| m.default).collect()
    }
}

impl ModelEntry {
    /// Local path of the file with `role`, under `root/<name>/`.
    pub fn path(&self, root: &Path, role: &str) -> Option<PathBuf> {
        self.files
            .iter()
            .find(|f| f.role == role)
            .map(|f| root.join(&self.name).join(&f.path))
    }
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut r = BufReader::new(File::open(path)?);
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Full check: every file present with matching size and SHA-256.
pub fn verify(root: &Path, entry: &ModelEntry) -> Vec<(String, FileStatus)> {
    entry
        .files
        .iter()
        .map(|f| {
            let p = root.join(&entry.name).join(&f.path);
            let status = match std::fs::metadata(&p) {
                Err(_) => FileStatus::Missing,
                Ok(m) if m.len() != f.size => FileStatus::Corrupt,
                Ok(_) => match sha256_file(&p) {
                    Ok(h) if h == f.sha256 => FileStatus::Ok,
                    _ => FileStatus::Corrupt,
                },
            };
            (f.path.clone(), status)
        })
        .collect()
}

/// Fast check used at load time: every file present with the pinned size.
pub fn quick_check(root: &Path, entry: &ModelEntry) -> bool {
    entry.files.iter().all(|f| {
        std::fs::metadata(root.join(&entry.name).join(&f.path)).is_ok_and(|m| m.len() == f.size)
    })
}

/// `dest`'s file name with `.part` appended (e.g. `model.onnx` ->
/// `model.onnx.part`), rather than [`Path::with_extension`], which replaces
/// the extension instead of appending to it: two files sharing a stem but
/// differing only in extension (there are none today, but the manifest does
/// not forbid it) would otherwise collide on the same in-progress path.
fn part_path(dest: &Path) -> PathBuf {
    let mut name = dest
        .file_name()
        .expect("file path has a file name")
        .to_os_string();
    name.push(".part");
    dest.with_file_name(name)
}

/// Downloads one file to `part`, verifying it against `expected` as it streams.
/// Leaves no assumptions about `part` on error; the caller removes it.
fn download_one(
    url: &str,
    part: &Path,
    expected: &ModelFile,
    progress: &mut dyn FnMut(&str, u64, u64),
) -> Result<(), FetchError> {
    let mut resp = ureq::get(url)
        .call()
        .map_err(|e| FetchError::Http(format!("{url}: {e}")))?;
    let mut reader = resp.body_mut().as_reader();
    let mut out = File::create(part).map_err(|_| FetchError::Io(part.display().to_string()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut done = 0u64;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| FetchError::Http(format!("{url}: {e}")))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        out.write_all(&buf[..n])
            .map_err(|_| FetchError::Io(part.display().to_string()))?;
        done += n as u64;
        progress(&expected.path, done, expected.size);
    }
    drop(out);
    if done != expected.size || hex(&h.finalize()) != expected.sha256 {
        return Err(FetchError::Checksum(expected.path.clone()));
    }
    Ok(())
}

/// Download every missing or corrupt file of `entry` from
/// `{base_url}/{repo}/resolve/{revision}/{path}`, verifying each against its
/// SHA-256 before moving it into place. `progress(path, done, total)` is
/// called while downloading. On any error (HTTP failure, a read or write
/// error mid-download, or a size/hash mismatch) the partial `.part` file is
/// removed; nothing is left behind for a later `pull` to trip over.
pub fn pull(
    root: &Path,
    entry: &ModelEntry,
    base_url: &str,
    progress: &mut dyn FnMut(&str, u64, u64),
) -> Result<(), FetchError> {
    let status = verify(root, entry);
    for (f, (_, st)) in entry.files.iter().zip(status) {
        if st == FileStatus::Ok {
            continue;
        }
        let dest = root.join(&entry.name).join(&f.path);
        let dir = dest.parent().expect("file path has a parent");
        std::fs::create_dir_all(dir).map_err(|_| FetchError::Io(dir.display().to_string()))?;
        let part = part_path(&dest);
        let url = format!(
            "{base_url}/{}/resolve/{}/{}",
            entry.repo, entry.revision, f.path
        );
        if let Err(e) = download_one(&url, &part, f, progress) {
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
        std::fs::rename(&part, &dest).map_err(|_| FetchError::Io(dest.display().to_string()))?;
    }
    Ok(())
}

/// Models directory: `cli` flag, else `INUMAKI_MODELS_DIR`, else the config
/// value, else `<data dir>/inumaki/models`, else `./models`.
pub fn resolve_models_dir(cli: Option<&Path>, config: Option<&Path>) -> PathBuf {
    if let Some(p) = cli {
        return p.to_path_buf();
    }
    if let Some(p) = std::env::var_os("INUMAKI_MODELS_DIR") {
        return PathBuf::from(p);
    }
    if let Some(p) = config {
        return p.to_path_buf();
    }
    dirs::data_dir().map_or_else(
        || PathBuf::from("models"),
        |d| d.join("inumaki").join("models"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // sha256("hello")
    const HELLO_SHA: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    fn fake_entry() -> ModelEntry {
        ModelEntry {
            name: "fake".into(),
            kind: "gliner".into(),
            repo: "org/fake".into(),
            revision: "abc".into(),
            license: "MIT".into(),
            license_url: "https://example.org".into(),
            default: false,
            files: vec![ModelFile {
                path: "dir/f.bin".into(),
                role: "model".into(),
                sha256: HELLO_SHA.into(),
                size: 5,
            }],
        }
    }

    #[test]
    fn embedded_manifest_has_both_defaults() {
        let m = Manifest::embedded();
        let names: Vec<&str> = m.defaults().iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["gliner-x-small", "mbert-ner-hrl"]);
        let g = m.get("gliner-x-small").unwrap();
        assert_eq!(g.revision, "d51a0984d11084a55f9df3899d9dbf7704f580f5");
        assert!(g.files.iter().any(|f| f.role == "config"));
    }

    #[test]
    fn kiji_entry_is_pinned_and_not_a_default() {
        let m = Manifest::embedded();
        let k = m.get("kiji-pii").unwrap();
        assert_eq!(k.kind, "kiji");
        assert!(!k.default, "evaluated, not shipped by default");
        assert_eq!(k.revision, "a0c9dd2ff9023b63378f67bafa50e33925663219");
        assert_eq!(k.license, "Apache-2.0");
        assert_eq!(
            k.files.iter().find(|f| f.role == "config").unwrap().path,
            "label_mappings.json"
        );
        assert_eq!(m.defaults().len(), 2);
    }

    #[test]
    fn manifest_without_a_role_is_rejected() {
        let src = "[[models]]\nname = \"x\"\nkind = \"gliner\"\nrepo = \"o/x\"\nrevision = \"r\"\nlicense = \"MIT\"\nlicense_url = \"u\"\n[[models.files]]\npath = \"m.onnx\"\nrole = \"model\"\nsha256 = \"00\"\nsize = 1\n";
        let err = Manifest::parse(src).unwrap_err();
        assert!(
            matches!(err, FetchError::Manifest(ref m) if m.contains("tokenizer")),
            "{err:?}"
        );
    }

    #[test]
    fn verify_reports_ok_missing_and_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let e = fake_entry();
        assert_eq!(verify(dir.path(), &e)[0].1, FileStatus::Missing);
        assert!(!quick_check(dir.path(), &e));
        let p = e.path(dir.path(), "model").unwrap();
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"hello").unwrap();
        assert_eq!(verify(dir.path(), &e)[0].1, FileStatus::Ok);
        assert!(quick_check(dir.path(), &e));
        std::fs::write(&p, b"hellp").unwrap();
        assert_eq!(verify(dir.path(), &e)[0].1, FileStatus::Corrupt);
    }

    fn serve_once(body: &'static [u8]) -> String {
        serve_status(200, "OK", body)
    }

    fn serve_status(status: u16, reason: &'static str, body: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let head = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes());
                let _ = s.write_all(body);
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn pull_downloads_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let base = serve_once(b"hello");
        pull(dir.path(), &fake_entry(), &base, &mut |_, _, _| {}).unwrap();
        assert_eq!(verify(dir.path(), &fake_entry())[0].1, FileStatus::Ok);
    }

    #[test]
    fn pull_rejects_wrong_checksum_and_leaves_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let base = serve_once(b"hellp");
        let err = pull(dir.path(), &fake_entry(), &base, &mut |_, _, _| {}).unwrap_err();
        assert!(matches!(err, FetchError::Checksum(_)), "{err:?}");
        let dest = fake_entry().path(dir.path(), "model").unwrap();
        assert!(!dest.exists());
        assert!(!part_path(&dest).exists(), "no .part file left behind");
    }

    #[test]
    fn pull_rejects_non_2xx_and_leaves_no_part_file() {
        let dir = tempfile::tempdir().unwrap();
        let base = serve_status(404, "Not Found", b"nope");
        let err = pull(dir.path(), &fake_entry(), &base, &mut |_, _, _| {}).unwrap_err();
        assert!(matches!(err, FetchError::Http(_)), "{err:?}");
        let dest = fake_entry().path(dir.path(), "model").unwrap();
        assert!(!dest.exists());
        assert!(!part_path(&dest).exists(), "no .part file left behind");
    }

    #[test]
    fn manifest_rejects_unsafe_file_paths() {
        let abs = "[[models]]\nname = \"x\"\nkind = \"gliner\"\nrepo = \"o/x\"\nrevision = \"r\"\nlicense = \"MIT\"\nlicense_url = \"u\"\n[[models.files]]\npath = \"/etc/passwd\"\nrole = \"model\"\nsha256 = \"00\"\nsize = 1\n[[models.files]]\npath = \"t\"\nrole = \"tokenizer\"\nsha256 = \"00\"\nsize = 1\n[[models.files]]\npath = \"c\"\nrole = \"config\"\nsha256 = \"00\"\nsize = 1\n";
        let err = Manifest::parse(abs).unwrap_err();
        assert!(
            matches!(err, FetchError::Manifest(ref m) if m.contains("unsafe file path")),
            "{err:?}"
        );
        let traversal = abs.replace("/etc/passwd", "../../etc/passwd");
        let err = Manifest::parse(&traversal).unwrap_err();
        assert!(
            matches!(err, FetchError::Manifest(ref m) if m.contains("unsafe file path")),
            "{err:?}"
        );
    }

    #[test]
    fn models_dir_resolution_order() {
        let cli = Path::new("/cli");
        let cfg = Path::new("/cfg");
        assert_eq!(
            resolve_models_dir(Some(cli), Some(cfg)),
            PathBuf::from("/cli")
        );
        // Environment is process-global; only assert the config fallback when the variable is unset.
        if std::env::var_os("INUMAKI_MODELS_DIR").is_none() {
            assert_eq!(resolve_models_dir(None, Some(cfg)), PathBuf::from("/cfg"));
        }
    }
}
