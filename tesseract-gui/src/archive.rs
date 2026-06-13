//! Folder ↔ tar helpers for file-mode encryption.
//!
//! Encrypting a folder: we tar it into a temporary file in `$XDG_RUNTIME_DIR`
//! (tmpfs — RAM-backed, cleared on logout), encrypt that, then delete the
//! temp immediately. Decrypting a folder-archive: the agent writes the
//! recovered tar to a temp, then we extract it into the chosen directory and
//! delete the temp. The plaintext tar exists only transiently on tmpfs; this
//! is the standard convenience tradeoff for "encrypt a whole folder" (noted
//! in DECISIONS.md).

use std::fs::File;
use std::path::{Path, PathBuf};

fn temp_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("tesseract")
}

/// A temp file that deletes itself on drop.
pub struct TempFile {
    pub path: PathBuf,
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

impl TempFile {
    /// Temp on tmpfs (`$XDG_RUNTIME_DIR/tesseract`). For plaintext that must
    /// be minimized (the tar of a folder being encrypted).
    pub fn new(hint: &str) -> std::io::Result<Self> {
        let dir = temp_dir();
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            path: dir.join(format!("{hint}-{}.tmp", nanos())),
        })
    }

    /// Temp in a specific directory (so a later rename to a sibling is atomic
    /// and free). Used for decrypt output, which lands on disk anyway.
    pub fn in_dir(dir: &Path, hint: &str) -> Self {
        Self {
            path: dir.join(format!(".tesseract-{hint}-{}.tmp", nanos())),
        }
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        std::fs::remove_file(&self.path).ok();
    }
}

/// Tar `dir` into a fresh temp file; returns the temp (caller encrypts it).
pub fn tar_directory(dir: &Path) -> std::io::Result<TempFile> {
    let temp = TempFile::new("archive")?;
    let file = File::create(&temp.path)?;
    let mut builder = tar::Builder::new(file);
    builder.follow_symlinks(false);
    // store paths relative to the directory's own name so extraction
    // recreates "<name>/..." under the target
    let base = dir.file_name().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("archive"));
    builder.append_dir_all(&base, dir)?;
    builder.finish()?;
    Ok(temp)
}

/// Extract the tar at `archive_path` into `target_dir`.
pub fn untar_into(archive_path: &Path, target_dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(target_dir)?;
    let file = File::open(archive_path)?;
    let mut ar = tar::Archive::new(file);
    ar.set_preserve_permissions(true);
    ar.set_overwrite(true);
    // guard against path traversal: tar crate's unpack already refuses
    // absolute paths and ".." components.
    ar.unpack(target_dir)?;
    Ok(())
}

/// True if `p` is a directory.
pub fn is_dir(p: &Path) -> bool {
    p.is_dir()
}
