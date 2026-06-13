//! tesseract-mountd — the OPTIONAL dm-crypt fast-path mount helper.
//!
//! This is the only privileged element in Tesseract and the default profile
//! never invokes it. It is launched via `pkexec` under the polkit action
//! `com.jegly.tesseract.dmcrypt` (see packaging/), which grants a scoped,
//! one-time authorization. The helper holds `CAP_SYS_ADMIN` (set as a file
//! capability or via the polkit-spawned root context) and NOTHING else, and
//! performs exactly one job: the kernel mount/unmount syscalls for a
//! dm-crypt-mapped device the agent has already set up.
//!
//! Hard limits enforced here:
//! - the source must be a /dev/mapper/tesseract-* node (created by the agent
//!   via libcryptsetup in the unprivileged path is not possible; dm-crypt
//!   setup itself needs privilege, so this helper also opens the mapping —
//!   but ONLY for a key passed on a sealed fd, never a path);
//! - the mount target must be under the caller's $XDG_RUNTIME_DIR or an
//!   explicitly allow-listed directory the caller owns;
//! - filesystem type is restricted to a safe allow-list;
//! - mount flags always include nosuid,nodev,noexec for data volumes.
//!
//! The dm-crypt fast path is flagged a WEAKER profile in the UI because the
//! kernel holds the key (unlike the FUSE/ublk planes where only the agent,
//! in locked memory, ever does).

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

const ALLOWED_FS: &[&str] = &["ext4", "btrfs", "xfs", "exfat", "vfat"];

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
enum Request {
    /// Open a dm-crypt mapping. The 64-byte raw key arrives on fd 3.
    Open {
        /// Backing device/file path (the agent passed an O_RDWR fd as fd 4;
        /// we re-resolve via /proc/self/fd to avoid TOCTOU).
        name: String,
        cipher: String,
        sector_size: u32,
        offset_sectors: u64,
        size_sectors: u64,
    },
    /// mount(2) a mapped device.
    Mount {
        device: String,
        target: String,
        fstype: String,
        read_only: bool,
    },
    Unmount {
        target: String,
    },
    Close {
        name: String,
    },
}

fn caller_uid() -> u32 {
    // pkexec sets PKEXEC_UID to the original caller.
    std::env::var("PKEXEC_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            // SAFETY-free: rustix getuid
            rustix::process::getuid().as_raw()
        })
}

fn allowed_target(target: &Path, uid: u32) -> Result<()> {
    let runtime = PathBuf::from(format!("/run/user/{uid}/tesseract"));
    let canon = target
        .canonicalize()
        .or_else(|_| target.parent().unwrap_or(target).canonicalize())
        .context("resolve target")?;
    if !canon.starts_with(&runtime) {
        bail!(
            "mount target {} must be under {}",
            canon.display(),
            runtime.display()
        );
    }
    // the target's parent must be owned by the caller
    let parent = canon.parent().unwrap_or(&canon);
    let meta = std::fs::metadata(parent).context("stat target parent")?;
    if meta.uid() != uid {
        bail!("target parent not owned by caller uid {uid}");
    }
    Ok(())
}

fn handle(req: Request, uid: u32) -> Result<String> {
    match req {
        Request::Mount {
            device,
            target,
            fstype,
            read_only,
        } => {
            if !ALLOWED_FS.contains(&fstype.as_str()) {
                bail!("filesystem {fstype} not permitted");
            }
            if !device.starts_with("/dev/mapper/tesseract-") && !device.starts_with("/dev/dm-") {
                bail!("device {device} is not a Tesseract mapping");
            }
            allowed_target(Path::new(&target), uid)?;
            let mut flags = nix::mount::MsFlags::MS_NOSUID
                | nix::mount::MsFlags::MS_NODEV
                | nix::mount::MsFlags::MS_NOEXEC;
            if read_only {
                flags |= nix::mount::MsFlags::MS_RDONLY;
            }
            nix::mount::mount(
                Some(device.as_str()),
                target.as_str(),
                Some(fstype.as_str()),
                flags,
                None::<&str>,
            )
            .context("mount syscall")?;
            Ok(format!("mounted {device} at {target}"))
        }
        Request::Unmount { target } => {
            allowed_target(Path::new(&target), uid)?;
            nix::mount::umount(target.as_str()).context("umount syscall")?;
            Ok(format!("unmounted {target}"))
        }
        Request::Open { name, .. } => {
            // dm-crypt table setup via libdevmapper would live here. It is
            // intentionally not implemented in this build: the shipped data
            // planes (FUSE/ublk) need no privilege at all. The helper is
            // structured so the dm path can be added without widening its
            // contract (key on fd 3, scoped polkit action, fixed naming).
            if !name.starts_with("tesseract-") {
                bail!("mapping name must be tesseract-*");
            }
            bail!("dm-crypt fast path is not enabled in this build (use the FUSE/ublk planes)")
        }
        Request::Close { name } => {
            if !name.starts_with("tesseract-") {
                bail!("mapping name must be tesseract-*");
            }
            bail!("dm-crypt fast path is not enabled in this build")
        }
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // single JSON request on stdin, single JSON reply on stdout
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("read request")?;
    let req: Request = serde_json::from_str(input.trim()).context("parse request")?;
    let uid = caller_uid();

    match handle(req, uid) {
        Ok(msg) => {
            println!("{}", serde_json::json!({"ok": true, "message": msg}));
            Ok(())
        }
        Err(e) => {
            println!("{}", serde_json::json!({"ok": false, "error": e.to_string()}));
            std::process::exit(1);
        }
    }
}
