//! OS integration. The ONLY modules in the agent allowed to use `unsafe`
//! (`secmem` for the guard-page allocator, `harden` for prctl/rlimit/
//! mlockall/seccomp). Everything else is `#![deny(unsafe_code)]`.

pub mod harden;
pub mod secmem;

use std::path::PathBuf;

/// `$XDG_RUNTIME_DIR/tesseract` — socket, FUSE mountpoints, volatile state.
pub fn runtime_dir() -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", rustix::process::getuid().as_raw())));
    base.join("tesseract")
}

pub fn socket_path() -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", rustix::process::getuid().as_raw())));
    base.join(tesseract_proto::SOCKET_NAME)
}

/// `~/.local/state/tesseract` — agent config, conversion journals.
pub fn state_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
            home.join(".local/state")
        })
        .join("tesseract")
}
