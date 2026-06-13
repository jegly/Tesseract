//! ublk (io_uring) data plane — feature "ublk".
//!
//! Serving a real /dev/ublkbN block device requires the `ublk_drv` kernel
//! module and udev rules granting the user access to /dev/ublk-control.
//! This backend is scaffolded behind the feature flag; the FUSE+udisks2
//! plane is the shipped, tested default (DECISIONS.md D-16).

use anyhow::bail;

pub fn available() -> bool {
    std::path::Path::new("/dev/ublk-control").exists()
}

pub fn serve(_plane: std::sync::Arc<super::fuse::VolumePlane>) -> anyhow::Result<()> {
    bail!("ublk backend not enabled in this build; use data_plane=fuse")
}
