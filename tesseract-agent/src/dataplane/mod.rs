//! Data planes. FUSE (default, fully unprivileged) presents the decrypted
//! image; udisks2 turns it into a mounted filesystem. ublk (feature "ublk")
//! serves a real block device via io_uring. The dm-crypt fast path goes
//! through `tesseract-mountd` and is opt-in (kernel holds the key — weaker
//! profile, flagged in the UI).

pub mod fuse;
pub mod udisks;

#[cfg(feature = "ublk")]
pub mod ublk;
