//! FUSE data plane: presents the decrypted volume as a single virtual file
//! `volume.img`. Every read/write passes through the cascade engine inside
//! this process; plaintext exists only transiently in our locked,
//! non-dumpable memory. The image is then loop-mounted via udisks2 (or used
//! directly in file-access mode).
//!
//! Hidden-volume protection: writes intersecting the protected byte range
//! are refused with EIO and flagged, exactly like VeraCrypt's behavior.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use fuser::{
    Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    LockOwner, MountOption, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    ReplyOpen, ReplyWrite, Request, WriteFlags,
};
use tesseract_core::cascade::CascadeEngine;
use tesseract_core::header::Geometry;

const ROOT_INO: u64 = 1;
const IMG_INO: u64 = 2;
const IMG_NAME: &str = "volume.img";
const TTL: Duration = Duration::from_secs(1);

/// Shared, thread-safe view of one unlocked volume's data plane.
pub struct VolumePlane {
    pub container: File,
    pub engine: Arc<CascadeEngine>,
    pub geometry: Geometry,
    pub read_only: bool,
    /// Hidden-volume protection: byte range (relative to data area) that
    /// must never be written through the outer volume.
    pub protect: Option<(u64, u64)>,
    pub protection_triggered: Arc<AtomicBool>,
    pub last_activity: Arc<AtomicU64>, // unix seconds
    pub io_error: Arc<AtomicBool>,     // tamper signal
}

impl VolumePlane {
    fn touch(&self) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_activity.store(now, Ordering::Relaxed);
    }

    fn sector_size(&self) -> u64 {
        self.geometry.sector_size as u64
    }

    fn data_len(&self) -> u64 {
        self.geometry.data_len
    }

    /// Read decrypted bytes at `offset` (relative to the data area).
    pub fn read_decrypted(&self, offset: u64, size: usize) -> std::io::Result<Vec<u8>> {
        self.touch();
        let dlen = self.data_len();
        if offset >= dlen {
            return Ok(Vec::new());
        }
        let size = size.min((dlen - offset) as usize);
        let ss = self.sector_size();
        let first = offset / ss;
        let last = (offset + size as u64 - 1) / ss;
        let count = last - first + 1;
        let mut buf = vec![0u8; (count * ss) as usize];
        let disk_off = self.geometry.data_offset + first * ss;
        self.container.read_exact_at(&mut buf, disk_off).map_err(|e| {
            self.io_error.store(true, Ordering::SeqCst);
            e
        })?;
        self.engine
            .decrypt_range(first, &mut buf)
            .map_err(|_| std::io::Error::other("decrypt"))?;
        let inner = (offset - first * ss) as usize;
        Ok(buf[inner..inner + size].to_vec())
    }

    /// Encrypt and write plaintext at `offset` (relative to the data area).
    pub fn write_encrypted(&self, offset: u64, data: &[u8]) -> std::io::Result<usize> {
        self.touch();
        if self.read_only {
            return Err(std::io::Error::from_raw_os_error(libc::EROFS));
        }
        let dlen = self.data_len();
        if offset >= dlen {
            return Err(std::io::Error::from_raw_os_error(libc::ENOSPC));
        }
        let len = data.len().min((dlen - offset) as usize);
        let data = &data[..len];

        if let Some((p_start, p_end)) = self.protect {
            let w_end = offset + len as u64;
            if offset < p_end && w_end > p_start {
                self.protection_triggered.store(true, Ordering::SeqCst);
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
        }

        let ss = self.sector_size();
        let first = offset / ss;
        let last = (offset + len as u64 - 1) / ss;
        let count = last - first + 1;
        let mut buf = vec![0u8; (count * ss) as usize];
        let disk_off = self.geometry.data_offset + first * ss;

        let head_partial = offset % ss != 0;
        let tail_partial = (offset + len as u64) % ss != 0;
        if head_partial || tail_partial {
            // read-modify-write around partial sectors
            self.container.read_exact_at(&mut buf, disk_off).map_err(|e| {
                self.io_error.store(true, Ordering::SeqCst);
                e
            })?;
            self.engine
                .decrypt_range(first, &mut buf)
                .map_err(|_| std::io::Error::other("decrypt"))?;
        }
        let inner = (offset - first * ss) as usize;
        buf[inner..inner + len].copy_from_slice(data);
        self.engine
            .encrypt_range(first, &mut buf)
            .map_err(|_| std::io::Error::other("encrypt"))?;
        self.container.write_all_at(&buf, disk_off).map_err(|e| {
            self.io_error.store(true, Ordering::SeqCst);
            e
        })?;
        Ok(len)
    }

    pub fn flush(&self) -> std::io::Result<()> {
        self.container.sync_data()
    }
}

struct ImgFs {
    plane: Arc<VolumePlane>,
    uid: u32,
    gid: u32,
}

impl ImgFs {
    fn img_attr(&self) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino: INodeNo(IMG_INO),
            size: self.plane.data_len(),
            blocks: self.plane.data_len() / 512,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::RegularFile,
            perm: if self.plane.read_only { 0o400 } else { 0o600 },
            nlink: 1,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: self.plane.geometry.sector_size,
            flags: 0,
        }
    }

    fn root_attr(&self) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino: INodeNo(ROOT_INO),
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: FileType::Directory,
            perm: 0o500,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }
}

impl Filesystem for ImgFs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &std::ffi::OsStr, reply: ReplyEntry) {
        if parent == INodeNo(ROOT_INO) && name.to_str() == Some(IMG_NAME) {
            reply.entry(&TTL, &self.img_attr(), Generation(0));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        match ino.0 {
            ROOT_INO => reply.attr(&TTL, &self.root_attr()),
            IMG_INO => reply.attr(&TTL, &self.img_attr()),
            _ => reply.error(Errno::ENOENT),
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if ino.0 != IMG_INO {
            return reply.error(Errno::EISDIR);
        }
        let write = flags.0 & libc::O_ACCMODE != libc::O_RDONLY;
        if write && self.plane.read_only {
            return reply.error(Errno::EROFS);
        }
        // direct IO: the page cache must never hold plaintext longer than
        // necessary, and sizes/offsets stay block-accurate for loop devices
        reply.opened(FileHandle(0), FopenFlags::FOPEN_DIRECT_IO);
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        if ino.0 != IMG_INO {
            return reply.error(Errno::EINVAL);
        }
        match self.plane.read_decrypted(offset, size as usize) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(Errno::from_i32(e.raw_os_error().unwrap_or(libc::EIO))),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        if ino.0 != IMG_INO {
            return reply.error(Errno::EINVAL);
        }
        match self.plane.write_encrypted(offset, data) {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(Errno::from_i32(e.raw_os_error().unwrap_or(libc::EIO))),
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: fuser::ReplyEmpty,
    ) {
        match self.plane.flush() {
            Ok(()) => reply.ok(),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: fuser::ReplyEmpty,
    ) {
        match self.plane.flush() {
            Ok(()) => reply.ok(),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if ino.0 != ROOT_INO {
            return reply.error(Errno::ENOTDIR);
        }
        let entries = [
            (ROOT_INO, FileType::Directory, "."),
            (ROOT_INO, FileType::Directory, ".."),
            (IMG_INO, FileType::RegularFile, IMG_NAME),
        ];
        for (i, (ino, kind, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(INodeNo(*ino), (i + 1) as u64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }
}

/// A mounted FUSE data plane.
pub struct FuseHandle {
    pub mountpoint: PathBuf,
    session: Option<fuser::BackgroundSession>,
}

impl std::fmt::Debug for FuseHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FuseHandle({})", self.mountpoint.display())
    }
}

impl FuseHandle {
    pub fn image_path(&self) -> PathBuf {
        self.mountpoint.join(IMG_NAME)
    }

    /// Tear down. Consumes self; the BackgroundSession unmounts on drop.
    pub fn unmount(mut self) {
        if let Some(s) = self.session.take() {
            drop(s); // joins and unmounts
        }
        std::fs::remove_dir(&self.mountpoint).ok();
    }
}

fn mount_with(plane: Arc<VolumePlane>, mountpoint: &Path, allow_root: bool) -> Result<FuseHandle> {
    std::fs::create_dir_all(mountpoint)
        .with_context(|| format!("mkdir {}", mountpoint.display()))?;
    let fs = ImgFs {
        plane,
        uid: rustix::process::getuid().as_raw(),
        gid: rustix::process::getgid().as_raw(),
    };
    let mut config = fuser::Config::default();
    config.mount_options = vec![
        MountOption::FSName("tesseract".into()),
        MountOption::Subtype("tesseract".into()),
        MountOption::DefaultPermissions,
        MountOption::NoExec,
        MountOption::NoAtime,
    ];
    // Loop devices do IO in kernel/root context: udisks loop-mounting the
    // image requires allowing root (needs user_allow_other in
    // /etc/fuse.conf; the installer adds it).
    config.acl = if allow_root {
        fuser::SessionACL::RootAndOwner
    } else {
        fuser::SessionACL::Owner
    };
    let session = fuser::spawn_mount2(fs, mountpoint, &config)?;
    Ok(FuseHandle {
        mountpoint: mountpoint.to_path_buf(),
        session: Some(session),
    })
}

/// Mount, preferring allow_root (loop-mountable) but degrading to private
/// file-access mode when fuse.conf forbids it. Returns (handle, loopable).
pub fn mount_auto(plane: Arc<VolumePlane>, mountpoint: &Path) -> Result<(FuseHandle, bool)> {
    match mount_with(plane.clone(), mountpoint, true) {
        Ok(h) => Ok((h, true)),
        Err(e) => {
            log::warn!("FUSE allow_root mount failed ({e}); falling back to file-access mode");
            let h = mount_with(plane, mountpoint, false)?;
            Ok((h, false))
        }
    }
}
