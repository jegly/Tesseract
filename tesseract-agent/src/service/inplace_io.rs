//! Real-file BlockIo + fsynced sidecar journal for in-place conversion.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use tesseract_core::inplace::{BlockIo, JournalStore};
use tesseract_core::{Error as CoreError, Result as CoreResult};

pub struct FileBlockIo {
    pub file: File,
}

impl BlockIo for FileBlockIo {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> CoreResult<()> {
        self.file
            .read_exact_at(buf, offset)
            .map_err(|_| CoreError::Io("read"))
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> CoreResult<()> {
        self.file
            .write_all_at(buf, offset)
            .map_err(|_| CoreError::Io("write"))
    }

    fn flush(&mut self) -> CoreResult<()> {
        self.file.sync_data().map_err(|_| CoreError::Io("fsync"))
    }

    fn set_len(&mut self, len: u64) -> CoreResult<()> {
        self.file.set_len(len).map_err(|_| CoreError::Io("truncate"))
    }

    fn len(&self) -> u64 {
        self.file.metadata().map(|m| m.len()).unwrap_or(0)
    }
}

/// Journal sidecar with atomic-rename durability:
/// write tmp → fsync tmp → rename → fsync dir.
pub struct SidecarJournal {
    pub path: PathBuf,
}

impl SidecarJournal {
    pub fn for_uuid(state_dir: &std::path::Path, uuid: &[u8; 16]) -> Self {
        let dir = state_dir.join("journals");
        std::fs::create_dir_all(&dir).ok();
        Self {
            path: dir.join(format!("{}.journal", hex::encode(uuid))),
        }
    }
}

impl JournalStore for SidecarJournal {
    fn save(&mut self, bytes: &[u8]) -> CoreResult<()> {
        let tmp = self.path.with_extension("journal.tmp");
        let write = || -> std::io::Result<()> {
            std::fs::write(&tmp, bytes)?;
            File::open(&tmp)?.sync_all()?;
            std::fs::rename(&tmp, &self.path)?;
            if let Some(dir) = self.path.parent() {
                File::open(dir)?.sync_all()?;
            }
            Ok(())
        };
        write().map_err(|_| CoreError::Io("journal save"))
    }

    fn load(&mut self) -> CoreResult<Option<Vec<u8>>> {
        match std::fs::read(&self.path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(CoreError::Io("journal load")),
        }
    }

    fn clear(&mut self) -> CoreResult<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(CoreError::Io("journal clear")),
        }
    }
}
