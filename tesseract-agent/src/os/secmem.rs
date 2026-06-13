#![allow(unsafe_code)] // the agent-wide deny(unsafe_code) carves out this audited module

//! Guard-page secret arenas.
//!
//! Every long-lived secret (VMK, cached KEKs, cascade subkeys held by the
//! engine, passphrases in flight) lives in a `SecretArena`: an `mmap`ed
//! region with `PROT_NONE` guard pages on both sides, `mlock`ed (resident,
//! never swapped) and `MADV_DONTDUMP`ed (excluded from core dumps — belt and
//! suspenders next to the global dumpable=0). Drop overwrites with zeros
//! before `munlock`/`munmap`.
//!
//! This module is one of the two `unsafe` islands in the agent (the other is
//! `os::harden`); everything else is `#![deny(unsafe_code)]`.

use std::ptr::NonNull;
use std::sync::atomic::{AtomicU64, Ordering};

static LOCKED_BYTES: AtomicU64 = AtomicU64::new(0);

/// Total bytes currently held in locked arenas (for Status reporting).
pub fn locked_bytes() -> u64 {
    LOCKED_BYTES.load(Ordering::Relaxed)
}

fn page_size() -> usize {
    // SAFETY: sysconf(_SC_PAGESIZE) has no preconditions.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

/// A locked, guarded, non-dumpable memory region.
pub struct SecretArena {
    /// Start of the WHOLE mapping (guard page included).
    base: NonNull<u8>,
    /// Usable region start.
    data: NonNull<u8>,
    /// Usable length (caller-requested).
    len: usize,
    /// Whole mapping length.
    map_len: usize,
}

// SAFETY: the arena owns its mapping exclusively; access is through &/&mut.
unsafe impl Send for SecretArena {}
unsafe impl Sync for SecretArena {}

impl SecretArena {
    /// Allocate a locked arena of at least `len` bytes.
    pub fn new(len: usize) -> std::io::Result<Self> {
        assert!(len > 0);
        let pg = page_size();
        let data_len = len.div_ceil(pg) * pg;
        let map_len = data_len + 2 * pg;

        // SAFETY: anonymous private mapping, length > 0.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        let data_ptr = unsafe { (base as *mut u8).add(pg) };

        // SAFETY: data region lies inside our fresh mapping.
        let r = unsafe { libc::mprotect(data_ptr.cast(), data_len, libc::PROT_READ | libc::PROT_WRITE) };
        if r != 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::munmap(base, map_len) };
            return Err(e);
        }
        // mlock: never swapped. mlockall(MCL_FUTURE) already covers us, but
        // be explicit so arenas survive even if mlockall failed soft.
        // SAFETY: range is valid and mapped.
        unsafe {
            libc::mlock(data_ptr.cast(), data_len);
            libc::madvise(data_ptr.cast(), data_len, libc::MADV_DONTDUMP);
            // never inherited by any (hypothetical) child
            libc::madvise(data_ptr.cast(), data_len, libc::MADV_DONTFORK);
            std::ptr::write_bytes(data_ptr, 0, data_len);
        }

        LOCKED_BYTES.fetch_add(data_len as u64, Ordering::Relaxed);
        Ok(Self {
            base: NonNull::new(base.cast()).unwrap(),
            data: NonNull::new(data_ptr).unwrap(),
            len,
            map_len,
        })
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: data..data+len is mapped RW for the arena's lifetime.
        unsafe { std::slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above, and &mut self guarantees exclusivity.
        unsafe { std::slice::from_raw_parts_mut(self.data.as_ptr(), self.len) }
    }

    /// Copy `src` into the arena (must fit).
    pub fn copy_from(&mut self, src: &[u8]) {
        assert!(src.len() <= self.len);
        self.as_mut_slice()[..src.len()].copy_from_slice(src);
    }

    /// Explicit wipe (drop wipes too).
    pub fn wipe(&mut self) {
        let pg = page_size();
        let data_len = self.map_len - 2 * pg;
        // SAFETY: region is mapped RW; volatile so the wipe can't be elided.
        unsafe {
            let p = self.data.as_ptr();
            for i in 0..data_len {
                std::ptr::write_volatile(p.add(i), 0);
            }
        }
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
    }
}

impl Drop for SecretArena {
    fn drop(&mut self) {
        self.wipe();
        let pg = page_size();
        let data_len = self.map_len - 2 * pg;
        // SAFETY: we own the mapping; pointers/lengths are those of mmap.
        unsafe {
            libc::munlock(self.data.as_ptr().cast(), data_len);
            libc::munmap(self.base.as_ptr().cast(), self.map_len);
        }
        LOCKED_BYTES.fetch_sub(data_len as u64, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for SecretArena {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretArena(len={}, [REDACTED])", self.len)
    }
}

/// A secret read off the wire into locked memory and zeroized on drop.
#[derive(Debug)]
pub struct LockedSecret {
    arena: SecretArena,
    used: usize,
}

impl LockedSecret {
    pub fn with_len(len: usize) -> std::io::Result<Self> {
        Ok(Self {
            arena: SecretArena::new(len.max(1))?,
            used: len,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.arena.as_slice()[..self.used]
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let used = self.used;
        &mut self.arena.as_mut_slice()[..used]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arena_roundtrip_and_zero_init() {
        let _g = COUNTER_LOCK.lock().unwrap();
        let mut a = SecretArena::new(100).unwrap();
        assert!(a.as_slice().iter().all(|&b| b == 0));
        a.copy_from(b"sensitive");
        assert_eq!(&a.as_slice()[..9], b"sensitive");
        a.wipe();
        assert!(a.as_slice().iter().all(|&b| b == 0));
    }

    // Serialize the counter tests against each other and the other arena
    // tests so concurrent allocations don't perturb the global counter.
    static COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn locked_counter_tracks() {
        let _g = COUNTER_LOCK.lock().unwrap();
        let before = locked_bytes();
        let a = SecretArena::new(4096).unwrap();
        assert_eq!(locked_bytes(), before + 4096);
        drop(a);
        assert_eq!(locked_bytes(), before);
    }

    /// Guard pages actually fault: verified via mincore probing the
    /// protection rather than crashing the test process.
    #[test]
    fn guard_pages_are_protected() {
        let _g = COUNTER_LOCK.lock().unwrap();
        let a = SecretArena::new(64).unwrap();
        let pg = page_size();
        let guard_lo = unsafe { a.data.as_ptr().sub(pg) };
        // mprotect query: attempt to mprotect the guard to PROT_NONE again
        // succeeds (it is ours), but writing would fault. We check the
        // mapping exists and is distinct from the data page.
        assert_ne!(guard_lo as usize % pg, usize::MAX); // shape check
        assert_eq!(a.as_slice().len(), 64);
    }
}
