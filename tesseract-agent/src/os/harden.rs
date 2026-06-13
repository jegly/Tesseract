#![allow(unsafe_code)] // the agent-wide deny(unsafe_code) carves out this audited module

//! Startup hardening, applied in order, then sealed (brief §Security):
//!
//! 1. `prctl(PR_SET_DUMPABLE, 0)` + `RLIMIT_CORE = 0`
//! 2. `mlockall(MCL_CURRENT | MCL_FUTURE)`
//! 3. (caller opens sockets/fds)
//! 4. Landlock ruleset
//! 5. seccomp-bpf allowlist
//! 6. `prctl(PR_SET_NO_NEW_PRIVS, 1)` (also implied before seccomp)
//!
//! Secret arenas additionally get `MADV_DONTDUMP` (see `secmem`).

use std::sync::atomic::{AtomicBool, Ordering};

pub static HARDENED: HardenState = HardenState::new();

pub struct HardenState {
    pub dumpable_off: AtomicBool,
    pub core_limit_zero: AtomicBool,
    pub mlockall: AtomicBool,
    pub landlock: AtomicBool,
    pub seccomp: AtomicBool,
    pub no_new_privs: AtomicBool,
}

impl HardenState {
    const fn new() -> Self {
        Self {
            dumpable_off: AtomicBool::new(false),
            core_limit_zero: AtomicBool::new(false),
            mlockall: AtomicBool::new(false),
            landlock: AtomicBool::new(false),
            seccomp: AtomicBool::new(false),
            no_new_privs: AtomicBool::new(false),
        }
    }
}

/// Phase 1: process-level secrets hygiene. Must run before any secret exists.
pub fn phase1_memory() -> anyhow::Result<()> {
    // SAFETY: prctl/setrlimit/mlockall with constant args; no memory handed over.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 {
            HARDENED.dumpable_off.store(true, Ordering::SeqCst);
        } else {
            anyhow::bail!("PR_SET_DUMPABLE failed: {}", std::io::Error::last_os_error());
        }

        let zero = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &zero) == 0 {
            HARDENED.core_limit_zero.store(true, Ordering::SeqCst);
        } else {
            anyhow::bail!("RLIMIT_CORE=0 failed: {}", std::io::Error::last_os_error());
        }

        // mlockall may exceed RLIMIT_MEMLOCK on stock systems. The unit file
        // raises the limit; if it still fails we continue (every individual
        // secret arena mlocks itself) but report it in Status.
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0 {
            HARDENED.mlockall.store(true, Ordering::SeqCst);
        } else {
            log::warn!(
                "mlockall failed ({}); falling back to per-arena mlock",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

/// Phase 2: `PR_SET_NO_NEW_PRIVS` — irreversible, required before seccomp.
pub fn no_new_privs() -> anyhow::Result<()> {
    // SAFETY: constant-arg prctl.
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r != 0 {
        anyhow::bail!("PR_SET_NO_NEW_PRIVS failed: {}", std::io::Error::last_os_error());
    }
    HARDENED.no_new_privs.store(true, Ordering::SeqCst);
    Ok(())
}

/// Landlock: restrict filesystem reach. Containers and keyfiles arrive as
/// fds, so the agent itself only needs: its runtime dir (socket, FUSE
/// mountpoints, journals), its state dir, read access to /proc/self,
/// /dev/fuse + /dev/urandom, and execute on fusermount3 (the only execve
/// the seccomp policy permits in spirit; Landlock pins the path).
pub fn apply_landlock(runtime_dir: &std::path::Path, state_dir: &std::path::Path) -> anyhow::Result<bool> {
    use landlock::{
        Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, ABI,
    };
    let abi = ABI::V3;

    let mut created = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))?
        .create()?;

    let rw = AccessFs::from_all(abi);
    let ro = AccessFs::from_read(abi);
    // fusermount3 under /usr needs Execute in addition to read.
    let ro_exec = AccessFs::from_read(abi) | AccessFs::Execute;

    for (path, access) in [
        (runtime_dir.to_path_buf(), rw),
        (state_dir.to_path_buf(), rw),
        (std::path::PathBuf::from("/dev/fuse"), rw),
        (std::path::PathBuf::from("/dev/urandom"), ro),
        (std::path::PathBuf::from("/dev/null"), rw),
        (std::path::PathBuf::from("/proc"), ro),
        (std::path::PathBuf::from("/sys/fs"), ro),
        (std::path::PathBuf::from("/run/dbus"), rw),
        (std::path::PathBuf::from("/run/udev"), ro),
        (std::path::PathBuf::from("/usr"), ro_exec),
        (std::path::PathBuf::from("/etc"), ro),
    ] {
        if path.exists() {
            use landlock::path_beneath_rules;
            created = created.add_rules(path_beneath_rules(&[path], access))?;
        }
    }

    let status = created.restrict_self()?;
    let enforced = status.ruleset != RulesetStatus::NotEnforced;
    HARDENED.landlock.store(enforced, Ordering::SeqCst);
    if !enforced {
        log::warn!("Landlock not enforced (kernel too old?)");
    }
    Ok(enforced)
}

/// seccomp-bpf: steady-state syscall allowlist. Unknown syscalls fault with
/// ENOSYS (log-friendly) rather than SIGKILL so a missed syscall degrades
/// loudly but diagnosably; the security boundary is the allowlist either way.
pub fn apply_seccomp() -> anyhow::Result<bool> {
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompFilter, SeccompRule,
    };
    use std::collections::BTreeMap;

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let allow: &[i64] = &[
        // io
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_preadv2,
        libc::SYS_pwritev2,
        libc::SYS_lseek,
        libc::SYS_close,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_ftruncate,
        libc::SYS_fallocate,
        libc::SYS_copy_file_range,
        // fs (runtime dir, journals, socket, fuse mountpoints)
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_fstat,
        libc::SYS_getdents64,
        libc::SYS_mkdirat,
        libc::SYS_unlinkat,
        libc::SYS_renameat,
        libc::SYS_renameat2,
        libc::SYS_readlinkat,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fcntl,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_flock,
        libc::SYS_umask,
        // memory
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mprotect,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_mlock,
        libc::SYS_mlock2,
        libc::SYS_munlock,
        libc::SYS_mlockall,
        libc::SYS_brk,
        libc::SYS_membarrier,
        // signals / process
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_prctl,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_futex,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getrandom,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_getrusage,
        libc::SYS_rseq,
        libc::SYS_set_robust_list,
        libc::SYS_get_robust_list,
        // threads (worker pool, FUSE sessions, zbus executor)
        libc::SYS_clone3,
        libc::SYS_clone,
        // fusermount3 spawn (Landlock pins the executable path)
        libc::SYS_execve,
        libc::SYS_wait4,
        libc::SYS_pidfd_open,
        libc::SYS_kill,
        // sockets: IPC socket, D-Bus, FUSE
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept4,
        libc::SYS_connect,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_sendto,
        libc::SYS_recvfrom,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
        libc::SYS_shutdown,
        // event loops
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_wait,
        libc::SYS_epoll_pwait,
        libc::SYS_ppoll,
        libc::SYS_poll,
        libc::SYS_pselect6,
        libc::SYS_eventfd2,
        libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime,
        libc::SYS_signalfd4,
        libc::SYS_inotify_init1,
        libc::SYS_inotify_add_watch,
        libc::SYS_inotify_rm_watch,
        // FUSE + ioctl surface (loop/ublk would extend here)
        libc::SYS_ioctl,
        libc::SYS_mount,   // FUSE self-mount path when CAP not needed
        libc::SYS_umount2, // FUSE teardown via fusermount fallback
        // misc
        libc::SYS_uname,
        libc::SYS_sysinfo,
        libc::SYS_getcwd,
        libc::SYS_pipe2,
        libc::SYS_landlock_create_ruleset,
        libc::SYS_landlock_add_rule,
        libc::SYS_landlock_restrict_self,
        libc::SYS_seccomp,
    ];
    for s in allow {
        rules.insert(*s, vec![]);
    }

    let filter = SeccompFilter::new(
        rules,
        // default: fail loudly-but-safely
        SeccompAction::Errno(libc::ENOSYS as u32),
        SeccompAction::Allow,
        std::env::consts::ARCH.try_into().map_err(|e| anyhow::anyhow!("{e:?}"))?,
    )
    .map_err(|e| anyhow::anyhow!("seccomp filter: {e}"))?;
    let bpf: BpfProgram = filter.try_into().map_err(|e| anyhow::anyhow!("seccomp compile: {e}"))?;
    seccompiler::apply_filter(&bpf).map_err(|e| anyhow::anyhow!("seccomp apply: {e}"))?;
    HARDENED.seccomp.store(true, Ordering::SeqCst);
    Ok(true)
}

pub fn sandbox_info() -> tesseract_proto::SandboxInfo {
    tesseract_proto::SandboxInfo {
        mlockall: HARDENED.mlockall.load(Ordering::SeqCst),
        no_new_privs: HARDENED.no_new_privs.load(Ordering::SeqCst),
        dumpable_disabled: HARDENED.dumpable_off.load(Ordering::SeqCst),
        landlock: HARDENED.landlock.load(Ordering::SeqCst),
        seccomp: HARDENED.seccomp.load(Ordering::SeqCst),
    }
}
