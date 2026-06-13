//! Tesseract IPC contract.
//!
//! Transport: Unix domain socket at `$XDG_RUNTIME_DIR/tesseract.sock`, mode
//! 0600, SO_PEERCRED-checked. Framing is length-prefixed:
//!
//! ```text
//! frame := kind(1) | len(4 LE) | payload(len)
//! kind  := 0 control (JSON RequestEnvelope / ResponseEnvelope / Event)
//!        | 1 secret  (raw bytes; the agent reads the payload DIRECTLY into
//!                     locked memory — it never passes through serde)
//! ```
//!
//! File descriptors ride as `SCM_RIGHTS` ancillary data on the control
//! frame's `sendmsg`. Container references are ALWAYS fds (TOCTOU-safe);
//! the agent refuses paths.
//!
//! Secret frames are positional and raw; their meaning per operation is
//! documented on each [`Op`] variant. Replies never carry secrets.
//!
//! This crate is pure (no OS calls): the frame codec is a fuzz target.

#![forbid(unsafe_code)]

#[cfg(feature = "client")]
pub mod client;

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;
pub const SOCKET_NAME: &str = "tesseract.sock";

pub const FRAME_CONTROL: u8 = 0;
pub const FRAME_SECRET: u8 = 1;

pub const MAX_CONTROL_LEN: u32 = 256 * 1024;
pub const MAX_SECRET_LEN: u32 = 64 * 1024;
pub const MAX_FDS: usize = 16;
pub const FRAME_HEADER_LEN: usize = 5;

/// Decoded frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub kind: u8,
    pub len: u32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("unknown frame kind {0}")]
    BadKind(u8),
    #[error("frame length {len} exceeds limit {max}")]
    TooLong { len: u32, max: u32 },
    #[error("incomplete header")]
    Incomplete,
}

/// Parse a frame header. The caller then reads exactly `len` payload bytes —
/// for secret frames, directly into locked memory.
pub fn decode_frame_header(bytes: &[u8]) -> Result<FrameHeader, FrameError> {
    if bytes.len() < FRAME_HEADER_LEN {
        return Err(FrameError::Incomplete);
    }
    let kind = bytes[0];
    let len = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    let max = match kind {
        FRAME_CONTROL => MAX_CONTROL_LEN,
        FRAME_SECRET => MAX_SECRET_LEN,
        k => return Err(FrameError::BadKind(k)),
    };
    if len > max {
        return Err(FrameError::TooLong { len, max });
    }
    Ok(FrameHeader { kind, len })
}

pub fn encode_frame_header(kind: u8, len: u32) -> [u8; FRAME_HEADER_LEN] {
    let mut h = [0u8; FRAME_HEADER_LEN];
    h[0] = kind;
    h[1..].copy_from_slice(&len.to_le_bytes());
    h
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestEnvelope {
    pub id: u64,
    /// Number of secret frames that follow this control frame.
    pub secrets: u8,
    /// Number of fds attached via SCM_RIGHTS.
    pub fds: u8,
    pub op: Op,
}

/// Mount options for unlock.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MountOptions {
    pub read_only: bool,
    /// Present the device as removable to udisks.
    pub removable: bool,
    /// Mount under this directory instead of the default runtime dir.
    pub mount_dir: Option<String>,
    /// Don't keep the derived credential cached for re-mount.
    pub no_cache: bool,
    /// Open the file manager after mount (handled by the GUI; echoed back).
    pub open_file_manager: bool,
    /// Preferred data plane: "ublk" | "fuse" | "dmcrypt".
    pub data_plane: Option<String>,
}

/// KDF cost preset sent by clients (mapped onto KdfParams by the agent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfChoice {
    /// "argon2id" | "scrypt" | "pbkdf2" | "balloon".
    pub kdf: String,
    /// Memory KiB for argon2/balloon s_cost; log2(N) for scrypt; iterations
    /// for pbkdf2. 0 = benchmarked default.
    pub memory: u32,
    /// Time cost / passes. 0 = benchmarked default.
    pub time: u32,
    pub parallelism: u32,
    /// PIM-equivalent extra passes.
    pub pim: u32,
}

impl Default for KdfChoice {
    fn default() -> Self {
        Self {
            kdf: "argon2id".into(),
            memory: 0,
            time: 0,
            parallelism: 0,
            pim: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVolumeReq {
    /// Cipher cascade, innermost first, registry ids.
    pub cascade: Vec<u16>,
    pub hash: u16,
    pub kdf: KdfChoice,
    /// Committing AEAD for keyslots, registry id.
    pub slot_aead: u16,
    pub label: String,
    pub size_bytes: u64,
    pub sector_size: u32,
    /// "standard" | "deniable".
    pub profile: String,
    /// Sparse/dynamic container (created sparse; grows on demand).
    pub dynamic: bool,
    /// Filesystem to create on the mapped device: "ext4" | "btrfs" | "xfs" |
    /// "exfat" | "vfat" | "none".
    pub filesystem: String,
    /// Overwrite with random data first (full format) vs quick.
    pub full_format: bool,
    /// Hidden volume size (deniable profile only, 0 = none).
    pub hidden_size: u64,
    /// Require the hybrid PQC keyslot (REQUIRE_PQC flag).
    pub require_pqc: bool,
    /// Base64 hybrid recipient (adds a PQC keyslot at create time).
    pub pqc_recipient: Option<String>,
    /// Allow experimental algorithms on this volume.
    pub experimental_ok: bool,
    /// secrets: [0] passphrase, [1] hidden passphrase (if hidden_size > 0).
    /// fds: [0] container file (O_RDWR, created by the client),
    ///      [1..] keyfiles.
    /// Number of keyfiles that apply to the hidden volume (taken from the
    /// END of the keyfile fd list).
    pub hidden_keyfiles: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockReq {
    pub options: MountOptions,
    /// PIM for deniable volumes (0 = default cost).
    pub pim: u32,
    /// Hidden volume protection: secrets[1] carries the hidden passphrase
    /// and the agent write-protects the hidden region of the outer volume.
    pub protect_hidden: bool,
    /// "passphrase" | "keyfile" | "identity" | "fido2".
    pub credential_kind: String,
    /// secrets: [0] passphrase (or identity-file passphrase),
    ///          [1] hidden passphrase when protect_hidden.
    /// fds: [0] container, [1..] keyfiles, last = identity file when
    ///      credential_kind == "identity".
    pub label_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyslotChangeReq {
    /// "add-passphrase" | "change-passphrase" | "add-keyfile" | "add-pqc" |
    /// "add-fido2" | "remove" | "change-kdf".
    pub action: String,
    pub slot_id: Option<u8>,
    pub kdf: Option<KdfChoice>,
    pub slot_aead: Option<u16>,
    pub label: Option<String>,
    pub pqc_recipient: Option<String>,
    /// secrets: [0] existing credential, [1] new credential (when adding).
    /// fds: [0] container, [1..] keyfiles (existing first, then new).
    pub existing_keyfiles: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEncryptReq {
    /// Base64 hybrid recipients (advanced public-key mode; may be empty).
    pub recipients: Vec<String>,
    /// Encrypt with a password (simple mode). The passphrase is the FIRST
    /// secret frame when set.
    pub use_password: bool,
    /// KDF for the password (ignored unless use_password).
    pub password_kdf: KdfChoice,
    /// Body AEAD cascade, registry ids, innermost first.
    pub layers: Vec<u16>,
    pub chunk_size: u32,
    /// Sign with the identity passed as the last fd.
    pub sign: bool,
    /// The input fd is a tar archive of a directory (mark it so decrypt
    /// extracts rather than writing a single file). The client tars the
    /// directory and passes the archive fd.
    pub is_archive: bool,
    /// secrets: [0] password (if use_password), then [.] signer identity
    /// passphrase (if sign and sealed).
    /// fds: [0] input, [1] output, [2] signature output (if sign),
    ///      [3] signer identity (if sign).
    pub plaintext_len: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDecryptReq {
    /// Open with a password instead of an identity. The passphrase is the
    /// first secret frame; no identity fd is needed.
    pub use_password: bool,
    /// Verify a detached signature too.
    pub verify: bool,
    /// secrets: [0] password (if use_password) OR identity passphrase.
    /// fds: [0] input, [1] output, then [identity] (unless use_password),
    ///      then [signature] (if verify).
    pub expect_signer_fp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Op {
    /// Handshake; returns agent + protocol versions.
    Hello { version: u32 },
    /// Full agent + volumes status snapshot.
    Status,
    /// Subscribe this connection to event frames.
    Subscribe,
    /// Mix client-collected entropy into the creation pool.
    /// secrets: [0] entropy bytes.
    MixEntropy,
    /// Create a volume. See [`CreateVolumeReq`].
    CreateVolume(CreateVolumeReq),
    /// Unlock + mount. See [`UnlockReq`].
    Unlock(UnlockReq),
    /// Lock + unmount a volume by uuid (hex).
    Lock { uuid: String, force: bool },
    /// Lock everything, wipe all key material, clear caches.
    Panic,
    /// Encrypt an existing plaintext container in place.
    /// fds: [0] container; secrets: [0] new passphrase.
    EncryptInPlace(CreateVolumeReq),
    /// Permanently decrypt in place.
    /// fds: [0] container, [1..] keyfiles; secrets: [0] passphrase.
    DecryptInPlace { pim: u32, credential_kind: String },
    /// Keyslot management. See [`KeyslotChangeReq`].
    ChangeKeyslot(KeyslotChangeReq),
    /// Copy the header region into the fd. fds: [0] container, [1] out.
    HeaderBackup,
    /// Restore a header backup. fds: [0] container, [1] backup.
    /// secrets: [0] passphrase (verifies the backup opens before writing).
    HeaderRestore { pim: u32 },
    /// Throughput/cost benchmark.
    Benchmark { kind: String },
    /// Generate a keyfile. fds: [0] output.
    GenerateKeyfile { length: u32 },
    /// Generate a hybrid identity. fds: [0] output.
    /// secrets: [0] passphrase to seal it (optional: secrets=0 → plain).
    GenerateIdentity,
    /// Show the public half of an identity. fds: [0] identity file.
    IdentityInfo,
    /// Encrypt a file to recipients. See [`FileEncryptReq`].
    FileEncrypt(FileEncryptReq),
    /// Decrypt a file. See [`FileDecryptReq`].
    FileDecrypt(FileDecryptReq),
    /// FIDO2: list authenticators.
    Fido2List,
    /// Get agent-side settings (auto-dismount, cache policy...).
    GetConfig,
    /// Update agent-side settings.
    SetConfig(AgentConfig),
}

/// Agent-side configuration (the GUI keeps its own UI config separately).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentConfig {
    pub dismount_on_lock: bool,
    pub dismount_on_logout: bool,
    pub dismount_on_suspend: bool,
    pub dismount_on_idle: bool,
    pub dismount_on_user_switch: bool,
    pub idle_timeout_secs: u32,
    /// Force unmount (and wipe) even if the filesystem is busy.
    pub force_unmount_on_trigger: bool,
    /// Cache derived credentials for re-mount within a session.
    pub cache_passphrases: bool,
    /// Wipe cache when the last volume unmounts.
    pub wipe_cache_on_dismount: bool,
    /// Preferred data plane: "ublk" | "fuse" | "dmcrypt".
    pub data_plane: String,
    /// External entropy source mixed into the creation pool (path of a file
    /// or fifo, e.g. output of trio-rng). Never replaces the OS CSPRNG.
    pub external_entropy_path: Option<String>,
    /// Log verbosity: "error" | "warn" | "info" | "debug".
    pub log_level: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            dismount_on_lock: true,
            dismount_on_logout: true,
            dismount_on_suspend: true,
            dismount_on_idle: true,
            dismount_on_user_switch: true,
            idle_timeout_secs: 15 * 60,
            force_unmount_on_trigger: true,
            cache_passphrases: false,
            wipe_cache_on_dismount: true,
            data_plane: "fuse".into(),
            external_entropy_path: None,
            log_level: "info".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Responses & events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseEnvelope {
    pub id: u64,
    pub ok: bool,
    /// User-displayable error. Unlock failures are intentionally generic.
    pub error: Option<String>,
    pub data: Option<ResponseData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ResponseData {
    Hello {
        agent_version: String,
        protocol: u32,
        hardened: bool,
    },
    Status(StatusInfo),
    Volume(VolumeInfo),
    Bench(BenchReport),
    Config(AgentConfig),
    Identity {
        public_b64: String,
        fingerprint: String,
        sealed: bool,
    },
    Progress {
        done: u64,
        total: u64,
    },
    Generic {
        message: String,
    },
    /// Result of a file decrypt: tells the client whether the recovered
    /// plaintext is a directory tar it should extract.
    FileDone {
        message: String,
        is_archive: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub agent_version: String,
    pub state_summary: String,
    pub volumes: Vec<VolumeInfo>,
    pub hardware: HardwareInfo,
    pub locked_memory_kib: u64,
    pub entropy_events: u64,
    pub uptime_secs: u64,
    pub sandbox: SandboxInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInfo {
    pub mlockall: bool,
    pub no_new_privs: bool,
    pub dumpable_disabled: bool,
    pub landlock: bool,
    pub seccomp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub aes_ni: bool,
    pub avx2: bool,
    pub sha_ext: bool,
    pub fido2_devices: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub uuid: String,
    pub label: String,
    /// State machine name: LOCKED, UNLOCKING, ACTIVE_MOUNTED...
    pub state: String,
    pub cascade: String,
    pub profile: String,
    pub mount_point: Option<String>,
    pub device: Option<String>,
    pub data_plane: Option<String>,
    pub read_only: bool,
    pub hidden_protection: bool,
    /// Hidden-volume protection tripped (writes were blocked).
    pub protection_triggered: bool,
    pub size_bytes: u64,
    /// Seconds until idle auto-dismount (None = no countdown running).
    pub idle_dismount_in: Option<u64>,
    pub slots: Vec<SlotInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotInfo {
    pub id: u8,
    pub kind: String,
    pub label: String,
    pub kdf: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    pub entries: Vec<BenchEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchEntry {
    pub name: String,
    /// MiB/s for ciphers/hashes; ms/op for KDFs and KEMs.
    pub value: f64,
    pub unit: String,
}

/// Push events for subscribed connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub enum Event {
    VolumeState {
        uuid: String,
        state: String,
        trigger: Option<String>,
    },
    Progress {
        operation: String,
        uuid: Option<String>,
        done: u64,
        total: u64,
    },
    IdleCountdown {
        uuid: String,
        seconds_left: u64,
    },
    PanicFired,
    ProtectionTriggered {
        uuid: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_roundtrip() {
        let h = encode_frame_header(FRAME_CONTROL, 1234);
        let d = decode_frame_header(&h).unwrap();
        assert_eq!(d.kind, FRAME_CONTROL);
        assert_eq!(d.len, 1234);
    }

    #[test]
    fn frame_header_limits() {
        let h = encode_frame_header(FRAME_SECRET, MAX_SECRET_LEN + 1);
        assert!(matches!(
            decode_frame_header(&h),
            Err(FrameError::TooLong { .. })
        ));
        let h2 = encode_frame_header(9, 1);
        assert!(matches!(
            decode_frame_header(&h2),
            Err(FrameError::BadKind(9))
        ));
        assert!(matches!(
            decode_frame_header(&[0, 1]),
            Err(FrameError::Incomplete)
        ));
    }

    #[test]
    fn request_json_roundtrip() {
        let req = RequestEnvelope {
            id: 7,
            secrets: 1,
            fds: 2,
            op: Op::Unlock(UnlockReq {
                options: MountOptions {
                    read_only: true,
                    ..Default::default()
                },
                pim: 0,
                protect_hidden: false,
                credential_kind: "passphrase".into(),
                label_hint: None,
            }),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: RequestEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, 7);
        assert!(matches!(back.op, Op::Unlock(_)));
    }

    #[test]
    fn response_json_roundtrip() {
        let resp = ResponseEnvelope {
            id: 1,
            ok: false,
            error: Some("unlock failed: wrong credentials or corrupted volume".into()),
            data: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: ResponseEnvelope = serde_json::from_str(&json).unwrap();
        assert!(!back.ok);
    }

    /// Malformed JSON must error, not panic (the agent additionally treats
    /// any parse error as a protocol violation and drops the connection).
    #[test]
    fn malformed_control_is_an_error() {
        for bad in [
            "",
            "{",
            "[1,2,3]",
            "{\"id\":\"x\"}",
            "{\"id\":1,\"secrets\":0,\"fds\":0,\"op\":{\"op\":\"nope\"}}",
        ] {
            assert!(serde_json::from_str::<RequestEnvelope>(bad).is_err());
        }
    }
}
