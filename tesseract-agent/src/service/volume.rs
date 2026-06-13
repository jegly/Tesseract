//! Volume lifecycle: create, unlock, lock, emergency wipe.
//!
//! The VMK's only long-lived copy sits in a guard-page `SecretArena`; the
//! cascade engine holds KMAC-derived subkeys (zeroize-on-drop, covered by
//! mlockall + dumpable=0). Unlock failure paths funnel into the single
//! generic `UnlockFailed` error from core — no step information leaks.

use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{anyhow, bail, Context, Result};
use tesseract_core::cascade::{CascadeEngine, CascadeSpec};
use tesseract_core::header::{
    compose_deniable_region, compose_standard_region, hidden_geometry, open_deniable,
    seal_deniable, DeniableInner, Geometry, VolumeHeader, FLAG_EXPERIMENTAL_OK, FLAG_REQUIRE_PQC,
    FORMAT_VERSION,
};
use tesseract_core::kdf::KdfParams;
use tesseract_core::keyfile::{KeyfileDigest, KEYFILE_DIGEST_LEN};
use tesseract_core::keyslot::{seal_slot, Credential, NewSlot, SlotSetup};
use tesseract_core::registry::{AeadId, CipherId, HashId};
use tesseract_core::secret::{Vmk, VMK_LEN};
use tesseract_core::statemachine::{next, Event as SmEvent, State, WipeTrigger};
use tesseract_core::{EntropySource, HEADER_REGION, HIDDEN_HEADER_OFFSET};
use tesseract_proto::{CreateVolumeReq, MountOptions, SlotInfo, UnlockReq, VolumeInfo};
use zbus::zvariant::OwnedObjectPath;

use crate::dataplane::fuse::{self, FuseHandle, VolumePlane};
use crate::os::secmem::{LockedSecret, SecretArena};

pub struct VolumeRuntime {
    pub uuid: [u8; 16],
    pub label: String,
    pub profile: String,
    pub cascade_display: String,
    pub state: State,
    pub size_bytes: u64,
    pub slots: Vec<SlotInfo>,
    pub options: MountOptions,
    pub data_plane: String,
    pub plane: Option<Arc<VolumePlane>>,
    pub fuse: Option<FuseHandle>,
    pub loop_obj: Option<OwnedObjectPath>,
    pub loop_dev: Option<String>,
    pub mount_point: Option<String>,
    vmk: Option<SecretArena>,
    pub protect_hidden: bool,
    pub protection_triggered: Arc<AtomicBool>,
    pub last_activity: Arc<AtomicU64>,
    pub io_error: Arc<AtomicBool>,
    /// Connection that unlocked this volume (subscribed GUIs); EOF -> wipe.
    pub owner_conn: Option<u64>,
}

impl std::fmt::Debug for VolumeRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VolumeRuntime({}, {})",
            hex::encode(self.uuid),
            self.state.name()
        )
    }
}

impl VolumeRuntime {
    pub fn vmk(&self) -> Option<Vmk> {
        self.vmk.as_ref().map(|a| {
            let mut b = [0u8; VMK_LEN];
            b.copy_from_slice(a.as_slice());
            Vmk::from_bytes(b)
        })
    }

    pub fn wipe_secrets(&mut self) {
        if let Some(mut a) = self.vmk.take() {
            a.wipe();
        }
        self.plane = None;
    }

    pub fn info(&self, idle_secs_left: Option<u64>) -> VolumeInfo {
        VolumeInfo {
            uuid: hex::encode(self.uuid),
            label: self.label.clone(),
            state: self.state.name().to_string(),
            cascade: self.cascade_display.clone(),
            profile: self.profile.clone(),
            mount_point: self.mount_point.clone(),
            device: self
                .loop_dev
                .clone()
                .or_else(|| self.fuse.as_ref().map(|f| f.image_path().display().to_string())),
            data_plane: Some(self.data_plane.clone()),
            read_only: self.options.read_only,
            hidden_protection: self.protect_hidden,
            protection_triggered: self.protection_triggered.load(Ordering::SeqCst),
            size_bytes: self.size_bytes,
            idle_dismount_in: idle_secs_left,
            slots: self.slots.clone(),
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Digest keyfiles from fds (the volume hash selects the digest function).
pub fn digest_keyfiles(hash: HashId, fds: &[OwnedFd]) -> Result<Vec<[u8; KEYFILE_DIGEST_LEN]>> {
    let mut out = Vec::with_capacity(fds.len());
    for fd in fds {
        let file = File::from(fd.try_clone().context("dup keyfile fd")?);
        let mut digest = KeyfileDigest::new(hash).map_err(|e| anyhow!("{e}"))?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut off = 0u64;
        loop {
            let n = file.read_at(&mut buf, off)?;
            if n == 0 {
                break;
            }
            digest.update(&buf[..n]);
            off += n as u64;
        }
        out.push(digest.finalize());
    }
    Ok(out)
}

pub fn read_header_region(container: &File, offset: u64) -> Result<Vec<u8>> {
    let mut region = vec![0u8; HEADER_REGION as usize];
    container
        .read_exact_at(&mut region, offset)
        .context("read header region")?;
    Ok(region)
}

pub fn map_kdf_pub(choice: &tesseract_proto::KdfChoice, salt: [u8; 32]) -> Result<KdfParams> {
    map_kdf(choice, salt)
}

fn map_kdf(choice: &tesseract_proto::KdfChoice, salt: [u8; 32]) -> Result<KdfParams> {
    let params = match choice.kdf.as_str() {
        "argon2id" => {
            let base = KdfParams::argon2_default(salt);
            let (m, t, p) = match base {
                KdfParams::Argon2id {
                    m_kib,
                    t_cost,
                    p_cost,
                    ..
                } => (m_kib, t_cost, p_cost),
                _ => unreachable!(),
            };
            KdfParams::Argon2id {
                m_kib: if choice.memory > 0 { choice.memory } else { m },
                t_cost: if choice.time > 0 { choice.time } else { t },
                p_cost: if choice.parallelism > 0 {
                    choice.parallelism
                } else {
                    p
                },
                salt,
            }
            .with_pim(choice.pim)
        }
        "scrypt" => KdfParams::Scrypt {
            log_n: if choice.memory > 0 {
                choice.memory.min(24) as u8
            } else {
                17
            },
            r: 8,
            p: if choice.parallelism > 0 {
                choice.parallelism
            } else {
                1
            },
            salt,
        },
        "pbkdf2" => KdfParams::Pbkdf2 {
            iters: if choice.time > 0 { choice.time } else { 600_000 },
            hash: HashId::Sha512.as_u16(),
            salt,
        },
        "balloon" => KdfParams::Balloon {
            s_cost: if choice.memory > 0 { choice.memory } else { 65536 },
            t_cost: if choice.time > 0 { choice.time } else { 4 },
            salt,
        },
        other => bail!("unknown KDF {other}"),
    };
    params.validate().map_err(|e| anyhow!("{e}"))?;
    Ok(params)
}

/// Run mkfs for `fstype` on the (FUSE-served decrypted) image file.
fn run_mkfs(fstype: &str, image: &std::path::Path, label: &str) -> Result<()> {
    use std::process::Command;
    let img = image.to_string_lossy().to_string();
    let mut cmd = match fstype {
        "ext4" => {
            let mut c = Command::new("mkfs.ext4");
            c.args(["-F", "-q"]);
            if !label.is_empty() {
                c.args(["-L", label]);
            }
            c.arg(&img);
            c
        }
        "btrfs" => {
            let mut c = Command::new("mkfs.btrfs");
            c.arg("-f");
            if !label.is_empty() {
                c.args(["-L", label]);
            }
            c.arg(&img);
            c
        }
        "xfs" => {
            let mut c = Command::new("mkfs.xfs");
            c.arg("-f");
            if !label.is_empty() {
                c.args(["-L", label]);
            }
            c.arg(&img);
            c
        }
        "exfat" => {
            let mut c = Command::new("mkfs.exfat");
            if !label.is_empty() {
                c.args(["-n", label]);
            }
            c.arg(&img);
            c
        }
        "vfat" => {
            let mut c = Command::new("mkfs.vfat");
            if !label.is_empty() {
                c.args(["-n", &label.chars().take(11).collect::<String>()]);
            }
            c.arg(&img);
            c
        }
        other => bail!("unsupported filesystem {other}"),
    };
    let out = cmd
        .output()
        .map_err(|e| anyhow!("could not run mkfs.{fstype}: {e} (is the {fstype} tool installed?)"))?;
    if !out.status.success() {
        bail!(
            "mkfs.{fstype} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Build a temporary FUSE data plane over the container and create a
/// filesystem on the decrypted image, then tear it down.
#[allow(clippy::too_many_arguments)]
fn format_filesystem(
    container: File,
    vmk: &Vmk,
    spec: &CascadeSpec,
    geometry: Geometry,
    sector_size: u32,
    fstype: &str,
    label: &str,
    runtime_dir: &std::path::Path,
    uuid: &[u8; 16],
) -> Result<()> {
    let engine = Arc::new(
        CascadeEngine::new(vmk, spec, sector_size as usize).map_err(|e| anyhow!("{e}"))?,
    );
    let plane = Arc::new(VolumePlane {
        container,
        engine,
        geometry,
        read_only: false,
        protect: None,
        protection_triggered: Arc::new(AtomicBool::new(false)),
        last_activity: Arc::new(AtomicU64::new(now_secs())),
        io_error: Arc::new(AtomicBool::new(false)),
    });
    let mp = runtime_dir.join(format!("fmt-{}", hex::encode(&uuid[..6])));
    let (handle, _loopable) = fuse::mount_auto(plane, &mp).map_err(|e| anyhow!("fuse: {e}"))?;
    let image = handle.image_path();
    std::thread::sleep(std::time::Duration::from_millis(200));
    let result = run_mkfs(fstype, &image, label);
    handle.unmount();
    result
}

/// Create a volume into the container fd. Returns runtime entry (LOCKED).
pub fn create_volume(
    req: &CreateVolumeReq,
    container_fd: OwnedFd,
    keyfile_fds: &[OwnedFd],
    secrets: &[LockedSecret],
    rng: &mut dyn EntropySource,
    runtime_dir: &std::path::Path,
) -> Result<VolumeRuntime> {
    let container = File::from(container_fd);
    let hash = HashId::from_u16(req.hash).map_err(|e| anyhow!("{e}"))?;
    let cascade_ids = req
        .cascade
        .iter()
        .map(|v| CipherId::from_u16(*v))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("{e}"))?;
    let spec = CascadeSpec::new(&cascade_ids).map_err(|e| anyhow!("{e}"))?;
    spec.validate(req.experimental_ok).map_err(|e| anyhow!("{e}"))?;
    let slot_aead = AeadId::from_u16(req.slot_aead).map_err(|e| anyhow!("{e}"))?;
    let geometry = Geometry::standard(req.size_bytes, req.sector_size).map_err(|e| anyhow!("{e}"))?;

    if secrets.is_empty() {
        bail!("missing passphrase secret");
    }
    let hidden_kf = req.hidden_keyfiles as usize;
    if hidden_kf > keyfile_fds.len() {
        bail!("hidden keyfile count exceeds supplied keyfiles");
    }
    let (outer_kf_fds, hidden_kf_fds) =
        keyfile_fds.split_at(keyfile_fds.len() - hidden_kf);
    let outer_keyfiles = digest_keyfiles(hash, outer_kf_fds)?;
    let hidden_keyfiles = digest_keyfiles(hash, hidden_kf_fds)?;

    // size the file
    container.set_len(req.size_bytes).context("set container size")?;
    if req.full_format {
        // overwrite the data area with random
        let mut buf = vec![0u8; 1024 * 1024];
        let mut off = geometry.data_offset;
        let end = geometry.data_offset + geometry.data_len;
        while off < end {
            let n = buf.len().min((end - off) as usize);
            rng.fill(&mut buf[..n]);
            container.write_all_at(&buf[..n], off)?;
            off += n as u64;
        }
    }

    let mut uuid = [0u8; 16];
    rng.fill(&mut uuid);
    let vmk = Vmk::generate(rng);

    let (region, label) = match req.profile.as_str() {
        "standard" => {
            if req.hidden_size > 0 {
                bail!("hidden volumes require the deniable profile");
            }
            let mut flags = 0u32;
            if req.require_pqc {
                flags |= FLAG_REQUIRE_PQC;
            }
            if req.experimental_ok {
                flags |= FLAG_EXPERIMENTAL_OK;
            }
            let mut header = VolumeHeader {
                version: FORMAT_VERSION,
                uuid,
                label: req.label.clone(),
                created_at: now_secs(),
                geometry,
                cascade: spec.clone(),
                hash: req.hash,
                flags,
                slots: vec![],
                header_mac: [0; 32],
                attest: vec![],
                attest_require_all: false,
            };
            let binding = header.essentials_digest();
            let mut salt = [0u8; 32];
            rng.fill(&mut salt);
            let slot = seal_slot(
                rng,
                &vmk,
                NewSlot {
                    id: 0,
                    aead: slot_aead,
                    label: "passphrase".into(),
                    created_at: now_secs(),
                    kdf: Some(map_kdf(&req.kdf, salt)?),
                    setup: SlotSetup::Passphrase {
                        passphrase: secrets[0].as_slice(),
                        keyfiles: &outer_keyfiles,
                    },
                },
                &binding,
            )
            .map_err(|e| anyhow!("{e}"))?;
            header.slots.push(slot);

            if let Some(recipient_b64) = &req.pqc_recipient {
                use base64::Engine;
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(recipient_b64)
                    .context("recipient base64")?;
                let recipient: tesseract_core::kem::HybridRecipient =
                    minicbor::decode(&bytes).map_err(|e| anyhow!("recipient cbor: {e}"))?;
                let slot = seal_slot(
                    rng,
                    &vmk,
                    NewSlot {
                        id: 1,
                        aead: slot_aead,
                        label: "hybrid-pqc".into(),
                        created_at: now_secs(),
                        kdf: None,
                        setup: SlotSetup::Hybrid(&recipient),
                    },
                    &binding,
                )
                .map_err(|e| anyhow!("{e}"))?;
                header.slots.push(slot);
            } else if req.require_pqc {
                bail!("require_pqc set but no PQC recipient supplied");
            }

            header.update_mac(&vmk);
            header.validate().map_err(|e| anyhow!("{e}"))?;
            let bytes = header.to_bytes().map_err(|e| anyhow!("{e}"))?;
            (
                compose_standard_region(&bytes).map_err(|e| anyhow!("{e}"))?,
                req.label.clone(),
            )
        }
        "deniable" => {
            let mut flags = 0u32;
            if req.experimental_ok {
                flags |= FLAG_EXPERIMENTAL_OK;
            }
            let inner = DeniableInner {
                version: FORMAT_VERSION,
                uuid,
                vmk: *vmk.as_bytes(),
                geometry,
                cascade: spec.clone(),
                hash: req.hash,
                flags,
                is_hidden: false,
            };
            let outer_blob = seal_deniable(
                rng,
                &inner,
                secrets[0].as_slice(),
                &outer_keyfiles,
                req.kdf.pim,
            )
            .map_err(|e| anyhow!("{e}"))?;

            let hidden_blob = if req.hidden_size > 0 {
                if secrets.len() < 2 {
                    bail!("hidden volume requires a second passphrase");
                }
                let hgeo = hidden_geometry(&geometry, req.hidden_size)
                    .map_err(|e| anyhow!("{e}"))?;
                let mut huuid = [0u8; 16];
                rng.fill(&mut huuid);
                let hvmk = Vmk::generate(rng);
                let hinner = DeniableInner {
                    version: FORMAT_VERSION,
                    uuid: huuid,
                    vmk: *hvmk.as_bytes(),
                    geometry: hgeo,
                    cascade: spec.clone(),
                    hash: req.hash,
                    flags,
                    is_hidden: true,
                };
                Some(
                    seal_deniable(
                        rng,
                        &hinner,
                        secrets[1].as_slice(),
                        &hidden_keyfiles,
                        req.kdf.pim,
                    )
                    .map_err(|e| anyhow!("{e}"))?,
                )
            } else {
                None
            };
            (
                compose_deniable_region(rng, &outer_blob, hidden_blob.as_deref())
                    .map_err(|e| anyhow!("{e}"))?,
                String::new(), // deniable volumes carry no plaintext label
            )
        }
        other => bail!("unknown profile {other}"),
    };

    container.write_all_at(&region, 0)?;
    // backup header region at the tail (deniable: fresh random fill around
    // the same blobs would be ideal; identical copy is the VeraCrypt model)
    container.write_all_at(&region, geometry.backup_offset())?;
    container.sync_all()?;

    // Create the requested filesystem on the decrypted data area so the
    // volume is usable as a drive immediately after mounting. Without this a
    // freshly created volume mounts to an unformatted (empty) device and
    // shows nothing. mkfs runs against the FUSE-served decrypted image; its
    // writes flow through the cascade engine into the container.
    if req.filesystem != "none" {
        format_filesystem(
            container,
            &vmk,
            &spec,
            geometry,
            req.sector_size,
            &req.filesystem,
            &label,
            runtime_dir,
            &uuid,
        )
        .map_err(|e| anyhow!("create filesystem: {e}"))?;
    }

    Ok(VolumeRuntime {
        uuid,
        label,
        profile: req.profile.clone(),
        cascade_display: spec.display(),
        state: next(State::Uninitialized, SmEvent::Initialized).unwrap(),
        size_bytes: req.size_bytes,
        slots: vec![],
        options: MountOptions::default(),
        data_plane: "fuse".into(),
        plane: None,
        fuse: None,
        loop_obj: None,
        loop_dev: None,
        mount_point: None,
        vmk: None,
        protect_hidden: false,
        protection_triggered: Arc::new(AtomicBool::new(false)),
        last_activity: Arc::new(AtomicU64::new(now_secs())),
        io_error: Arc::new(AtomicBool::new(false)),
        owner_conn: None,
    })
}

/// Everything needed to unlock, parsed off the container.
pub struct UnlockedHeader {
    pub uuid: [u8; 16],
    pub label: String,
    pub profile: String,
    pub geometry: Geometry,
    pub cascade: CascadeSpec,
    pub vmk: Vmk,
    pub slots: Vec<SlotInfo>,
    pub is_hidden: bool,
}

impl std::fmt::Debug for UnlockedHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UnlockedHeader({})", hex::encode(self.uuid))
    }
}

/// Build an `UnlockedHeader` from a standard-profile header + recovered VMK.
fn build_unlocked_std(header: &VolumeHeader, vmk: Vmk, is_hidden: bool) -> UnlockedHeader {
    UnlockedHeader {
        uuid: header.uuid,
        label: header.label.clone(),
        profile: "standard".into(),
        geometry: header.geometry,
        cascade: header.cascade.clone(),
        vmk,
        slots: header
            .slots
            .iter()
            .map(|s| SlotInfo {
                id: s.id,
                kind: s.kind_label().to_string(),
                label: s.label.clone(),
                kdf: s
                    .kdf
                    .as_ref()
                    .map(|k| k.id().label().to_string())
                    .unwrap_or_else(|| "KEM".into()),
                created_at: s.created_at,
            })
            .collect(),
        is_hidden,
    }
}

/// Try to unlock a container with the given credentials. Order: standard
/// header, deniable outer, deniable hidden; then the same against the backup
/// region. Returns the generic unlock error on total failure.
pub fn try_unlock(
    container: &File,
    req: &UnlockReq,
    keyfile_fds: &[OwnedFd],
    secrets: &[LockedSecret],
) -> Result<UnlockedHeader> {
    let total_len = container.metadata()?.len();
    if total_len < 2 * HEADER_REGION {
        bail!("not a tesseract container (too small)");
    }
    let passphrase = secrets
        .first()
        .map(|s| s.as_slice())
        .ok_or_else(|| anyhow!("missing credential secret"))?;

    let identity = if req.credential_kind == "identity" {
        let id_fd = keyfile_fds
            .last()
            .ok_or_else(|| anyhow!("identity credential needs an identity fd"))?;
        let f = File::from(id_fd.try_clone()?);
        let mut bytes = Vec::new();
        let mut off = 0u64;
        let mut buf = vec![0u8; 4096];
        loop {
            let n = f.read_at(&mut buf, off)?;
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..n]);
            off += n as u64;
            if bytes.len() > 64 * 1024 {
                bail!("identity file too large");
            }
        }
        let pass = if tesseract_core::kem::identity_is_sealed(&bytes).map_err(|e| anyhow!("{e}"))? {
            Some(passphrase)
        } else {
            None
        };
        Some(
            tesseract_core::kem::open_identity(&bytes, pass)
                .map_err(|_| anyhow!("{}", tesseract_core::Error::UnlockFailed))?,
        )
    } else {
        None
    };

    let kf_for_digest: &[OwnedFd] = if req.credential_kind == "identity" {
        &keyfile_fds[..keyfile_fds.len().saturating_sub(1)]
    } else {
        keyfile_fds
    };

    for base in [0u64, total_len - HEADER_REGION] {
        let Ok(region) = read_header_region(container, base) else {
            continue;
        };
        // 1) standard header
        if let Ok(header) = VolumeHeader::from_bytes(&region) {
            // FIDO2 / security-key unlock: perform a CTAP2 assertion for each
            // enrolled security-key slot (the user touches the key), derive
            // the KEK, and open the slot.
            #[cfg(feature = "fido2")]
            if req.credential_kind == "fido2" {
                use tesseract_core::keyslot::{open_slot, Credential, SlotKind};
                let binding = header.essentials_digest();
                let pin = (!passphrase.is_empty())
                    .then(|| String::from_utf8_lossy(passphrase).into_owned());
                for slot in &header.slots {
                    if let SlotKind::Fido2(meta) = &slot.kind {
                        let Ok(hmac_out) = super::fido2::hmac_secret(
                            &meta.credential_id,
                            &meta.hmac_salt,
                            pin.as_deref(),
                        ) else {
                            continue;
                        };
                        let cred = Credential::Fido2 {
                            hmac_output: &hmac_out,
                            passphrase: None,
                        };
                        if let Ok(vmk) = open_slot(slot, &cred, &binding) {
                            if header.verify_mac(&vmk).is_ok() {
                                return Ok(build_unlocked_std(&header, vmk, false));
                            }
                        }
                    }
                }
                continue;
            }
            let keyfiles = digest_keyfiles(header.hash_id().map_err(|e| anyhow!("{e}"))?, kf_for_digest)?;
            let cred = match (&identity, req.credential_kind.as_str()) {
                (Some(id), _) => Credential::Hybrid(id),
                (None, "keyfile") => Credential::Keyfiles(&keyfiles),
                _ => Credential::Passphrase {
                    passphrase,
                    keyfiles: &keyfiles,
                },
            };
            if let Ok((vmk, _slot)) = header.unlock(&cred) {
                return Ok(build_unlocked_std(&header, vmk, false));
            }
            continue; // standard volume, wrong creds: don't try deniable parse
        }
        // 2) deniable: keyfiles digested with BLAKE3 by convention
        let keyfiles = digest_keyfiles(HashId::Blake3, kf_for_digest)?;
        for (off, hidden) in [(0u64, false), (HIDDEN_HEADER_OFFSET, true)] {
            let blob = &region[off as usize..off as usize + tesseract_core::DENIABLE_BLOB_LEN];
            if let Ok(inner) = open_deniable(blob, passphrase, &keyfiles, req.pim) {
                return Ok(UnlockedHeader {
                    uuid: inner.uuid,
                    label: String::new(),
                    profile: "deniable".into(),
                    geometry: inner.geometry,
                    cascade: inner.cascade.clone(),
                    vmk: Vmk::from_bytes(inner.vmk),
                    slots: vec![],
                    is_hidden: hidden,
                });
            }
        }
    }
    Err(anyhow!("{}", tesseract_core::Error::UnlockFailed))
}

/// Open the hidden header for protection mode (outer mount with hidden
/// passphrase supplied as secrets[1]).
pub fn open_hidden_for_protection(
    container: &File,
    secrets: &[LockedSecret],
    keyfile_fds: &[OwnedFd],
    pim: u32,
) -> Result<(u64, u64)> {
    if secrets.len() < 2 {
        bail!("hidden protection requires the hidden passphrase");
    }
    let region = read_header_region(container, 0)?;
    let keyfiles = digest_keyfiles(HashId::Blake3, keyfile_fds)?;
    let blob = &region[HIDDEN_HEADER_OFFSET as usize
        ..HIDDEN_HEADER_OFFSET as usize + tesseract_core::DENIABLE_BLOB_LEN];
    let inner = open_deniable(blob, secrets[1].as_slice(), &keyfiles, pim)
        .map_err(|_| anyhow!("{}", tesseract_core::Error::UnlockFailed))?;
    Ok((inner.geometry.data_offset, inner.geometry.data_offset + inner.geometry.data_len))
}

/// Build the runtime for an unlocked volume (engine + plane, no mounts yet).
pub fn build_runtime(
    container: File,
    unlocked: UnlockedHeader,
    req: &UnlockReq,
    protect: Option<(u64, u64)>,
    owner_conn: Option<u64>,
) -> Result<VolumeRuntime> {
    let engine = Arc::new(
        CascadeEngine::new(&unlocked.vmk, &unlocked.cascade, unlocked.geometry.sector_size as usize)
            .map_err(|e| anyhow!("{e}"))?,
    );
    let mut vmk_arena = SecretArena::new(VMK_LEN)?;
    vmk_arena.copy_from(unlocked.vmk.as_bytes());

    // protection range relative to the data area
    let protect_rel = protect.map(|(s, e)| {
        (
            s.saturating_sub(unlocked.geometry.data_offset),
            e.saturating_sub(unlocked.geometry.data_offset),
        )
    });

    let protection_triggered = Arc::new(AtomicBool::new(false));
    let last_activity = Arc::new(AtomicU64::new(now_secs()));
    let io_error = Arc::new(AtomicBool::new(false));

    let plane = Arc::new(VolumePlane {
        container,
        engine,
        geometry: unlocked.geometry,
        read_only: req.options.read_only,
        protect: protect_rel,
        protection_triggered: protection_triggered.clone(),
        last_activity: last_activity.clone(),
        io_error: io_error.clone(),
    });

    Ok(VolumeRuntime {
        uuid: unlocked.uuid,
        label: unlocked.label,
        profile: unlocked.profile,
        cascade_display: unlocked.cascade.display(),
        state: State::Unlocking,
        size_bytes: unlocked.geometry.total_len,
        slots: unlocked.slots,
        options: req.options.clone(),
        data_plane: req
            .options
            .data_plane
            .clone()
            .unwrap_or_else(|| "fuse".into()),
        plane: Some(plane),
        fuse: None,
        loop_obj: None,
        loop_dev: None,
        mount_point: None,
        vmk: Some(vmk_arena),
        protect_hidden: protect.is_some(),
        protection_triggered,
        last_activity,
        io_error,
        owner_conn,
    })
}

/// Tear down mounts + wipe key material. Returns clean/dirty.
pub fn teardown(
    vol: &mut VolumeRuntime,
    udisks: Option<&crate::dataplane::udisks::Udisks>,
    force: bool,
    trigger: Option<WipeTrigger>,
) -> bool {
    let mut clean = true;
    if let (Some(u), Some(obj)) = (udisks, vol.loop_obj.take()) {
        if vol.mount_point.is_some() {
            if let Err(e) = u.unmount(&obj, force) {
                log::warn!("unmount failed: {e}");
                clean = false;
            }
        }
        if let Err(e) = u.loop_delete(&obj) {
            log::warn!("loop delete failed: {e}");
            clean = false;
        }
    }
    vol.loop_dev = None;
    vol.mount_point = None;
    if let Some(fuse) = vol.fuse.take() {
        fuse.unmount();
    }
    vol.wipe_secrets();
    vol.state = if trigger.is_some() {
        State::Locked
    } else {
        next(vol.state, SmEvent::UnmountDone).unwrap_or(State::Locked)
    };
    clean
}
