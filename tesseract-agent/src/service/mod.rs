//! Agent service: state, request dispatch, events, emergency wipe.

pub mod benchmark;
pub mod fido2;
pub mod fileops;
pub mod inplace_io;
pub mod volume;

use std::collections::HashMap;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{anyhow, bail, Result};
use tesseract_core::entropy::EntropyPool;
use tesseract_core::statemachine::{next, Event as SmEvent, State, WipeTrigger};
use tesseract_core::HEADER_REGION;
use tesseract_proto::{
    AgentConfig, Event, Op, RequestEnvelope, ResponseData, ResponseEnvelope, StatusInfo,
};

use crate::dataplane::fuse;
use crate::dataplane::udisks::Udisks;
use crate::ipc::push_event;
use crate::os::secmem::{locked_bytes, LockedSecret};
use volume::VolumeRuntime;

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub struct Agent {
    pub volumes: Mutex<HashMap<[u8; 16], VolumeRuntime>>,
    pub config: Mutex<AgentConfig>,
    pub pool: Mutex<EntropyPool>,
    pub subscribers: Mutex<Vec<(u64, UnixStream)>>,
    pub started: Instant,
    pub runtime_dir: std::path::PathBuf,
    pub state_dir: std::path::PathBuf,
    udisks: Mutex<Option<Udisks>>,
}

impl Agent {
    pub fn new(runtime_dir: std::path::PathBuf, state_dir: std::path::PathBuf) -> Arc<Self> {
        let config = Self::load_config(&state_dir);
        Arc::new(Self {
            volumes: Mutex::new(HashMap::new()),
            config: Mutex::new(config),
            pool: Mutex::new(EntropyPool::new()),
            subscribers: Mutex::new(Vec::new()),
            started: Instant::now(),
            runtime_dir,
            state_dir,
            udisks: Mutex::new(None),
        })
    }

    fn load_config(state_dir: &std::path::Path) -> AgentConfig {
        let path = state_dir.join("agent.json");
        std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save_config(&self) {
        let cfg = self.config.lock().unwrap().clone();
        let path = self.state_dir.join("agent.json");
        if let Ok(json) = serde_json::to_vec_pretty(&cfg) {
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, &json).is_ok() {
                std::fs::rename(&tmp, &path).ok();
            }
        }
    }

    /// OS CSPRNG XOR entropy-pool stream — the only randomness source used
    /// for key material. Mix-only: at least as strong as getrandom alone.
    pub fn rng(&self) -> impl FnMut(&mut [u8]) + '_ {
        move |buf: &mut [u8]| {
            getrandom::getrandom(buf).expect("getrandom");
            let mut pool_bytes = vec![0u8; buf.len()];
            self.pool.lock().unwrap().extract(&mut pool_bytes);
            for (b, p) in buf.iter_mut().zip(pool_bytes.iter()) {
                *b ^= p;
            }
        }
    }

    fn mix_external_entropy(&self) {
        let path = self.config.lock().unwrap().external_entropy_path.clone();
        if let Some(p) = path {
            match std::fs::File::open(&p) {
                Ok(f) => {
                    use std::io::Read;
                    let mut buf = vec![0u8; 4096];
                    let mut take = f.take(64 * 1024);
                    let mut total = 0;
                    while let Ok(n) = take.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        self.pool.lock().unwrap().mix(&buf[..n]);
                        total += n;
                    }
                    log::info!("mixed {total} bytes of external entropy from {p}");
                }
                Err(e) => log::warn!("external entropy source {p}: {e}"),
            }
        }
    }

    fn udisks(&self) -> Option<Udisks> {
        let mut guard = self.udisks.lock().unwrap();
        if guard.is_none() {
            match Udisks::connect() {
                Ok(u) => *guard = Some(u),
                Err(e) => {
                    log::warn!("udisks unavailable: {e}");
                    return None;
                }
            }
        }
        // Udisks holds a zbus Connection which is cheaply clonable inside;
        // we reconnect per use to keep this simple and robust.
        guard.take()
    }

    fn put_udisks(&self, u: Udisks) {
        *self.udisks.lock().unwrap() = Some(u);
    }

    pub fn broadcast(&self, event: &Event) {
        let mut subs = self.subscribers.lock().unwrap();
        subs.retain_mut(|(_, stream)| push_event(stream, event));
    }

    /// EmergencyWipe across volumes for `trigger`, honoring config flags.
    pub fn emergency_wipe(&self, trigger: WipeTrigger, only_conn: Option<u64>) {
        let cfg = self.config.lock().unwrap().clone();
        let enabled = match trigger {
            WipeTrigger::SessionLock => cfg.dismount_on_lock,
            WipeTrigger::Logout => cfg.dismount_on_logout,
            WipeTrigger::PrepareForSleep => cfg.dismount_on_suspend,
            WipeTrigger::IdleTimeout => cfg.dismount_on_idle,
            WipeTrigger::FastUserSwitch => cfg.dismount_on_user_switch,
            // panic, tamper, socket EOF are not configurable
            _ => true,
        };
        if !enabled {
            return;
        }
        let udisks = self.udisks();
        let mut volumes = self.volumes.lock().unwrap();
        for vol in volumes.values_mut() {
            if let Some(conn) = only_conn {
                if vol.owner_conn != Some(conn) {
                    continue;
                }
            }
            if matches!(vol.state, State::Locked | State::Uninitialized) {
                continue;
            }
            log::warn!(
                "EmergencyWipe({}) on volume {}",
                trigger.name(),
                hex::encode(vol.uuid)
            );
            vol.state = next(vol.state, SmEvent::Wipe(trigger)).unwrap_or(State::EmergencyWiping);
            volume::teardown(vol, udisks.as_ref(), cfg.force_unmount_on_trigger, Some(trigger));
            vol.state = State::Locked;
            self.broadcast(&Event::VolumeState {
                uuid: hex::encode(vol.uuid),
                state: vol.state.name().into(),
                trigger: Some(trigger.name().into()),
            });
        }
        if let Some(u) = udisks {
            self.put_udisks(u);
        }
        if matches!(trigger, WipeTrigger::Panic) {
            self.broadcast(&Event::PanicFired);
        }
    }

    /// Idle scan: returns seconds left per active volume, fires wipes.
    pub fn idle_tick(&self) {
        let cfg = self.config.lock().unwrap().clone();
        if !cfg.dismount_on_idle {
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut to_wipe = false;
        {
            let volumes = self.volumes.lock().unwrap();
            for vol in volumes.values() {
                if vol.state != State::ActiveMounted {
                    continue;
                }
                let last = vol.last_activity.load(Ordering::Relaxed);
                let idle = now.saturating_sub(last);
                let left = (cfg.idle_timeout_secs as u64).saturating_sub(idle);
                if left == 0 {
                    to_wipe = true;
                } else if left <= 60 {
                    self.broadcast(&Event::IdleCountdown {
                        uuid: hex::encode(vol.uuid),
                        seconds_left: left,
                    });
                }
                // tamper check piggybacks on the tick
                if vol.io_error.load(Ordering::SeqCst) {
                    log::error!("container IO error on {} — tamper wipe", hex::encode(vol.uuid));
                    to_wipe = true;
                }
                if vol.protection_triggered.load(Ordering::SeqCst) {
                    self.broadcast(&Event::ProtectionTriggered {
                        uuid: hex::encode(vol.uuid),
                    });
                }
            }
        }
        if to_wipe {
            self.emergency_wipe(WipeTrigger::IdleTimeout, None);
        }
    }

    pub fn connection_closed(&self, conn_id: u64) {
        self.subscribers
            .lock()
            .unwrap()
            .retain(|(id, _)| *id != conn_id);
        let owned: bool = self
            .volumes
            .lock()
            .unwrap()
            .values()
            .any(|v| v.owner_conn == Some(conn_id) && v.state == State::ActiveMounted);
        if owned {
            log::warn!("owning connection {conn_id} EOF — wiping its volumes");
            self.emergency_wipe(WipeTrigger::SocketEof, Some(conn_id));
        }
    }

    fn status(&self) -> StatusInfo {
        let cfg = self.config.lock().unwrap().clone();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let volumes = self.volumes.lock().unwrap();
        let infos: Vec<_> = volumes
            .values()
            .map(|v| {
                let left = if v.state == State::ActiveMounted && cfg.dismount_on_idle {
                    let last = v.last_activity.load(Ordering::Relaxed);
                    Some((cfg.idle_timeout_secs as u64).saturating_sub(now.saturating_sub(last)))
                } else {
                    None
                };
                v.info(left)
            })
            .collect();
        StatusInfo {
            agent_version: AGENT_VERSION.into(),
            state_summary: format!(
                "{} volume(s), {} mounted",
                infos.len(),
                infos.iter().filter(|v| v.state == "ACTIVE_MOUNTED").count()
            ),
            volumes: infos,
            hardware: benchmark::hardware_info(),
            locked_memory_kib: locked_bytes() / 1024,
            entropy_events: self.pool.lock().unwrap().events(),
            uptime_secs: self.started.elapsed().as_secs(),
            sandbox: crate::os::harden::sandbox_info(),
        }
    }

    fn unlock(
        &self,
        req: &tesseract_proto::UnlockReq,
        fds: &[OwnedFd],
        secrets: &[LockedSecret],
        conn_id: u64,
        subscribed: bool,
    ) -> Result<ResponseData> {
        if fds.is_empty() {
            bail!("unlock needs the container fd");
        }
        let container = File::from(fds[0].try_clone()?);
        let keyfile_fds = &fds[1..];

        let unlocked = volume::try_unlock(&container, req, keyfile_fds, secrets)?;
        let uuid = unlocked.uuid;
        {
            let volumes = self.volumes.lock().unwrap();
            if let Some(v) = volumes.get(&uuid) {
                if v.state == State::ActiveMounted {
                    bail!("volume already mounted at {:?}", v.mount_point);
                }
            }
        }

        let protect = if req.protect_hidden && !unlocked.is_hidden {
            Some(volume::open_hidden_for_protection(
                &container,
                secrets,
                if req.credential_kind == "identity" {
                    &keyfile_fds[..keyfile_fds.len().saturating_sub(1)]
                } else {
                    keyfile_fds
                },
                req.pim,
            )?)
        } else {
            None
        };

        let owner = subscribed.then_some(conn_id);
        let mut vol = volume::build_runtime(container, unlocked, req, protect, owner)?;

        // FUSE plane
        let mountpoint = self
            .runtime_dir
            .join(format!("vol-{}", hex::encode(&uuid[..8])));
        let plane = vol.plane.clone().expect("plane built");
        let (handle, loopable) = fuse::mount_auto(plane, &mountpoint)?;
        let image = handle.image_path();
        vol.fuse = Some(handle);

        // loop + filesystem mount through udisks (best effort)
        if loopable && vol.data_plane != "none" {
            if let Some(u) = self.udisks() {
                match std::fs::File::open(&image) {
                    Ok(img) => match u.loop_setup(OwnedFd::from(img), req.options.read_only) {
                        Ok(lh) => {
                            vol.loop_dev = Some(lh.device.clone());
                            match u.mount(&lh.object, req.options.read_only) {
                                Ok(mp) => vol.mount_point = Some(mp),
                                Err(e) => log::warn!("udisks mount: {e} (filesystem may need formatting)"),
                            }
                            vol.loop_obj = Some(lh.object);
                        }
                        Err(e) => log::warn!("udisks loop-setup: {e}; image stays in file-access mode"),
                    },
                    Err(e) => log::warn!("open image: {e}"),
                }
                self.put_udisks(u);
            }
        }

        vol.state = next(State::Unlocking, SmEvent::UnlockSucceeded).unwrap();
        let info = vol.info(None);
        self.volumes.lock().unwrap().insert(uuid, vol);
        self.broadcast(&Event::VolumeState {
            uuid: hex::encode(uuid),
            state: "ACTIVE_MOUNTED".into(),
            trigger: None,
        });
        Ok(ResponseData::Volume(info))
    }

    fn lock(&self, uuid_hex: &str, force: bool) -> Result<ResponseData> {
        let uuid: [u8; 16] = hex::decode(uuid_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| anyhow!("bad uuid"))?;
        let udisks = self.udisks();
        let mut volumes = self.volumes.lock().unwrap();
        let vol = volumes
            .get_mut(&uuid)
            .ok_or_else(|| anyhow!("unknown volume"))?;
        if vol.state != State::ActiveMounted {
            bail!("volume is not mounted");
        }
        vol.state = next(vol.state, SmEvent::LockRequested).unwrap();
        let clean = volume::teardown(vol, udisks.as_ref(), force, None);
        if let Some(u) = udisks {
            self.put_udisks(u);
        }
        if !clean && !force {
            bail!("unmount incomplete (busy?); retry with force");
        }
        let info = vol.info(None);
        self.broadcast(&Event::VolumeState {
            uuid: uuid_hex.into(),
            state: "LOCKED".into(),
            trigger: None,
        });
        Ok(ResponseData::Volume(info))
    }

    fn header_backup(&self, fds: &[OwnedFd]) -> Result<ResponseData> {
        if fds.len() < 2 {
            bail!("header-backup needs container and output fds");
        }
        let container = File::from(fds[0].try_clone()?);
        let out = File::from(fds[1].try_clone()?);
        let region = volume::read_header_region(&container, 0)?;
        out.write_all_at(&region, 0)?;
        out.sync_all()?;
        Ok(ResponseData::Generic {
            message: format!("backed up {} KiB header region", HEADER_REGION / 1024),
        })
    }

    fn header_restore(
        &self,
        pim: u32,
        fds: &[OwnedFd],
        secrets: &[LockedSecret],
    ) -> Result<ResponseData> {
        if fds.len() < 2 {
            bail!("header-restore needs container and backup fds");
        }
        let container = File::from(fds[0].try_clone()?);
        let backup = File::from(fds[1].try_clone()?);
        let mut region = vec![0u8; HEADER_REGION as usize];
        backup.read_exact_at(&mut region, 0)?;

        // the backup must open with the supplied credentials before we
        // overwrite anything
        let passphrase = secrets
            .first()
            .map(|s| s.as_slice())
            .ok_or_else(|| anyhow!("missing passphrase"))?;
        let standard = tesseract_core::header::VolumeHeader::from_bytes(&region);
        let opens = match &standard {
            Ok(h) => h
                .unlock(&tesseract_core::keyslot::Credential::Passphrase {
                    passphrase,
                    keyfiles: &[],
                })
                .is_ok(),
            Err(_) => {
                let blob = &region[..tesseract_core::DENIABLE_BLOB_LEN];
                tesseract_core::header::open_deniable(blob, passphrase, &[], pim).is_ok()
            }
        };
        if !opens {
            bail!("{}", tesseract_core::Error::UnlockFailed);
        }
        container.write_all_at(&region, 0)?;
        // refresh the tail backup too when geometry is known
        if let Ok(h) = standard {
            container.write_all_at(&region, h.geometry.backup_offset())?;
        }
        container.sync_all()?;
        Ok(ResponseData::Generic {
            message: "header restored".into(),
        })
    }

    /// Top-level dispatch (one request).
    pub fn handle(
        self: &Arc<Self>,
        req: RequestEnvelope,
        fds: Vec<OwnedFd>,
        secrets: Vec<LockedSecret>,
        conn_id: u64,
        stream: &UnixStream,
        subscribed: &mut bool,
    ) -> ResponseEnvelope {
        let id = req.id;
        let result: Result<Option<ResponseData>> = (|| {
            match req.op {
                Op::Hello { version } => {
                    if version != tesseract_proto::PROTOCOL_VERSION {
                        bail!("protocol mismatch: agent {} / client {version}", tesseract_proto::PROTOCOL_VERSION);
                    }
                    Ok(Some(ResponseData::Hello {
                        agent_version: AGENT_VERSION.into(),
                        protocol: tesseract_proto::PROTOCOL_VERSION,
                        hardened: crate::os::harden::sandbox_info().seccomp,
                    }))
                }
                Op::Status => Ok(Some(ResponseData::Status(self.status()))),
                Op::Subscribe => {
                    *subscribed = true;
                    self.subscribers
                        .lock()
                        .unwrap()
                        .push((conn_id, stream.try_clone()?));
                    Ok(None)
                }
                Op::MixEntropy => {
                    if let Some(s) = secrets.first() {
                        self.pool.lock().unwrap().mix(s.as_slice());
                    }
                    Ok(None)
                }
                Op::CreateVolume(ref create) => {
                    self.mix_external_entropy();
                    if fds.is_empty() {
                        bail!("create needs the container fd");
                    }
                    let mut fds = fds;
                    let container = fds.remove(0);
                    let mut rng = self.rng();
                    let vol = volume::create_volume(
                        create,
                        container,
                        &fds,
                        &secrets,
                        &mut rng,
                        &self.runtime_dir,
                    )?;
                    let uuid = vol.uuid;
                    let info = vol.info(None);
                    self.volumes.lock().unwrap().insert(uuid, vol);
                    Ok(Some(ResponseData::Volume(info)))
                }
                Op::Unlock(ref unlock_req) => self
                    .unlock(unlock_req, &fds, &secrets, conn_id, *subscribed)
                    .map(Some),
                Op::Lock { ref uuid, force } => self.lock(uuid, force).map(Some),
                Op::Panic => {
                    self.emergency_wipe(WipeTrigger::Panic, None);
                    Ok(Some(ResponseData::Generic {
                        message: "panic: all volumes locked, key material wiped".into(),
                    }))
                }
                Op::EncryptInPlace(ref create) => {
                    self.mix_external_entropy();
                    let mut rng = self.rng();
                    crate::service::convert::encrypt_in_place(self, create, &fds, &secrets, &mut rng)
                        .map(Some)
                }
                Op::DecryptInPlace { pim, ref credential_kind } => {
                    crate::service::convert::decrypt_in_place(self, pim, credential_kind, &fds, &secrets)
                        .map(Some)
                }
                Op::ChangeKeyslot(ref change) => {
                    let mut rng = self.rng();
                    crate::service::keyslots::change(change, &fds, &secrets, &mut rng).map(Some)
                }
                Op::HeaderBackup => self.header_backup(&fds).map(Some),
                Op::HeaderRestore { pim } => self.header_restore(pim, &fds, &secrets).map(Some),
                Op::Benchmark { ref kind } => {
                    Ok(Some(ResponseData::Bench(benchmark::run(kind))))
                }
                Op::GenerateKeyfile { length } => {
                    let mut rng = self.rng();
                    fileops::generate_keyfile(length, &fds, &mut rng)
                        .map(|m| Some(ResponseData::Generic { message: m }))
                }
                Op::GenerateIdentity => {
                    self.mix_external_entropy();
                    let mut rng = self.rng();
                    fileops::generate_identity(&fds, &secrets, &mut rng).map(
                        |(public_b64, fingerprint, sealed)| {
                            Some(ResponseData::Identity {
                                public_b64,
                                fingerprint,
                                sealed,
                            })
                        },
                    )
                }
                Op::IdentityInfo => fileops::identity_info(&fds).map(
                    |(public_b64, fingerprint, sealed)| {
                        Some(ResponseData::Identity {
                            public_b64,
                            fingerprint,
                            sealed,
                        })
                    },
                ),
                Op::FileEncrypt(ref fe) => {
                    let mut rng = self.rng();
                    let agent = self.clone();
                    fileops::file_encrypt(fe, &fds, &secrets, &mut rng, move |done, total| {
                        agent.broadcast(&Event::Progress {
                            operation: "file-encrypt".into(),
                            uuid: None,
                            done,
                            total,
                        });
                    })
                    .map(|m| Some(ResponseData::Generic { message: m }))
                }
                Op::FileDecrypt(ref fd_req) => {
                    let agent = self.clone();
                    fileops::file_decrypt(fd_req, &fds, &secrets, move |done, total| {
                        agent.broadcast(&Event::Progress {
                            operation: "file-decrypt".into(),
                            uuid: None,
                            done,
                            total,
                        });
                    })
                    .map(|(message, is_archive)| {
                        Some(ResponseData::FileDone { message, is_archive })
                    })
                }
                Op::Fido2List => {
                    let devices = fido2::list_devices()?;
                    Ok(Some(ResponseData::Generic {
                        message: if devices.is_empty() {
                            "no FIDO2 devices".into()
                        } else {
                            devices.join("\n")
                        },
                    }))
                }
                Op::GetConfig => Ok(Some(ResponseData::Config(
                    self.config.lock().unwrap().clone(),
                ))),
                Op::SetConfig(cfg) => {
                    *self.config.lock().unwrap() = cfg;
                    self.save_config();
                    Ok(Some(ResponseData::Config(
                        self.config.lock().unwrap().clone(),
                    )))
                }
            }
        })();

        match result {
            Ok(data) => ResponseEnvelope {
                id,
                ok: true,
                error: None,
                data,
            },
            Err(e) => ResponseEnvelope {
                id,
                ok: false,
                error: Some(e.to_string()),
                data: None,
            },
        }
    }
}

pub mod convert;
pub mod keyslots;
