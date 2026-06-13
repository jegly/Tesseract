//! In-place conversion orchestration: wires core's resumable converter to
//! real file IO + the fsynced sidecar journal, emitting progress events.

use std::fs::File;
use std::os::fd::OwnedFd;
use std::sync::Arc;

use anyhow::{anyhow, bail, Result};
use tesseract_core::cascade::CascadeSpec;
use tesseract_core::header::{
    compose_standard_region, Geometry, VolumeHeader, FLAG_CONVERTING, FLAG_EXPERIMENTAL_OK,
    FORMAT_VERSION,
};
use tesseract_core::inplace;
use tesseract_core::keyslot::{seal_slot, Credential, NewSlot, SlotSetup};
use tesseract_core::registry::{AeadId, CipherId, HashId};
use tesseract_core::secret::Vmk;
use tesseract_core::EntropySource;
use tesseract_core::HEADER_REGION;
use tesseract_proto::{CreateVolumeReq, Event, ResponseData};

use super::inplace_io::{FileBlockIo, SidecarJournal};
use super::volume::{digest_keyfiles, read_header_region};
use super::Agent;
use crate::os::secmem::LockedSecret;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Encrypt an existing plaintext container in place (standard profile only).
/// Resumable: if a CONVERTING backup header + journal exist, continues.
pub fn encrypt_in_place(
    agent: &Arc<Agent>,
    req: &CreateVolumeReq,
    fds: &[OwnedFd],
    secrets: &[LockedSecret],
    rng: &mut dyn EntropySource,
) -> Result<ResponseData> {
    if fds.is_empty() {
        bail!("encrypt-in-place needs the container fd");
    }
    if req.profile != "standard" {
        bail!("in-place encryption supports the standard profile only");
    }
    let container = File::from(fds[0].try_clone()?);
    let keyfiles = digest_keyfiles(HashId::from_u16(req.hash).map_err(|e| anyhow!("{e}"))?, &fds[1..])?;
    let passphrase = secrets
        .first()
        .map(|s| s.as_slice())
        .ok_or_else(|| anyhow!("missing passphrase"))?;

    let total = container.metadata()?.len();
    let sector = req.sector_size.max(512);

    // resume path: tail backup header with CONVERTING set?
    let resume = (|| -> Option<(VolumeHeader, Vmk)> {
        if total < 2 * HEADER_REGION {
            return None;
        }
        let region = read_header_region(&container, total - HEADER_REGION).ok()?;
        let header = VolumeHeader::from_bytes(&region).ok()?;
        if !header.flag(FLAG_CONVERTING) {
            return None;
        }
        let cred = Credential::Passphrase {
            passphrase,
            keyfiles: &keyfiles,
        };
        let (vmk, _) = header.unlock(&cred).ok()?;
        Some((header, vmk))
    })();

    let (mut header, vmk, plain_len) = match resume {
        Some((header, vmk)) => {
            log::info!("resuming in-place encryption of {}", hex::encode(header.uuid));
            let plain_len = header.geometry.data_len;
            (header, vmk, plain_len)
        }
        None => {
            // fresh start: plaintext must be sector-aligned; pad by growing
            let plain_len = total.div_ceil(sector as u64) * sector as u64;
            if plain_len != total {
                container.set_len(plain_len)?;
            }
            let cascade_ids = req
                .cascade
                .iter()
                .map(|v| CipherId::from_u16(*v))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("{e}"))?;
            let spec = CascadeSpec::new(&cascade_ids).map_err(|e| anyhow!("{e}"))?;
            spec.validate(req.experimental_ok).map_err(|e| anyhow!("{e}"))?;
            let geometry = Geometry {
                sector_size: sector,
                data_offset: HEADER_REGION,
                data_len: plain_len,
                total_len: plain_len + 2 * HEADER_REGION,
            };
            geometry.validate().map_err(|e| anyhow!("{e}"))?;

            let mut uuid = [0u8; 16];
            rng.fill(&mut uuid);
            let vmk = Vmk::generate(rng);
            let mut flags = FLAG_CONVERTING;
            if req.experimental_ok {
                flags |= FLAG_EXPERIMENTAL_OK;
            }
            let mut header = VolumeHeader {
                version: FORMAT_VERSION,
                uuid,
                label: req.label.clone(),
                created_at: now_secs(),
                geometry,
                cascade: spec,
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
                    aead: AeadId::from_u16(req.slot_aead).map_err(|e| anyhow!("{e}"))?,
                    label: "passphrase".into(),
                    created_at: now_secs(),
                    kdf: Some(super::volume::map_kdf_pub(&req.kdf, salt)?),
                    setup: SlotSetup::Passphrase {
                        passphrase,
                        keyfiles: &keyfiles,
                    },
                },
                &binding,
            )
            .map_err(|e| anyhow!("{e}"))?;
            header.slots.push(slot);
            header.update_mac(&vmk);
            (header, vmk, plain_len)
        }
    };

    // region images: converting backup first, then final front+backup
    let converting_bytes = header.to_bytes().map_err(|e| anyhow!("{e}"))?;
    let backup_converting =
        compose_standard_region(&converting_bytes).map_err(|e| anyhow!("{e}"))?;
    header.flags &= !FLAG_CONVERTING;
    header.update_mac(&vmk);
    let final_bytes = header.to_bytes().map_err(|e| anyhow!("{e}"))?;
    let final_region = compose_standard_region(&final_bytes).map_err(|e| anyhow!("{e}"))?;

    let mut io = FileBlockIo { file: container };
    let mut journal = SidecarJournal::for_uuid(&agent.state_dir, &header.uuid);
    let agent2 = agent.clone();
    let uuid_hex = hex::encode(header.uuid);
    inplace::encrypt_in_place(
        &mut io,
        &mut journal,
        &vmk,
        &header.cascade,
        sector,
        plain_len,
        header.uuid,
        &final_region,
        &backup_converting,
        &final_region,
        inplace::DEFAULT_CHUNK,
        &mut |done, total| {
            agent2.broadcast(&Event::Progress {
                operation: "encrypt-in-place".into(),
                uuid: Some(uuid_hex.clone()),
                done,
                total,
            });
        },
    )
    .map_err(|e| anyhow!("{e}"))?;

    Ok(ResponseData::Generic {
        message: format!("encrypted {plain_len} bytes in place ({})", hex::encode(header.uuid)),
    })
}

/// Permanently decrypt a standard volume in place.
pub fn decrypt_in_place(
    agent: &Arc<Agent>,
    _pim: u32,
    _credential_kind: &str,
    fds: &[OwnedFd],
    secrets: &[LockedSecret],
) -> Result<ResponseData> {
    if fds.is_empty() {
        bail!("decrypt-in-place needs the container fd");
    }
    let container = File::from(fds[0].try_clone()?);
    let passphrase = secrets
        .first()
        .map(|s| s.as_slice())
        .ok_or_else(|| anyhow!("missing passphrase"))?;

    let region = read_header_region(&container, 0)
        .or_else(|_| {
            let total = container.metadata()?.len();
            read_header_region(&container, total - HEADER_REGION)
        })?;
    let header = VolumeHeader::from_bytes(&region).map_err(|e| anyhow!("{e}"))?;
    let keyfiles = digest_keyfiles(header.hash_id().map_err(|e| anyhow!("{e}"))?, &fds[1..])?;
    let cred = Credential::Passphrase {
        passphrase,
        keyfiles: &keyfiles,
    };
    let (vmk, _) = header.unlock(&cred).map_err(|e| anyhow!("{e}"))?;

    {
        // refuse if mounted
        let volumes = agent.volumes.lock().unwrap();
        if let Some(v) = volumes.get(&header.uuid) {
            if v.state == tesseract_core::statemachine::State::ActiveMounted {
                bail!("volume is mounted; lock it first");
            }
        }
    }

    let mut io = FileBlockIo { file: container };
    let mut journal = SidecarJournal::for_uuid(&agent.state_dir, &header.uuid);
    let agent2 = agent.clone();
    let uuid_hex = hex::encode(header.uuid);
    inplace::decrypt_in_place(
        &mut io,
        &mut journal,
        &vmk,
        &header.cascade,
        header.geometry.sector_size,
        header.geometry.data_len,
        header.uuid,
        inplace::DEFAULT_CHUNK,
        &mut |done, total| {
            agent2.broadcast(&Event::Progress {
                operation: "decrypt-in-place".into(),
                uuid: Some(uuid_hex.clone()),
                done,
                total,
            });
        },
    )
    .map_err(|e| anyhow!("{e}"))?;

    agent.volumes.lock().unwrap().remove(&header.uuid);
    Ok(ResponseData::Generic {
        message: format!(
            "decrypted {} bytes; container returned to plaintext",
            header.geometry.data_len
        ),
    })
}
