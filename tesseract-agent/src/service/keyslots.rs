//! Keyslot management on standard-profile volumes, and passphrase rotation
//! on deniable ones (single-slot reseal).

use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileExt;

use anyhow::{anyhow, bail, Result};
use tesseract_core::header::{open_deniable, seal_deniable, VolumeHeader};
use tesseract_core::keyslot::{seal_slot, Credential, NewSlot, SlotSetup};
use tesseract_core::registry::{AeadId, HashId};
use tesseract_core::EntropySource;
use tesseract_core::{DENIABLE_BLOB_LEN, HEADER_REGION};
use tesseract_proto::{KeyslotChangeReq, ResponseData};

use super::volume::{digest_keyfiles, read_header_region};
use crate::os::secmem::LockedSecret;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// fds: [0] container, [1..existing_keyfiles] existing keyfiles, rest = new.
/// secrets: [0] existing credential, [1] new credential.
pub fn change(
    req: &KeyslotChangeReq,
    fds: &[OwnedFd],
    secrets: &[LockedSecret],
    rng: &mut dyn EntropySource,
) -> Result<ResponseData> {
    if fds.is_empty() {
        bail!("keyslot change needs the container fd");
    }
    let container = File::from(fds[0].try_clone()?);
    let kf_fds = &fds[1..];
    let split = (req.existing_keyfiles as usize).min(kf_fds.len());
    let (existing_kf_fds, new_kf_fds) = kf_fds.split_at(split);

    let existing_pass = secrets
        .first()
        .map(|s| s.as_slice())
        .ok_or_else(|| anyhow!("missing existing credential"))?;

    let region = read_header_region(&container, 0)?;
    match VolumeHeader::from_bytes(&region) {
        Ok(mut header) => {
            let hash = header.hash_id().map_err(|e| anyhow!("{e}"))?;
            let existing_kf = digest_keyfiles(hash, existing_kf_fds)?;
            let new_kf = digest_keyfiles(hash, new_kf_fds)?;
            let binding = header.essentials_digest();
            let cred = Credential::Passphrase {
                passphrase: existing_pass,
                keyfiles: &existing_kf,
            };
            let (vmk, used_slot) = header
                .unlock(&cred)
                .map_err(|e| anyhow!("{e}"))?;

            let aead = req
                .slot_aead
                .map(AeadId::from_u16)
                .transpose()
                .map_err(|e| anyhow!("{e}"))?
                .unwrap_or(AeadId::XChaCha20Poly1305);
            let mut salt = [0u8; 32];
            rng.fill(&mut salt);
            let kdf_params = req
                .kdf
                .as_ref()
                .map(|c| super::volume::map_kdf_pub(c, salt))
                .transpose()?
                .unwrap_or_else(|| tesseract_core::kdf::KdfParams::argon2_default(salt));

            let message = match req.action.as_str() {
                "add-passphrase" => {
                    let new_pass = secrets
                        .get(1)
                        .map(|s| s.as_slice())
                        .ok_or_else(|| anyhow!("missing new passphrase"))?;
                    let id = header.next_slot_id().map_err(|e| anyhow!("{e}"))?;
                    let slot = seal_slot(
                        rng,
                        &vmk,
                        NewSlot {
                            id,
                            aead,
                            label: req.label.clone().unwrap_or_else(|| "passphrase".into()),
                            created_at: now_secs(),
                            kdf: Some(kdf_params),
                            setup: SlotSetup::Passphrase {
                                passphrase: new_pass,
                                keyfiles: &new_kf,
                            },
                        },
                        &binding,
                    )
                    .map_err(|e| anyhow!("{e}"))?;
                    header.slots.push(slot);
                    format!("added passphrase slot {id}")
                }
                "change-passphrase" | "change-kdf" => {
                    let new_pass = if req.action == "change-kdf" {
                        existing_pass
                    } else {
                        secrets
                            .get(1)
                            .map(|s| s.as_slice())
                            .ok_or_else(|| anyhow!("missing new passphrase"))?
                    };
                    let keyfiles = if req.action == "change-kdf" { &existing_kf } else { &new_kf };
                    let slot = seal_slot(
                        rng,
                        &vmk,
                        NewSlot {
                            id: used_slot,
                            aead,
                            label: req.label.clone().unwrap_or_else(|| "passphrase".into()),
                            created_at: now_secs(),
                            kdf: Some(kdf_params),
                            setup: SlotSetup::Passphrase {
                                passphrase: new_pass,
                                keyfiles,
                            },
                        },
                        &binding,
                    )
                    .map_err(|e| anyhow!("{e}"))?;
                    let pos = header
                        .slots
                        .iter()
                        .position(|s| s.id == used_slot)
                        .expect("slot exists");
                    header.slots[pos] = slot;
                    format!("rotated slot {used_slot}")
                }
                "add-keyfile" => {
                    if new_kf.is_empty() {
                        bail!("no new keyfiles supplied");
                    }
                    let id = header.next_slot_id().map_err(|e| anyhow!("{e}"))?;
                    let slot = seal_slot(
                        rng,
                        &vmk,
                        NewSlot {
                            id,
                            aead,
                            label: req.label.clone().unwrap_or_else(|| "keyfile".into()),
                            created_at: now_secs(),
                            kdf: Some(tesseract_core::kdf::KdfParams::keyfile_slot(salt)),
                            setup: SlotSetup::Keyfiles(&new_kf),
                        },
                        &binding,
                    )
                    .map_err(|e| anyhow!("{e}"))?;
                    header.slots.push(slot);
                    format!("added keyfile slot {id}")
                }
                "add-pqc" => {
                    let recipient_b64 = req
                        .pqc_recipient
                        .as_ref()
                        .ok_or_else(|| anyhow!("missing recipient"))?;
                    let recipient = super::fileops::parse_recipient(recipient_b64)?;
                    let id = header.next_slot_id().map_err(|e| anyhow!("{e}"))?;
                    let slot = seal_slot(
                        rng,
                        &vmk,
                        NewSlot {
                            id,
                            aead,
                            label: req.label.clone().unwrap_or_else(|| "hybrid-pqc".into()),
                            created_at: now_secs(),
                            kdf: None,
                            setup: SlotSetup::Hybrid(&recipient),
                        },
                        &binding,
                    )
                    .map_err(|e| anyhow!("{e}"))?;
                    header.slots.push(slot);
                    format!("added hybrid PQC slot {id}")
                }
                "add-fido2" => {
                    let pin_str;
                    let pin = match secrets.get(1) {
                        Some(s) if !s.as_slice().is_empty() => {
                            pin_str = String::from_utf8_lossy(s.as_slice()).into_owned();
                            Some(pin_str.as_str())
                        }
                        _ => None,
                    };
                    let credential_id = super::fido2::enroll(pin)?;
                    let mut hmac_salt = [0u8; 32];
                    rng.fill(&mut hmac_salt);
                    let hmac_out = super::fido2::hmac_secret(&credential_id, &hmac_salt, pin)?;
                    let id = header.next_slot_id().map_err(|e| anyhow!("{e}"))?;
                    let slot = seal_slot(
                        rng,
                        &vmk,
                        NewSlot {
                            id,
                            aead,
                            label: req.label.clone().unwrap_or_else(|| "security key".into()),
                            created_at: now_secs(),
                            kdf: Some(kdf_params),
                            setup: SlotSetup::Fido2 {
                                meta: tesseract_core::keyslot::Fido2Meta {
                                    credential_id,
                                    rp_id: "tesseract.local".into(),
                                    hmac_salt,
                                    require_uv: pin.is_some(),
                                },
                                hmac_output: &hmac_out,
                                passphrase: None,
                            },
                        },
                        &binding,
                    )
                    .map_err(|e| anyhow!("{e}"))?;
                    header.slots.push(slot);
                    format!("enrolled FIDO2 security key as slot {id}")
                }
                "remove" => {
                    let id = req.slot_id.ok_or_else(|| anyhow!("missing slot id"))?;
                    header.remove_slot(id).map_err(|e| anyhow!("{e}"))?;
                    format!("removed slot {id}")
                }
                other => bail!("unknown keyslot action {other}"),
            };

            header.update_mac(&vmk);
            header.validate().map_err(|e| anyhow!("{e}"))?;
            let bytes = header.to_bytes().map_err(|e| anyhow!("{e}"))?;
            let region =
                tesseract_core::header::compose_standard_region(&bytes).map_err(|e| anyhow!("{e}"))?;
            container.write_all_at(&region, 0)?;
            container.write_all_at(&region, header.geometry.backup_offset())?;
            container.sync_all()?;
            Ok(ResponseData::Generic { message })
        }
        Err(_) => {
            // deniable: single credential — only passphrase rotation
            if req.action != "change-passphrase" {
                bail!("deniable volumes support only change-passphrase");
            }
            let new_pass = secrets
                .get(1)
                .map(|s| s.as_slice())
                .ok_or_else(|| anyhow!("missing new passphrase"))?;
            let existing_kf = digest_keyfiles(HashId::Blake3, existing_kf_fds)?;
            let new_kf = digest_keyfiles(HashId::Blake3, new_kf_fds)?;
            let pim = req.kdf.as_ref().map(|k| k.pim).unwrap_or(0);

            let mut updated_any = false;
            let total_len = container.metadata()?.len();
            for base in [0u64, total_len - HEADER_REGION] {
                let mut region = read_header_region(&container, base)?;
                for off in [0usize, tesseract_core::HIDDEN_HEADER_OFFSET as usize] {
                    let blob = &region[off..off + DENIABLE_BLOB_LEN];
                    if let Ok(inner) = open_deniable(blob, existing_pass, &existing_kf, pim) {
                        let new_blob = seal_deniable(rng, &inner, new_pass, &new_kf, pim)
                            .map_err(|e| anyhow!("{e}"))?;
                        region[off..off + DENIABLE_BLOB_LEN].copy_from_slice(&new_blob);
                        container.write_all_at(&region, base)?;
                        updated_any = true;
                    }
                }
            }
            if !updated_any {
                bail!("{}", tesseract_core::Error::UnlockFailed);
            }
            container.sync_all()?;
            Ok(ResponseData::Generic {
                message: "deniable header re-sealed with the new passphrase".into(),
            })
        }
    }
}
