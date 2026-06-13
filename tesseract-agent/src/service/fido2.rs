//! FIDO2 / YubiKey integration (feature "fido2", on by default in packaging).
//!
//! Tesseract uses the CTAP2 `hmac-secret` extension: at enrollment we create
//! a discoverable-less credential bound to rp id "tesseract.local" and store
//! (credential_id, salt) in the keyslot metadata (public). At unlock, an
//! assertion with the stored salt makes the authenticator return
//! HMAC-SHA-256(cred_secret, salt) — a stable 32-byte secret that never
//! leaves the token in derivable form. That output (optionally mixed with a
//! passphrase) feeds the slot KDF. Losing the token = losing the slot, which
//! is exactly the point; keep a passphrase slot as recovery.

use anyhow::Result;

#[cfg(feature = "fido2")]
mod imp {
    use super::*;
    use ctap_hid_fido2::fidokey::get_assertion::get_assertion_params::Extension as GExt;
    use ctap_hid_fido2::fidokey::make_credential::make_credential_params::Extension as MExt;
    use ctap_hid_fido2::{Cfg, FidoKeyHidFactory};

    pub const RP_ID: &str = "tesseract.local";

    pub fn list_devices() -> Result<Vec<String>> {
        let devs = ctap_hid_fido2::get_fidokey_devices();
        Ok(devs
            .into_iter()
            .map(|d| format!("{} ({:04x}:{:04x})", d.info, d.vid, d.pid))
            .collect())
    }

    pub fn device_count() -> u32 {
        ctap_hid_fido2::get_fidokey_devices().len() as u32
    }

    /// Enroll: create a credential with hmac-secret. Returns credential_id.
    pub fn enroll(pin: Option<&str>) -> Result<Vec<u8>> {
        let device = FidoKeyHidFactory::create(&Cfg::init())
            .map_err(|e| anyhow::anyhow!("no FIDO2 device: {e}"))?;
        let challenge = ctap_hid_fido2::verifier::create_challenge();
        let ext = MExt::HmacSecret(Some(true));
        let att = device
            .make_credential_with_extensions(RP_ID, &challenge, pin, Some(&vec![ext]))
            .map_err(|e| anyhow::anyhow!("make_credential: {e}"))?;
        Ok(att.credential_descriptor.id)
    }

    /// Get the hmac-secret output for (credential_id, salt).
    pub fn hmac_secret(
        credential_id: &[u8],
        salt: &[u8; 32],
        pin: Option<&str>,
    ) -> Result<[u8; 32]> {
        let device = FidoKeyHidFactory::create(&Cfg::init())
            .map_err(|e| anyhow::anyhow!("no FIDO2 device: {e}"))?;
        let challenge = ctap_hid_fido2::verifier::create_challenge();
        let ext = GExt::HmacSecret(Some(*salt));
        let assertion = device
            .get_assertion_with_extensios(
                RP_ID,
                &challenge,
                &[credential_id.to_vec()],
                pin,
                Some(&vec![ext]),
            )
            .map_err(|e| anyhow::anyhow!("get_assertion: {e}"))?;
        for e in &assertion.extensions {
            if let GExt::HmacSecret(Some(out)) = e {
                return Ok(*out);
            }
        }
        anyhow::bail!("authenticator returned no hmac-secret output")
    }
}

#[cfg(not(feature = "fido2"))]
mod imp {
    use super::*;

    pub fn list_devices() -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    pub fn device_count() -> u32 {
        0
    }

    pub fn enroll(_pin: Option<&str>) -> Result<Vec<u8>> {
        anyhow::bail!("this build has no FIDO2 support (rebuild with --features fido2)")
    }

    pub fn hmac_secret(
        _credential_id: &[u8],
        _salt: &[u8; 32],
        _pin: Option<&str>,
    ) -> Result<[u8; 32]> {
        anyhow::bail!("this build has no FIDO2 support (rebuild with --features fido2)")
    }
}

pub use imp::*;
