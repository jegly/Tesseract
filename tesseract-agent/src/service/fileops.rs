//! File-mode operations: HPKE encrypt/decrypt, identities, keyfiles.
//! All streaming; plaintext chunks only ever live transiently here.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use tesseract_core::filemode::{FileDecryptor, FileEncryptor, FileHeader};
use tesseract_core::kem::{self, HybridIdentity, HybridRecipient};
use tesseract_core::registry::{AeadId, SigId};
use tesseract_core::sign::{SigBundle, SignerIdentity};
use tesseract_core::EntropySource;
use tesseract_proto::{FileDecryptReq, FileEncryptReq};

use crate::os::secmem::LockedSecret;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn read_all_limited(fd: &OwnedFd, cap: usize) -> Result<Vec<u8>> {
    let mut f = File::from(fd.try_clone()?);
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; 8192];
    loop {
        let n = f.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > cap {
            bail!("input exceeds limit");
        }
    }
    Ok(buf)
}

pub fn parse_recipient(b64: &str) -> Result<HybridRecipient> {
    let bytes = B64.decode(b64.trim()).context("recipient base64")?;
    let r: HybridRecipient = minicbor::decode(&bytes).map_err(|e| anyhow!("recipient cbor: {e}"))?;
    r.validate().map_err(|e| anyhow!("{e}"))?;
    Ok(r)
}

pub fn encode_recipient(r: &HybridRecipient) -> String {
    B64.encode(minicbor::to_vec(r).expect("encode"))
}

fn open_identity_fd(fd: &OwnedFd, passphrase: Option<&[u8]>) -> Result<HybridIdentity> {
    let bytes = read_all_limited(fd, 64 * 1024)?;
    let pass = if kem::identity_is_sealed(&bytes).map_err(|e| anyhow!("{e}"))? {
        passphrase
    } else {
        None
    };
    kem::open_identity(&bytes, pass).map_err(|e| anyhow!("{e}"))
}

/// fds: [0] input, [1] output, [2] signature out (if sign), [3] signer
/// identity (if sign). secrets: [0] signer identity passphrase (optional).
pub fn file_encrypt(
    req: &FileEncryptReq,
    fds: &[OwnedFd],
    secrets: &[LockedSecret],
    rng: &mut dyn EntropySource,
    mut progress: impl FnMut(u64, u64),
) -> Result<String> {
    if fds.len() < 2 {
        bail!("file-encrypt needs input and output fds");
    }
    let mut input = File::from(fds[0].try_clone()?);
    let mut output = File::from(fds[1].try_clone()?);
    let plaintext_len = input.metadata()?.len();

    let recipients: Vec<HybridRecipient> = req
        .recipients
        .iter()
        .map(|r| parse_recipient(r))
        .collect::<Result<_>>()?;
    let layers: Vec<AeadId> = req
        .layers
        .iter()
        .map(|l| AeadId::from_u16(*l).map_err(|e| anyhow!("{e}")))
        .collect::<Result<_>>()?;
    let chunk_size = if req.chunk_size == 0 {
        tesseract_core::filemode::DEFAULT_CHUNK_SIZE
    } else {
        req.chunk_size
    };

    // password mode: secrets[0] is the file password; signer pass (if any)
    // shifts to the next secret.
    let mut signer_secret_idx = 0;
    let mut salt = [0u8; 32];
    rng.fill(&mut salt);
    let password_params = if req.use_password {
        Some(super::volume::map_kdf_pub(&req.password_kdf, salt)?)
    } else {
        None
    };
    let password = match (req.use_password, &password_params) {
        (true, Some(params)) => {
            let pw = secrets
                .first()
                .ok_or_else(|| anyhow!("password mode needs a passphrase"))?;
            signer_secret_idx = 1;
            Some((pw.as_slice(), params.clone()))
        }
        _ => None,
    };

    let mut enc = FileEncryptor::with_openers(
        rng,
        tesseract_core::filemode::Openers {
            password,
            recipients: &recipients,
        },
        &layers,
        tesseract_core::hpke::AEAD_CHACHA20POLY1305,
        chunk_size,
        plaintext_len,
        req.sign,
        req.is_archive,
    )
    .map_err(|e| anyhow!("{e}"))?;

    let mut hasher = blake3::Hasher::new();
    output.write_all(enc.header_bytes())?;
    hasher.update(enc.header_bytes());

    let mut buf = vec![0u8; chunk_size as usize];
    let mut done = 0u64;
    if plaintext_len == 0 {
        let ct = enc.encrypt_chunk(b"").map_err(|e| anyhow!("{e}"))?;
        output.write_all(&ct)?;
        hasher.update(&ct);
    } else {
        while done < plaintext_len {
            let take = (plaintext_len - done).min(chunk_size as u64) as usize;
            input.read_exact(&mut buf[..take])?;
            let ct = enc.encrypt_chunk(&buf[..take]).map_err(|e| anyhow!("{e}"))?;
            output.write_all(&ct)?;
            hasher.update(&ct);
            done += take as u64;
            progress(done, plaintext_len);
        }
    }
    output.sync_all()?;

    if req.sign {
        if fds.len() < 4 {
            bail!("signing needs signature-out and identity fds");
        }
        let seed_identity =
            open_identity_fd(&fds[3], secrets.get(signer_secret_idx).map(|s| s.as_slice()))?;
        // signer key derived from the hybrid identity's signing seed: use the
        // ML-DSA-87 seed derived from the identity's x25519 secret via KMAC
        // would couple keys; instead identities carry an independent signing
        // seed derived from the ml seed (domain-separated).
        let (_, ml_seed) = seed_identity.parts();
        let mut sig_seed = [0u8; 32];
        tesseract_core::kmac::kmac256(ml_seed, b"tsr/sign-seed", b"ml-dsa-87", &mut sig_seed);
        let signer = SignerIdentity::from_seed(SigId::MlDsa87, sig_seed);
        let digest = *hasher.finalize().as_bytes();
        let bundle = tesseract_core::filemode::sign_file(&signer, &digest);
        let mut sig_out = File::from(fds[2].try_clone()?);
        sig_out.write_all(&minicbor::to_vec(&bundle).map_err(|e| anyhow!("{e}"))?)?;
        sig_out.sync_all()?;
    }

    let how = match (req.use_password, recipients.len()) {
        (true, 0) => "with a password".to_string(),
        (true, n) => format!("with a password and {n} recipient(s)"),
        (false, n) => format!("to {n} recipient(s)"),
    };
    let what = if req.is_archive { "folder" } else { "file" };
    Ok(format!("encrypted {what} ({plaintext_len} bytes) {how}"))
}

/// fds: [0] input, [1] output, [2] identity, [3] signature (if verify).
/// secrets: [0] identity passphrase (optional).
pub fn file_decrypt(
    req: &FileDecryptReq,
    fds: &[OwnedFd],
    secrets: &[LockedSecret],
    mut progress: impl FnMut(u64, u64),
) -> Result<(String, bool)> {
    if fds.len() < 2 {
        bail!("file-decrypt needs input and output fds");
    }
    let mut input = File::from(fds[0].try_clone()?);
    let mut output = File::from(fds[1].try_clone()?);

    // password mode needs no identity fd; the signature fd (if verifying)
    // shifts down by one.
    let sig_fd_idx = if req.use_password { 2 } else { 3 };

    // header: read prefix incrementally (verify-before-parse inside core)
    let mut head = vec![0u8; 64 * 1024];
    let mut got = 0usize;
    let (header, header_len) = loop {
        let n = input.read(&mut head[got..])?;
        got += n;
        match FileHeader::from_bytes(&head[..got]) {
            Ok(h) => break h,
            Err(tesseract_core::Error::FileFormat("length")) if n > 0 => {
                if got == head.len() {
                    head.resize(head.len() * 2, 0);
                    if head.len() > 2 * 1024 * 1024 {
                        bail!("header too large");
                    }
                }
                continue;
            }
            Err(e) => bail!("{e}"),
        }
    };

    if req.verify && fds.len() <= sig_fd_idx {
        bail!("verification needs the signature fd");
    }

    let chunk_ct_len = header.chunk_size as usize + header.chunk_overhead();
    let total = header.plaintext_len;
    let mut dec = if req.use_password {
        let pw = secrets
            .first()
            .ok_or_else(|| anyhow!("password mode needs a passphrase"))?;
        FileDecryptor::with_password(header, pw.as_slice()).map_err(|e| anyhow!("{e}"))?
    } else {
        if fds.len() < 3 {
            bail!("identity mode needs the identity fd");
        }
        let identity = open_identity_fd(&fds[2], secrets.first().map(|s| s.as_slice()))?;
        FileDecryptor::new(header, &identity).map_err(|e| anyhow!("{e}"))?
    };

    let mut hasher = blake3::Hasher::new();
    hasher.update(&head[..header_len]);

    // leftover bytes already read past the header
    let mut pending: Vec<u8> = head[header_len..got].to_vec();
    let mut buf = vec![0u8; chunk_ct_len];
    let mut written = 0u64;
    while !dec.is_complete() {
        // fill pending up to one ciphertext chunk (final chunk may be short)
        while pending.len() < chunk_ct_len {
            let n = input.read(&mut buf[..chunk_ct_len - pending.len()])?;
            if n == 0 {
                break;
            }
            pending.extend_from_slice(&buf[..n]);
        }
        if pending.is_empty() {
            bail!("truncated file");
        }
        let take = pending.len().min(chunk_ct_len);
        let chunk = &pending[..take];
        hasher.update(chunk);
        let pt = dec.decrypt_chunk(chunk).map_err(|e| anyhow!("{e}"))?;
        output.write_all(&pt)?;
        written += pt.len() as u64;
        progress(written.min(total), total);
        pending.drain(..take);
    }
    if !pending.is_empty() || input.read(&mut [0u8; 1])? != 0 {
        bail!("trailing data after final chunk");
    }
    output.sync_all()?;

    if req.verify {
        let sig_bytes = read_all_limited(&fds[sig_fd_idx], 1024 * 1024)?;
        let bundle: SigBundle =
            minicbor::decode(&sig_bytes).map_err(|e| anyhow!("signature cbor: {e}"))?;
        let digest = *hasher.finalize().as_bytes();
        tesseract_core::filemode::verify_file(&bundle, &digest).map_err(|e| anyhow!("{e}"))?;
        if let Some(expect) = &req.expect_signer_fp {
            let fp = hex::encode(&blake3::hash(&bundle.public_key).as_bytes()[..8]);
            if &fp != expect {
                bail!("signer fingerprint mismatch: {fp}");
            }
        }
    }

    let is_archive = dec.header().is_archive();
    Ok((format!("decrypted {written} bytes"), is_archive))
}

/// fds: [0] output; secrets: [0] sealing passphrase (optional).
pub fn generate_identity(
    fds: &[OwnedFd],
    secrets: &[LockedSecret],
    rng: &mut dyn EntropySource,
) -> Result<(String, String, bool)> {
    if fds.is_empty() {
        bail!("identity generation needs an output fd");
    }
    let identity = HybridIdentity::generate(rng);
    let pass = secrets.first().map(|s| s.as_slice()).filter(|s| !s.is_empty());
    let bytes = kem::seal_identity(&identity, pass, rng).map_err(|e| anyhow!("{e}"))?;
    let mut out = File::from(fds[0].try_clone()?);
    out.write_all(&bytes)?;
    out.sync_all()?;
    let public = identity.public();
    Ok((
        encode_recipient(&public),
        hex::encode(public.fingerprint()),
        pass.is_some(),
    ))
}

/// fds: [0] identity file.
pub fn identity_info(fds: &[OwnedFd]) -> Result<(String, String, bool)> {
    if fds.is_empty() {
        bail!("identity-info needs an fd");
    }
    let bytes = read_all_limited(&fds[0], 64 * 1024)?;
    let public = kem::identity_public(&bytes).map_err(|e| anyhow!("{e}"))?;
    let sealed = kem::identity_is_sealed(&bytes).map_err(|e| anyhow!("{e}"))?;
    Ok((
        encode_recipient(&public),
        hex::encode(public.fingerprint()),
        sealed,
    ))
}

/// fds: [0] output.
pub fn generate_keyfile(length: u32, fds: &[OwnedFd], rng: &mut dyn EntropySource) -> Result<String> {
    if fds.is_empty() {
        bail!("keyfile generation needs an output fd");
    }
    let len = if length == 0 { 4096 } else { length.min(16 * 1024 * 1024) };
    let bytes = tesseract_core::keyfile::generate_keyfile(rng, len as usize);
    let mut out = File::from(fds[0].try_clone()?);
    out.write_all(&bytes)?;
    out.sync_all()?;
    Ok(format!("generated {len}-byte keyfile"))
}
