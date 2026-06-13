//! Benchmarks: cipher/cascade throughput, hashes, KDF cost, KEM and
//! signature ops, with hardware capability detection. Core is clock-free;
//! all timing lives here (DECISIONS.md D-11).

use std::time::Instant;

use tesseract_core::cascade::{CascadeEngine, CascadeSpec};
use tesseract_core::kdf::{derive_kek, KdfParams};
use tesseract_core::kem::HybridIdentity;
use tesseract_core::registry::{CipherId, HashId, SigId};
use tesseract_core::secret::Vmk;
use tesseract_core::sign::SignerIdentity;
use tesseract_proto::{BenchEntry, BenchReport, HardwareInfo};

pub fn hardware_info() -> HardwareInfo {
    HardwareInfo {
        aes_ni: std::arch::is_x86_feature_detected!("aes"),
        avx2: std::arch::is_x86_feature_detected!("avx2"),
        sha_ext: std::arch::is_x86_feature_detected!("sha"),
        fido2_devices: super::fido2::device_count(),
    }
}

fn mib_per_sec(bytes: usize, elapsed_s: f64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / elapsed_s.max(1e-9)
}

fn bench_cipher(id: CipherId, buf: &mut [u8]) -> Option<BenchEntry> {
    if !id.is_available() {
        return None;
    }
    let vmk = Vmk::from_bytes([0xA5; 64]);
    let spec = CascadeSpec::new(&[id]).ok()?;
    let engine = CascadeEngine::new(&vmk, &spec, 4096).ok()?;
    // warmup
    engine.encrypt_range(0, &mut buf[..4096]).ok()?;
    let start = Instant::now();
    let mut done = 0usize;
    while start.elapsed().as_millis() < 250 {
        engine.encrypt_range(0, buf).ok()?;
        done += buf.len();
    }
    Some(BenchEntry {
        name: format!("{} (XTS sector)", id.label()),
        value: mib_per_sec(done, start.elapsed().as_secs_f64()),
        unit: "MiB/s".into(),
    })
}

fn bench_cascade(ids: &[CipherId], buf: &mut [u8]) -> Option<BenchEntry> {
    let vmk = Vmk::from_bytes([0xA5; 64]);
    let spec = CascadeSpec::new(ids).ok()?;
    let engine = CascadeEngine::new(&vmk, &spec, 4096).ok()?;
    let start = Instant::now();
    let mut done = 0usize;
    while start.elapsed().as_millis() < 250 {
        engine.encrypt_range(0, buf).ok()?;
        done += buf.len();
    }
    Some(BenchEntry {
        name: format!("Cascade: {}", spec.display()),
        value: mib_per_sec(done, start.elapsed().as_secs_f64()),
        unit: "MiB/s".into(),
    })
}

fn bench_hash(id: HashId, buf: &[u8]) -> Option<BenchEntry> {
    if !id.is_available() {
        return None;
    }
    let start = Instant::now();
    let mut done = 0usize;
    while start.elapsed().as_millis() < 200 {
        let mut d = tesseract_core::keyfile::KeyfileDigest::new(id).ok()?;
        d.update(buf);
        let _ = d.finalize();
        done += buf.len();
    }
    Some(BenchEntry {
        name: id.label().to_string(),
        value: mib_per_sec(done, start.elapsed().as_secs_f64()),
        unit: "MiB/s".into(),
    })
}

fn bench_kdf(name: &str, params: KdfParams) -> Option<BenchEntry> {
    let start = Instant::now();
    derive_kek(&params, b"benchmark passphrase").ok()?;
    Some(BenchEntry {
        name: name.to_string(),
        value: start.elapsed().as_secs_f64() * 1000.0,
        unit: "ms".into(),
    })
}

pub fn run(kind: &str) -> BenchReport {
    let mut entries = Vec::new();
    let mut buf = vec![0u8; 8 * 1024 * 1024];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = i as u8;
    }

    if kind == "all" || kind == "ciphers" {
        for &id in CipherId::ALL {
            if let Some(e) = bench_cipher(id, &mut buf) {
                entries.push(e);
            }
        }
        for ids in [
            &[CipherId::Aes256, CipherId::Serpent256][..],
            &[CipherId::Aes256, CipherId::Serpent256, CipherId::Twofish256][..],
        ] {
            if let Some(e) = bench_cascade(ids, &mut buf) {
                entries.push(e);
            }
        }
    }

    if kind == "all" || kind == "hashes" {
        for &id in HashId::ALL {
            if let Some(e) = bench_hash(id, &buf[..4 * 1024 * 1024]) {
                entries.push(e);
            }
        }
    }

    if kind == "all" || kind == "kdf" {
        let salt = [7u8; 32];
        for (name, params) in [
            (
                "Argon2id 256 MiB t=3",
                KdfParams::Argon2id {
                    m_kib: 256 * 1024,
                    t_cost: 3,
                    p_cost: 4,
                    salt,
                },
            ),
            (
                "Argon2id 512 MiB t=4 (default)",
                KdfParams::argon2_default(salt),
            ),
            (
                "scrypt 2^17",
                KdfParams::Scrypt {
                    log_n: 17,
                    r: 8,
                    p: 1,
                    salt,
                },
            ),
            (
                "PBKDF2-SHA512 600k",
                KdfParams::Pbkdf2 {
                    iters: 600_000,
                    hash: HashId::Sha512.as_u16(),
                    salt,
                },
            ),
        ] {
            if let Some(e) = bench_kdf(name, params) {
                entries.push(e);
            }
        }
    }

    if kind == "all" || kind == "pq" {
        let mut rng_state = blake3::Hasher::new();
        rng_state.update(b"bench");
        let mut xof = rng_state.finalize_xof();
        let mut rng = move |buf: &mut [u8]| {
            use std::io::Read;
            xof.read_exact(buf).unwrap();
        };
        let id = HybridIdentity::generate(&mut rng);
        let pk = id.public();

        let start = Instant::now();
        let mut n = 0;
        let mut last_ct = Vec::new();
        while start.elapsed().as_millis() < 200 {
            let (ct, _ss) = tesseract_core::kem::encapsulate(&mut rng, &pk).unwrap();
            last_ct = ct;
            n += 1;
        }
        entries.push(BenchEntry {
            name: "Hybrid X25519+ML-KEM-1024 encapsulate".into(),
            value: start.elapsed().as_secs_f64() * 1000.0 / n as f64,
            unit: "ms/op".into(),
        });

        let start = Instant::now();
        let mut n = 0;
        while start.elapsed().as_millis() < 200 {
            let _ = id.decapsulate(&last_ct).unwrap();
            n += 1;
        }
        entries.push(BenchEntry {
            name: "Hybrid X25519+ML-KEM-1024 decapsulate".into(),
            value: start.elapsed().as_secs_f64() * 1000.0 / n as f64,
            unit: "ms/op".into(),
        });

        for sig in [SigId::Ed25519, SigId::MlDsa87] {
            let signer = SignerIdentity::generate(sig, &mut rng);
            let start = Instant::now();
            let mut n = 0;
            while start.elapsed().as_millis() < 200 {
                let _ = signer.sign(b"benchmark message");
                n += 1;
            }
            entries.push(BenchEntry {
                name: format!("{} sign", sig.label()),
                value: start.elapsed().as_secs_f64() * 1000.0 / n as f64,
                unit: "ms/op".into(),
            });
        }
    }

    BenchReport { entries }
}
