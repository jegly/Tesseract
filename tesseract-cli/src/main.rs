//! tesseract — command-line interface. Scripting parity with the GUI.
//!
//! Holds zero key material: passphrases are read once, shipped to the agent
//! in a secret frame, and wiped. Containers are opened here and passed as
//! fds (the agent refuses paths).

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::os::fd::AsFd;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use tesseract_proto::client::Client;
use tesseract_proto::{
    CreateVolumeReq, FileDecryptReq, FileEncryptReq, KdfChoice, KeyslotChangeReq, MountOptions,
    Op, ResponseData, UnlockReq,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "tesseract",
    version,
    about = "Tesseract: post-quantum disk & file encryption",
    long_about = "Tesseract: post-quantum disk and file encryption.\n\
        All cryptography runs inside the memory-locked tesseract-agent;\n\
        this CLI only carries intent."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone)]
struct KdfArgs {
    /// KDF: argon2id | scrypt | pbkdf2 | balloon
    #[arg(long, default_value = "argon2id")]
    kdf: String,
    /// Memory (KiB for argon2/balloon, log2 N for scrypt)
    #[arg(long, default_value_t = 0)]
    kdf_memory: u32,
    /// Time cost / iterations (0 = default)
    #[arg(long, default_value_t = 0)]
    kdf_time: u32,
    /// Parallelism (0 = default)
    #[arg(long, default_value_t = 0)]
    kdf_parallelism: u32,
    /// PIM-equivalent cost knob (extra passes)
    #[arg(long, default_value_t = 0)]
    pim: u32,
}

impl KdfArgs {
    fn choice(&self) -> KdfChoice {
        KdfChoice {
            kdf: self.kdf.clone(),
            memory: self.kdf_memory,
            time: self.kdf_time,
            parallelism: self.kdf_parallelism,
            pim: self.pim,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Agent + volume status
    Status {
        /// JSON output
        #[arg(long)]
        json: bool,
    },
    /// Create an encrypted volume
    Create {
        /// Container file to create
        container: PathBuf,
        /// Size, e.g. 100M, 2G
        #[arg(long)]
        size: String,
        /// Cascade, e.g. aes or aes,serpent,twofish (innermost first)
        #[arg(long, default_value = "aes")]
        cascade: String,
        /// Hash: sha512 | sha256 | blake3 | blake2b
        #[arg(long, default_value = "blake3")]
        hash: String,
        /// Keyslot AEAD: xchacha20poly1305 | aes256gcmsiv
        #[arg(long, default_value = "xchacha20poly1305")]
        slot_aead: String,
        /// Volume profile: standard | deniable
        #[arg(long, default_value = "standard")]
        profile: String,
        /// Filesystem to create: ext4 | btrfs | xfs | exfat | vfat | none
        #[arg(long, default_value = "ext4")]
        filesystem: String,
        #[arg(long, default_value = "")]
        label: String,
        /// Sector size (512..65536, power of two)
        #[arg(long, default_value_t = 4096)]
        sector_size: u32,
        /// Sparse (dynamic) container
        #[arg(long)]
        dynamic: bool,
        /// Overwrite data area with random data first
        #[arg(long)]
        full_format: bool,
        /// Hidden volume size (deniable profile), e.g. 50M
        #[arg(long)]
        hidden_size: Option<String>,
        /// Keyfile(s)
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
        /// Keyfile(s) for the hidden volume
        #[arg(long = "hidden-keyfile")]
        hidden_keyfiles: Vec<PathBuf>,
        /// Require a hybrid PQC keyslot (pass --pqc-recipient)
        #[arg(long)]
        require_pqc: bool,
        /// Base64 hybrid recipient public key for a PQC keyslot
        #[arg(long)]
        pqc_recipient: Option<String>,
        /// Allow experimental algorithms on this volume
        #[arg(long)]
        experimental: bool,
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Unlock and mount a volume
    Mount {
        container: PathBuf,
        /// Mount read-only
        #[arg(long)]
        read_only: bool,
        /// PIM (deniable volumes)
        #[arg(long, default_value_t = 0)]
        pim: u32,
        /// Protect a hidden volume while mounting the outer one
        #[arg(long)]
        protect_hidden: bool,
        /// Credential: passphrase | keyfile | identity
        #[arg(long, default_value = "passphrase")]
        credential: String,
        /// Keyfile(s)
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
        /// Identity file (with --credential identity)
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Data plane: fuse | none (none = expose image only)
        #[arg(long, default_value = "fuse")]
        data_plane: String,
    },
    /// Lock and unmount a volume
    Unmount {
        /// Volume uuid (hex, from status)
        uuid: String,
        #[arg(long)]
        force: bool,
    },
    /// Lock everything and wipe key material NOW
    Panic,
    /// Encrypt an existing plaintext container in place
    EncryptInPlace {
        container: PathBuf,
        #[arg(long, default_value = "aes")]
        cascade: String,
        #[arg(long, default_value = "blake3")]
        hash: String,
        #[arg(long, default_value = "xchacha20poly1305")]
        slot_aead: String,
        #[arg(long, default_value = "")]
        label: String,
        #[arg(long, default_value_t = 4096)]
        sector_size: u32,
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Permanently decrypt a volume in place
    DecryptInPlace {
        container: PathBuf,
        #[arg(long, default_value_t = 0)]
        pim: u32,
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
    },
    /// Keyslot management
    Keyslot {
        #[command(subcommand)]
        action: KeyslotCmd,
    },
    /// Back up the volume header region
    HeaderBackup { container: PathBuf, output: PathBuf },
    /// Restore a volume header from a backup
    HeaderRestore {
        container: PathBuf,
        backup: PathBuf,
        #[arg(long, default_value_t = 0)]
        pim: u32,
    },
    /// Benchmark ciphers, hashes, KDFs, and PQ operations
    Bench {
        /// all | ciphers | hashes | kdf | pq
        #[arg(default_value = "all")]
        kind: String,
    },
    /// File encryption (HPKE, age-style)
    File {
        #[command(subcommand)]
        action: FileCmd,
    },
    /// Generate a random keyfile
    KeyfileGen {
        output: PathBuf,
        #[arg(long, default_value_t = 4096)]
        length: u32,
    },
    /// Identity (recipient keypair) management
    Identity {
        #[command(subcommand)]
        action: IdentityCmd,
    },
    /// List FIDO2 security keys
    Fido2List,
    /// Get or set agent configuration
    Config {
        /// key=value pairs, e.g. idle_timeout_secs=600 (empty: show)
        sets: Vec<String>,
    },
}

#[derive(Subcommand)]
enum KeyslotCmd {
    /// Add a new passphrase slot
    AddPassphrase {
        container: PathBuf,
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
        #[arg(long = "new-keyfile")]
        new_keyfiles: Vec<PathBuf>,
        #[arg(long)]
        label: Option<String>,
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Change the passphrase of the slot that opens
    ChangePassphrase {
        container: PathBuf,
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
        #[arg(long = "new-keyfile")]
        new_keyfiles: Vec<PathBuf>,
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Re-derive the opening slot with new KDF parameters
    ChangeKdf {
        container: PathBuf,
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
        #[command(flatten)]
        kdf: KdfArgs,
    },
    /// Add a keyfile-only slot
    AddKeyfile {
        container: PathBuf,
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
        #[arg(long = "new-keyfile", required = true)]
        new_keyfiles: Vec<PathBuf>,
        #[arg(long)]
        label: Option<String>,
    },
    /// Add a hybrid PQC slot for a recipient
    AddPqc {
        container: PathBuf,
        #[arg(long)]
        recipient: String,
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
        #[arg(long)]
        label: Option<String>,
    },
    /// Enroll a FIDO2 security key (YubiKey etc.) as a slot
    AddFido2 {
        container: PathBuf,
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
        /// Prompt for an authenticator PIN
        #[arg(long)]
        pin: bool,
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a slot
    Remove {
        container: PathBuf,
        #[arg(long)]
        slot: u8,
        #[arg(long = "keyfile")]
        keyfiles: Vec<PathBuf>,
    },
}

#[derive(Subcommand)]
enum FileCmd {
    /// Encrypt a file with a password, or to recipients' public keys
    Encrypt {
        input: PathBuf,
        output: PathBuf,
        /// Encrypt with a password (simple mode); prompted if no recipients
        #[arg(long)]
        password: bool,
        /// Recipient public key (base64), repeatable; or @identity-file
        #[arg(long = "to")]
        recipients: Vec<String>,
        /// AEAD cascade: e.g. chacha20poly1305 or xchacha20poly1305,aes256gcm
        #[arg(long, default_value = "chacha20poly1305")]
        layers: String,
        /// Sign with this identity (writes .sig next to output)
        #[arg(long)]
        signer: Option<PathBuf>,
        #[arg(long, default_value_t = 262144)]
        chunk_size: u32,
    },
    /// Decrypt a file with a password or your identity
    Decrypt {
        input: PathBuf,
        output: PathBuf,
        /// Decrypt with a password (simple mode)
        #[arg(long)]
        password: bool,
        /// Decrypt with your identity file (recipient mode)
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Verify the detached signature
        #[arg(long)]
        verify: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Generate a new hybrid (X25519+ML-KEM-1024) identity
    Generate {
        output: PathBuf,
        /// Seal the identity file with a passphrase
        #[arg(long)]
        seal: bool,
    },
    /// Show the public half / fingerprint of an identity file
    Show { identity: PathBuf },
}

fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('K') | Some('k') => (&s[..s.len() - 1], 1024u64),
        Some('M') | Some('m') => (&s[..s.len() - 1], 1024 * 1024),
        Some('G') | Some('g') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        Some('T') | Some('t') => (&s[..s.len() - 1], 1024u64 * 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    Ok(num.parse::<u64>().context("bad size")? * mult)
}

fn cipher_id(name: &str) -> Result<u16> {
    Ok(match name.trim().to_lowercase().as_str() {
        "aes" | "aes256" | "aes-256" => 1,
        "serpent" => 2,
        "twofish" => 3,
        "camellia" => 4,
        "chacha20" => 5,
        "xchacha20" => 6,
        "threefish" => 100,
        "kuznyechik" => 101,
        "sm4" => 102,
        "aria" => 103,
        "adiantum" => 104,
        other => bail!("unknown cipher {other}"),
    })
}

fn hash_id(name: &str) -> Result<u16> {
    Ok(match name.trim().to_lowercase().as_str() {
        "sha512" | "sha-512" => 1,
        "sha256" | "sha-256" => 2,
        "blake3" => 3,
        "blake2b" => 4,
        "whirlpool" => 100,
        "streebog" => 101,
        other => bail!("unknown hash {other}"),
    })
}

fn aead_id(name: &str) -> Result<u16> {
    Ok(match name.trim().to_lowercase().as_str() {
        "xchacha20poly1305" => 1,
        "aes256gcmsiv" | "aes-256-gcm-siv" => 2,
        "aes256gcm" | "aes-256-gcm" => 3,
        "chacha20poly1305" => 4,
        other => bail!("unknown AEAD {other}"),
    })
}

fn cascade_ids(s: &str) -> Result<Vec<u16>> {
    s.split(',').map(cipher_id).collect()
}

fn layer_ids(s: &str) -> Result<Vec<u16>> {
    s.split(',').map(aead_id).collect()
}

fn prompt_secret(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    if let Ok(v) = std::env::var("TESSERACT_PASSPHRASE") {
        return Ok(Zeroizing::new(v.into_bytes()));
    }
    // No controlling terminal (scripted/piped use): read one line from
    // stdin. An empty line yields an empty credential — the agent rejects it
    // if one was actually required (e.g. a sealed identity), which smooths
    // the common unsealed-identity case while still supporting `echo pw | …`.
    use std::io::{BufRead, IsTerminal};
    if !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        return Ok(Zeroizing::new(line.into_bytes()));
    }
    let pw = rpassword::prompt_password(prompt).context("read passphrase")?;
    Ok(Zeroizing::new(pw.into_bytes()))
}

fn prompt_secret_confirm(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    let a = prompt_secret(prompt)?;
    if std::env::var("TESSERACT_PASSPHRASE").is_ok() {
        return Ok(a);
    }
    let b = prompt_secret("Confirm: ")?;
    if *a != *b {
        bail!("passphrases do not match");
    }
    Ok(a)
}

fn open_ro(path: &PathBuf) -> Result<std::fs::File> {
    OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}

fn open_rw(path: &PathBuf) -> Result<std::fs::File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}

fn create_file(path: &PathBuf) -> Result<std::fs::File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))
}

fn print_response(data: Option<ResponseData>, json: bool) {
    let Some(data) = data else {
        println!("ok");
        return;
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&data).unwrap());
        return;
    }
    match data {
        ResponseData::Status(s) => {
            println!("agent {} — {}", s.agent_version, s.state_summary);
            println!(
                "sandbox: mlockall={} no_new_privs={} dumpable_off={} landlock={} seccomp={}",
                s.sandbox.mlockall,
                s.sandbox.no_new_privs,
                s.sandbox.dumpable_disabled,
                s.sandbox.landlock,
                s.sandbox.seccomp
            );
            println!(
                "hardware: aes-ni={} avx2={} sha={} fido2={}",
                s.hardware.aes_ni, s.hardware.avx2, s.hardware.sha_ext, s.hardware.fido2_devices
            );
            println!(
                "locked memory: {} KiB | entropy events: {} | uptime: {}s",
                s.locked_memory_kib, s.entropy_events, s.uptime_secs
            );
            for v in &s.volumes {
                println!(
                    "\n  {}  [{}]  {}",
                    &v.uuid[..16],
                    v.state,
                    if v.label.is_empty() { "(no label)" } else { &v.label }
                );
                println!("    cascade: {} | profile: {}", v.cascade, v.profile);
                if let Some(mp) = &v.mount_point {
                    println!("    mounted: {mp}{}", if v.read_only { " (ro)" } else { "" });
                }
                if let Some(dev) = &v.device {
                    println!("    device: {dev}");
                }
                if let Some(idle) = v.idle_dismount_in {
                    println!("    auto-dismount in: {idle}s");
                }
                if v.protection_triggered {
                    println!("    !! hidden-volume protection TRIGGERED");
                }
                for s in &v.slots {
                    println!("    slot {}: {} ({}) {}", s.id, s.kind, s.kdf, s.label);
                }
            }
        }
        ResponseData::Volume(v) => {
            println!("volume {} [{}]", v.uuid, v.state);
            if let Some(mp) = &v.mount_point {
                println!("mounted at {mp}");
            } else if let Some(dev) = &v.device {
                println!("image at {dev} (no filesystem mount; use udisksctl or format it)");
            }
        }
        ResponseData::Bench(b) => {
            for e in b.entries {
                println!("{:>10.2} {:<8} {}", e.value, e.unit, e.name);
            }
        }
        ResponseData::Config(c) => {
            println!("{}", serde_json::to_string_pretty(&c).unwrap());
        }
        ResponseData::Identity {
            public_b64,
            fingerprint,
            sealed,
        } => {
            println!("recipient: {public_b64}");
            println!("fingerprint: {fingerprint}");
            println!("sealed: {sealed}");
        }
        ResponseData::Hello {
            agent_version,
            protocol,
            hardened,
        } => {
            println!("agent {agent_version} (protocol {protocol}, hardened={hardened})");
        }
        ResponseData::Generic { message } => println!("{message}"),
        ResponseData::FileDone { message, .. } => println!("{message}"),
        ResponseData::Progress { done, total } => println!("{done}/{total}"),
    }
}

fn resolve_recipients(client: &mut Client, recipients: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for r in recipients {
        if let Some(path) = r.strip_prefix('@') {
            let f = open_ro(&PathBuf::from(path))?;
            let resp = client.call_ok(Op::IdentityInfo, &[f.as_fd()], vec![])?;
            match resp.data {
                Some(ResponseData::Identity { public_b64, .. }) => out.push(public_b64),
                _ => bail!("unexpected response for identity {path}"),
            }
        } else {
            out.push(r.clone());
        }
    }
    Ok(out)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut client = Client::connect_autostart()?;

    match cli.command {
        Command::Status { json } => {
            let resp = client.call_ok(Op::Status, &[], vec![])?;
            print_response(resp.data, json);
        }
        Command::Create {
            container,
            size,
            cascade,
            hash,
            slot_aead,
            profile,
            filesystem,
            label,
            sector_size,
            dynamic,
            full_format,
            hidden_size,
            keyfiles,
            hidden_keyfiles,
            require_pqc,
            pqc_recipient,
            experimental,
            kdf,
        } => {
            let size_bytes = parse_size(&size)?;
            let hidden = hidden_size.as_deref().map(parse_size).transpose()?.unwrap_or(0);
            let cascade_ids_v = cascade_ids(&cascade)?;
            // auto-enable experimental if any chosen cipher is experimental
            let experimental = experimental || cascade_ids_v.iter().any(|&id| id >= 100);
            let file = create_file(&container)?;
            let kf: Vec<_> = keyfiles.iter().map(open_ro).collect::<Result<_>>()?;
            let hkf: Vec<_> = hidden_keyfiles.iter().map(open_ro).collect::<Result<_>>()?;

            let mut fds = vec![file.as_fd()];
            fds.extend(kf.iter().map(|f| f.as_fd()));
            fds.extend(hkf.iter().map(|f| f.as_fd()));

            let mut secrets = vec![prompt_secret_confirm("Volume passphrase: ")?];
            if hidden > 0 {
                secrets.push(prompt_secret_confirm("HIDDEN volume passphrase: ")?);
            }

            let req = CreateVolumeReq {
                cascade: cascade_ids_v,
                hash: hash_id(&hash)?,
                kdf: kdf.choice(),
                slot_aead: aead_id(&slot_aead)?,
                label,
                size_bytes,
                sector_size,
                profile,
                dynamic,
                filesystem,
                full_format,
                hidden_size: hidden,
                require_pqc,
                pqc_recipient,
                experimental_ok: experimental,
                hidden_keyfiles: hkf.len() as u8,
            };
            let resp = match client.call_ok(Op::CreateVolume(req), &fds, secrets) {
                Ok(r) => r,
                Err(e) => {
                    std::fs::remove_file(&container).ok();
                    return Err(e.into());
                }
            };
            print_response(resp.data, false);
            println!("created. mount it, then format the mapped device (udisksctl / GNOME Disks).");
        }
        Command::Mount {
            container,
            read_only,
            pim,
            protect_hidden,
            credential,
            keyfiles,
            identity,
            data_plane,
        } => {
            let file = if read_only { open_ro(&container)? } else { open_rw(&container)? };
            let kf: Vec<_> = keyfiles.iter().map(open_ro).collect::<Result<_>>()?;
            let idf = identity.as_ref().map(open_ro).transpose()?;

            let mut fds = vec![file.as_fd()];
            fds.extend(kf.iter().map(|f| f.as_fd()));
            if let Some(f) = &idf {
                fds.push(f.as_fd());
            }

            let mut secrets = vec![prompt_secret("Passphrase: ")?];
            if protect_hidden {
                secrets.push(prompt_secret("Hidden volume passphrase (protection): ")?);
            }

            let req = UnlockReq {
                options: MountOptions {
                    read_only,
                    data_plane: Some(data_plane),
                    ..Default::default()
                },
                pim,
                protect_hidden,
                credential_kind: if identity.is_some() { "identity".into() } else { credential },
                label_hint: None,
            };
            let resp = client.call_ok(Op::Unlock(req), &fds, secrets)?;
            print_response(resp.data, false);
        }
        Command::Unmount { uuid, force } => {
            let resp = client.call_ok(Op::Lock { uuid, force }, &[], vec![])?;
            print_response(resp.data, false);
        }
        Command::Panic => {
            let resp = client.call_ok(Op::Panic, &[], vec![])?;
            print_response(resp.data, false);
        }
        Command::EncryptInPlace {
            container,
            cascade,
            hash,
            slot_aead,
            label,
            sector_size,
            keyfiles,
            kdf,
        } => {
            let file = open_rw(&container)?;
            let kf: Vec<_> = keyfiles.iter().map(open_ro).collect::<Result<_>>()?;
            let mut fds = vec![file.as_fd()];
            fds.extend(kf.iter().map(|f| f.as_fd()));
            let secrets = vec![prompt_secret_confirm("New volume passphrase: ")?];
            let req = CreateVolumeReq {
                cascade: cascade_ids(&cascade)?,
                hash: hash_id(&hash)?,
                kdf: kdf.choice(),
                slot_aead: aead_id(&slot_aead)?,
                label,
                size_bytes: 0,
                sector_size,
                profile: "standard".into(),
                dynamic: false,
                filesystem: "none".into(),
                full_format: false,
                hidden_size: 0,
                require_pqc: false,
                pqc_recipient: None,
                experimental_ok: false,
                hidden_keyfiles: 0,
            };
            println!("encrypting in place (crash-safe, resumable)...");
            let resp = client.call_ok(Op::EncryptInPlace(req), &fds, secrets)?;
            print_response(resp.data, false);
        }
        Command::DecryptInPlace {
            container,
            pim,
            keyfiles,
        } => {
            let file = open_rw(&container)?;
            let kf: Vec<_> = keyfiles.iter().map(open_ro).collect::<Result<_>>()?;
            let mut fds = vec![file.as_fd()];
            fds.extend(kf.iter().map(|f| f.as_fd()));
            let secrets = vec![prompt_secret("Passphrase: ")?];
            println!("decrypting in place (crash-safe, resumable)...");
            let resp = client.call_ok(
                Op::DecryptInPlace {
                    pim,
                    credential_kind: "passphrase".into(),
                },
                &fds,
                secrets,
            )?;
            print_response(resp.data, false);
        }
        Command::Keyslot { action } => keyslot_cmd(&mut client, action)?,
        Command::HeaderBackup { container, output } => {
            let c = open_ro(&container)?;
            let o = create_file(&output)?;
            let resp = client.call_ok(Op::HeaderBackup, &[c.as_fd(), o.as_fd()], vec![])?;
            print_response(resp.data, false);
        }
        Command::HeaderRestore {
            container,
            backup,
            pim,
        } => {
            let c = open_rw(&container)?;
            let b = open_ro(&backup)?;
            let secrets = vec![prompt_secret("Passphrase (must open the backup): ")?];
            let resp =
                client.call_ok(Op::HeaderRestore { pim }, &[c.as_fd(), b.as_fd()], secrets)?;
            print_response(resp.data, false);
        }
        Command::Bench { kind } => {
            println!("benchmarking ({kind})... KDF presets run fully, this can take a minute");
            let resp = client.call_ok(Op::Benchmark { kind }, &[], vec![])?;
            print_response(resp.data, false);
        }
        Command::File { action } => file_cmd(&mut client, action)?,
        Command::KeyfileGen { output, length } => {
            let o = create_file(&output)?;
            let resp = client.call_ok(Op::GenerateKeyfile { length }, &[o.as_fd()], vec![])?;
            print_response(resp.data, false);
        }
        Command::Identity { action } => match action {
            IdentityCmd::Generate { output, seal } => {
                let o = create_file(&output)?;
                let secrets = if seal {
                    vec![prompt_secret_confirm("Identity passphrase: ")?]
                } else {
                    vec![]
                };
                let resp = client.call_ok(Op::GenerateIdentity, &[o.as_fd()], secrets)?;
                print_response(resp.data, false);
            }
            IdentityCmd::Show { identity } => {
                let f = open_ro(&identity)?;
                let resp = client.call_ok(Op::IdentityInfo, &[f.as_fd()], vec![])?;
                print_response(resp.data, false);
            }
        },
        Command::Fido2List => {
            let resp = client.call_ok(Op::Fido2List, &[], vec![])?;
            print_response(resp.data, false);
        }
        Command::Config { sets } => {
            if sets.is_empty() {
                let resp = client.call_ok(Op::GetConfig, &[], vec![])?;
                print_response(resp.data, false);
            } else {
                let resp = client.call_ok(Op::GetConfig, &[], vec![])?;
                let Some(ResponseData::Config(cfg)) = resp.data else {
                    bail!("unexpected response");
                };
                let mut value = serde_json::to_value(&cfg)?;
                for kv in sets {
                    let (k, v) = kv
                        .split_once('=')
                        .with_context(|| format!("expected key=value, got {kv}"))?;
                    let parsed: serde_json::Value = serde_json::from_str(v)
                        .unwrap_or_else(|_| serde_json::Value::String(v.to_string()));
                    let obj = value.as_object_mut().unwrap();
                    if !obj.contains_key(k) {
                        bail!("unknown config key {k}");
                    }
                    obj.insert(k.to_string(), parsed);
                }
                let new_cfg: tesseract_proto::AgentConfig = serde_json::from_value(value)?;
                let resp = client.call_ok(Op::SetConfig(new_cfg), &[], vec![])?;
                print_response(resp.data, false);
            }
        }
    }
    Ok(())
}

fn keyslot_cmd(client: &mut Client, action: KeyslotCmd) -> Result<()> {
    let (container, req, kf_paths, new_kf_paths, secrets) = match action {
        KeyslotCmd::AddPassphrase {
            container,
            keyfiles,
            new_keyfiles,
            label,
            kdf,
        } => {
            let s = vec![
                prompt_secret("Existing passphrase: ")?,
                prompt_secret_confirm("New passphrase: ")?,
            ];
            (
                container,
                KeyslotChangeReq {
                    action: "add-passphrase".into(),
                    slot_id: None,
                    kdf: Some(kdf.choice()),
                    slot_aead: None,
                    label,
                    pqc_recipient: None,
                    existing_keyfiles: keyfiles.len() as u8,
                },
                keyfiles,
                new_keyfiles,
                s,
            )
        }
        KeyslotCmd::ChangePassphrase {
            container,
            keyfiles,
            new_keyfiles,
            kdf,
        } => {
            let s = vec![
                prompt_secret("Existing passphrase: ")?,
                prompt_secret_confirm("New passphrase: ")?,
            ];
            (
                container,
                KeyslotChangeReq {
                    action: "change-passphrase".into(),
                    slot_id: None,
                    kdf: Some(kdf.choice()),
                    slot_aead: None,
                    label: None,
                    pqc_recipient: None,
                    existing_keyfiles: keyfiles.len() as u8,
                },
                keyfiles,
                new_keyfiles,
                s,
            )
        }
        KeyslotCmd::ChangeKdf {
            container,
            keyfiles,
            kdf,
        } => {
            let s = vec![prompt_secret("Passphrase: ")?];
            (
                container,
                KeyslotChangeReq {
                    action: "change-kdf".into(),
                    slot_id: None,
                    kdf: Some(kdf.choice()),
                    slot_aead: None,
                    label: None,
                    pqc_recipient: None,
                    existing_keyfiles: keyfiles.len() as u8,
                },
                keyfiles,
                vec![],
                s,
            )
        }
        KeyslotCmd::AddKeyfile {
            container,
            keyfiles,
            new_keyfiles,
            label,
        } => {
            let s = vec![prompt_secret("Existing passphrase: ")?];
            (
                container,
                KeyslotChangeReq {
                    action: "add-keyfile".into(),
                    slot_id: None,
                    kdf: None,
                    slot_aead: None,
                    label,
                    pqc_recipient: None,
                    existing_keyfiles: keyfiles.len() as u8,
                },
                keyfiles,
                new_keyfiles,
                s,
            )
        }
        KeyslotCmd::AddPqc {
            container,
            recipient,
            keyfiles,
            label,
        } => {
            let s = vec![prompt_secret("Existing passphrase: ")?];
            (
                container,
                KeyslotChangeReq {
                    action: "add-pqc".into(),
                    slot_id: None,
                    kdf: None,
                    slot_aead: None,
                    label,
                    pqc_recipient: Some(recipient),
                    existing_keyfiles: keyfiles.len() as u8,
                },
                keyfiles,
                vec![],
                s,
            )
        }
        KeyslotCmd::AddFido2 {
            container,
            keyfiles,
            pin,
            label,
        } => {
            let mut s = vec![prompt_secret("Existing passphrase: ")?];
            if pin {
                s.push(prompt_secret("Authenticator PIN: ")?);
            }
            (
                container,
                KeyslotChangeReq {
                    action: "add-fido2".into(),
                    slot_id: None,
                    kdf: None,
                    slot_aead: None,
                    label,
                    pqc_recipient: None,
                    existing_keyfiles: keyfiles.len() as u8,
                },
                keyfiles,
                vec![],
                s,
            )
        }
        KeyslotCmd::Remove {
            container,
            slot,
            keyfiles,
        } => {
            let s = vec![prompt_secret("Passphrase: ")?];
            (
                container,
                KeyslotChangeReq {
                    action: "remove".into(),
                    slot_id: Some(slot),
                    kdf: None,
                    slot_aead: None,
                    label: None,
                    pqc_recipient: None,
                    existing_keyfiles: keyfiles.len() as u8,
                },
                keyfiles,
                vec![],
                s,
            )
        }
    };

    let file = open_rw(&container)?;
    let kf: Vec<_> = kf_paths.iter().map(open_ro).collect::<Result<_>>()?;
    let nkf: Vec<_> = new_kf_paths.iter().map(open_ro).collect::<Result<_>>()?;
    let mut fds = vec![file.as_fd()];
    fds.extend(kf.iter().map(|f| f.as_fd()));
    fds.extend(nkf.iter().map(|f| f.as_fd()));
    let resp = client.call_ok(Op::ChangeKeyslot(req), &fds, secrets)?;
    print_response(resp.data, false);
    Ok(())
}

/// Tar a directory into a temp file on tmpfs; returns the temp path.
fn tar_directory(dir: &PathBuf) -> Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("tesseract");
    std::fs::create_dir_all(&base)?;
    let path = base.join(format!("archive-{}.tar", std::process::id()));
    let file = std::fs::File::create(&path)?;
    let mut builder = tar::Builder::new(file);
    builder.follow_symlinks(false);
    let name = dir
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("archive"));
    builder
        .append_dir_all(&name, dir)
        .context("pack folder")?;
    builder.finish()?;
    Ok(path)
}

/// Extract a tar file into `target_dir`.
fn untar_into(archive: &PathBuf, target_dir: &PathBuf) -> Result<()> {
    std::fs::create_dir_all(target_dir)?;
    let file = open_ro(archive)?;
    let mut ar = tar::Archive::new(file);
    ar.set_preserve_permissions(true);
    ar.set_overwrite(true);
    ar.unpack(target_dir).context("extract folder")?;
    Ok(())
}

fn file_cmd(client: &mut Client, action: FileCmd) -> Result<()> {
    match action {
        FileCmd::Encrypt {
            input,
            output,
            password,
            recipients,
            layers,
            signer,
            chunk_size,
        } => {
            // password mode if requested or if no recipients were given
            let use_password = password || recipients.is_empty();
            let recipients = resolve_recipients(client, &recipients)?;

            // folder support: tar a directory into a temp and encrypt that
            let is_archive = input.is_dir();
            let archive_temp = if is_archive {
                Some(tar_directory(&input)?)
            } else {
                None
            };
            let actual_input = archive_temp.as_ref().map(|t| t.clone()).unwrap_or_else(|| input.clone());

            let inf = open_ro(&actual_input)?;
            let outf = create_file(&output)?;
            let plaintext_len = inf.metadata()?.len();
            let mut fds = vec![inf.as_fd(), outf.as_fd()];
            let mut secrets = vec![];
            if use_password {
                secrets.push(prompt_secret_confirm("File password: ")?);
            }
            let sig_files;
            if let Some(signer_path) = &signer {
                let mut sig_name = output.as_os_str().to_owned();
                sig_name.push(".sig");
                let sig_out = create_file(&PathBuf::from(sig_name))?;
                let signer_f = open_ro(signer_path)?;
                sig_files = (sig_out, signer_f);
                fds.push(sig_files.0.as_fd());
                fds.push(sig_files.1.as_fd());
                secrets.push(prompt_secret("Signer identity passphrase (empty if unsealed): ")?);
            }
            let req = FileEncryptReq {
                recipients,
                use_password,
                password_kdf: KdfChoice::default(),
                layers: layer_ids(&layers)?,
                chunk_size,
                sign: signer.is_some(),
                is_archive,
                plaintext_len,
            };
            let result = client.call_ok(Op::FileEncrypt(req), &fds, secrets);
            if let Some(t) = &archive_temp {
                std::fs::remove_file(t).ok();
            }
            print_response(result?.data, false);
        }
        FileCmd::Decrypt {
            input,
            output,
            password,
            identity,
            verify,
        } => {
            let use_password = password || identity.is_none();
            let inf = open_ro(&input)?;
            // decrypt to a temp beside the output, then place file/folder
            let out_parent = output.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
            std::fs::create_dir_all(&out_parent).ok();
            let temp = out_parent.join(format!(".tesseract-dec-{}.tmp", std::process::id()));
            let outf = create_file(&temp)?;
            let mut fds = vec![inf.as_fd(), outf.as_fd()];
            let idf = match &identity {
                Some(p) => Some(open_ro(p)?),
                None => None,
            };
            if let Some(f) = &idf {
                fds.push(f.as_fd());
            }
            let sig_f;
            if let Some(sig) = &verify {
                sig_f = open_ro(sig)?;
                fds.push(sig_f.as_fd());
            }
            let prompt = if use_password {
                "File password: "
            } else {
                "Identity passphrase (empty if unsealed): "
            };
            let secrets = vec![prompt_secret(prompt)?];
            let req = FileDecryptReq {
                use_password,
                verify: verify.is_some(),
                expect_signer_fp: None,
            };
            let result = client.call_ok(Op::FileDecrypt(req), &fds, secrets);
            match result {
                Ok(resp) => {
                    let is_archive = matches!(
                        &resp.data,
                        Some(ResponseData::FileDone { is_archive: true, .. })
                    );
                    if is_archive {
                        untar_into(&temp, &output)?;
                        std::fs::remove_file(&temp).ok();
                        println!("decrypted; folder extracted to {}", output.display());
                    } else {
                        if std::fs::rename(&temp, &output).is_err() {
                            std::fs::copy(&temp, &output)?;
                            std::fs::remove_file(&temp).ok();
                        }
                        print_response(resp.data, false);
                    }
                }
                Err(e) => {
                    std::fs::remove_file(&temp).ok();
                    return Err(e.into());
                }
            }
        }
    }
    Ok(())
}
