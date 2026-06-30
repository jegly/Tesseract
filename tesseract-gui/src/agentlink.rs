//! Bridge between the GTK main thread and the blocking agent socket.
//!
//! All IPC runs on a dedicated worker thread; the GUI submits `Command`s over
//! a channel and receives `AgentMsg`s back through a `relm4` sender, so the UI
//! never blocks on a KDF or a mount. A second connection is dedicated to the
//! event stream (Subscribe) and forwards push events.
//!
//! The GUI passes file paths to the worker (not fds); the worker opens them
//! and hands fds to the agent. The GUI still never sees key material: the only
//! secrets it forwards are passphrases the user typed, which go straight into
//! the secret frame and are dropped.

use std::os::fd::AsFd;
use std::path::PathBuf;

use tesseract_proto::client::Client;
use tesseract_proto::{Event, Op, ResponseData};
use zeroize::Zeroizing;

/// What the GUI asks the worker to do. File arguments are paths; the worker
/// opens them with the right mode and passes fds.
#[allow(dead_code)]
pub enum Command {
    Status,
    Create {
        req: tesseract_proto::CreateVolumeReq,
        container: PathBuf,
        keyfiles: Vec<PathBuf>,
        hidden_keyfiles: Vec<PathBuf>,
        passphrase: Zeroizing<Vec<u8>>,
        hidden_passphrase: Option<Zeroizing<Vec<u8>>>,
    },
    Mount {
        req: tesseract_proto::UnlockReq,
        container: PathBuf,
        keyfiles: Vec<PathBuf>,
        identity: Option<PathBuf>,
        passphrase: Zeroizing<Vec<u8>>,
        hidden_passphrase: Option<Zeroizing<Vec<u8>>>,
        read_only: bool,
    },
    Lock {
        uuid: String,
        force: bool,
    },
    Panic,
    Benchmark {
        kind: String,
    },
    GetConfig,
    SetConfig(tesseract_proto::AgentConfig),
    GenerateIdentity {
        output: PathBuf,
        passphrase: Option<Zeroizing<Vec<u8>>>,
    },
    IdentityInfo {
        path: PathBuf,
    },
    GenerateKeyfile {
        output: PathBuf,
        length: u32,
    },
    FileEncrypt {
        input: PathBuf,
        output: PathBuf,
        req: tesseract_proto::FileEncryptReq,
        /// File password (simple mode); first secret frame when present.
        password: Option<Zeroizing<Vec<u8>>>,
        signer: Option<PathBuf>,
        signer_pass: Option<Zeroizing<Vec<u8>>>,
    },
    FileDecrypt {
        input: PathBuf,
        output: PathBuf,
        /// Some = identity-mode; None = password mode.
        identity: Option<PathBuf>,
        signature: Option<PathBuf>,
        /// Password (password mode) or identity passphrase (identity mode).
        passphrase: Zeroizing<Vec<u8>>,
    },
    Keyslot {
        req: tesseract_proto::KeyslotChangeReq,
        container: PathBuf,
        keyfiles: Vec<PathBuf>,
        new_keyfiles: Vec<PathBuf>,
        existing: Zeroizing<Vec<u8>>,
        new_secret: Option<Zeroizing<Vec<u8>>>,
    },
    HeaderBackup {
        container: PathBuf,
        output: PathBuf,
    },
}

#[derive(Debug)]
pub enum AgentMsg {
    Connected { hardened: bool, version: String },
    Disconnected(String),
    Status(tesseract_proto::StatusInfo),
    Config(tesseract_proto::AgentConfig),
    Bench(tesseract_proto::BenchReport),
    Identity { public_b64: String, fingerprint: String, sealed: bool },
    Ok(String),
    Error(String),
    Event(Event),
}

fn open_ro(p: &PathBuf) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().read(true).open(p)
}
fn open_rw(p: &PathBuf) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().read(true).write(true).open(p)
}
fn create_new(p: &PathBuf) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(p)
}

fn data_of(resp: tesseract_proto::ResponseEnvelope) -> Result<Option<ResponseData>, String> {
    if resp.ok {
        Ok(resp.data)
    } else {
        Err(resp.error.unwrap_or_else(|| "agent error".into()))
    }
}

fn run_command(client: &mut Client, cmd: Command) -> AgentMsg {
    let result: Result<AgentMsg, String> = (|| {
        match cmd {
            Command::Status => {
                let resp = client.call(Op::Status, &[], vec![]).map_err(|e| e.to_string())?;
                match data_of(resp)? {
                    Some(ResponseData::Status(s)) => Ok(AgentMsg::Status(s)),
                    _ => Err("unexpected status reply".into()),
                }
            }
            Command::Create {
                req,
                container,
                keyfiles,
                hidden_keyfiles,
                passphrase,
                hidden_passphrase,
            } => {
                // A freshly created (newly made) container that fails creation
                // must be removed so it can't be opened later as a 0-byte file.
                let newly_created = !container.exists();
                let file = create_new(&container)
                    .or_else(|_| open_rw(&container))
                    .map_err(|e| e.to_string())?;
                let kf: Vec<_> = keyfiles.iter().map(open_ro).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
                let hkf: Vec<_> = hidden_keyfiles.iter().map(open_ro).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
                let mut fds = vec![file.as_fd()];
                fds.extend(kf.iter().map(|f| f.as_fd()));
                fds.extend(hkf.iter().map(|f| f.as_fd()));
                let mut secrets = vec![passphrase];
                if let Some(h) = hidden_passphrase {
                    secrets.push(h);
                }
                let result = client
                    .call(Op::CreateVolume(req), &fds, secrets)
                    .map_err(|e| e.to_string())
                    .and_then(data_of);
                match result {
                    Ok(_) => Ok(AgentMsg::Ok("Volume created".into())),
                    Err(e) => {
                        if newly_created {
                            // don't leave a half-written / empty container behind
                            std::fs::remove_file(&container).ok();
                        }
                        Err(e)
                    }
                }
            }
            Command::Mount {
                req,
                container,
                keyfiles,
                identity,
                passphrase,
                hidden_passphrase,
                read_only,
            } => {
                let file = if read_only { open_ro(&container) } else { open_rw(&container) }
                    .map_err(|e| e.to_string())?;
                let kf: Vec<_> = keyfiles.iter().map(open_ro).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
                let idf = identity.as_ref().map(open_ro).transpose().map_err(|e| e.to_string())?;
                let mut fds = vec![file.as_fd()];
                fds.extend(kf.iter().map(|f| f.as_fd()));
                if let Some(f) = &idf {
                    fds.push(f.as_fd());
                }
                let mut secrets = vec![passphrase];
                if let Some(h) = hidden_passphrase {
                    secrets.push(h);
                }
                let resp = client.call(Op::Unlock(req), &fds, secrets).map_err(|e| e.to_string())?;
                data_of(resp)?;
                Ok(AgentMsg::Ok("Volume mounted".into()))
            }
            Command::Lock { uuid, force } => {
                let resp = client.call(Op::Lock { uuid, force }, &[], vec![]).map_err(|e| e.to_string())?;
                data_of(resp)?;
                Ok(AgentMsg::Ok("Volume locked".into()))
            }
            Command::Panic => {
                let resp = client.call(Op::Panic, &[], vec![]).map_err(|e| e.to_string())?;
                data_of(resp)?;
                Ok(AgentMsg::Ok("Panic: all volumes locked and wiped".into()))
            }
            Command::Benchmark { kind } => {
                let resp = client.call(Op::Benchmark { kind }, &[], vec![]).map_err(|e| e.to_string())?;
                match data_of(resp)? {
                    Some(ResponseData::Bench(b)) => Ok(AgentMsg::Bench(b)),
                    _ => Err("unexpected bench reply".into()),
                }
            }
            Command::GetConfig => {
                let resp = client.call(Op::GetConfig, &[], vec![]).map_err(|e| e.to_string())?;
                match data_of(resp)? {
                    Some(ResponseData::Config(c)) => Ok(AgentMsg::Config(c)),
                    _ => Err("unexpected config reply".into()),
                }
            }
            Command::SetConfig(cfg) => {
                let resp = client.call(Op::SetConfig(cfg), &[], vec![]).map_err(|e| e.to_string())?;
                match data_of(resp)? {
                    Some(ResponseData::Config(c)) => Ok(AgentMsg::Config(c)),
                    _ => Ok(AgentMsg::Ok("Settings saved".into())),
                }
            }
            Command::GenerateIdentity { output, passphrase } => {
                let o = create_new(&output).map_err(|e| e.to_string())?;
                let secrets = passphrase.map(|p| vec![p]).unwrap_or_default();
                let resp = client.call(Op::GenerateIdentity, &[o.as_fd()], secrets).map_err(|e| e.to_string())?;
                match data_of(resp)? {
                    Some(ResponseData::Identity { public_b64, fingerprint, sealed }) => {
                        Ok(AgentMsg::Identity { public_b64, fingerprint, sealed })
                    }
                    _ => Ok(AgentMsg::Ok("Identity created".into())),
                }
            }
            Command::IdentityInfo { path } => {
                let f = open_ro(&path).map_err(|e| e.to_string())?;
                let resp = client.call(Op::IdentityInfo, &[f.as_fd()], vec![]).map_err(|e| e.to_string())?;
                match data_of(resp)? {
                    Some(ResponseData::Identity { public_b64, fingerprint, sealed }) => {
                        Ok(AgentMsg::Identity { public_b64, fingerprint, sealed })
                    }
                    _ => Err("unexpected identity reply".into()),
                }
            }
            Command::GenerateKeyfile { output, length } => {
                let o = create_new(&output).map_err(|e| e.to_string())?;
                let resp = client.call(Op::GenerateKeyfile { length }, &[o.as_fd()], vec![]).map_err(|e| e.to_string())?;
                data_of(resp)?;
                Ok(AgentMsg::Ok("Keyfile generated".into()))
            }
            Command::FileEncrypt { input, output, mut req, password, signer, signer_pass } => {
                // folder support: tar a directory to a tmpfs temp and encrypt
                // that. The TempFile stays alive (and deletes itself) for the
                // duration of this block.
                let archive_temp;
                let actual_input = if crate::archive::is_dir(&input) {
                    let t = crate::archive::tar_directory(&input).map_err(|e| format!("archive folder: {e}"))?;
                    req.is_archive = true;
                    let p = t.path.clone();
                    archive_temp = Some(t);
                    p
                } else {
                    req.is_archive = false;
                    archive_temp = None;
                    input.clone()
                };
                let _ = &archive_temp;
                let inf = open_ro(&actual_input).map_err(|e| e.to_string())?;
                let outf = create_new(&output).map_err(|e| e.to_string())?;
                req.plaintext_len = inf.metadata().map(|m| m.len()).unwrap_or(0);
                let mut fds = vec![inf.as_fd(), outf.as_fd()];
                let mut secrets = vec![];
                // password secret comes FIRST when present
                req.use_password = password.is_some();
                if let Some(pw) = password {
                    secrets.push(pw);
                }
                let sig_files;
                if let Some(signer_path) = &signer {
                    let mut name = output.clone().into_os_string();
                    name.push(".sig");
                    let sig_out = create_new(&PathBuf::from(name)).map_err(|e| e.to_string())?;
                    let signer_f = open_ro(signer_path).map_err(|e| e.to_string())?;
                    sig_files = (sig_out, signer_f);
                    fds.push(sig_files.0.as_fd());
                    fds.push(sig_files.1.as_fd());
                    secrets.push(signer_pass.unwrap_or_else(|| Zeroizing::new(Vec::new())));
                }
                req.sign = signer.is_some();
                let resp = client.call(Op::FileEncrypt(req), &fds, secrets).map_err(|e| e.to_string())?;
                match data_of(resp)? {
                    Some(ResponseData::Generic { message }) => Ok(AgentMsg::Ok(message)),
                    _ => Ok(AgentMsg::Ok("File encrypted".into())),
                }
            }
            Command::FileDecrypt { input, output, identity, signature, passphrase } => {
                let inf = open_ro(&input).map_err(|e| e.to_string())?;
                // Decrypt into a temp beside the chosen output (same
                // filesystem → atomic rename). We only learn whether the
                // plaintext is a folder-archive after the agent reports it.
                let out_parent = output.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
                std::fs::create_dir_all(&out_parent).ok();
                let temp = crate::archive::TempFile::in_dir(&out_parent, "decrypt");
                let outf = create_new(&temp.path).map_err(|e| e.to_string())?;
                let mut fds = vec![inf.as_fd(), outf.as_fd()];
                let use_password = identity.is_none();
                let idf = match &identity {
                    Some(p) => Some(open_ro(p).map_err(|e| e.to_string())?),
                    None => None,
                };
                if let Some(f) = &idf {
                    fds.push(f.as_fd());
                }
                let sig_f;
                if let Some(sig) = &signature {
                    sig_f = open_ro(sig).map_err(|e| e.to_string())?;
                    fds.push(sig_f.as_fd());
                }
                let req = tesseract_proto::FileDecryptReq {
                    use_password,
                    verify: signature.is_some(),
                    expect_signer_fp: None,
                };
                let resp = client.call(Op::FileDecrypt(req), &fds, vec![passphrase]).map_err(|e| e.to_string())?;
                let (message, is_archive) = match data_of(resp)? {
                    Some(ResponseData::FileDone { message, is_archive }) => (message, is_archive),
                    Some(ResponseData::Generic { message }) => (message, false),
                    _ => ("File decrypted".to_string(), false),
                };
                if is_archive {
                    crate::archive::untar_into(&temp.path, &output)
                        .map_err(|e| format!("extract folder: {e}"))?;
                    Ok(AgentMsg::Ok(format!("{message} — folder extracted to {}", output.display())))
                } else if std::fs::rename(&temp.path, &output).is_err() {
                    std::fs::copy(&temp.path, &output).map_err(|e| format!("write output: {e}"))?;
                    Ok(AgentMsg::Ok(message))
                } else {
                    Ok(AgentMsg::Ok(message))
                }
            }
            Command::Keyslot { req, container, keyfiles, new_keyfiles, existing, new_secret } => {
                let file = open_rw(&container).map_err(|e| e.to_string())?;
                let kf: Vec<_> = keyfiles.iter().map(open_ro).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
                let nkf: Vec<_> = new_keyfiles.iter().map(open_ro).collect::<Result<_, _>>().map_err(|e| e.to_string())?;
                let mut fds = vec![file.as_fd()];
                fds.extend(kf.iter().map(|f| f.as_fd()));
                fds.extend(nkf.iter().map(|f| f.as_fd()));
                let mut secrets = vec![existing];
                if let Some(s) = new_secret {
                    secrets.push(s);
                }
                let resp = client.call(Op::ChangeKeyslot(req), &fds, secrets).map_err(|e| e.to_string())?;
                match data_of(resp)? {
                    Some(ResponseData::Generic { message }) => Ok(AgentMsg::Ok(message)),
                    _ => Ok(AgentMsg::Ok("Keyslot updated".into())),
                }
            }
            Command::HeaderBackup { container, output } => {
                let c = open_ro(&container).map_err(|e| e.to_string())?;
                let o = create_new(&output).map_err(|e| e.to_string())?;
                let resp = client.call(Op::HeaderBackup, &[c.as_fd(), o.as_fd()], vec![]).map_err(|e| e.to_string())?;
                data_of(resp)?;
                Ok(AgentMsg::Ok("Header backed up".into()))
            }
        }
    })();
    result.unwrap_or_else(AgentMsg::Error)
}

/// Spawn the worker thread. Returns the command sender.
pub fn spawn(out: relm4::Sender<AgentMsg>) -> std::sync::mpsc::Sender<Command> {
    let (tx, rx) = std::sync::mpsc::channel::<Command>();

    // event-stream connection
    {
        let out = out.clone();
        std::thread::Builder::new()
            .name("agent-events".into())
            .spawn(move || loop {
                match Client::connect() {
                    Ok(mut c) => {
                        if c.call(Op::Subscribe, &[], vec![]).is_ok() {
                            loop {
                                match c.next_event() {
                                    Ok(ev) => {
                                        if out.send(AgentMsg::Event(ev)).is_err() {
                                            return;
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                    Err(_) => {}
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            })
            .ok();
    }

    // command connection
    std::thread::Builder::new()
        .name("agent-commands".into())
        .spawn(move || {
            let mut client = match Client::connect_autostart() {
                Ok(mut c) => {
                    match c.call(Op::Hello { version: tesseract_proto::PROTOCOL_VERSION }, &[], vec![]) {
                        Ok(resp) => {
                            if let Some(ResponseData::Hello { hardened, agent_version, .. }) = resp.data {
                                out.send(AgentMsg::Connected { hardened, version: agent_version }).ok();
                            }
                        }
                        Err(e) => {
                            out.send(AgentMsg::Disconnected(e.to_string())).ok();
                        }
                    }
                    Some(c)
                }
                Err(e) => {
                    out.send(AgentMsg::Disconnected(e.to_string())).ok();
                    None
                }
            };

            while let Ok(cmd) = rx.recv() {
                if client.is_none() {
                    client = Client::connect_autostart().ok();
                    if client.is_none() {
                        out.send(AgentMsg::Error("agent unreachable".into())).ok();
                        continue;
                    }
                }
                let c = client.as_mut().unwrap();
                let msg = run_command(c, cmd);
                if matches!(msg, AgentMsg::Error(ref e) if e.contains("unreachable") || e.contains("Broken pipe")) {
                    client = None;
                }
                if out.send(msg).is_err() {
                    return;
                }
            }
        })
        .ok();

    tx
}
