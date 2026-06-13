//! tesseract-agent: the memory-locked key daemon.
//!
//! Startup order (brief §Security): dumpable off + core limit 0 →
//! mlockall → open socket & dirs → Landlock → no_new_privs → seccomp →
//! serve. The GUI/CLI talk to us over the 0600 peer-checked socket; every
//! cryptographic operation happens here, inside the sandbox, in locked
//! non-dumpable memory.

#![deny(unsafe_code)] // unsafe lives only in os::{secmem,harden}

mod dataplane;
mod ipc;
mod os;
mod service;
mod watch;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Context;
use tesseract_core::statemachine::WipeTrigger;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let mut no_sandbox = false;
    let mut foreground_log = "info".to_string();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--no-sandbox" => no_sandbox = true,
            "--log" => foreground_log = args.next().unwrap_or_else(|| "info".into()),
            "--version" => {
                println!("tesseract-agent {}", service::AGENT_VERSION);
                return Ok(());
            }
            other => anyhow::bail!("unknown argument {other}"),
        }
    }

    env_logger::Builder::new()
        .parse_filters(&std::env::var("RUST_LOG").unwrap_or(foreground_log))
        .init();

    // ---- phase 1: memory hygiene before any secret can exist ----
    os::harden::phase1_memory()?;

    // ---- open everything we need while we still can ----
    let runtime_dir = os::runtime_dir();
    let state_dir = os::state_dir();
    std::fs::create_dir_all(&runtime_dir).context("create runtime dir")?;
    std::fs::create_dir_all(&state_dir).context("create state dir")?;
    let socket_path = os::socket_path();
    let listener = ipc::bind(&socket_path)?;
    log::info!("listening on {}", socket_path.display());

    let agent = service::Agent::new(runtime_dir.clone(), state_dir.clone());

    // session/power watchers connect to D-Bus before the sandbox tightens
    watch::spawn_all(agent.clone());

    // ---- phase 2: sandbox ----
    if no_sandbox {
        log::warn!("--no-sandbox: Landlock/seccomp DISABLED (development only)");
    } else {
        match os::harden::apply_landlock(&runtime_dir, &state_dir) {
            Ok(true) => log::info!("Landlock enforced"),
            Ok(false) => log::warn!("Landlock unavailable"),
            Err(e) => log::warn!("Landlock failed: {e}"),
        }
        os::harden::no_new_privs()?;
        match os::harden::apply_seccomp() {
            Ok(_) => log::info!("seccomp filter active"),
            Err(e) => log::warn!("seccomp failed: {e} — continuing WITHOUT syscall filter"),
        }
    }

    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
    log::info!(
        "tesseract-agent {} ready (sandbox: {:?})",
        service::AGENT_VERSION,
        os::harden::sandbox_info()
    );

    // ---- serve ----
    static CONN_IDS: AtomicU64 = AtomicU64::new(1);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                log::warn!("accept: {e}");
                continue;
            }
        };
        let agent = agent.clone();
        let conn_id = CONN_IDS.fetch_add(1, Ordering::Relaxed);
        std::thread::Builder::new()
            .name(format!("conn-{conn_id}"))
            .spawn(move || {
                let mut conn = match ipc::Connection::new(stream) {
                    Ok(c) => c,
                    Err(e) => {
                        log::warn!("rejected connection: {e}");
                        return;
                    }
                };
                let mut subscribed = false;
                loop {
                    match conn.read_request() {
                        Ok(Some((req, fds, secrets))) => {
                            let resp = agent.handle(
                                req,
                                fds,
                                secrets,
                                conn_id,
                                &conn.stream,
                                &mut subscribed,
                            );
                            if conn.write_response(&resp).is_err() {
                                break;
                            }
                        }
                        Ok(None) => break, // clean EOF
                        Err(e) => {
                            log::warn!("conn-{conn_id} protocol error: {e}");
                            break;
                        }
                    }
                }
                agent.connection_closed(conn_id);
            })
            .ok();
    }

    // listener gone (shutdown): treat as logout
    agent.emergency_wipe(WipeTrigger::Logout, None);
    Ok(())
}
