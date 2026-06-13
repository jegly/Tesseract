//! Power/session watchers feeding EmergencyWipe triggers:
//! - logind `PrepareForSleep` (system bus) → suspend wipe
//! - logind session `Lock` + `Active` property → lock / fast-user-switch
//! - `org.freedesktop.ScreenSaver` + `org.gnome.ScreenSaver` `ActiveChanged`
//!   (session bus) → lock wipe
//! - SIGTERM/unit stop → logout wipe (systemd user unit stops at logout)
//! - 5s idle ticker → inactivity wipe + countdown events + tamper checks

use std::sync::Arc;
use std::time::Duration;

use tesseract_core::statemachine::WipeTrigger;
use zbus::blocking::{Connection, MessageIterator};
use zbus::MatchRule;

use crate::service::Agent;

pub fn spawn_all(agent: Arc<Agent>) {
    {
        let agent = agent.clone();
        std::thread::Builder::new()
            .name("watch-logind".into())
            .spawn(move || {
                if let Err(e) = watch_logind(agent) {
                    log::warn!("logind watcher stopped: {e}");
                }
            })
            .ok();
    }
    {
        let agent = agent.clone();
        std::thread::Builder::new()
            .name("watch-screensaver".into())
            .spawn(move || {
                if let Err(e) = watch_screensaver(agent) {
                    log::warn!("screensaver watcher stopped: {e}");
                }
            })
            .ok();
    }
    {
        let agent = agent.clone();
        std::thread::Builder::new()
            .name("idle-ticker".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_secs(5));
                agent.idle_tick();
            })
            .ok();
    }
}

fn watch_logind(agent: Arc<Agent>) -> anyhow::Result<()> {
    let conn = Connection::system()?;

    // PrepareForSleep(true) fires just before suspend/hibernate
    let sleep_rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.login1.Manager")?
        .member("PrepareForSleep")?
        .build();
    // session Lock signal + property changes (Active=false on user switch)
    let lock_rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.login1.Session")?
        .member("Lock")?
        .build();
    let props_rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.DBus.Properties")?
        .member("PropertiesChanged")?
        .path_namespace("/org/freedesktop/login1/session")?
        .build();
    let removed_rule = MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface("org.freedesktop.login1.Manager")?
        .member("SessionRemoved")?
        .build();

    for rule in [&sleep_rule, &lock_rule, &props_rule, &removed_rule] {
        conn.call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "AddMatch",
            &rule.to_string(),
        )?;
    }

    let my_session = std::env::var("XDG_SESSION_ID").unwrap_or_default();
    let iter = MessageIterator::from(&conn);
    for msg in iter.flatten() {
        let header = msg.header();
        let member = header.member().map(|m| m.to_string()).unwrap_or_default();
        match member.as_str() {
            "PrepareForSleep" => {
                if let Ok(start) = msg.body().deserialize::<bool>() {
                    if start {
                        log::info!("PrepareForSleep → wipe");
                        agent.emergency_wipe(WipeTrigger::PrepareForSleep, None);
                    }
                }
            }
            "Lock" => {
                log::info!("session Lock → wipe");
                agent.emergency_wipe(WipeTrigger::SessionLock, None);
            }
            "SessionRemoved" => {
                if let Ok((id, _path)) = msg
                    .body()
                    .deserialize::<(String, zbus::zvariant::OwnedObjectPath)>()
                {
                    if !my_session.is_empty() && id == my_session {
                        log::info!("our session removed → logout wipe");
                        agent.emergency_wipe(WipeTrigger::Logout, None);
                    }
                }
            }
            "PropertiesChanged" => {
                if let Ok((iface, changed, _inv)) = msg.body().deserialize::<(
                    String,
                    std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
                    Vec<String>,
                )>() {
                    let _ = iface;
                    if let Some(v) = changed.get("Active") {
                        if let Ok(active) = bool::try_from(v.try_clone().unwrap_or_else(|_| zbus::zvariant::OwnedValue::from(true))) {
                            if !active {
                                log::info!("session inactive → fast-user-switch wipe");
                                agent.emergency_wipe(WipeTrigger::FastUserSwitch, None);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn watch_screensaver(agent: Arc<Agent>) -> anyhow::Result<()> {
    let conn = Connection::session()?;
    for iface in ["org.freedesktop.ScreenSaver", "org.gnome.ScreenSaver"] {
        let rule = MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .interface(iface)?
            .member("ActiveChanged")?
            .build();
        conn.call_method(
            Some("org.freedesktop.DBus"),
            "/org/freedesktop/DBus",
            Some("org.freedesktop.DBus"),
            "AddMatch",
            &rule.to_string(),
        )?;
    }
    let iter = MessageIterator::from(&conn);
    for msg in iter.flatten() {
        let header = msg.header();
        if header.member().map(|m| m.as_str() == "ActiveChanged") == Some(true) {
            if let Ok(active) = msg.body().deserialize::<bool>() {
                if active {
                    log::info!("screensaver/lock active → wipe");
                    agent.emergency_wipe(WipeTrigger::SessionLock, None);
                }
            }
        }
    }
    Ok(())
}
