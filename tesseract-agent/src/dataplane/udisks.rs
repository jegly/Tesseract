//! udisks2 integration: the desktop-standard, polkit-mediated, non-root path
//! for turning the decrypted image into a mounted filesystem (DECISIONS.md
//! D-06). Loop-setup → Filesystem.Mount / Block.Format → Unmount → Delete.
//! Every call is unprivileged D-Bus; polkit policy is the distro's, exactly
//! as for USB sticks.

use std::collections::HashMap;
use std::os::fd::{AsFd, OwnedFd};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use zbus::blocking::Connection;
use zbus::zvariant::{Fd, ObjectPath, OwnedObjectPath, Value};

const UDISKS_DEST: &str = "org.freedesktop.UDisks2";
const MANAGER_PATH: &str = "/org/freedesktop/UDisks2/Manager";

pub struct Udisks {
    conn: Connection,
}

impl std::fmt::Debug for Udisks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Udisks")
    }
}

#[derive(Debug, Clone)]
pub struct LoopHandle {
    pub object: OwnedObjectPath,
    pub device: String,
}

impl Udisks {
    pub fn connect() -> Result<Self> {
        let conn = Connection::system().context("connect system bus")?;
        Ok(Self { conn })
    }

    /// Set up a loop device over the (FUSE-served) image fd.
    pub fn loop_setup(&self, image: OwnedFd, read_only: bool) -> Result<LoopHandle> {
        let mut opts: HashMap<&str, Value> = HashMap::new();
        opts.insert("read-only", Value::from(read_only));
        let reply = self.conn.call_method(
            Some(UDISKS_DEST),
            MANAGER_PATH,
            Some("org.freedesktop.UDisks2.Manager"),
            "LoopSetup",
            &(Fd::from(image.as_fd()), opts),
        )?;
        let body = reply.body();
        let path: OwnedObjectPath = body.deserialize()?;
        // resolve the /dev name
        let device = self.block_device_name(&path)?;
        // give udev a moment to settle the new node
        std::thread::sleep(Duration::from_millis(150));
        Ok(LoopHandle { object: path, device })
    }

    fn block_device_name(&self, obj: &OwnedObjectPath) -> Result<String> {
        let reply = self.conn.call_method(
            Some(UDISKS_DEST),
            obj,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.UDisks2.Block", "Device"),
        )?;
        let body = reply.body();
        let v: zbus::zvariant::OwnedValue = body.deserialize()?;
        let bytes: Vec<u8> = Vec::try_from(v).map_err(|_| anyhow!("Device type"))?;
        let s = String::from_utf8_lossy(&bytes);
        Ok(s.trim_end_matches('\0').to_string())
    }

    /// Mount the filesystem on a block object. Returns the mount point.
    pub fn mount(&self, obj: &OwnedObjectPath, read_only: bool) -> Result<String> {
        let mut opts: HashMap<&str, Value> = HashMap::new();
        if read_only {
            opts.insert("options", Value::from("ro"));
        }
        let reply = self.conn.call_method(
            Some(UDISKS_DEST),
            obj,
            Some("org.freedesktop.UDisks2.Filesystem"),
            "Mount",
            &(opts,),
        )?;
        let body = reply.body();
        let mp: String = body.deserialize()?;
        Ok(mp)
    }

    pub fn unmount(&self, obj: &OwnedObjectPath, force: bool) -> Result<()> {
        let mut opts: HashMap<&str, Value> = HashMap::new();
        opts.insert("force", Value::from(force));
        self.conn
            .call_method(
                Some(UDISKS_DEST),
                obj,
                Some("org.freedesktop.UDisks2.Filesystem"),
                "Unmount",
                &(opts,),
            )
            .map(|_| ())
            .context("udisks unmount")
    }

    /// mkfs via udisks (used at create time).
    pub fn format(&self, obj: &OwnedObjectPath, fstype: &str, label: &str) -> Result<()> {
        let mut opts: HashMap<&str, Value> = HashMap::new();
        opts.insert("update-partition-type", Value::from(false));
        if !label.is_empty() {
            opts.insert("label", Value::from(label));
        }
        self.conn
            .call_method(
                Some(UDISKS_DEST),
                obj,
                Some("org.freedesktop.UDisks2.Block"),
                "Format",
                &(fstype, opts),
            )
            .map(|_| ())
            .context("udisks format")
    }

    /// Tear down the loop device.
    pub fn loop_delete(&self, obj: &OwnedObjectPath) -> Result<()> {
        let opts: HashMap<&str, Value> = HashMap::new();
        self.conn
            .call_method(
                Some(UDISKS_DEST),
                obj,
                Some("org.freedesktop.UDisks2.Loop"),
                "Delete",
                &(opts,),
            )
            .map(|_| ())
            .context("udisks loop delete")
    }

    /// Find the filesystem mount points of a block object (if mounted).
    pub fn mount_points(&self, obj: &OwnedObjectPath) -> Result<Vec<String>> {
        let reply = self.conn.call_method(
            Some(UDISKS_DEST),
            obj,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &("org.freedesktop.UDisks2.Filesystem", "MountPoints"),
        )?;
        let body = reply.body();
        let v: zbus::zvariant::OwnedValue = body.deserialize()?;
        let arrays: Vec<Vec<u8>> = Vec::try_from(v).unwrap_or_default();
        Ok(arrays
            .into_iter()
            .map(|b| String::from_utf8_lossy(&b).trim_end_matches('\0').to_string())
            .collect())
    }
}

// keep ObjectPath import used even when features shift
#[allow(dead_code)]
fn _t(p: ObjectPath<'_>) -> String {
    p.to_string()
}
