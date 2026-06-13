//! GUI settings: TOML at ~/.config/tesseract/settings.toml (DECISIONS.md
//! D-08). Atomic-rename writes; trivially importable/exportable. Agent-side
//! behavior (auto-dismount, cache policy, data plane) lives in the agent's
//! own config and is edited through the same Preferences dialog over IPC.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

fn config_dir() -> PathBuf {
    // Travel mode: a `tesseract-portable` marker next to the executable
    // keeps every setting on the removable medium.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let portable = dir.join("tesseract-portable");
            if portable.exists() {
                return portable;
            }
        }
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("tesseract")
}

pub fn settings_path() -> PathBuf {
    config_dir().join("settings.toml")
}

pub fn themes_dir() -> PathBuf {
    config_dir().join("themes")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Appearance {
    /// Theme id: "follow-system", "dracula", "catppuccin-latte",
    /// "catppuccin-frappe", "catppuccin-macchiato", "catppuccin-mocha",
    /// "vintage-light", "neon-tessera", or a user theme file stem.
    pub theme: String,
    /// Accent override as #RRGGBB ("" = theme default).
    pub accent: String,
    /// Interface density: "comfortable" | "compact".
    pub density: String,
    /// UI font override ("" = system).
    pub font: String,
    /// Monospace for technical values (uuids, fingerprints).
    pub mono_technical: bool,
    /// Animations: "system" | "on" | "off" (system = honor reduce-motion).
    pub animations: String,
    /// Serif accent font for the Vintage theme.
    pub vintage_serif: bool,
    /// Neon glow intensity for Neon Tessera (0-100).
    pub glow_intensity: u32,
    /// Remember window size.
    pub remember_window: bool,
    pub window_width: i32,
    pub window_height: i32,
    /// Start hidden in the background (service mode).
    pub start_in_background: bool,
    /// Keep running when the window closes.
    pub run_in_background: bool,
    /// Show the status footer bar.
    pub show_status_bar: bool,
    /// Show idle-dismount countdowns on volume rows.
    pub show_countdowns: bool,
}

impl Default for Appearance {
    fn default() -> Self {
        Self {
            theme: "follow-system".into(),
            accent: String::new(),
            density: "comfortable".into(),
            font: String::new(),
            mono_technical: true,
            animations: "system".into(),
            vintage_serif: true,
            glow_intensity: 60,
            remember_window: true,
            window_width: 1040,
            window_height: 720,
            start_in_background: false,
            run_in_background: true,
            show_status_bar: true,
            show_countdowns: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SecurityDefaults {
    /// Default cascade for new volumes (registry ids, innermost first).
    pub cascade: Vec<u16>,
    pub hash: u16,
    /// "argon2id" | "scrypt" | "pbkdf2" | "balloon"
    pub kdf: String,
    /// 0 = benchmarked defaults.
    pub kdf_memory: u32,
    pub kdf_time: u32,
    pub kdf_parallelism: u32,
    /// Default PIM-equivalent.
    pub default_pim: u32,
    /// Keyslot AEAD registry id.
    pub slot_aead: u16,
    /// Offer experimental algorithms in pickers (per-volume opt-in still
    /// required and labeled).
    pub show_experimental: bool,
    /// Minimum passphrase length the wizard accepts.
    pub min_passphrase_len: u32,
    /// Warn (don't block) below this zxcvbn-ish strength score (0-4).
    pub warn_strength_below: u32,
    /// Clear clipboard after copying anything sensitive (seconds, 0 = never).
    pub clipboard_clear_secs: u32,
    /// Require typing the label to confirm decrypt-in-place.
    pub confirm_destructive: bool,
    /// Panic hotkey enabled (global within the app window).
    pub panic_hotkey: bool,
    /// Panic requires a confirmation dialog.
    pub panic_confirm: bool,
    /// Warn when swap is enabled without encryption.
    pub warn_swap: bool,
    /// Default to requiring a PQC keyslot on new volumes.
    pub default_require_pqc: bool,
    /// Lock the app window behind a password on launch.
    pub app_lock_enabled: bool,
    /// Argon2id PHC hash of the app-lock password ("" = not set).
    pub app_lock_hash: String,
}

impl Default for SecurityDefaults {
    fn default() -> Self {
        Self {
            cascade: vec![1], // AES-256
            hash: 3,          // BLAKE3
            kdf: "argon2id".into(),
            kdf_memory: 0,
            kdf_time: 0,
            kdf_parallelism: 0,
            default_pim: 0,
            slot_aead: 1, // XChaCha20-Poly1305
            show_experimental: false,
            min_passphrase_len: 8,
            warn_strength_below: 3,
            clipboard_clear_secs: 45,
            confirm_destructive: true,
            panic_hotkey: true,
            panic_confirm: true,
            warn_swap: true,
            default_require_pqc: false,
            app_lock_enabled: false,
            app_lock_hash: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MountingDefaults {
    /// "" = $XDG_RUNTIME_DIR/tesseract.
    pub default_mount_dir: String,
    pub read_only_default: bool,
    pub removable_default: bool,
    pub open_file_manager: bool,
    pub no_cache_default: bool,
    /// Mount favorites automatically when the GUI starts.
    pub auto_mount_favorites: bool,
    /// Ask for confirmation before force-unmounting busy volumes.
    pub confirm_force_unmount: bool,
}

impl Default for MountingDefaults {
    fn default() -> Self {
        Self {
            default_mount_dir: String::new(),
            read_only_default: false,
            removable_default: true,
            open_file_manager: true,
            no_cache_default: false,
            auto_mount_favorites: false,
            confirm_force_unmount: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct VolumeDefaults {
    /// "ext4" | "btrfs" | "xfs" | "exfat" | "vfat" | "none"
    pub filesystem: String,
    pub quick_format: bool,
    pub dynamic_default: bool,
    pub sector_size: u32,
    /// Default new-volume size string shown in the wizard.
    pub default_size: String,
    /// Default container directory ("" = ~/Documents).
    pub container_dir: String,
}

impl Default for VolumeDefaults {
    fn default() -> Self {
        Self {
            filesystem: "ext4".into(),
            quick_format: true,
            dynamic_default: false,
            sector_size: 4096,
            default_size: "1G".into(),
            container_dir: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct KeyfileSettings {
    /// "" = ~/.config/tesseract/keyfiles
    pub keyfile_dir: String,
    pub generator_default_len: u32,
    /// Remember keyfile paths per favorite (paths only, never contents).
    pub remember_keyfiles: bool,
}

impl Default for KeyfileSettings {
    fn default() -> Self {
        Self {
            keyfile_dir: String::new(),
            generator_default_len: 4096,
            remember_keyfiles: true,
        }
    }
}

/// A saved volume (favorites).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Favorite {
    pub label: String,
    pub container: String,
    pub read_only: bool,
    pub protect_hidden: bool,
    pub pim: u32,
    pub keyfiles: Vec<String>,
    pub identity: String,
    pub auto_mount: bool,
    pub open_file_manager: bool,
    pub data_plane: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Advanced {
    /// "" = default $XDG_RUNTIME_DIR/tesseract.sock
    pub socket_path: String,
    /// "error" | "warn" | "info" | "debug"
    pub log_level: String,
    /// Data plane preference: "fuse" | "ublk" | "dmcrypt"
    pub data_plane: String,
    /// Path to an external entropy source file/FIFO (e.g. trio-rng output).
    pub external_entropy: String,
    /// Collect pointer-timing entropy during wizards.
    pub collect_ui_entropy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Settings {
    pub appearance: Appearance,
    pub security: SecurityDefaults,
    pub mounting: MountingDefaults,
    pub volume_defaults: VolumeDefaults,
    pub keyfiles: KeyfileSettings,
    pub advanced: Advanced,
    pub favorites: Vec<Favorite>,
}

impl Settings {
    pub fn load() -> Self {
        std::fs::read_to_string(settings_path())
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        let path = settings_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        if let Ok(s) = toml::to_string_pretty(self) {
            let tmp = path.with_extension("toml.tmp");
            if std::fs::write(&tmp, s).is_ok() {
                std::fs::rename(&tmp, &path).ok();
            }
        }
    }

    pub fn export_to(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::write(path, toml::to_string_pretty(self).unwrap_or_default())
    }

    pub fn import_from(path: &std::path::Path) -> std::io::Result<Self> {
        let s = std::fs::read_to_string(path)?;
        toml::from_str(&s).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}
