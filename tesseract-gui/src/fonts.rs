//! Bundled DotGothic16 font.
//!
//! The TTF is embedded in the binary (so the app is self-contained) and
//! written into the user font directory on first launch, where fontconfig
//! picks it up — no separate install step. Used for titles, headings, and
//! the lock screen (see `theme::compile_css`).

/// Font family name as reported by fontconfig.
pub const HEADING_FAMILY: &str = "DotGothic16";

const FONT_TTF: &[u8] = include_bytes!("../resources/fonts/DotGothic16-Regular.ttf");

/// Ensure the bundled font is available to fontconfig for this session.
/// Writes it to `~/.local/share/fonts` if absent; fontconfig rescans the
/// directory (its mtime changes) the first time GTK needs a font, which
/// happens after this runs.
pub fn install_bundled() {
    let Some(dir) = dirs::data_dir().map(|d| d.join("fonts")) else {
        return;
    };
    let path = dir.join("DotGothic16-Regular.ttf");
    if path.exists() {
        return;
    }
    if std::fs::create_dir_all(&dir).is_ok() {
        let _ = std::fs::write(&path, FONT_TTF);
        // Best-effort cache refresh so the current process sees it even if
        // fontconfig was already initialised.
        let _ = std::process::Command::new("fc-cache")
            .arg("-f")
            .arg(&dir)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}
