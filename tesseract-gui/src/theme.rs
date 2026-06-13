//! Theme engine: palette manifests (TOML) compiled into GTK CSS through a
//! user-priority `CssProvider`, layered over libadwaita's `StyleManager`
//! light/dark base. Live switching, custom accent override, density, glow.
//!
//! Built-ins: Dracula, Catppuccin (Latte/Frappé/Macchiato/Mocha), Vintage
//! Light, Neon Tessera (cyberpunk), Follow System. User themes drop into
//! ~/.config/tesseract/themes/*.toml with the same manifest schema.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Palette {
    pub id: String,
    pub name: String,
    pub dark: bool,
    /// Pure libadwaita look (no palette override), only accent applies.
    pub follow_system: bool,

    pub window_bg: String,
    pub view_bg: String,
    pub surface: String,
    pub surface_alt: String,
    pub headerbar: String,
    pub sidebar: String,
    pub card: String,
    pub popover: String,
    pub text: String,
    pub text_dim: String,
    pub accent: String,
    pub accent_fg: String,
    /// Secondary accent (chips, gradients, neon highlights).
    pub accent2: String,
    pub success: String,
    pub warning: String,
    pub error: String,
    pub border: String,

    /// Corner radius token (px) for cards/dialogs; buttons use pill shape.
    pub radius: u32,
    /// Neon glow box-shadows (cyberpunk).
    pub glow: bool,
    /// Serif accent font for headings (vintage).
    pub serif: bool,
}

impl Default for Palette {
    fn default() -> Self {
        Self {
            id: "follow-system".into(),
            name: "Follow System".into(),
            dark: false,
            follow_system: true,
            window_bg: String::new(),
            view_bg: String::new(),
            surface: String::new(),
            surface_alt: String::new(),
            headerbar: String::new(),
            sidebar: String::new(),
            card: String::new(),
            popover: String::new(),
            text: String::new(),
            text_dim: String::new(),
            accent: String::new(),
            accent_fg: String::new(),
            accent2: String::new(),
            success: String::new(),
            warning: String::new(),
            error: String::new(),
            border: String::new(),
            radius: 12,
            glow: false,
            serif: false,
        }
    }
}

macro_rules! palette {
    ($id:expr, $name:expr, dark=$dark:expr, win=$win:expr, view=$view:expr,
     surface=$surface:expr, alt=$alt:expr, header=$header:expr, side=$side:expr,
     card=$card:expr, pop=$pop:expr, text=$text:expr, dim=$dim:expr,
     accent=$accent:expr, accent_fg=$afg:expr, accent2=$a2:expr,
     ok=$ok:expr, warn=$warn:expr, err=$err:expr, border=$border:expr,
     radius=$radius:expr, glow=$glow:expr, serif=$serif:expr) => {
        Palette {
            id: $id.into(),
            name: $name.into(),
            dark: $dark,
            follow_system: false,
            window_bg: $win.into(),
            view_bg: $view.into(),
            surface: $surface.into(),
            surface_alt: $alt.into(),
            headerbar: $header.into(),
            sidebar: $side.into(),
            card: $card.into(),
            popover: $pop.into(),
            text: $text.into(),
            text_dim: $dim.into(),
            accent: $accent.into(),
            accent_fg: $afg.into(),
            accent2: $a2.into(),
            success: $ok.into(),
            warning: $warn.into(),
            error: $err.into(),
            border: $border.into(),
            radius: $radius,
            glow: $glow,
            serif: $serif,
        }
    };
}

pub fn builtin_themes() -> Vec<Palette> {
    vec![
        Palette::default(), // follow-system
        palette!("dracula", "Dracula", dark = true,
            win = "#282a36", view = "#21222c", surface = "#343746", alt = "#3c3f51",
            header = "#21222c", side = "#262833", card = "#313342", pop = "#343746",
            text = "#f8f8f2", dim = "#9ea8c7",
            accent = "#bd93f9", accent_fg = "#1c1d26", accent2 = "#ff79c6",
            ok = "#50fa7b", warn = "#f1fa8c", err = "#ff5555", border = "#44475a",
            radius = 12, glow = false, serif = false),
        palette!("catppuccin-latte", "Catppuccin Latte", dark = false,
            win = "#eff1f5", view = "#ffffff", surface = "#e6e9ef", alt = "#dce0e8",
            header = "#e6e9ef", side = "#e9ecf2", card = "#ffffff", pop = "#eff1f5",
            text = "#4c4f69", dim = "#6c6f85",
            accent = "#8839ef", accent_fg = "#ffffff", accent2 = "#ea76cb",
            ok = "#40a02b", warn = "#df8e1d", err = "#d20f39", border = "#ccd0da",
            radius = 12, glow = false, serif = false),
        palette!("catppuccin-frappe", "Catppuccin Frappé", dark = true,
            win = "#303446", view = "#292c3c", surface = "#414559", alt = "#51576d",
            header = "#292c3c", side = "#2e3244", card = "#3b3f54", pop = "#414559",
            text = "#c6d0f5", dim = "#a5adce",
            accent = "#ca9ee6", accent_fg = "#232634", accent2 = "#f4b8e4",
            ok = "#a6d189", warn = "#e5c890", err = "#e78284", border = "#51576d",
            radius = 12, glow = false, serif = false),
        palette!("catppuccin-macchiato", "Catppuccin Macchiato", dark = true,
            win = "#24273a", view = "#1e2030", surface = "#363a4f", alt = "#494d64",
            header = "#1e2030", side = "#222539", card = "#2f3247", pop = "#363a4f",
            text = "#cad3f5", dim = "#a5adcb",
            accent = "#c6a0f6", accent_fg = "#181926", accent2 = "#f5bde6",
            ok = "#a6da95", warn = "#eed49f", err = "#ed8796", border = "#494d64",
            radius = 12, glow = false, serif = false),
        palette!("catppuccin-mocha", "Catppuccin Mocha", dark = true,
            win = "#1e1e2e", view = "#181825", surface = "#313244", alt = "#45475a",
            header = "#181825", side = "#1c1c2c", card = "#2a2a3c", pop = "#313244",
            text = "#cdd6f4", dim = "#a6adc8",
            accent = "#cba6f7", accent_fg = "#11111b", accent2 = "#f5c2e7",
            ok = "#a6e3a1", warn = "#f9e2af", err = "#f38ba8", border = "#45475a",
            radius = 12, glow = false, serif = false),
        palette!("vintage-light", "Vintage Light", dark = false,
            win = "#f6efe1", view = "#fbf6ea", surface = "#efe5d0", alt = "#e7dabf",
            header = "#efe5d0", side = "#f1e9d7", card = "#fbf6ea", pop = "#f3ecdc",
            text = "#46392b", dim = "#7a6a55",
            accent = "#b07d3a", accent_fg = "#fff8ec", accent2 = "#4f7c74",
            ok = "#5f7d4f", warn = "#b07d3a", err = "#a14d3a", border = "#d8c8a8",
            radius = 14, glow = false, serif = true),
        palette!("neon-tessera", "Neon Tessera", dark = true,
            win = "#0a0e14", view = "#070a10", surface = "#11161f", alt = "#161d29",
            header = "#0a0e14", side = "#0d1118", card = "#10151e", pop = "#131923",
            text = "#d8e6f2", dim = "#7e93a8",
            accent = "#00e5ff", accent_fg = "#03131a", accent2 = "#ff2ec4",
            ok = "#00ff9c", warn = "#ffc400", err = "#ff3860", border = "#1d2735",
            radius = 10, glow = true, serif = false),

        // --- terminal / editor schemes (Gogh-derived palettes) ---
        palette!("adventure-time", "Adventure Time", dark = true,
            win = "#1f1d45", view = "#17152f", surface = "#2a2755", alt = "#34306a",
            header = "#17152f", side = "#1b1940", card = "#252253", pop = "#2a2755",
            text = "#f8dcc0", dim = "#a39ac4",
            accent = "#e7741e", accent_fg = "#1f1d45", accent2 = "#5cf9ff",
            ok = "#4ab118", warn = "#e7b000", err = "#bd0013", border = "#3a356f",
            radius = 12, glow = false, serif = false),
        palette!("borland", "Borland", dark = true,
            win = "#0000a4", view = "#000084", surface = "#0a1ab0", alt = "#1730c0",
            header = "#000084", side = "#00118f", card = "#0817ac", pop = "#0a1ab0",
            text = "#ffff80", dim = "#b6b6e6",
            accent = "#ffff4e", accent_fg = "#0000a4", accent2 = "#4fe9fc",
            ok = "#4efa78", warn = "#ffff4e", err = "#ff5959", border = "#2a40c4",
            radius = 8, glow = false, serif = false),
        palette!("c64", "Commodore 64", dark = true,
            win = "#40318d", view = "#352978", surface = "#4d3ea0", alt = "#5a4bb0",
            header = "#352978", side = "#3a2e85", card = "#473a98", pop = "#4d3ea0",
            text = "#cabdf2", dim = "#9385c9",
            accent = "#bfce72", accent_fg = "#40318d", accent2 = "#67b6bd",
            ok = "#55a049", warn = "#bfce72", err = "#883932", border = "#5648a8",
            radius = 8, glow = false, serif = false),
        palette!("fairy-floss-dark", "Fairy Floss Dark", dark = true,
            win = "#3b364c", view = "#332f42", surface = "#4a4564", alt = "#56506f",
            header = "#332f42", side = "#3d3850", card = "#453f5c", pop = "#4a4564",
            text = "#f8f8f2", dim = "#c5bdda",
            accent = "#ffb8d1", accent_fg = "#3b364c", accent2 = "#c5a3ff",
            ok = "#c2ffdf", warn = "#ffea00", err = "#ff857f", border = "#564f6f",
            radius = 14, glow = false, serif = false),
        palette!("flat", "Flat", dark = true,
            win = "#2c3e50", view = "#243342", surface = "#34495e", alt = "#3e5870",
            header = "#243342", side = "#2a3a4a", card = "#324356", pop = "#34495e",
            text = "#ecf0f1", dim = "#a4b5c4",
            accent = "#3498db", accent_fg = "#ffffff", accent2 = "#9b59b6",
            ok = "#2ecc71", warn = "#f1c40f", err = "#e74c3c", border = "#3e5066",
            radius = 12, glow = false, serif = false),
        palette!("gogh", "Gogh — Starry Night", dark = true,
            win = "#0d1b34", view = "#0a1628", surface = "#14264a", alt = "#1b3260",
            header = "#0a1628", side = "#0f1d38", card = "#122243", pop = "#14264a",
            text = "#e8eeff", dim = "#94a8cc",
            accent = "#f4cd3a", accent_fg = "#0d1b34", accent2 = "#5b8dd9",
            ok = "#6bbf59", warn = "#f4cd3a", err = "#d9603b", border = "#21345f",
            radius = 12, glow = false, serif = false),
        palette!("grass", "Grass", dark = true,
            win = "#13773d", view = "#0f6234", surface = "#1c8a4a", alt = "#239a55",
            header = "#0f6234", side = "#126b38", card = "#188044", pop = "#1c8a4a",
            text = "#fff0a5", dim = "#bcd6a0",
            accent = "#e7b000", accent_fg = "#13773d", accent2 = "#7fd9b0",
            ok = "#9bea6a", warn = "#e7b000", err = "#cf3a2a", border = "#2a9a5e",
            radius = 12, glow = false, serif = false),
        palette!("gruvbox-material", "Gruvbox Material", dark = true,
            win = "#282828", view = "#1f1f1f", surface = "#32302f", alt = "#3c3836",
            header = "#1f1f1f", side = "#252423", card = "#2f2d2c", pop = "#32302f",
            text = "#d4be98", dim = "#a89984",
            accent = "#d8a657", accent_fg = "#282828", accent2 = "#7daea3",
            ok = "#a9b665", warn = "#d8a657", err = "#ea6962", border = "#45403d",
            radius = 12, glow = false, serif = false),
        palette!("homebrew", "Homebrew", dark = true,
            win = "#000000", view = "#050505", surface = "#0c140c", alt = "#122012",
            header = "#000000", side = "#040804", card = "#0a120a", pop = "#0c140c",
            text = "#00d000", dim = "#1f8a1f",
            accent = "#00ff00", accent_fg = "#001500", accent2 = "#00d8b2",
            ok = "#00c800", warn = "#9a9a00", err = "#c80000", border = "#103810",
            radius = 8, glow = true, serif = false),
        palette!("ocean", "Ocean", dark = true,
            win = "#2b303b", view = "#232831", surface = "#343d46", alt = "#3e4855",
            header = "#232831", side = "#2a2f39", card = "#313844", pop = "#343d46",
            text = "#c0c5ce", dim = "#8b95a4",
            accent = "#8fa1b3", accent_fg = "#1b2027", accent2 = "#b48ead",
            ok = "#a3be8c", warn = "#ebcb8b", err = "#bf616a", border = "#3e4855",
            radius = 12, glow = false, serif = false),
        palette!("kokuban", "Kokuban", dark = true,
            win = "#1f3526", view = "#192c1f", surface = "#274030", alt = "#2f4c39",
            header = "#192c1f", side = "#1d3123", card = "#243c2d", pop = "#274030",
            text = "#f0f0e8", dim = "#a9c2af",
            accent = "#f2e9c8", accent_fg = "#1f3526", accent2 = "#f2b4b4",
            ok = "#a8d8a0", warn = "#f0e68c", err = "#f2a0a0", border = "#315040",
            radius = 12, glow = false, serif = false),
        palette!("mono-cyan", "Mono Cyan", dark = true,
            win = "#081414", view = "#040e0e", surface = "#0e1f1f", alt = "#143030",
            header = "#040e0e", side = "#0a1818", card = "#0c1c1c", pop = "#0e1f1f",
            text = "#c8f0f0", dim = "#5c9a9a",
            accent = "#00d0d0", accent_fg = "#021616", accent2 = "#5ce0e0",
            ok = "#00d0a0", warn = "#80e0e0", err = "#e08585", border = "#163838",
            radius = 10, glow = true, serif = false),
    ]
}

/// All themes: built-ins + user manifests from the themes dir.
pub fn all_themes() -> Vec<Palette> {
    let mut themes = builtin_themes();
    if let Ok(entries) = std::fs::read_dir(crate::config::themes_dir()) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                if let Ok(s) = std::fs::read_to_string(&path) {
                    if let Ok(mut p) = toml::from_str::<Palette>(&s) {
                        if p.id.is_empty() {
                            p.id = path
                                .file_stem()
                                .map(|s| s.to_string_lossy().into_owned())
                                .unwrap_or_default();
                        }
                        p.follow_system = false;
                        themes.push(p);
                    }
                }
            }
        }
    }
    themes
}

pub fn find_theme(id: &str) -> Palette {
    all_themes()
        .into_iter()
        .find(|t| t.id == id)
        .unwrap_or_default()
}

fn alpha(hex: &str, a: f32) -> String {
    let h = hex.trim_start_matches('#');
    if h.len() != 6 {
        return format!("alpha(currentColor, {a})");
    }
    let r = u8::from_str_radix(&h[0..2], 16).unwrap_or(0);
    let g = u8::from_str_radix(&h[2..4], 16).unwrap_or(0);
    let b = u8::from_str_radix(&h[4..6], 16).unwrap_or(0);
    format!("rgba({r}, {g}, {b}, {a:.2})")
}

/// Compile the palette + user preferences into CSS.
pub fn compile_css(p: &Palette, accent_override: &str, glow_intensity: u32, density: &str, font: &str) -> String {
    let mut css = String::with_capacity(8192);
    let accent = if accent_override.len() == 7 && accent_override.starts_with('#') {
        accent_override.to_string()
    } else {
        p.accent.clone()
    };

    // ---- palette: libadwaita CSS variables (adw >= 1.6) ----
    if !p.follow_system {
        css.push_str(&format!(
            ":root {{
  --window-bg-color: {win};
  --window-fg-color: {text};
  --view-bg-color: {view};
  --view-fg-color: {text};
  --headerbar-bg-color: {header};
  --headerbar-fg-color: {text};
  --headerbar-backdrop-color: {win};
  --sidebar-bg-color: {side};
  --sidebar-fg-color: {text};
  --sidebar-backdrop-color: {win};
  --secondary-sidebar-bg-color: {side};
  --secondary-sidebar-fg-color: {text};
  --card-bg-color: {card};
  --card-fg-color: {text};
  --dialog-bg-color: {surface};
  --dialog-fg-color: {text};
  --popover-bg-color: {pop};
  --popover-fg-color: {text};
  --success-color: {ok};
  --success-bg-color: {ok};
  --success-fg-color: {afg};
  --warning-color: {warn};
  --warning-bg-color: {warn};
  --warning-fg-color: {afg};
  --error-color: {err};
  --error-bg-color: {err};
  --error-fg-color: {afg};
  --destructive-color: {err};
  --destructive-bg-color: {err};
  --destructive-fg-color: {afg};
}}\n",
            win = p.window_bg,
            view = p.view_bg,
            header = p.headerbar,
            side = p.sidebar,
            card = p.card,
            pop = p.popover,
            surface = p.surface,
            text = p.text,
            ok = p.success,
            warn = p.warning,
            err = p.error,
            afg = p.accent_fg,
        ));
    }
    if !accent.is_empty() {
        css.push_str(&format!(
            ":root {{
  --accent-bg-color: {accent};
  --accent-fg-color: {afg};
  --accent-color: {accent};
}}\n",
            afg = if p.accent_fg.is_empty() { "#ffffff".into() } else { p.accent_fg.clone() },
        ));
    }

    // ---- shape language: rounded cards, pill controls, soft elevation ----
    let radius = p.radius;
    let shadow = if p.dark {
        "0 1px 3px rgba(0,0,0,0.42), 0 4px 14px rgba(0,0,0,0.28)"
    } else {
        "0 1px 3px rgba(60,50,40,0.10), 0 4px 16px rgba(60,50,40,0.08)"
    };
    css.push_str(&format!(
        "
.card, .tsr-card, preferencesgroup > box > listbox.boxed-list {{
  border-radius: {radius}px;
}}
.tsr-card {{
  background-color: var(--card-bg-color);
  box-shadow: {shadow};
  border: 1px solid {border};
  padding: 4px;
}}
.tsr-elevated {{ box-shadow: {shadow}; }}
button.pill {{ border-radius: 999px; padding-left: 22px; padding-right: 22px; }}
button {{ border-radius: 10px; }}
entry, spinbutton {{ border-radius: 10px; }}
.boxed-list {{ border-radius: {radius}px; }}
.tsr-chip {{
  border-radius: 999px;
  padding: 2px 10px;
  font-size: 0.82em;
  font-weight: 600;
  background-color: {chipbg};
  color: var(--window-fg-color);
}}
.tsr-chip.mounted {{ background-color: {okbg}; color: {ok}; }}
.tsr-chip.locked {{ background-color: {dimbg}; }}
.tsr-chip.busy {{ background-color: {warnbg}; color: {warn}; }}
.tsr-chip.danger {{ background-color: {errbg}; color: {err}; }}
.tsr-dim {{ color: {dim}; }}
.tsr-mono {{ font-family: monospace; font-size: 0.88em; }}
.tsr-statusbar {{
  border-top: 1px solid {border};
  padding: 6px 14px;
  background-color: var(--headerbar-bg-color);
}}
.tsr-hero {{ font-weight: 800; font-size: 1.7em; color: {accent}; }}
.tsr-section-title {{ font-weight: 700; font-size: 1.06em; color: {a2solid}; }}
/* multi-colour roles so a theme reads as a full palette, not one accent */
levelbar block.filled {{ background-color: {accent}; }}
levelbar block.high {{ background-color: {ok}; }}
levelbar block.low {{ background-color: {warn}; }}
progressbar progress {{ background-color: {a2solid}; }}
checkbutton check:checked, checkbutton radio:checked {{ background-color: {a2solid}; }}
.tsr-card {{ border-top: 2px solid {a2line}; }}
spinner {{ color: {accent}; }}
.tsr-mono {{ color: {a2solid}; }}
switch:checked {{ background-color: {accent}; }}
row.tsr-volume-row image {{ color: {a2solid}; }}
.tsr-drop-zone {{
  border: 2px dashed {border};
  border-radius: {radius}px;
  padding: 28px;
  background-color: {dropbg};
  transition: border-color 160ms ease, background-color 160ms ease;
}}
.tsr-drop-zone.hover {{ border-color: {accent}; background-color: {acc06}; }}
.tsr-help {{
  border-radius: {radius}px;
  padding: 10px 12px;
  background-color: {acc10};
  border: 1px solid {acc20};
}}
.tsr-help label {{ font-size: 0.92em; }}
button.tsr-panic {{
  border-radius: 999px;
  font-weight: 700;
  background-color: {errbg2};
  color: {err};
  border: 1px solid {err40};
}}
button.tsr-panic:hover {{ background-color: {err}; color: #ffffff; }}
.tsr-entropy-pad {{
  border-radius: {radius}px;
  background: linear-gradient(135deg, {acc10}, {a210});
  border: 1px solid {border};
}}
",
        border = if p.border.is_empty() { "alpha(currentColor, 0.12)".into() } else { p.border.clone() },
        chipbg = alpha(if p.text_dim.is_empty() { "#888888" } else { &p.text_dim }, 0.18),
        dimbg = alpha(if p.text_dim.is_empty() { "#888888" } else { &p.text_dim }, 0.14),
        okbg = alpha(if p.success.is_empty() { "#2ec27e" } else { &p.success }, 0.16),
        ok = if p.success.is_empty() { "var(--success-color)".into() } else { p.success.clone() },
        warnbg = alpha(if p.warning.is_empty() { "#e5a50a" } else { &p.warning }, 0.16),
        warn = if p.warning.is_empty() { "var(--warning-color)".into() } else { p.warning.clone() },
        errbg = alpha(if p.error.is_empty() { "#e01b24" } else { &p.error }, 0.16),
        errbg2 = alpha(if p.error.is_empty() { "#e01b24" } else { &p.error }, 0.12),
        err40 = alpha(if p.error.is_empty() { "#e01b24" } else { &p.error }, 0.4),
        err = if p.error.is_empty() { "var(--error-color)".into() } else { p.error.clone() },
        dim = if p.text_dim.is_empty() { "alpha(currentColor, 0.6)".into() } else { p.text_dim.clone() },
        dropbg = alpha(if p.surface_alt.is_empty() { "#808080" } else { &p.surface_alt }, 0.25),
        accent = if accent.is_empty() { "var(--accent-bg-color)".into() } else { accent.clone() },
        acc06 = alpha(if accent.is_empty() { "#3584e4" } else { &accent }, 0.07),
        acc10 = alpha(if accent.is_empty() { "#3584e4" } else { &accent }, 0.10),
        acc20 = alpha(if accent.is_empty() { "#3584e4" } else { &accent }, 0.20),
        a210 = alpha(if p.accent2.is_empty() { "#3584e4" } else { &p.accent2 }, 0.10),
        a2solid = if p.accent2.is_empty() { "var(--accent-color)".into() } else { p.accent2.clone() },
        a2line = alpha(if p.accent2.is_empty() { "#3584e4" } else { &p.accent2 }, 0.55),
    ));

    // ---- neon glow (cyberpunk) ----
    if p.glow {
        let g = (glow_intensity.min(100)) as f32 / 100.0;
        let acc = if accent.is_empty() { p.accent.clone() } else { accent.clone() };
        css.push_str(&format!(
            "
.tsr-card {{
  box-shadow: 0 0 {r1}px {a1}, 0 1px 3px rgba(0,0,0,0.5);
  border: 1px solid {a35};
}}
button.suggested-action {{
  box-shadow: 0 0 {r2}px {a2};
  text-shadow: 0 0 6px {a2};
}}
headerbar {{ border-bottom: 1px solid {a25}; }}
.tsr-hero {{ color: {acc}; text-shadow: 0 0 12px {a45}; }}
.tsr-chip.mounted {{ box-shadow: 0 0 8px {okglow}; }}
button.tsr-panic {{ box-shadow: 0 0 {r2}px {errglow}; }}
.tsr-statusbar {{ border-top: 1px solid {a25}; }}
levelbar block.filled {{ background-color: {acc}; box-shadow: 0 0 6px {a45}; }}
",
            r1 = (10.0 + 14.0 * g) as u32,
            r2 = (6.0 + 10.0 * g) as u32,
            a1 = alpha(&acc, 0.10 + 0.10 * g),
            a2 = alpha(&acc, 0.25 + 0.25 * g),
            a25 = alpha(&acc, 0.25),
            a35 = alpha(&acc, 0.30),
            a45 = alpha(&acc, 0.45),
            okglow = alpha(&p.success, 0.5),
            errglow = alpha(&p.error, 0.35),
            acc = acc,
        ));
    }

    // ---- vintage serif accent (body only; titles use DotGothic16 below) ----
    if p.serif {
        css.push_str(
            "
.tsr-dim, .tsr-help label {
  font-family: \"Source Serif Pro\", \"Noto Serif\", \"Georgia\", serif;
}
",
        );
    }

    // ---- bundled DotGothic16 for every title / header / lock screen ----
    // Applied last so it wins over any theme's serif heading. Targets the
    // big title classes and our own heading classes, not body/form text.
    css.push_str(
        "
.tsr-hero, .tsr-section-title, .heading,
windowtitle > .title, window > headerbar .title,
.title-1, .title-2, .title-3, .title-4 {
  font-family: \"DotGothic16\", sans-serif;
  letter-spacing: 0.3px;
}
button, button label {
  font-family: \"DotGothic16\", sans-serif;
}
",
    );

    // ---- density ----
    if density == "compact" {
        css.push_str(
            "
row.tsr-volume-row { padding: 6px 10px; }
listbox row { min-height: 30px; }
headerbar { min-height: 38px; }
button { padding-top: 2px; padding-bottom: 2px; }
",
        );
    } else {
        css.push_str("row.tsr-volume-row { padding: 12px 14px; }\n");
    }

    // ---- font override ----
    if !font.is_empty() {
        css.push_str(&format!("window {{ font-family: \"{font}\"; }}\n"));
    }

    css
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_present() {
        let t = builtin_themes();
        for id in [
            "follow-system",
            "dracula",
            "catppuccin-latte",
            "catppuccin-frappe",
            "catppuccin-macchiato",
            "catppuccin-mocha",
            "vintage-light",
            "neon-tessera",
        ] {
            assert!(t.iter().any(|p| p.id == id), "{id} missing");
        }
    }

    #[test]
    fn css_compiles_for_all() {
        for p in builtin_themes() {
            let css = compile_css(&p, "", 60, "comfortable", "");
            assert!(css.contains(".tsr-card"));
            if !p.follow_system {
                assert!(css.contains("--window-bg-color"));
            }
        }
        // accent override lands in css
        let css = compile_css(&builtin_themes()[1], "#ff0000", 60, "compact", "Inter");
        assert!(css.contains("#ff0000"));
        assert!(css.contains("Inter"));
    }

    #[test]
    fn palette_toml_roundtrip() {
        let p = builtin_themes().remove(7);
        let s = toml::to_string_pretty(&p).unwrap();
        let q: Palette = toml::from_str(&s).unwrap();
        assert_eq!(p, q);
    }
}
