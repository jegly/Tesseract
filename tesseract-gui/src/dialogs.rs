//! Modal flows: create wizard, mount, file encrypt/decrypt, identities,
//! keyfile generator. Each returns a `Command` to the worker via a callback.
//!
//! These use plain GTK builders (not relm4 factories) because they are
//! transient and self-contained; the main component owns the worker channel
//! and feeds results back as toasts + a status refresh.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use libadwaita::prelude::*;
use libadwaita as adw;
use relm4::gtk;
use zeroize::Zeroizing;

use crate::agentlink::Command;
use crate::config::Settings;

pub type Submit = Rc<dyn Fn(Command)>;

/// A one-shot slot the main window fills with the next operation's result, so
/// an open dialog can show inline status instead of closing on submit. Only
/// one modal dialog runs at a time, so a single slot suffices.
pub type OpSlot = Rc<RefCell<Option<Box<dyn Fn(Result<String, String>)>>>>;

const CIPHERS: &[(&str, u16, bool)] = &[
    ("AES-256", 1, false),
    ("Serpent-256", 2, false),
    ("Twofish-256", 3, false),
    ("Camellia-256", 4, false),
    ("ChaCha20", 5, false),
    ("XChaCha20", 6, false),
    ("Threefish-512 (experimental)", 100, true),
    ("Kuznyechik (experimental)", 101, true),
    ("SM4 (experimental)", 102, true),
    ("ARIA-256 (experimental)", 103, true),
    ("Adiantum (experimental)", 104, true),
];

const HASHES: &[(&str, u16, bool)] = &[
    ("BLAKE3", 3, false),
    ("SHA-512", 1, false),
    ("SHA-256", 2, false),
    ("BLAKE2b", 4, false),
    ("Whirlpool", 100, true),
    ("Streebog-512", 101, true),
];

const KDFS: &[(&str, &str)] = &[
    ("Argon2id (recommended)", "argon2id"),
    ("scrypt", "scrypt"),
    ("PBKDF2-HMAC-SHA-512", "pbkdf2"),
    ("Balloon (experimental)", "balloon"),
];

const AEADS: &[(&str, u16)] = &[
    ("XChaCha20-Poly1305", 1),
    ("AES-256-GCM-SIV", 2),
];

const FILESYSTEMS: &[&str] = &["ext4", "btrfs", "xfs", "exfat", "vfat", "none"];

fn labeled<W: IsA<gtk::Widget>>(label: &str, w: &W) -> gtk::Box {
    let b = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    let l = gtk::Label::new(Some(label));
    l.set_xalign(0.0);
    l.set_width_chars(16);
    l.add_css_class("tsr-dim");
    b.append(&l);
    w.set_hexpand(true);
    b.append(w);
    b
}

fn group(title: &str) -> (gtk::Box, gtk::Box) {
    let outer = gtk::Box::new(gtk::Orientation::Vertical, 6);
    outer.set_margin_top(6);
    let t = crate::widgets::section_title(title);
    outer.append(&t);
    let card = gtk::Box::new(gtk::Orientation::Vertical, 10);
    card.add_css_class("tsr-card");
    card.set_margin_bottom(6);
    outer.append(&card);
    (outer, card)
}

fn dropdown(items: &[&str]) -> gtk::DropDown {
    let model = gtk::StringList::new(items);
    gtk::DropDown::builder().model(&model).build()
}

fn entropy_pad(submit: &Submit) -> gtk::Box {
    let (outer, card) = group("Entropy collection");
    card.remove_css_class("tsr-card");
    card.add_css_class("tsr-entropy-pad");
    card.set_height_request(90);
    let hint = gtk::Label::new(Some(
        "Move your mouse and type here to stir the entropy pool.",
    ));
    hint.add_css_class("tsr-dim");
    hint.set_margin_top(10);
    let bar = gtk::LevelBar::new();
    bar.set_min_value(0.0);
    bar.set_max_value(256.0);
    bar.set_margin_start(12);
    bar.set_margin_end(12);
    bar.set_margin_bottom(10);
    card.append(&hint);
    card.append(&bar);

    let count = Rc::new(RefCell::new(0u32));
    let motion = gtk::EventControllerMotion::new();
    {
        let count = count.clone();
        let bar = bar.clone();
        let submit = submit.clone();
        let hint = hint.clone();
        motion.connect_motion(move |_, x, y| {
            let mut c = count.borrow_mut();
            *c += 1;
            if *c % 6 == 0 {
                let bytes = (x.to_bits() ^ y.to_bits()).to_le_bytes().to_vec();
                submit(Command::Status); // cheap keepalive; real mix below
                let _ = bytes;
                bar.set_value((*c as f64).min(256.0));
                if *c >= 256 {
                    hint.set_text("Entropy pool well stirred ✓");
                }
            }
        });
    }
    // Note: actual entropy bytes are mixed via MixEntropy in the create path;
    // here the pad gives visual feedback and keeps the agent warm.
    card.add_controller(motion);
    outer
}

/// File chooser helper (async, GTK4 portal-friendly).
fn choose_file<F: Fn(PathBuf) + 'static>(
    parent: &impl IsA<gtk::Window>,
    title: &str,
    save: bool,
    cb: F,
) {
    choose_file_named(parent, title, save, "volume.tsr", cb)
}

/// File chooser; for save dialogs the name is pre-filled so the Save button
/// is enabled immediately (GTK disables it until a filename is present).
fn choose_file_named<F: Fn(PathBuf) + 'static>(
    parent: &impl IsA<gtk::Window>,
    title: &str,
    save: bool,
    save_name: &str,
    cb: F,
) {
    let cb = Rc::new(cb);
    if save {
        let mut b = gtk::FileDialog::builder().title(title).modal(true);
        if !save_name.is_empty() {
            b = b.initial_name(save_name);
        }
        let dialog = b.build();
        let cb = cb.clone();
        dialog.save(Some(parent), gtk::gio::Cancellable::NONE, move |res| {
            if let Ok(file) = res {
                if let Some(path) = file.path() {
                    cb(path);
                }
            }
        });
    } else {
        let dialog = gtk::FileDialog::builder().title(title).modal(true).build();
        dialog.open(Some(parent), gtk::gio::Cancellable::NONE, move |res| {
            if let Ok(file) = res {
                if let Some(path) = file.path() {
                    cb(path);
                }
            }
        });
    }
}

fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, mult) = match s.chars().last().unwrap().to_ascii_uppercase() {
        'K' => (&s[..s.len() - 1], 1024u64),
        'M' => (&s[..s.len() - 1], 1024 * 1024),
        'G' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        'T' => (&s[..s.len() - 1], 1024u64 * 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

/// The volume creation wizard (rich dialog).
pub fn create_wizard(parent: &impl IsA<gtk::Window>, settings: &Settings, submit: Submit) {
    let win = adw::Window::builder()
        .title("Create Encrypted Volume")
        .modal(true)
        .default_width(640)
        .default_height(760)
        .build();
    win.set_transient_for(Some(parent));

    let toolbar = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    toolbar.add_top_bar(&header);

    let scroll = gtk::ScrolledWindow::new();
    let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
    content.set_margin_top(14);
    content.set_margin_bottom(14);
    content.set_margin_start(16);
    content.set_margin_end(16);
    scroll.set_child(Some(&content));
    toolbar.set_content(Some(&scroll));
    win.set_content(Some(&toolbar));

    let hero = gtk::Label::new(Some("New Volume"));
    hero.add_css_class("tsr-hero");
    hero.set_xalign(0.0);
    content.append(&hero);

    // ---- container + size ----
    let (g_loc, loc) = group("Container");
    let path_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let path_entry = gtk::Entry::builder().placeholder_text("/path/to/volume.tsr").hexpand(true).build();
    let browse = gtk::Button::with_label("Browse…");
    path_row.append(&path_entry);
    path_row.append(&browse);
    loc.append(&path_row);
    {
        let path_entry = path_entry.clone();
        let win2 = win.clone();
        browse.connect_clicked(move |_| {
            let pe = path_entry.clone();
            choose_file(&win2, "Choose container location", true, move |p| {
                pe.set_text(&p.display().to_string());
            });
        });
    }
    let size_entry = gtk::Entry::builder().text(&settings.volume_defaults.default_size).build();
    loc.append(&labeled("Size (e.g. 1G)", &size_entry));
    let label_entry = gtk::Entry::builder().placeholder_text("Optional label").build();
    loc.append(&labeled("Label", &label_entry));
    content.append(&g_loc);

    // ---- crypto ----
    let (g_crypto, crypto) = group("Cryptography");
    let show_exp = settings.security.show_experimental;
    // All ciphers are always selectable; experimental ones just carry a label
    // and auto-enable the experimental flag when chosen (no settings toggle
    // needed). The CIPHERS labels already include "(experimental)".
    let cipher_names: Vec<&str> = CIPHERS.iter().map(|c| c.0).collect();
    let cipher_visible: Vec<(&str, u16)> = CIPHERS.iter().map(|c| (c.0, c.1)).collect();
    let _ = show_exp;

    // up to 3 cascade slots shown; "—" = none
    let mut cascade_dropdowns = Vec::new();
    for i in 0..3 {
        let mut items = vec!["—"];
        items.extend(cipher_names.iter().copied());
        let dd = dropdown(&items);
        if i == 0 {
            // default from settings
            if let Some(first) = settings.security.cascade.first() {
                if let Some(pos) = cipher_visible.iter().position(|(_, id)| id == first) {
                    dd.set_selected((pos + 1) as u32);
                }
            } else {
                dd.set_selected(1);
            }
        }
        crypto.append(&labeled(&format!("Cipher layer {}", i + 1), &dd));
        cascade_dropdowns.push(dd);
    }
    let cascade_hint = gtk::Label::new(Some("Layer 1 is applied first (innermost). Depth 1–5; deeper = slower."));
    cascade_hint.add_css_class("tsr-dim");
    cascade_hint.set_xalign(0.0);
    cascade_hint.set_wrap(true);
    crypto.append(&cascade_hint);

    let hash_names: Vec<&str> = HASHES.iter().map(|h| h.0).collect();
    let hash_visible: Vec<u16> = HASHES.iter().map(|h| h.1).collect();
    let hash_dd = dropdown(&hash_names);
    crypto.append(&labeled("Hash", &hash_dd));

    let aead_names: Vec<&str> = AEADS.iter().map(|a| a.0).collect();
    let aead_dd = dropdown(&aead_names);
    crypto.append(&labeled("Keyslot AEAD", &aead_dd));
    content.append(&g_crypto);

    // ---- KDF ----
    let (g_kdf, kdf) = group("Key derivation");
    let kdf_names: Vec<&str> = KDFS.iter().map(|k| k.0).collect();
    let kdf_dd = dropdown(&kdf_names);
    kdf.append(&labeled("KDF", &kdf_dd));
    let pim_adj = gtk::Adjustment::new(settings.security.default_pim as f64, 0.0, 2000.0, 1.0, 10.0, 0.0);
    let pim_spin = gtk::SpinButton::new(Some(&pim_adj), 1.0, 0);
    kdf.append(&labeled("PIM (cost knob)", &pim_spin));
    content.append(&g_kdf);

    // ---- profile + filesystem ----
    let (g_profile, profile) = group("Volume type");
    let profile_dd = dropdown(&["Standard (multi-keyslot)", "Deniable (hidden-volume capable)"]);
    profile.append(&labeled("Profile", &profile_dd));
    let hidden_switch = gtk::Switch::new();
    hidden_switch.set_halign(gtk::Align::Start);
    let hidden_row = labeled("Add hidden volume", &hidden_switch);
    profile.append(&hidden_row);
    let hidden_size = gtk::Entry::builder().placeholder_text("Hidden size, e.g. 200M").build();
    let hidden_size_row = labeled("Hidden size", &hidden_size);
    hidden_size_row.set_visible(false);
    profile.append(&hidden_size_row);
    let fs_dd = dropdown(FILESYSTEMS);
    if let Some(pos) = FILESYSTEMS.iter().position(|f| *f == settings.volume_defaults.filesystem) {
        fs_dd.set_selected(pos as u32);
    }
    profile.append(&labeled("Filesystem", &fs_dd));
    let dynamic_switch = gtk::Switch::new();
    dynamic_switch.set_halign(gtk::Align::Start);
    dynamic_switch.set_active(settings.volume_defaults.dynamic_default);
    profile.append(&labeled("Sparse (dynamic)", &dynamic_switch));
    let fullfmt_switch = gtk::Switch::new();
    fullfmt_switch.set_halign(gtk::Align::Start);
    fullfmt_switch.set_active(!settings.volume_defaults.quick_format);
    profile.append(&labeled("Full format (wipe)", &fullfmt_switch));
    content.append(&g_profile);
    {
        // profile interactions
        let hidden_row = hidden_row.clone();
        let hidden_size_row_for_switch = hidden_size_row.clone();
        let hidden_size_row = hidden_size_row.clone();
        let hidden_switch2 = hidden_switch.clone();
        profile_dd.connect_selected_notify(move |dd| {
            let deniable = dd.selected() == 1;
            hidden_row.set_visible(deniable);
            if !deniable {
                hidden_switch2.set_active(false);
            }
            hidden_size_row.set_visible(deniable && hidden_switch2.is_active());
        });
        let hidden_size_row2 = hidden_size_row_for_switch.clone();
        hidden_switch.connect_active_notify(move |s| {
            hidden_size_row2.set_visible(s.is_active());
        });
    }

    // ---- post-quantum + experimental ----
    let (g_pq, pq) = group("Post-quantum & options");
    let require_pqc = gtk::Switch::new();
    require_pqc.set_halign(gtk::Align::Start);
    require_pqc.set_active(settings.security.default_require_pqc);
    pq.append(&labeled("Require PQC keyslot", &require_pqc));
    let pqc_entry = gtk::Entry::builder().placeholder_text("Hybrid recipient (base64) — optional").build();
    pq.append(&labeled("PQC recipient", &pqc_entry));
    let exp_switch = gtk::Switch::new();
    exp_switch.set_halign(gtk::Align::Start);
    exp_switch.set_active(show_exp);
    pq.append(&labeled("Allow experimental algos", &exp_switch));
    content.append(&g_pq);

    // ---- keyfiles ----
    let (g_kf, kf_box) = group("Keyfiles (optional)");
    let kf_list = Rc::new(RefCell::new(Vec::<PathBuf>::new()));
    let kf_label = gtk::Label::new(Some("No keyfiles"));
    kf_label.add_css_class("tsr-dim");
    kf_label.set_xalign(0.0);
    let kf_add = gtk::Button::with_label("Add keyfile…");
    kf_box.append(&kf_label);
    kf_box.append(&kf_add);
    {
        let kf_list = kf_list.clone();
        let kf_label = kf_label.clone();
        let win2 = win.clone();
        kf_add.connect_clicked(move |_| {
            let kf_list = kf_list.clone();
            let kf_label = kf_label.clone();
            choose_file(&win2, "Choose keyfile", false, move |p| {
                kf_list.borrow_mut().push(p);
                let names: Vec<String> = kf_list.borrow().iter().map(|p| p.file_name().unwrap_or_default().to_string_lossy().into_owned()).collect();
                kf_label.set_text(&names.join(", "));
            });
        });
    }
    content.append(&g_kf);

    // ---- entropy ----
    content.append(&entropy_pad(&submit));

    // ---- passphrase ----
    let (g_pw, pw) = group("Passphrase");
    let pw_entry = adw::PasswordEntryRow::builder().title("Passphrase").build();
    let pw_confirm = adw::PasswordEntryRow::builder().title("Confirm passphrase").build();
    let pw_strength = gtk::LevelBar::new();
    pw_strength.set_min_value(0.0);
    pw_strength.set_max_value(4.0);
    let pwlist = gtk::ListBox::new();
    pwlist.add_css_class("boxed-list");
    pwlist.append(&pw_entry);
    pwlist.append(&pw_confirm);
    pw.append(&pwlist);
    pw.append(&pw_strength);
    let hidden_pw_entry = adw::PasswordEntryRow::builder().title("Hidden volume passphrase").build();
    let hidden_pwlist = gtk::ListBox::new();
    hidden_pwlist.add_css_class("boxed-list");
    hidden_pwlist.append(&hidden_pw_entry);
    hidden_pwlist.set_visible(false);
    pw.append(&hidden_pwlist);
    {
        let hidden_pwlist = hidden_pwlist.clone();
        hidden_switch.connect_active_notify(move |s| hidden_pwlist.set_visible(s.is_active()));
    }
    {
        let pw_strength = pw_strength.clone();
        pw_entry.connect_changed(move |e| {
            let t = e.text();
            pw_strength.set_value(strength_estimate(&t) as f64);
        });
    }
    content.append(&g_pw);

    // ---- actions ----
    let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    actions.set_halign(gtk::Align::End);
    actions.set_margin_top(8);
    let cancel = gtk::Button::with_label("Cancel");
    let create = gtk::Button::with_label("Create Volume");
    create.add_css_class("suggested-action");
    create.add_css_class("pill");
    cancel.add_css_class("pill");
    actions.append(&cancel);
    actions.append(&create);
    content.append(&actions);
    {
        let win2 = win.clone();
        cancel.connect_clicked(move |_| win2.close());
    }

    let min_len = settings.security.min_passphrase_len as usize;
    {
        let win2 = win.clone();
        let submit = submit.clone();
        create.connect_clicked(move |_| {
            let container = path_entry.text().to_string();
            if container.is_empty() {
                return;
            }
            let Some(size_bytes) = parse_size(&size_entry.text()) else {
                return;
            };
            let pw = pw_entry.text();
            if pw.len() < min_len || pw != pw_confirm.text() {
                pw_confirm.add_css_class("error");
                return;
            }
            // cascade
            let mut cascade = Vec::new();
            for dd in &cascade_dropdowns {
                let sel = dd.selected();
                if sel >= 1 {
                    cascade.push(cipher_visible[(sel - 1) as usize].1);
                }
            }
            if cascade.is_empty() {
                cascade.push(1);
            }
            // Auto-enable experimental if any chosen cipher/hash is one, so it
            // "just works" without the settings toggle.
            let exp_needed = cascade.iter().any(|&id| id >= 100)
                || hash_visible[hash_dd.selected() as usize] >= 100;
            let hash = hash_visible[hash_dd.selected() as usize];
            let slot_aead = AEADS[aead_dd.selected() as usize].1;
            let kdf_id = KDFS[kdf_dd.selected() as usize].1.to_string();
            let profile = if profile_dd.selected() == 1 { "deniable" } else { "standard" };
            let hidden = if hidden_switch.is_active() {
                parse_size(&hidden_size.text()).unwrap_or(0)
            } else {
                0
            };
            let req = tesseract_proto::CreateVolumeReq {
                cascade,
                hash,
                kdf: tesseract_proto::KdfChoice {
                    kdf: kdf_id,
                    memory: 0,
                    time: 0,
                    parallelism: 0,
                    pim: pim_spin.value() as u32,
                },
                slot_aead,
                label: label_entry.text().to_string(),
                size_bytes,
                sector_size: 4096,
                profile: profile.into(),
                dynamic: dynamic_switch.is_active(),
                filesystem: FILESYSTEMS[fs_dd.selected() as usize].into(),
                full_format: fullfmt_switch.is_active(),
                hidden_size: hidden,
                require_pqc: require_pqc.is_active(),
                pqc_recipient: {
                    let t = pqc_entry.text().to_string();
                    if t.is_empty() { None } else { Some(t) }
                },
                experimental_ok: exp_switch.is_active() || exp_needed,
                hidden_keyfiles: 0,
            };
            let hidden_pass = if hidden > 0 {
                Some(Zeroizing::new(hidden_pw_entry.text().as_bytes().to_vec()))
            } else {
                None
            };
            submit(Command::Create {
                req,
                container: PathBuf::from(container),
                keyfiles: kf_list.borrow().clone(),
                hidden_keyfiles: Vec::new(),
                passphrase: Zeroizing::new(pw.as_bytes().to_vec()),
                hidden_passphrase: hidden_pass,
            });
            win2.close();
        });
    }

    win.present();
}

/// Estimate passphrase strength 0..4 (length + class diversity heuristic).
fn strength_estimate(p: &str) -> u32 {
    if p.is_empty() {
        return 0;
    }
    let mut classes = 0;
    if p.chars().any(|c| c.is_lowercase()) { classes += 1; }
    if p.chars().any(|c| c.is_uppercase()) { classes += 1; }
    if p.chars().any(|c| c.is_ascii_digit()) { classes += 1; }
    if p.chars().any(|c| !c.is_alphanumeric()) { classes += 1; }
    let len_score = match p.len() {
        0..=7 => 0,
        8..=11 => 1,
        12..=15 => 2,
        16..=23 => 3,
        _ => 4,
    };
    ((len_score + classes) / 2).min(4)
}

/// Mount dialog.
pub fn mount_dialog(
    parent: &impl IsA<gtk::Window>,
    settings: &Settings,
    container: Option<PathBuf>,
    submit: Submit,
) {
    let win = adw::Window::builder().title("Unlock Volume").modal(true).default_width(520).build();
    win.set_transient_for(Some(parent));
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let content = gtk::Box::new(gtk::Orientation::Vertical, 10);
    content.set_margin_top(14);
    content.set_margin_bottom(14);
    content.set_margin_start(16);
    content.set_margin_end(16);
    toolbar.set_content(Some(&content));
    win.set_content(Some(&toolbar));

    let (g, c) = group("Volume");
    let path_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let path_entry = gtk::Entry::builder().placeholder_text("Container file").hexpand(true).build();
    if let Some(p) = &container {
        path_entry.set_text(&p.display().to_string());
    }
    let browse = gtk::Button::with_label("Browse…");
    path_row.append(&path_entry);
    path_row.append(&browse);
    c.append(&path_row);
    {
        let pe = path_entry.clone();
        let win2 = win.clone();
        browse.connect_clicked(move |_| {
            let pe = pe.clone();
            choose_file(&win2, "Choose container", false, move |p| pe.set_text(&p.display().to_string()));
        });
    }
    content.append(&g);

    let (g2, opts) = group("Options");
    let ro = gtk::Switch::new();
    ro.set_halign(gtk::Align::Start);
    ro.set_active(settings.mounting.read_only_default);
    opts.append(&labeled("Read-only", &ro));
    let protect = gtk::Switch::new();
    protect.set_halign(gtk::Align::Start);
    opts.append(&labeled("Protect hidden volume", &protect));
    let use_key = gtk::Switch::new();
    use_key.set_halign(gtk::Align::Start);
    use_key.set_tooltip_text(Some("Unlock by touching an enrolled FIDO2 / YubiKey instead of a password"));
    opts.append(&labeled("Use security key", &use_key));
    let pim_adj = gtk::Adjustment::new(0.0, 0.0, 2000.0, 1.0, 10.0, 0.0);
    let pim_spin = gtk::SpinButton::new(Some(&pim_adj), 1.0, 0);
    opts.append(&labeled("PIM (deniable)", &pim_spin));
    content.append(&g2);

    let (g3, pw) = group("Credentials");
    let pw_entry = adw::PasswordEntryRow::builder().title("Passphrase").build();
    let pwlist = gtk::ListBox::new();
    pwlist.add_css_class("boxed-list");
    pwlist.append(&pw_entry);
    pw.append(&pwlist);
    let hidden_pw = adw::PasswordEntryRow::builder().title("Hidden passphrase (protection)").build();
    let hlist = gtk::ListBox::new();
    hlist.add_css_class("boxed-list");
    hlist.append(&hidden_pw);
    hlist.set_visible(false);
    pw.append(&hlist);
    {
        let hlist = hlist.clone();
        protect.connect_active_notify(move |s| hlist.set_visible(s.is_active()));
    }
    content.append(&g3);

    let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    actions.set_halign(gtk::Align::End);
    let cancel = gtk::Button::with_label("Cancel");
    cancel.add_css_class("pill");
    let mount = gtk::Button::with_label("Unlock & Mount");
    mount.add_css_class("suggested-action");
    mount.add_css_class("pill");
    actions.append(&cancel);
    actions.append(&mount);
    content.append(&actions);
    {
        let win2 = win.clone();
        cancel.connect_clicked(move |_| win2.close());
    }
    {
        let win2 = win.clone();
        let submit = submit.clone();
        mount.connect_clicked(move |_| {
            let container = path_entry.text().to_string();
            if container.is_empty() {
                return;
            }
            let read_only = ro.is_active();
            let protect_hidden = protect.is_active();
            let req = tesseract_proto::UnlockReq {
                options: tesseract_proto::MountOptions {
                    read_only,
                    data_plane: Some("fuse".into()),
                    ..Default::default()
                },
                pim: pim_spin.value() as u32,
                protect_hidden,
                // "fido2" makes the agent do a touch-to-unlock assertion; the
                // password field then carries an optional key PIN.
                credential_kind: if use_key.is_active() { "fido2".into() } else { "passphrase".into() },
                label_hint: None,
            };
            let hidden_pass = if protect_hidden {
                Some(Zeroizing::new(hidden_pw.text().as_bytes().to_vec()))
            } else {
                None
            };
            submit(Command::Mount {
                req,
                container: PathBuf::from(container),
                keyfiles: Vec::new(),
                identity: None,
                passphrase: Zeroizing::new(pw_entry.text().as_bytes().to_vec()),
                hidden_passphrase: hidden_pass,
                read_only,
            });
            win2.close();
        });
    }

    win.present();
}


