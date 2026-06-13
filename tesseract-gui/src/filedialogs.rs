//! File-mode (QNSQY/KyberLock-style) and identity dialogs: encrypt a file to
//! recipients with the hybrid PQ KEM, optionally signed; decrypt; generate
//! and inspect identities; generate keyfiles. A native, drag-and-drop GTK
//! surface — no web runtime (hard invariant).

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;
use zeroize::Zeroizing;

use crate::agentlink::Command;
use crate::dialogs::{OpSlot, Submit};

/// Volume key manager: add a password or enrol a FIDO2 / YubiKey security
/// key as a keyslot, change a password, or back up the header. Works on any
/// container file (mounted or not).
pub fn manage_keys(parent: &impl IsA<gtk::Window>, submit: Submit, op_slot: OpSlot) {
    let win = adw::Window::builder()
        .title("Volume Keys")
        .modal(true)
        .default_width(560)
        .default_height(620)
        .build();
    win.set_transient_for(Some(parent));
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let scroll = gtk::ScrolledWindow::new();
    let page = gtk::Box::new(gtk::Orientation::Vertical, 10);
    page.set_margin_top(14);
    page.set_margin_bottom(14);
    page.set_margin_start(16);
    page.set_margin_end(16);
    scroll.set_child(Some(&page));
    toolbar.set_content(Some(&scroll));
    win.set_content(Some(&toolbar));

    let hero = gtk::Label::new(Some("Volume keys"));
    hero.add_css_class("tsr-hero");
    hero.set_xalign(0.0);
    page.append(&hero);
    page.append(&help_banner(
        "Add another way to unlock a volume: a second password, or a YubiKey / \
         security key you touch to unlock. You must enter an existing password \
         first to authorise the change.",
        "volkeys-intro",
    ));

    // container + existing password
    let (g_c, c_box) = group("Volume & current password");
    let (c_row, c_entry) = path_picker(&win, "Container file", false);
    c_box.append(&c_row);
    let exist_pw = adw::PasswordEntryRow::builder().title("An existing password").build();
    let pwlist = gtk::ListBox::new();
    pwlist.add_css_class("boxed-list");
    pwlist.append(&exist_pw);
    c_box.append(&pwlist);
    page.append(&g_c);

    // add a password
    let (g_p, p_box) = group("Add a password");
    let new_pw = adw::PasswordEntryRow::builder().title("New password").build();
    let new_pw2 = adw::PasswordEntryRow::builder().title("Confirm new password").build();
    let plist = gtk::ListBox::new();
    plist.add_css_class("boxed-list");
    plist.append(&new_pw);
    plist.append(&new_pw2);
    p_box.append(&plist);
    let add_pw_btn = gtk::Button::with_label("Add password");
    add_pw_btn.add_css_class("pill");
    add_pw_btn.set_halign(gtk::Align::End);
    p_box.append(&add_pw_btn);
    page.append(&g_p);

    // add a security key
    let (g_k, k_box) = group("Add a security key (YubiKey)");
    k_box.append(&gtk::Label::builder()
        .label("Plug in your FIDO2 security key. When you click the button, touch the key when it blinks.")
        .xalign(0.0).wrap(true).css_classes(["tsr-dim"]).build());
    let pin = adw::PasswordEntryRow::builder().title("Key PIN (only if your key needs one)").build();
    let pinlist = gtk::ListBox::new();
    pinlist.add_css_class("boxed-list");
    pinlist.append(&pin);
    k_box.append(&pinlist);
    let add_key_btn = gtk::Button::with_label("Enrol security key");
    add_key_btn.add_css_class("suggested-action");
    add_key_btn.add_css_class("pill");
    add_key_btn.set_halign(gtk::Align::End);
    k_box.append(&add_key_btn);
    page.append(&g_k);

    // backup header
    let (g_b, b_box) = group("Back up the header");
    b_box.append(&gtk::Label::builder()
        .label("Save a copy of the volume header so you can recover if it is damaged.")
        .xalign(0.0).wrap(true).css_classes(["tsr-dim"]).build());
    let backup_btn = gtk::Button::with_label("Back up header…");
    backup_btn.add_css_class("pill");
    backup_btn.set_halign(gtk::Align::End);
    b_box.append(&backup_btn);
    page.append(&g_b);

    let (status, spinner, status_label) = status_row();
    page.append(&status);

    let need_container = {
        let c_entry = c_entry.clone();
        let status_label = status_label.clone();
        move || -> Option<PathBuf> {
            let t = c_entry.text().to_string();
            if t.is_empty() {
                status_label.remove_css_class("success");
                status_label.add_css_class("error");
                status_label.set_text("\u{2715}  Choose the container file first.");
                None
            } else {
                Some(PathBuf::from(t))
            }
        }
    };

    // add password
    {
        let submit = submit.clone();
        let op_slot = op_slot.clone();
        let need_container = need_container.clone();
        let exist_pw = exist_pw.clone();
        let new_pw = new_pw.clone();
        let new_pw2 = new_pw2.clone();
        let status_label = status_label.clone();
        let spinner = spinner.clone();
        let btn = add_pw_btn.clone();
        add_pw_btn.connect_clicked(move |_| {
            let Some(container) = need_container() else { return };
            if new_pw.text().is_empty() || new_pw.text() != new_pw2.text() {
                status_label.remove_css_class("success");
                status_label.add_css_class("error");
                status_label.set_text("\u{2715}  New passwords are empty or don't match.");
                return;
            }
            begin_op(&op_slot, &btn, &spinner, &status_label, "Adding password\u{2026}");
            submit(Command::Keyslot {
                req: tesseract_proto::KeyslotChangeReq {
                    action: "add-passphrase".into(),
                    slot_id: None,
                    kdf: Some(tesseract_proto::KdfChoice::default()),
                    slot_aead: None,
                    label: Some("password".into()),
                    pqc_recipient: None,
                    existing_keyfiles: 0,
                },
                container,
                keyfiles: vec![],
                new_keyfiles: vec![],
                existing: Zeroizing::new(exist_pw.text().as_bytes().to_vec()),
                new_secret: Some(Zeroizing::new(new_pw.text().as_bytes().to_vec())),
            });
        });
    }

    // enrol security key
    {
        let submit = submit.clone();
        let op_slot = op_slot.clone();
        let need_container = need_container.clone();
        let exist_pw = exist_pw.clone();
        let pin = pin.clone();
        let status_label = status_label.clone();
        let spinner = spinner.clone();
        let btn = add_key_btn.clone();
        add_key_btn.connect_clicked(move |_| {
            let Some(container) = need_container() else { return };
            let pin_secret = if pin.text().is_empty() {
                None
            } else {
                Some(Zeroizing::new(pin.text().as_bytes().to_vec()))
            };
            begin_op(&op_slot, &btn, &spinner, &status_label, "Touch your security key when it blinks\u{2026}");
            submit(Command::Keyslot {
                req: tesseract_proto::KeyslotChangeReq {
                    action: "add-fido2".into(),
                    slot_id: None,
                    kdf: Some(tesseract_proto::KdfChoice::default()),
                    slot_aead: None,
                    label: Some("security key".into()),
                    pqc_recipient: None,
                    existing_keyfiles: 0,
                },
                container,
                keyfiles: vec![],
                new_keyfiles: vec![],
                existing: Zeroizing::new(exist_pw.text().as_bytes().to_vec()),
                new_secret: pin_secret,
            });
        });
    }

    // backup header
    {
        let submit = submit.clone();
        let need_container = need_container.clone();
        let win2 = win.clone();
        backup_btn.connect_clicked(move |_| {
            let Some(container) = need_container() else { return };
            let submit = submit.clone();
            choose_save(&win2, "Save header backup", "header.tsrbak", move |out| {
                submit(Command::HeaderBackup {
                    container: container.clone(),
                    output: out,
                });
            });
        });
    }

    win.present();
}

fn group(title: &str) -> (gtk::Box, gtk::Box) {
    let outer = gtk::Box::new(gtk::Orientation::Vertical, 6);
    let t = crate::widgets::section_title(title);
    outer.append(&t);
    let card = gtk::Box::new(gtk::Orientation::Vertical, 10);
    card.add_css_class("tsr-card");
    outer.append(&card);
    (outer, card)
}

fn labeled<W: IsA<gtk::Widget>>(label: &str, w: &W) -> gtk::Box {
    let b = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    let l = gtk::Label::new(Some(label));
    l.set_xalign(0.0);
    l.set_width_chars(14);
    l.add_css_class("tsr-dim");
    b.append(&l);
    w.set_hexpand(true);
    b.append(w);
    b
}

fn choose_open<F: Fn(PathBuf) + 'static>(parent: &impl IsA<gtk::Window>, title: &str, cb: F) {
    let dialog = gtk::FileDialog::builder().title(title).modal(true).build();
    dialog.open(Some(parent), gtk::gio::Cancellable::NONE, move |res| {
        if let Ok(f) = res {
            if let Some(p) = f.path() {
                cb(p);
            }
        }
    });
}

/// Save dialog with a pre-filled filename so the Save button is immediately
/// enabled (GTK disables it until a name is present — this was a hard
/// usability blocker before).
fn choose_save<F: Fn(PathBuf) + 'static>(
    parent: &impl IsA<gtk::Window>,
    title: &str,
    initial_name: &str,
    cb: F,
) {
    let mut b = gtk::FileDialog::builder().title(title).modal(true);
    if !initial_name.is_empty() {
        b = b.initial_name(initial_name);
    }
    let dialog = b.build();
    dialog.save(Some(parent), gtk::gio::Cancellable::NONE, move |res| {
        if let Ok(f) = res {
            if let Some(p) = f.path() {
                cb(p);
            }
        }
    });
}

/// Back-compat shim used by a few open-only call sites.
fn choose_file<F: Fn(PathBuf) + 'static>(parent: &impl IsA<gtk::Window>, title: &str, save: bool, cb: F) {
    if save {
        choose_save(parent, title, "untitled", cb);
    } else {
        choose_open(parent, title, cb);
    }
}

fn choose_folder<F: Fn(PathBuf) + 'static>(parent: &impl IsA<gtk::Window>, title: &str, cb: F) {
    let dialog = gtk::FileDialog::builder().title(title).modal(true).build();
    dialog.select_folder(Some(parent), gtk::gio::Cancellable::NONE, move |res| {
        if let Ok(f) = res {
            if let Some(p) = f.path() {
                cb(p);
            }
        }
    });
}

/// `save_name` is the default filename for save pickers (so Save is enabled).
fn path_picker_named(parent: &adw::Window, placeholder: &str, save: bool, save_name: &str) -> (gtk::Box, gtk::Entry) {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let entry = gtk::Entry::builder().placeholder_text(placeholder).hexpand(true).build();
    let browse = gtk::Button::with_label("Browse…");
    row.append(&entry);
    row.append(&browse);
    {
        let entry = entry.clone();
        let parent = parent.clone();
        let title = placeholder.to_string();
        let save_name = save_name.to_string();
        browse.connect_clicked(move |_| {
            let entry = entry.clone();
            if save {
                // seed the dialog with the current filename, or the default
                let seed = {
                    let t = entry.text().to_string();
                    let fname = std::path::Path::new(&t)
                        .file_name()
                        .map(|f| f.to_string_lossy().into_owned())
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| save_name.clone());
                    fname
                };
                choose_save(&parent, &title, &seed, move |p| entry.set_text(&p.display().to_string()));
            } else {
                choose_open(&parent, &title, move |p| entry.set_text(&p.display().to_string()));
            }
        });
    }
    (row, entry)
}

fn path_picker(parent: &adw::Window, placeholder: &str, save: bool) -> (gtk::Box, gtk::Entry) {
    path_picker_named(parent, placeholder, save, "untitled")
}

/// Input picker that accepts a single file OR a whole folder.
fn input_picker(parent: &adw::Window) -> (gtk::Box, gtk::Entry) {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let entry = gtk::Entry::builder().placeholder_text("File or folder to encrypt").hexpand(true).build();
    let file_btn = gtk::Button::with_label("File…");
    let folder_btn = gtk::Button::with_label("Folder…");
    folder_btn.set_tooltip_text(Some("Encrypt an entire folder (packed into one encrypted archive)"));
    row.append(&entry);
    row.append(&file_btn);
    row.append(&folder_btn);
    {
        let entry = entry.clone();
        let parent = parent.clone();
        file_btn.connect_clicked(move |_| {
            let entry = entry.clone();
            choose_file(&parent, "Choose a file", false, move |p| entry.set_text(&p.display().to_string()));
        });
    }
    {
        let entry = entry.clone();
        let parent = parent.clone();
        folder_btn.connect_clicked(move |_| {
            let entry = entry.clone();
            choose_folder(&parent, "Choose a folder", move |p| entry.set_text(&p.display().to_string()));
        });
    }
    (row, entry)
}

/// A dismissable help banner. Once dismissed, the key is remembered in
/// `~/.config/tesseract/dismissed.json` so it doesn't reappear.
fn help_banner(text: &str, key: &str) -> gtk::Widget {
    if dismissed_contains(key) {
        // already dismissed: return an empty, zero-size box
        let b = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        return b.upcast();
    }
    let banner = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    banner.add_css_class("tsr-help");
    banner.set_margin_top(2);
    banner.set_margin_bottom(2);
    let icon = gtk::Image::from_icon_name("dialog-information-symbolic");
    icon.set_valign(gtk::Align::Start);
    banner.append(&icon);
    let label = gtk::Label::new(Some(text));
    label.set_wrap(true);
    label.set_xalign(0.0);
    label.set_hexpand(true);
    banner.append(&label);
    let close = gtk::Button::from_icon_name("window-close-symbolic");
    close.add_css_class("flat");
    close.add_css_class("circular");
    close.set_valign(gtk::Align::Start);
    close.set_tooltip_text(Some("Dismiss this tip"));
    banner.append(&close);
    {
        let banner = banner.clone();
        let key = key.to_string();
        close.connect_clicked(move |_| {
            banner.set_visible(false);
            dismissed_add(&key);
        });
    }
    banner.upcast()
}

fn dismissed_path() -> PathBuf {
    dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("tesseract").join("dismissed.json")
}

fn dismissed_set() -> std::collections::HashSet<String> {
    std::fs::read_to_string(dismissed_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn dismissed_contains(key: &str) -> bool {
    dismissed_set().contains(key)
}

fn dismissed_add(key: &str) {
    let mut set = dismissed_set();
    set.insert(key.to_string());
    let path = dismissed_path();
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d).ok();
    }
    if let Ok(s) = serde_json::to_string(&set) {
        std::fs::write(path, s).ok();
    }
}

/// The File Encryption surface (encrypt + decrypt tabs).

// Friendly algorithm choices for file mode. (label, layer-id-vector)
// File mode uses authenticated ciphers (AEADs). For the full block-cipher
// cascade (Serpent, Twofish, Camellia, …) use an encrypted volume, which is
// length-preserving disk encryption — a different construction.
const FILE_ALGOS: &[(&str, &[u16])] = &[
    ("ChaCha20-Poly1305 — fast, recommended", &[4]),
    ("AES-256-GCM — hardware accelerated", &[3]),
    ("XChaCha20-Poly1305 — extended nonce", &[1]),
    ("AES-256-GCM-SIV — nonce-misuse resistant", &[2]),
    ("Cascade: AES-256-GCM → ChaCha20-Poly1305", &[3, 4]),
    ("Cascade: ChaCha20-Poly1305 → AES-256-GCM", &[4, 3]),
    ("Cascade: XChaCha20-Poly1305 → AES-256-GCM (paranoid)", &[1, 3]),
    ("Triple: XChaCha20 → AES-256-GCM → ChaCha20 (max)", &[1, 3, 4]),
];

fn algo_dropdown() -> gtk::DropDown {
    let names: Vec<&str> = FILE_ALGOS.iter().map(|a| a.0).collect();
    gtk::DropDown::from_strings(&names)
}

/// A two-option segmented toggle with a symbolic icon + label on each side.
fn mode_toggle(
    left_icon: &str,
    left: &str,
    right_icon: &str,
    right: &str,
) -> (gtk::Box, gtk::ToggleButton, gtk::ToggleButton) {
    fn btn(icon: &str, label: &str) -> gtk::ToggleButton {
        let content = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        content.set_halign(gtk::Align::Center);
        let img = gtk::Image::from_icon_name(icon);
        let lbl = gtk::Label::new(Some(label));
        content.append(&img);
        content.append(&lbl);
        let b = gtk::ToggleButton::new();
        b.set_child(Some(&content));
        b.add_css_class("pill");
        b
    }
    let b = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    b.add_css_class("linked");
    b.set_halign(gtk::Align::Center);
    b.set_margin_bottom(4);
    let a = btn(left_icon, left);
    a.set_active(true);
    let c = btn(right_icon, right);
    c.set_group(Some(&a));
    b.append(&a);
    b.append(&c);
    (b, a, c)
}

/// Build an inline status row (hidden spinner + label) for a dialog page.
fn status_row() -> (gtk::Box, gtk::Spinner, gtk::Label) {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    row.set_margin_top(4);
    let spinner = gtk::Spinner::new();
    spinner.set_visible(false);
    let label = gtk::Label::new(None);
    label.set_xalign(0.0);
    label.set_wrap(true);
    label.set_hexpand(true);
    row.append(&spinner);
    row.append(&label);
    (row, spinner, label)
}

/// Set the op slot so the next agent result updates this page's status row
/// and re-enables the action button. `working` is shown immediately.
fn begin_op(
    op_slot: &crate::dialogs::OpSlot,
    button: &gtk::Button,
    spinner: &gtk::Spinner,
    label: &gtk::Label,
    working: &str,
) {
    button.set_sensitive(false);
    spinner.set_visible(true);
    spinner.start();
    label.remove_css_class("success");
    label.remove_css_class("error");
    label.add_css_class("tsr-dim");
    label.set_text(working);
    let button = button.clone();
    let spinner = spinner.clone();
    let label = label.clone();
    *op_slot.borrow_mut() = Some(Box::new(move |res: Result<String, String>| {
        spinner.stop();
        spinner.set_visible(false);
        button.set_sensitive(true);
        label.remove_css_class("tsr-dim");
        match res {
            Ok(msg) => {
                label.remove_css_class("error");
                label.add_css_class("success");
                label.set_text(&format!("✓  {msg}"));
            }
            Err(e) => {
                label.remove_css_class("success");
                label.add_css_class("error");
                label.set_text(&format!("✕  {e}"));
            }
        }
    }));
}

/// The File Encryption surface (encrypt + decrypt tabs), password-first.
pub fn file_mode(parent: &impl IsA<gtk::Window>, submit: Submit, op_slot: crate::dialogs::OpSlot) {
    let win = adw::Window::builder()
        .title("File Encryption")
        .modal(true)
        .default_width(620)
        .default_height(680)
        .build();
    win.set_transient_for(Some(parent));
    let toolbar = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    let stack_switcher = adw::ViewSwitcher::builder().policy(adw::ViewSwitcherPolicy::Wide).build();
    header.set_title_widget(Some(&stack_switcher));
    toolbar.add_top_bar(&header);
    let stack = adw::ViewStack::new();
    stack_switcher.set_stack(Some(&stack));
    toolbar.set_content(Some(&stack));
    win.set_content(Some(&toolbar));

    // ---------- ENCRYPT ----------
    {
        let scroll = gtk::ScrolledWindow::new();
        let page = gtk::Box::new(gtk::Orientation::Vertical, 10);
        page.set_margin_top(14);
        page.set_margin_bottom(14);
        page.set_margin_start(16);
        page.set_margin_end(16);
        scroll.set_child(Some(&page));

        let hero = gtk::Label::new(Some("Encrypt a file or folder"));
        hero.add_css_class("tsr-hero");
        hero.set_xalign(0.0);
        page.append(&hero);

        page.append(&help_banner(
            "Pick a file or a whole folder, choose where to save the encrypted \
             output (.tsrf), and either set a password or encrypt to someone's \
             public key. The password mode is the simplest: anyone with the \
             password can open it.",
            "encrypt-intro",
        ));

        // mode toggle: Password (default) vs Recipients
        let (toggle_box, pw_mode, recip_mode) = mode_toggle("dialog-password-symbolic", "Password", "system-users-symbolic", "Recipients");
        page.append(&toggle_box);

        let (g_in, in_box) = group("What to encrypt");
        let (in_row, in_entry) = input_picker(&win);
        in_box.append(&in_row);
        let (out_row, out_entry) = path_picker_named(&win, "Save encrypted file as (.tsrf)", true, "encrypted.tsrf");
        in_box.append(&out_row);
        // auto-suggest output name
        {
            let out_entry = out_entry.clone();
            in_entry.connect_changed(move |e| {
                let t = e.text();
                if !t.is_empty() && out_entry.text().is_empty() {
                    out_entry.set_text(&format!("{t}.tsrf"));
                }
            });
        }
        page.append(&g_in);

        // password group
        let (g_pw, pw_box) = group("Password");
        let pw_entry = adw::PasswordEntryRow::builder().title("Password").build();
        let pw_confirm = adw::PasswordEntryRow::builder().title("Confirm password").build();
        let pwlist = gtk::ListBox::new();
        pwlist.add_css_class("boxed-list");
        pwlist.append(&pw_entry);
        pwlist.append(&pw_confirm);
        pw_box.append(&pwlist);
        let pw_hint = gtk::Label::new(Some("Anyone with this password can decrypt the file. There is no recovery if you forget it."));
        pw_hint.add_css_class("tsr-dim");
        pw_hint.set_xalign(0.0);
        pw_hint.set_wrap(true);
        pw_box.append(&pw_hint);
        page.append(&g_pw);

        // recipients group
        let (g_r, r_box) = group("Recipients (public keys)");
        let r_explain = gtk::Label::new(Some(
            "Recipient mode encrypts to someone's public key so only they can open it — no shared password. \
             Generate a keypair from the menu ▸ Identities, share the recipient line, and paste recipients here (one per line). \
             Uses hybrid X25519 + ML-KEM-1024 (quantum-resistant).",
        ));
        r_explain.add_css_class("tsr-dim");
        r_explain.set_xalign(0.0);
        r_explain.set_wrap(true);
        r_box.append(&r_explain);
        let recip_view = gtk::TextView::new();
        recip_view.set_monospace(true);
        recip_view.set_top_margin(6);
        recip_view.set_left_margin(6);
        let recip_scroll = gtk::ScrolledWindow::new();
        recip_scroll.set_min_content_height(90);
        recip_scroll.set_child(Some(&recip_view));
        recip_scroll.add_css_class("card");
        r_box.append(&recip_scroll);
        let add_id = gtk::Button::with_label("Add from identity file…");
        add_id.set_halign(gtk::Align::Start);
        r_box.append(&add_id);
        {
            let recip_view = recip_view.clone();
            let win2 = win.clone();
            add_id.connect_clicked(move |_| {
                let recip_view = recip_view.clone();
                choose_file(&win2, "Identity file", false, move |p| {
                    let buf = recip_view.buffer();
                    let mut end = buf.end_iter();
                    buf.insert(&mut end, &format!("@{}\n", p.display()));
                });
            });
        }
        page.append(&g_r);

        // algorithm + advanced
        let (g_opt, opt_box) = group("Algorithm");
        opt_box.append(&help_banner(
            "All choices are authenticated (they detect tampering). ChaCha20-Poly1305 \
             is fastest on most machines; AES-256-GCM is fastest where the CPU has \
             AES-NI. “Cascade” options encrypt twice with different ciphers for extra \
             margin (slower). For the full Serpent/Twofish/Camellia cascade, create an \
             encrypted volume instead — that’s disk encryption, a different mode.",
            "algo-explain",
        ));
        let algo_dd = algo_dropdown();
        opt_box.append(&labeled("Encryption", &algo_dd));
        page.append(&g_opt);

        let adv = adw::ExpanderRow::builder().title("Advanced: sign this file").build();
        let advlist = gtk::ListBox::new();
        advlist.add_css_class("boxed-list");
        advlist.append(&adv);
        let sign_switch = gtk::Switch::new();
        sign_switch.set_valign(gtk::Align::Center);
        let sign_row = adw::ActionRow::builder().title("Add ML-DSA-87 signature").subtitle("Proves the file came from you").build();
        sign_row.add_suffix(&sign_switch);
        adv.add_row(&sign_row);
        let signer_action = adw::ActionRow::builder().title("Signer identity").build();
        let signer_btn = gtk::Button::with_label("Choose…");
        signer_btn.set_valign(gtk::Align::Center);
        signer_action.add_suffix(&signer_btn);
        adv.add_row(&signer_action);
        let signer_path: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));
        {
            let signer_path = signer_path.clone();
            let signer_action = signer_action.clone();
            let win2 = win.clone();
            signer_btn.connect_clicked(move |_| {
                let signer_path = signer_path.clone();
                let signer_action = signer_action.clone();
                choose_file(&win2, "Signer identity", false, move |p| {
                    signer_action.set_subtitle(&p.display().to_string());
                    *signer_path.borrow_mut() = Some(p);
                });
            });
        }
        page.append(&advlist);

        // mode switching shows/hides groups
        {
            let g_pw = g_pw.clone();
            let g_r = g_r.clone();
            let upd = move |password: bool| {
                g_pw.set_visible(password);
                g_r.set_visible(!password);
            };
            upd(true);
            let upd1 = upd.clone();
            pw_mode.connect_toggled(move |b| if b.is_active() { upd1(true); });
            recip_mode.connect_toggled(move |b| if b.is_active() { upd(false); });
        }

        let (status, spinner, status_label) = status_row();
        page.append(&status);

        let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        actions.set_halign(gtk::Align::End);
        actions.set_margin_top(6);
        let go = gtk::Button::with_label("Encrypt");
        go.add_css_class("suggested-action");
        go.add_css_class("pill");
        actions.append(&go);
        page.append(&actions);
        {
            let submit = submit.clone();
            let pw_mode = pw_mode.clone();
            let op_slot = op_slot.clone();
            let go2 = go.clone();
            go.connect_clicked(move |_| {
                let input = in_entry.text().to_string();
                let output = out_entry.text().to_string();
                let err = |label: &gtk::Label, msg: &str| {
                    label.remove_css_class("success");
                    label.remove_css_class("tsr-dim");
                    label.add_css_class("error");
                    label.set_text(msg);
                };
                if input.is_empty() || output.is_empty() {
                    err(&status_label, "\u{2715}  Choose both an input and an output location.");
                    return;
                }
                let layers = FILE_ALGOS[algo_dd.selected() as usize].1.to_vec();
                let signer = signer_path.borrow().clone().filter(|_| sign_switch.is_active());
                let (password, recipients) = if pw_mode.is_active() {
                    let pw = pw_entry.text();
                    if pw.is_empty() || pw != pw_confirm.text() {
                        pw_confirm.add_css_class("error");
                        err(&status_label, "\u{2715}  Passwords are empty or don't match.");
                        return;
                    }
                    (Some(Zeroizing::new(pw.as_bytes().to_vec())), Vec::new())
                } else {
                    let buf = recip_view.buffer();
                    let text = buf.text(&buf.start_iter(), &buf.end_iter(), false);
                    let recipients: Vec<String> = text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
                    if recipients.is_empty() {
                        err(&status_label, "\u{2715}  Add at least one recipient.");
                        return;
                    }
                    (None, recipients)
                };
                let working = if std::path::Path::new(&input).is_dir() {
                    "Packing and encrypting folder\u{2026}"
                } else {
                    "Encrypting\u{2026}"
                };
                begin_op(&op_slot, &go2, &spinner, &status_label, working);
                submit(Command::FileEncrypt {
                    input: PathBuf::from(input),
                    output: PathBuf::from(output),
                    req: tesseract_proto::FileEncryptReq {
                        recipients,
                        use_password: password.is_some(),
                        password_kdf: tesseract_proto::KdfChoice::default(),
                        layers,
                        chunk_size: 262144,
                        sign: signer.is_some(),
                        // the worker sets this true when the input is a folder
                        is_archive: false,
                        plaintext_len: 0,
                    },
                    password,
                    signer,
                    signer_pass: None,
                });
            });
        }

        stack.add_titled_with_icon(&scroll, Some("encrypt"), "Encrypt", "changes-prevent-symbolic");
    }

    // ---------- DECRYPT ----------
    {
        let scroll = gtk::ScrolledWindow::new();
        let page = gtk::Box::new(gtk::Orientation::Vertical, 10);
        page.set_margin_top(14);
        page.set_margin_bottom(14);
        page.set_margin_start(16);
        page.set_margin_end(16);
        scroll.set_child(Some(&page));

        let hero = gtk::Label::new(Some("Decrypt a file"));
        hero.add_css_class("tsr-hero");
        hero.set_xalign(0.0);
        page.append(&hero);

        page.append(&help_banner(
            "Choose the encrypted .tsrf file and where to put the result, then enter \
             the password (or pick your identity for recipient-encrypted files). If \
             the file was an encrypted folder, it is extracted into a folder at the \
             output location you choose.",
            "decrypt-intro",
        ));

        let (toggle_box, pw_mode, id_mode) = mode_toggle("dialog-password-symbolic", "Password", "system-users-symbolic", "Identity");
        page.append(&toggle_box);

        let (g, b) = group("Files");
        let (in_row, in_entry) = path_picker(&win, "Encrypted file (.tsrf)", false);
        b.append(&in_row);
        let (out_row, out_entry) = path_picker_named(&win, "Save result as (file, or folder name)", true, "decrypted");
        b.append(&out_row);
        page.append(&g);

        let (g_pw, pw_box) = group("Password");
        let pw = adw::PasswordEntryRow::builder().title("Password").build();
        let pwlist = gtk::ListBox::new();
        pwlist.add_css_class("boxed-list");
        pwlist.append(&pw);
        pw_box.append(&pwlist);
        page.append(&g_pw);

        let (g_id, id_box) = group("Identity");
        let (id_row, id_entry) = path_picker(&win, "Your identity file", false);
        id_box.append(&id_row);
        let id_pw = adw::PasswordEntryRow::builder().title("Identity passphrase (if sealed)").build();
        let idpwlist = gtk::ListBox::new();
        idpwlist.add_css_class("boxed-list");
        idpwlist.append(&id_pw);
        id_box.append(&idpwlist);
        page.append(&g_id);

        let adv = adw::ExpanderRow::builder().title("Advanced: verify signature").build();
        let advlist = gtk::ListBox::new();
        advlist.add_css_class("boxed-list");
        advlist.append(&adv);
        let verify_switch = gtk::Switch::new();
        verify_switch.set_valign(gtk::Align::Center);
        let verify_row = adw::ActionRow::builder().title("Verify signature").build();
        verify_row.add_suffix(&verify_switch);
        adv.add_row(&verify_row);
        let sig_action = adw::ActionRow::builder().title("Signature file (.sig)").build();
        let sig_btn = gtk::Button::with_label("Choose…");
        sig_btn.set_valign(gtk::Align::Center);
        sig_action.add_suffix(&sig_btn);
        adv.add_row(&sig_action);
        let sig_path: Rc<RefCell<Option<PathBuf>>> = Rc::new(RefCell::new(None));
        {
            let sig_path = sig_path.clone();
            let sig_action = sig_action.clone();
            let win2 = win.clone();
            sig_btn.connect_clicked(move |_| {
                let sig_path = sig_path.clone();
                let sig_action = sig_action.clone();
                choose_file(&win2, "Signature file", false, move |p| {
                    sig_action.set_subtitle(&p.display().to_string());
                    *sig_path.borrow_mut() = Some(p);
                });
            });
        }
        page.append(&advlist);

        {
            let g_pw = g_pw.clone();
            let g_id = g_id.clone();
            let upd = move |password: bool| {
                g_pw.set_visible(password);
                g_id.set_visible(!password);
            };
            upd(true);
            let upd1 = upd.clone();
            pw_mode.connect_toggled(move |b| if b.is_active() { upd1(true); });
            id_mode.connect_toggled(move |b| if b.is_active() { upd(false); });
        }

        let (status, spinner, status_label) = status_row();
        page.append(&status);

        let actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        actions.set_halign(gtk::Align::End);
        let go = gtk::Button::with_label("Decrypt");
        go.add_css_class("suggested-action");
        go.add_css_class("pill");
        actions.append(&go);
        page.append(&actions);
        {
            let submit = submit.clone();
            let pw_mode = pw_mode.clone();
            let op_slot = op_slot.clone();
            let go2 = go.clone();
            go.connect_clicked(move |_| {
                let input = in_entry.text().to_string();
                let output = out_entry.text().to_string();
                let err = |label: &gtk::Label, msg: &str| {
                    label.remove_css_class("success");
                    label.remove_css_class("tsr-dim");
                    label.add_css_class("error");
                    label.set_text(msg);
                };
                if input.is_empty() || output.is_empty() {
                    err(&status_label, "\u{2715}  Choose both the encrypted file and an output location.");
                    return;
                }
                let signature = sig_path.borrow().clone().filter(|_| verify_switch.is_active());
                let (identity, passphrase) = if pw_mode.is_active() {
                    (None, Zeroizing::new(pw.text().as_bytes().to_vec()))
                } else {
                    let id = id_entry.text().to_string();
                    if id.is_empty() {
                        err(&status_label, "\u{2715}  Choose your identity file.");
                        return;
                    }
                    (Some(PathBuf::from(id)), Zeroizing::new(id_pw.text().as_bytes().to_vec()))
                };
                begin_op(&op_slot, &go2, &spinner, &status_label, "Decrypting\u{2026}");
                submit(Command::FileDecrypt {
                    input: PathBuf::from(input),
                    output: PathBuf::from(output),
                    identity,
                    signature,
                    passphrase,
                });
            });
        }

        stack.add_titled_with_icon(&scroll, Some("decrypt"), "Decrypt", "changes-allow-symbolic");
    }

    win.present();
}


/// Identity manager: generate + inspect hybrid recipient keypairs.
pub fn identity_manager(parent: &impl IsA<gtk::Window>, last_identity: Rc<RefCell<Option<(String, String)>>>, submit: Submit) {
    let win = adw::Window::builder().title("Identities").modal(true).default_width(560).default_height(420).build();
    win.set_transient_for(Some(parent));
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let page = gtk::Box::new(gtk::Orientation::Vertical, 10);
    page.set_margin_top(14);
    page.set_margin_bottom(14);
    page.set_margin_start(16);
    page.set_margin_end(16);
    toolbar.set_content(Some(&page));
    win.set_content(Some(&toolbar));

    let hero = gtk::Label::new(Some("Hybrid PQ identities"));
    hero.add_css_class("tsr-hero");
    hero.set_xalign(0.0);
    page.append(&hero);
    let sub = gtk::Label::new(Some("X25519 + ML-KEM-1024. Share the recipient line; keep the identity file secret."));
    sub.add_css_class("tsr-dim");
    sub.set_xalign(0.0);
    sub.set_wrap(true);
    page.append(&sub);

    let (g, b) = group("Generate");
    let (out_row, out_entry) = path_picker_named(&win, "Identity file (.tsrid)", true, "identity.tsrid");
    b.append(&out_row);
    let seal = gtk::Switch::new();
    seal.set_halign(gtk::Align::Start);
    b.append(&labeled("Seal with passphrase", &seal));
    let pw = adw::PasswordEntryRow::builder().title("Passphrase").build();
    let pwlist = gtk::ListBox::new();
    pwlist.add_css_class("boxed-list");
    pwlist.append(&pw);
    pwlist.set_visible(false);
    b.append(&pwlist);
    {
        let pwlist = pwlist.clone();
        seal.connect_active_notify(move |s| pwlist.set_visible(s.is_active()));
    }
    let gen = gtk::Button::with_label("Generate identity");
    gen.add_css_class("suggested-action");
    gen.add_css_class("pill");
    gen.set_halign(gtk::Align::End);
    b.append(&gen);
    page.append(&g);

    let (g2, b2) = group("Latest recipient");
    let recip_label = gtk::Label::new(Some("—"));
    recip_label.add_css_class("tsr-mono");
    recip_label.set_wrap(true);
    recip_label.set_selectable(true);
    recip_label.set_xalign(0.0);
    let fp_label = gtk::Label::new(Some(""));
    fp_label.add_css_class("tsr-dim");
    fp_label.set_xalign(0.0);
    b2.append(&recip_label);
    b2.append(&fp_label);
    let copy = gtk::Button::with_label("Copy recipient");
    copy.add_css_class("pill");
    copy.set_halign(gtk::Align::Start);
    b2.append(&copy);
    page.append(&g2);
    if let Some((pubk, fp)) = last_identity.borrow().clone() {
        recip_label.set_text(&pubk);
        fp_label.set_text(&format!("fingerprint: {fp}"));
    }
    {
        let recip_label = recip_label.clone();
        copy.connect_clicked(move |btn| {
            if let Some(disp) = gtk::prelude::WidgetExt::display(btn).clipboard().into() {
                let _ = disp;
            }
            let clip = btn.clipboard();
            clip.set_text(&recip_label.text());
        });
    }
    {
        let submit = submit.clone();
        gen.connect_clicked(move |_| {
            let output = out_entry.text().to_string();
            if output.is_empty() {
                return;
            }
            let passphrase = if seal.is_active() {
                Some(Zeroizing::new(pw.text().as_bytes().to_vec()))
            } else {
                None
            };
            submit(Command::GenerateIdentity {
                output: PathBuf::from(output),
                passphrase,
            });
        });
    }

    win.present();
}
