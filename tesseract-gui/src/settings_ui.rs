//! Preferences window: deep settings across pages (Appearance, Security,
//! Auto-dismount, Mounting, Volume defaults, Keyfiles, Hardware, Advanced,
//! Import/Export). Appearance changes apply live; agent-side pages round-trip
//! through the worker. Built with libadwaita preference widgets.

use std::cell::RefCell;
use std::rc::Rc;

use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;

use crate::agentlink::Command;
use crate::config::Settings;
use crate::dialogs::Submit;
use crate::theme;

/// Small dialog to set/confirm the app-lock password. Stores an Argon2id
/// hash in settings and syncs the enable switch.
fn set_app_password_dialog(
    parent: &adw::PreferencesWindow,
    settings: Rc<RefCell<Settings>>,
    enable_switch: adw::SwitchRow,
) {
    let dialog = adw::MessageDialog::builder()
        .heading("Set app password")
        .body("This password opens the app. It is separate from your file and volume passwords. There is no recovery if you forget it.")
        .transient_for(parent)
        .modal(true)
        .build();
    let list = gtk::ListBox::new();
    list.add_css_class("boxed-list");
    list.set_margin_top(8);
    let pw = adw::PasswordEntryRow::builder().title("New app password").build();
    let confirm = adw::PasswordEntryRow::builder().title("Confirm password").build();
    list.append(&pw);
    list.append(&confirm);
    let err = gtk::Label::new(None);
    err.add_css_class("error");
    err.set_visible(false);
    err.set_margin_top(6);
    let wrap = gtk::Box::new(gtk::Orientation::Vertical, 0);
    wrap.append(&list);
    wrap.append(&err);
    dialog.set_extra_child(Some(&wrap));
    dialog.add_responses(&[("cancel", "Cancel"), ("save", "Save")]);
    dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);
    dialog.set_default_response(Some("save"));

    let had_password = !settings.borrow().security.app_lock_hash.is_empty();
    dialog.connect_response(None, move |dlg, resp| {
        if resp != "save" {
            // reflect the real state if the user cancelled
            enable_switch.set_active(
                settings.borrow().security.app_lock_enabled
                    && !settings.borrow().security.app_lock_hash.is_empty(),
            );
            let _ = had_password;
            return;
        }
        let p = pw.text();
        if p.is_empty() || p != confirm.text() {
            err.set_text("Passwords are empty or don't match.");
            err.set_visible(true);
            // keep the dialog open: re-present
            dlg.set_visible(true);
            return;
        }
        match crate::applock::hash_password(&p) {
            Some(hash) => {
                let mut s = settings.borrow_mut();
                s.security.app_lock_hash = hash;
                s.security.app_lock_enabled = true;
                drop(s);
                settings.borrow().save();
                enable_switch.set_active(true);
            }
            None => {
                enable_switch.set_active(false);
            }
        }
    });
    dialog.present();
}

/// Called when appearance settings change so the main window restyles live.
pub type ApplyTheme = Rc<dyn Fn(&Settings)>;

pub fn open(
    parent: &impl IsA<gtk::Window>,
    settings: Rc<RefCell<Settings>>,
    agent_config: Rc<RefCell<tesseract_proto::AgentConfig>>,
    apply_theme: ApplyTheme,
    submit: Submit,
) {
    let win = adw::PreferencesWindow::builder()
        .title("Tesseract Preferences")
        .modal(true)
        .search_enabled(true)
        .default_width(860)
        .default_height(660)
        .build();
    win.set_transient_for(Some(parent));

    appearance_page(&win, &settings, &apply_theme);
    security_page(&win, &settings, &submit);
    autodismount_page(&win, &agent_config, &submit);
    mounting_page(&win, &settings);
    volume_defaults_page(&win, &settings);
    keyfiles_page(&win, &settings, &submit);
    hardware_page(&win, &submit);
    advanced_page(&win, &settings, &agent_config, &submit);
    importexport_page(&win, &settings, &apply_theme);

    win.present();
}

fn appearance_page(win: &adw::PreferencesWindow, settings: &Rc<RefCell<Settings>>, apply: &ApplyTheme) {
    let page = adw::PreferencesPage::builder().title("Appearance").icon_name("applications-graphics-symbolic").build();

    let theme_group = adw::PreferencesGroup::builder().title("Theme").description("Live switching, no restart").build();
    let themes = theme::all_themes();
    let theme_names: Vec<String> = themes.iter().map(|t| t.name.clone()).collect();
    let names_ref: Vec<&str> = theme_names.iter().map(|s| s.as_str()).collect();
    let theme_model = gtk::StringList::new(&names_ref);
    let theme_row = adw::ComboRow::builder().title("Theme").model(&theme_model).build();
    let cur = settings.borrow().appearance.theme.clone();
    if let Some(pos) = themes.iter().position(|t| t.id == cur) {
        theme_row.set_selected(pos as u32);
    }
    theme_group.add(&theme_row);

    // accent picker
    let accent_row = adw::ActionRow::builder().title("Accent color").subtitle("Override the theme accent").build();
    let accent_btn = gtk::ColorDialogButton::new(Some(gtk::ColorDialog::new()));
    accent_btn.set_valign(gtk::Align::Center);
    let cur_accent = settings.borrow().appearance.accent.clone();
    if let Ok(rgba) = cur_accent.parse::<gtk::gdk::RGBA>() {
        accent_btn.set_rgba(&rgba);
    }
    let accent_reset = gtk::Button::from_icon_name("edit-clear-symbolic");
    accent_reset.set_valign(gtk::Align::Center);
    accent_reset.set_tooltip_text(Some("Use theme default accent"));
    let accent_box = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    accent_box.append(&accent_reset);
    accent_box.append(&accent_btn);
    accent_row.add_suffix(&accent_box);
    theme_group.add(&accent_row);

    let glow_row = adw::SpinRow::builder()
        .title("Neon glow intensity")
        .subtitle("For the Neon Tessera theme")
        .adjustment(&gtk::Adjustment::new(settings.borrow().appearance.glow_intensity as f64, 0.0, 100.0, 5.0, 10.0, 0.0))
        .build();
    theme_group.add(&glow_row);
    page.add(&theme_group);

    let layout_group = adw::PreferencesGroup::builder().title("Layout & motion").build();
    let density_row = adw::ComboRow::builder().title("Density").model(&gtk::StringList::new(&["Comfortable", "Compact"])).build();
    density_row.set_selected(if settings.borrow().appearance.density == "compact" { 1 } else { 0 });
    layout_group.add(&density_row);
    let anim_row = adw::ComboRow::builder().title("Animations").model(&gtk::StringList::new(&["Follow system (reduce-motion)", "Always on", "Off"])).build();
    anim_row.set_selected(match settings.borrow().appearance.animations.as_str() {
        "on" => 1,
        "off" => 2,
        _ => 0,
    });
    layout_group.add(&anim_row);
    let serif_row = adw::SwitchRow::builder().title("Vintage serif headings").active(settings.borrow().appearance.vintage_serif).build();
    layout_group.add(&serif_row);
    let mono_row = adw::SwitchRow::builder().title("Monospace technical values").subtitle("UUIDs, fingerprints").active(settings.borrow().appearance.mono_technical).build();
    layout_group.add(&mono_row);
    let font_row = adw::EntryRow::builder().title("UI font (blank = system)").text(&settings.borrow().appearance.font).build();
    layout_group.add(&font_row);
    page.add(&layout_group);

    let window_group = adw::PreferencesGroup::builder().title("Window & background").build();
    let remember_row = adw::SwitchRow::builder().title("Remember window size").active(settings.borrow().appearance.remember_window).build();
    window_group.add(&remember_row);
    let bg_row = adw::SwitchRow::builder().title("Keep running in background").subtitle("Agent keeps volumes; window can reopen").active(settings.borrow().appearance.run_in_background).build();
    window_group.add(&bg_row);
    let startbg_row = adw::SwitchRow::builder().title("Start hidden").active(settings.borrow().appearance.start_in_background).build();
    window_group.add(&startbg_row);
    let statusbar_row = adw::SwitchRow::builder().title("Show status bar").active(settings.borrow().appearance.show_status_bar).build();
    window_group.add(&statusbar_row);
    let countdown_row = adw::SwitchRow::builder().title("Show auto-dismount countdowns").active(settings.borrow().appearance.show_countdowns).build();
    window_group.add(&countdown_row);
    page.add(&window_group);

    win.add(&page);

    // ---- wire live-apply ----
    let apply_all: Rc<dyn Fn()> = {
        let settings = settings.clone();
        let apply = apply.clone();
        let themes = themes.clone();
        let theme_row = theme_row.clone();
        let accent_btn = accent_btn.clone();
        let glow_row = glow_row.clone();
        let density_row = density_row.clone();
        let anim_row = anim_row.clone();
        let serif_row = serif_row.clone();
        let mono_row = mono_row.clone();
        let font_row = font_row.clone();
        let remember_row = remember_row.clone();
        let bg_row = bg_row.clone();
        let startbg_row = startbg_row.clone();
        let statusbar_row = statusbar_row.clone();
        let countdown_row = countdown_row.clone();
        Rc::new(move || {
            {
                let mut s = settings.borrow_mut();
                s.appearance.theme = themes[theme_row.selected() as usize].id.clone();
                let rgba = accent_btn.rgba();
                s.appearance.accent = format!(
                    "#{:02x}{:02x}{:02x}",
                    (rgba.red() * 255.0) as u8,
                    (rgba.green() * 255.0) as u8,
                    (rgba.blue() * 255.0) as u8
                );
                s.appearance.glow_intensity = glow_row.value() as u32;
                s.appearance.density = if density_row.selected() == 1 { "compact" } else { "comfortable" }.into();
                s.appearance.animations = match anim_row.selected() {
                    1 => "on",
                    2 => "off",
                    _ => "system",
                }.into();
                s.appearance.vintage_serif = serif_row.is_active();
                s.appearance.mono_technical = mono_row.is_active();
                s.appearance.font = font_row.text().to_string();
                s.appearance.remember_window = remember_row.is_active();
                s.appearance.run_in_background = bg_row.is_active();
                s.appearance.start_in_background = startbg_row.is_active();
                s.appearance.show_status_bar = statusbar_row.is_active();
                s.appearance.show_countdowns = countdown_row.is_active();
            }
            apply(&settings.borrow());
            settings.borrow().save();
        })
    };

    theme_row.connect_selected_notify({ let a = apply_all.clone(); move |_| a() });
    glow_row.connect_value_notify({ let a = apply_all.clone(); move |_| a() });
    density_row.connect_selected_notify({ let a = apply_all.clone(); move |_| a() });
    anim_row.connect_selected_notify({ let a = apply_all.clone(); move |_| a() });
    serif_row.connect_active_notify({ let a = apply_all.clone(); move |_| a() });
    mono_row.connect_active_notify({ let a = apply_all.clone(); move |_| a() });
    font_row.connect_changed({ let a = apply_all.clone(); move |_| a() });
    remember_row.connect_active_notify({ let a = apply_all.clone(); move |_| a() });
    bg_row.connect_active_notify({ let a = apply_all.clone(); move |_| a() });
    startbg_row.connect_active_notify({ let a = apply_all.clone(); move |_| a() });
    statusbar_row.connect_active_notify({ let a = apply_all.clone(); move |_| a() });
    countdown_row.connect_active_notify({ let a = apply_all.clone(); move |_| a() });
    accent_btn.connect_rgba_notify({ let a = apply_all.clone(); move |_| a() });
    accent_reset.connect_clicked({
        let settings = settings.clone();
        let apply = apply.clone();
        move |_| {
            settings.borrow_mut().appearance.accent = String::new();
            apply(&settings.borrow());
            settings.borrow().save();
        }
    });
}

fn security_page(win: &adw::PreferencesWindow, settings: &Rc<RefCell<Settings>>, _submit: &Submit) {
    let page = adw::PreferencesPage::builder().title("Security").icon_name("security-high-symbolic").build();

    let defaults = adw::PreferencesGroup::builder()
        .title("Defaults for new volumes")
        .description("The default cipher cascade. Layer 1 is the inner cipher; add up to two more for a cascade.")
        .build();
    // Cipher cascade as proper dropdowns (was a raw text field).
    let cipher_names: Vec<&str> = CIPHER_LIST.iter().map(|c| c.0).collect();
    let mut none_and_ciphers = vec!["— None —"];
    none_and_ciphers.extend(cipher_names.iter().copied());
    let casc = settings.borrow().security.cascade.clone();
    let cipher_pos = |id: u16| CIPHER_LIST.iter().position(|c| c.1 == id);

    let l1 = adw::ComboRow::builder().title("Cipher layer 1").model(&gtk::StringList::new(&cipher_names)).build();
    l1.set_selected(casc.first().and_then(|id| cipher_pos(*id)).unwrap_or(0) as u32);
    defaults.add(&l1);
    let l2 = adw::ComboRow::builder().title("Cipher layer 2").subtitle("optional").model(&gtk::StringList::new(&none_and_ciphers)).build();
    l2.set_selected(casc.get(1).and_then(|id| cipher_pos(*id)).map(|p| p + 1).unwrap_or(0) as u32);
    defaults.add(&l2);
    let l3 = adw::ComboRow::builder().title("Cipher layer 3").subtitle("optional").model(&gtk::StringList::new(&none_and_ciphers)).build();
    l3.set_selected(casc.get(2).and_then(|id| cipher_pos(*id)).map(|p| p + 1).unwrap_or(0) as u32);
    defaults.add(&l3);
    let hash_row = adw::ComboRow::builder().title("Default hash").model(&gtk::StringList::new(&["BLAKE3", "SHA-512", "SHA-256", "BLAKE2b"])).build();
    hash_row.set_selected(match settings.borrow().security.hash { 1 => 1, 2 => 2, 4 => 3, _ => 0 });
    defaults.add(&hash_row);
    let kdf_row = adw::ComboRow::builder().title("Default KDF").model(&gtk::StringList::new(&["Argon2id", "scrypt", "PBKDF2", "Balloon (experimental)"])).build();
    kdf_row.set_selected(match settings.borrow().security.kdf.as_str() { "scrypt" => 1, "pbkdf2" => 2, "balloon" => 3, _ => 0 });
    defaults.add(&kdf_row);
    let pim_row = adw::SpinRow::builder().title("Default PIM").adjustment(&gtk::Adjustment::new(settings.borrow().security.default_pim as f64, 0.0, 2000.0, 1.0, 10.0, 0.0)).build();
    defaults.add(&pim_row);
    let aead_row = adw::ComboRow::builder().title("Committing keyslot AEAD").model(&gtk::StringList::new(&["XChaCha20-Poly1305", "AES-256-GCM-SIV"])).build();
    aead_row.set_selected(if settings.borrow().security.slot_aead == 2 { 1 } else { 0 });
    defaults.add(&aead_row);
    let exp_row = adw::SwitchRow::builder().title("Show experimental algorithms").subtitle("Per-volume opt-in still required; labeled non-standard").active(settings.borrow().security.show_experimental).build();
    defaults.add(&exp_row);
    let reqpqc_row = adw::SwitchRow::builder().title("Default to requiring PQC keyslot").active(settings.borrow().security.default_require_pqc).build();
    defaults.add(&reqpqc_row);
    page.add(&defaults);

    let policy = adw::PreferencesGroup::builder().title("Passphrase & clipboard policy").build();
    let minlen_row = adw::SpinRow::builder().title("Minimum passphrase length").adjustment(&gtk::Adjustment::new(settings.borrow().security.min_passphrase_len as f64, 1.0, 128.0, 1.0, 4.0, 0.0)).build();
    policy.add(&minlen_row);
    let warn_row = adw::SpinRow::builder().title("Warn below strength (0–4)").adjustment(&gtk::Adjustment::new(settings.borrow().security.warn_strength_below as f64, 0.0, 4.0, 1.0, 1.0, 0.0)).build();
    policy.add(&warn_row);
    let clip_row = adw::SpinRow::builder().title("Clear clipboard after (seconds, 0 = never)").adjustment(&gtk::Adjustment::new(settings.borrow().security.clipboard_clear_secs as f64, 0.0, 600.0, 5.0, 30.0, 0.0)).build();
    policy.add(&clip_row);
    page.add(&policy);

    let panic_group = adw::PreferencesGroup::builder().title("Panic & destructive actions").build();
    let confirm_row = adw::SwitchRow::builder().title("Confirm destructive actions").subtitle("Type the label before decrypt-in-place").active(settings.borrow().security.confirm_destructive).build();
    panic_group.add(&confirm_row);
    let panic_hotkey_row = adw::SwitchRow::builder().title("Panic hotkey (Ctrl+Shift+P)").active(settings.borrow().security.panic_hotkey).build();
    panic_group.add(&panic_hotkey_row);
    let panic_confirm_row = adw::SwitchRow::builder().title("Confirm before panic").active(settings.borrow().security.panic_confirm).build();
    panic_group.add(&panic_confirm_row);
    let swap_row = adw::SwitchRow::builder().title("Warn about unencrypted swap").active(settings.borrow().security.warn_swap).build();
    panic_group.add(&swap_row);
    page.add(&panic_group);

    // ---- App lock ----
    let applock_group = adw::PreferencesGroup::builder()
        .title("App lock")
        .description("Require a password to open this app (separate from your file and volume passwords)")
        .build();
    let applock_enable = adw::SwitchRow::builder()
        .title("Lock app with a password")
        .active(settings.borrow().security.app_lock_enabled && !settings.borrow().security.app_lock_hash.is_empty())
        .build();
    applock_group.add(&applock_enable);
    let applock_set = adw::ActionRow::builder()
        .title("Set / change app password")
        .build();
    let applock_btn = gtk::Button::with_label("Set password…");
    applock_btn.add_css_class("pill");
    applock_btn.set_valign(gtk::Align::Center);
    applock_set.add_suffix(&applock_btn);
    applock_group.add(&applock_set);
    page.add(&applock_group);
    {
        // "Set password…" opens a small set/confirm dialog.
        let settings = settings.clone();
        let applock_enable = applock_enable.clone();
        let parent = win.clone();
        applock_btn.connect_clicked(move |_| {
            set_app_password_dialog(&parent, settings.clone(), applock_enable.clone());
        });
    }
    {
        // Toggling on with no password set prompts to create one; toggling
        // off clears the stored hash.
        let settings = settings.clone();
        let parent = win.clone();
        let applock_enable2 = applock_enable.clone();
        applock_enable.connect_active_notify(move |sw| {
            if sw.is_active() {
                if settings.borrow().security.app_lock_hash.is_empty() {
                    set_app_password_dialog(&parent, settings.clone(), applock_enable2.clone());
                } else {
                    settings.borrow_mut().security.app_lock_enabled = true;
                    settings.borrow().save();
                }
            } else {
                let mut s = settings.borrow_mut();
                s.security.app_lock_enabled = false;
                s.security.app_lock_hash = String::new();
                drop(s);
                settings.borrow().save();
            }
        });
    }

    win.add(&page);

    let apply: Rc<dyn Fn()> = {
        let settings = settings.clone();
        let l1 = l1.clone();
        let l2 = l2.clone();
        let l3 = l3.clone();
        let hash_row = hash_row.clone();
        let kdf_row = kdf_row.clone();
        let pim_row = pim_row.clone();
        let aead_row = aead_row.clone();
        let exp_row = exp_row.clone();
        let reqpqc_row = reqpqc_row.clone();
        let minlen_row = minlen_row.clone();
        let warn_row = warn_row.clone();
        let clip_row = clip_row.clone();
        let confirm_row = confirm_row.clone();
        let panic_hotkey_row = panic_hotkey_row.clone();
        let panic_confirm_row = panic_confirm_row.clone();
        let swap_row = swap_row.clone();
        Rc::new(move || {
            let mut s = settings.borrow_mut();
            // assemble the cascade from the three cipher dropdowns
            let mut cascade = vec![CIPHER_LIST[l1.selected() as usize].1];
            if l2.selected() > 0 {
                cascade.push(CIPHER_LIST[(l2.selected() - 1) as usize].1);
            }
            if l3.selected() > 0 {
                cascade.push(CIPHER_LIST[(l3.selected() - 1) as usize].1);
            }
            s.security.cascade = cascade;
            s.security.hash = [3u16, 1, 2, 4][hash_row.selected() as usize];
            s.security.kdf = ["argon2id", "scrypt", "pbkdf2", "balloon"][kdf_row.selected() as usize].into();
            s.security.default_pim = pim_row.value() as u32;
            s.security.slot_aead = if aead_row.selected() == 1 { 2 } else { 1 };
            s.security.show_experimental = exp_row.is_active();
            s.security.default_require_pqc = reqpqc_row.is_active();
            s.security.min_passphrase_len = minlen_row.value() as u32;
            s.security.warn_strength_below = warn_row.value() as u32;
            s.security.clipboard_clear_secs = clip_row.value() as u32;
            s.security.confirm_destructive = confirm_row.is_active();
            s.security.panic_hotkey = panic_hotkey_row.is_active();
            s.security.panic_confirm = panic_confirm_row.is_active();
            s.security.warn_swap = swap_row.is_active();
            drop(s);
            settings.borrow().save();
        })
    };
    for r in [&l1, &l2, &l3, &hash_row, &kdf_row, &aead_row] {
        r.connect_selected_notify({ let a = apply.clone(); move |_| a() });
    }
    for r in [&pim_row, &minlen_row, &warn_row, &clip_row] {
        r.connect_value_notify({ let a = apply.clone(); move |_| a() });
    }
    for r in [&exp_row, &reqpqc_row, &confirm_row, &panic_hotkey_row, &panic_confirm_row, &swap_row] {
        r.connect_active_notify({ let a = apply.clone(); move |_| a() });
    }
}

fn autodismount_page(win: &adw::PreferencesWindow, cfg: &Rc<RefCell<tesseract_proto::AgentConfig>>, submit: &Submit) {
    let page = adw::PreferencesPage::builder().title("Auto-dismount").icon_name("changes-prevent-symbolic").build();
    let triggers = adw::PreferencesGroup::builder().title("Triggers").description("Agent locks volumes and wipes keys on these events").build();
    let lock = adw::SwitchRow::builder().title("On screen lock / screensaver").active(cfg.borrow().dismount_on_lock).build();
    let logout = adw::SwitchRow::builder().title("On logout").active(cfg.borrow().dismount_on_logout).build();
    let suspend = adw::SwitchRow::builder().title("On suspend / hibernate").active(cfg.borrow().dismount_on_suspend).build();
    let idle = adw::SwitchRow::builder().title("On inactivity").active(cfg.borrow().dismount_on_idle).build();
    let switch = adw::SwitchRow::builder().title("On fast user switch").active(cfg.borrow().dismount_on_user_switch).build();
    for r in [&lock, &logout, &suspend, &idle, &switch] {
        triggers.add(r);
    }
    page.add(&triggers);

    let behavior = adw::PreferencesGroup::builder().title("Behavior").build();
    let timeout = adw::SpinRow::builder().title("Inactivity timeout (seconds)").adjustment(&gtk::Adjustment::new(cfg.borrow().idle_timeout_secs as f64, 30.0, 86400.0, 30.0, 300.0, 0.0)).build();
    behavior.add(&timeout);
    let force = adw::SwitchRow::builder().title("Force unmount on trigger").subtitle("Tear down even if the filesystem is busy").active(cfg.borrow().force_unmount_on_trigger).build();
    behavior.add(&force);
    page.add(&behavior);
    win.add(&page);

    let apply: Rc<dyn Fn()> = {
        let cfg = cfg.clone();
        let submit = submit.clone();
        let (lock, logout, suspend, idle, switch, timeout, force) =
            (lock.clone(), logout.clone(), suspend.clone(), idle.clone(), switch.clone(), timeout.clone(), force.clone());
        Rc::new(move || {
            {
                let mut c = cfg.borrow_mut();
                c.dismount_on_lock = lock.is_active();
                c.dismount_on_logout = logout.is_active();
                c.dismount_on_suspend = suspend.is_active();
                c.dismount_on_idle = idle.is_active();
                c.dismount_on_user_switch = switch.is_active();
                c.idle_timeout_secs = timeout.value() as u32;
                c.force_unmount_on_trigger = force.is_active();
            }
            submit(Command::SetConfig(cfg.borrow().clone()));
        })
    };
    for r in [&lock, &logout, &suspend, &idle, &switch, &force] {
        r.connect_active_notify({ let a = apply.clone(); move |_| a() });
    }
    timeout.connect_value_notify({ let a = apply.clone(); move |_| a() });
}

fn mounting_page(win: &adw::PreferencesWindow, settings: &Rc<RefCell<Settings>>) {
    let page = adw::PreferencesPage::builder().title("Mounting").icon_name("drive-harddisk-symbolic").build();
    let group = adw::PreferencesGroup::builder().title("Mount defaults").build();
    let dir = adw::EntryRow::builder().title("Default mount directory (blank = runtime dir)").text(&settings.borrow().mounting.default_mount_dir).build();
    group.add(&dir);
    let ro = adw::SwitchRow::builder().title("Read-only by default").active(settings.borrow().mounting.read_only_default).build();
    group.add(&ro);
    let removable = adw::SwitchRow::builder().title("Mount as removable medium").active(settings.borrow().mounting.removable_default).build();
    group.add(&removable);
    let fm = adw::SwitchRow::builder().title("Open file manager on mount").active(settings.borrow().mounting.open_file_manager).build();
    group.add(&fm);
    let nocache = adw::SwitchRow::builder().title("Do not cache passphrase").active(settings.borrow().mounting.no_cache_default).build();
    group.add(&nocache);
    let automount = adw::SwitchRow::builder().title("Auto-mount favorites on launch").active(settings.borrow().mounting.auto_mount_favorites).build();
    group.add(&automount);
    let confirm = adw::SwitchRow::builder().title("Confirm force-unmount").active(settings.borrow().mounting.confirm_force_unmount).build();
    group.add(&confirm);
    page.add(&group);
    win.add(&page);

    let apply: Rc<dyn Fn()> = {
        let settings = settings.clone();
        let (dir, ro, removable, fm, nocache, automount, confirm) =
            (dir.clone(), ro.clone(), removable.clone(), fm.clone(), nocache.clone(), automount.clone(), confirm.clone());
        Rc::new(move || {
            {
                let mut s = settings.borrow_mut();
                s.mounting.default_mount_dir = dir.text().to_string();
                s.mounting.read_only_default = ro.is_active();
                s.mounting.removable_default = removable.is_active();
                s.mounting.open_file_manager = fm.is_active();
                s.mounting.no_cache_default = nocache.is_active();
                s.mounting.auto_mount_favorites = automount.is_active();
                s.mounting.confirm_force_unmount = confirm.is_active();
            }
            settings.borrow().save();
        })
    };
    dir.connect_changed({ let a = apply.clone(); move |_| a() });
    for r in [&ro, &removable, &fm, &nocache, &automount, &confirm] {
        r.connect_active_notify({ let a = apply.clone(); move |_| a() });
    }
}

fn volume_defaults_page(win: &adw::PreferencesWindow, settings: &Rc<RefCell<Settings>>) {
    let page = adw::PreferencesPage::builder().title("Volumes").icon_name("drive-multidisk-symbolic").build();
    let group = adw::PreferencesGroup::builder().title("New volume defaults").build();
    let fs = adw::ComboRow::builder().title("Default filesystem").model(&gtk::StringList::new(&["ext4", "btrfs", "xfs", "exfat", "vfat", "none"])).build();
    let fslist = ["ext4", "btrfs", "xfs", "exfat", "vfat", "none"];
    fs.set_selected(fslist.iter().position(|f| *f == settings.borrow().volume_defaults.filesystem).unwrap_or(0) as u32);
    group.add(&fs);
    let quick = adw::SwitchRow::builder().title("Quick format").subtitle("Off = full random overwrite").active(settings.borrow().volume_defaults.quick_format).build();
    group.add(&quick);
    let dynamic = adw::SwitchRow::builder().title("Sparse (dynamic) by default").active(settings.borrow().volume_defaults.dynamic_default).build();
    group.add(&dynamic);
    let size = adw::EntryRow::builder().title("Default size").text(&settings.borrow().volume_defaults.default_size).build();
    group.add(&size);
    let dir = adw::EntryRow::builder().title("Default container directory").text(&settings.borrow().volume_defaults.container_dir).build();
    group.add(&dir);
    page.add(&group);
    win.add(&page);

    let apply: Rc<dyn Fn()> = {
        let settings = settings.clone();
        let (fs, quick, dynamic, size, dir) = (fs.clone(), quick.clone(), dynamic.clone(), size.clone(), dir.clone());
        Rc::new(move || {
            {
                let mut s = settings.borrow_mut();
                s.volume_defaults.filesystem = ["ext4", "btrfs", "xfs", "exfat", "vfat", "none"][fs.selected() as usize].into();
                s.volume_defaults.quick_format = quick.is_active();
                s.volume_defaults.dynamic_default = dynamic.is_active();
                s.volume_defaults.default_size = size.text().to_string();
                s.volume_defaults.container_dir = dir.text().to_string();
            }
            settings.borrow().save();
        })
    };
    fs.connect_selected_notify({ let a = apply.clone(); move |_| a() });
    for r in [&quick, &dynamic] {
        r.connect_active_notify({ let a = apply.clone(); move |_| a() });
    }
    size.connect_changed({ let a = apply.clone(); move |_| a() });
    dir.connect_changed({ let a = apply.clone(); move |_| a() });
}

fn keyfiles_page(win: &adw::PreferencesWindow, settings: &Rc<RefCell<Settings>>, submit: &Submit) {
    let page = adw::PreferencesPage::builder().title("Keyfiles").icon_name("dialog-password-symbolic").build();
    let group = adw::PreferencesGroup::builder().title("Keyfiles").build();
    let dir = adw::EntryRow::builder().title("Default keyfile directory").text(&settings.borrow().keyfiles.keyfile_dir).build();
    group.add(&dir);
    let len = adw::SpinRow::builder().title("Generator length (bytes)").adjustment(&gtk::Adjustment::new(settings.borrow().keyfiles.generator_default_len as f64, 64.0, 1048576.0, 64.0, 1024.0, 0.0)).build();
    group.add(&len);
    let remember = adw::SwitchRow::builder().title("Remember keyfile paths in favorites").subtitle("Paths only, never contents").active(settings.borrow().keyfiles.remember_keyfiles).build();
    group.add(&remember);
    page.add(&group);

    let tools = adw::PreferencesGroup::builder().title("Generator").build();
    let gen_row = adw::ActionRow::builder().title("Generate a keyfile now").build();
    let gen_btn = gtk::Button::with_label("Generate…");
    gen_btn.add_css_class("pill");
    gen_btn.set_valign(gtk::Align::Center);
    gen_row.add_suffix(&gen_btn);
    tools.add(&gen_row);
    page.add(&tools);
    win.add(&page);
    {
        let submit = submit.clone();
        let len = len.clone();
        let win2 = win.clone();
        gen_btn.connect_clicked(move |_| {
            let dialog = gtk::FileDialog::builder().title("Save keyfile").modal(true).build();
            let submit = submit.clone();
            let length = len.value() as u32;
            dialog.save(Some(&win2), gtk::gio::Cancellable::NONE, move |res| {
                if let Ok(f) = res {
                    if let Some(p) = f.path() {
                        submit(Command::GenerateKeyfile { output: p, length });
                    }
                }
            });
        });
    }

    let apply: Rc<dyn Fn()> = {
        let settings = settings.clone();
        let (dir, len, remember) = (dir.clone(), len.clone(), remember.clone());
        Rc::new(move || {
            {
                let mut s = settings.borrow_mut();
                s.keyfiles.keyfile_dir = dir.text().to_string();
                s.keyfiles.generator_default_len = len.value() as u32;
                s.keyfiles.remember_keyfiles = remember.is_active();
            }
            settings.borrow().save();
        })
    };
    dir.connect_changed({ let a = apply.clone(); move |_| a() });
    len.connect_value_notify({ let a = apply.clone(); move |_| a() });
    remember.connect_active_notify({ let a = apply.clone(); move |_| a() });
}

fn hardware_page(win: &adw::PreferencesWindow, submit: &Submit) {
    let page = adw::PreferencesPage::builder().title("Hardware").icon_name("cpu-symbolic").build();
    let group = adw::PreferencesGroup::builder().title("Acceleration & tokens").description("Detected on the agent").build();
    let info = adw::ActionRow::builder().title("Refresh status").subtitle("AES-NI, AVX2, SHA, FIDO2 — see the footer & status").build();
    let refresh = gtk::Button::with_label("Refresh");
    refresh.add_css_class("pill");
    refresh.set_valign(gtk::Align::Center);
    info.add_suffix(&refresh);
    group.add(&info);
    let fido = adw::ActionRow::builder().title("FIDO2 / security tokens").subtitle("Enroll a key as a keyslot from a volume's detail panel").build();
    let list = gtk::Button::with_label("List devices");
    list.add_css_class("pill");
    list.set_valign(gtk::Align::Center);
    fido.add_suffix(&list);
    group.add(&fido);
    page.add(&group);
    win.add(&page);
    {
        let submit = submit.clone();
        refresh.connect_clicked(move |_| submit(Command::Status));
    }
    {
        let submit = submit.clone();
        list.connect_clicked(move |_| submit(Command::Status));
    }
}

fn advanced_page(win: &adw::PreferencesWindow, settings: &Rc<RefCell<Settings>>, cfg: &Rc<RefCell<tesseract_proto::AgentConfig>>, submit: &Submit) {
    let page = adw::PreferencesPage::builder().title("Advanced").icon_name("applications-engineering-symbolic").build();
    let group = adw::PreferencesGroup::builder().title("Data plane & logging").build();
    let plane = adw::ComboRow::builder().title("Data plane preference").model(&gtk::StringList::new(&["FUSE (default, unprivileged)", "ublk (io_uring)", "dm-crypt fast path (weaker, polkit)"])).build();
    plane.set_selected(match cfg.borrow().data_plane.as_str() { "ublk" => 1, "dmcrypt" => 2, _ => 0 });
    group.add(&plane);
    let log = adw::ComboRow::builder().title("Log verbosity").model(&gtk::StringList::new(&["error", "warn", "info", "debug"])).build();
    log.set_selected(match cfg.borrow().log_level.as_str() { "error" => 0, "warn" => 1, "debug" => 3, _ => 2 });
    group.add(&log);
    let socket = adw::EntryRow::builder().title("IPC socket path (blank = default)").text(&settings.borrow().advanced.socket_path).build();
    group.add(&socket);
    page.add(&group);

    let entropy = adw::PreferencesGroup::builder().title("Entropy").description("External sources are mixed into — never replace — the OS CSPRNG").build();
    let ext = adw::EntryRow::builder().title("External entropy source (file/FIFO, e.g. trio-rng)").text(cfg.borrow().external_entropy_path.as_deref().unwrap_or("")).build();
    entropy.add(&ext);
    let ui_entropy = adw::SwitchRow::builder().title("Collect pointer-timing entropy in wizards").active(settings.borrow().advanced.collect_ui_entropy).build();
    entropy.add(&ui_entropy);
    page.add(&entropy);

    let dmcrypt = adw::PreferencesGroup::builder().title("dm-crypt authorization").description("The fast path needs a one-time polkit grant to pkexec tesseract-mountd").build();
    let dm_info = adw::ActionRow::builder().title("Manage polkit authorization").subtitle("Default profile never invokes dm-crypt").build();
    dmcrypt.add(&dm_info);
    page.add(&dmcrypt);
    win.add(&page);

    let apply: Rc<dyn Fn()> = {
        let settings = settings.clone();
        let cfg = cfg.clone();
        let submit = submit.clone();
        let (plane, log, socket, ext, ui_entropy) = (plane.clone(), log.clone(), socket.clone(), ext.clone(), ui_entropy.clone());
        Rc::new(move || {
            {
                let mut s = settings.borrow_mut();
                s.advanced.socket_path = socket.text().to_string();
                s.advanced.collect_ui_entropy = ui_entropy.is_active();
                s.advanced.data_plane = ["fuse", "ublk", "dmcrypt"][plane.selected() as usize].into();
                s.advanced.log_level = ["error", "warn", "info", "debug"][log.selected() as usize].into();
            }
            settings.borrow().save();
            {
                let mut c = cfg.borrow_mut();
                c.data_plane = ["fuse", "ublk", "dmcrypt"][plane.selected() as usize].into();
                c.log_level = ["error", "warn", "info", "debug"][log.selected() as usize].into();
                let e = ext.text().to_string();
                c.external_entropy_path = if e.is_empty() { None } else { Some(e) };
            }
            submit(Command::SetConfig(cfg.borrow().clone()));
        })
    };
    plane.connect_selected_notify({ let a = apply.clone(); move |_| a() });
    log.connect_selected_notify({ let a = apply.clone(); move |_| a() });
    socket.connect_changed({ let a = apply.clone(); move |_| a() });
    ext.connect_changed({ let a = apply.clone(); move |_| a() });
    ui_entropy.connect_active_notify({ let a = apply.clone(); move |_| a() });
}

fn importexport_page(win: &adw::PreferencesWindow, settings: &Rc<RefCell<Settings>>, apply_theme: &ApplyTheme) {
    let page = adw::PreferencesPage::builder().title("Backup").icon_name("document-save-symbolic").build();
    let group = adw::PreferencesGroup::builder().title("Settings & favorites").description("Portable TOML — copy to another machine or removable media").build();
    let export_row = adw::ActionRow::builder().title("Export settings").build();
    let export = gtk::Button::with_label("Export…");
    export.add_css_class("pill");
    export.set_valign(gtk::Align::Center);
    export_row.add_suffix(&export);
    group.add(&export_row);
    let import_row = adw::ActionRow::builder().title("Import settings").build();
    let import = gtk::Button::with_label("Import…");
    import.add_css_class("pill");
    import.set_valign(gtk::Align::Center);
    import_row.add_suffix(&import);
    group.add(&import_row);
    page.add(&group);
    win.add(&page);
    {
        let settings = settings.clone();
        let win2 = win.clone();
        export.connect_clicked(move |_| {
            let dialog = gtk::FileDialog::builder().title("Export settings").modal(true).initial_name("tesseract-settings.toml").build();
            let settings = settings.clone();
            dialog.save(Some(&win2), gtk::gio::Cancellable::NONE, move |res| {
                if let Ok(f) = res {
                    if let Some(p) = f.path() {
                        settings.borrow().export_to(&p).ok();
                    }
                }
            });
        });
    }
    {
        let settings = settings.clone();
        let apply_theme = apply_theme.clone();
        let win2 = win.clone();
        import.connect_clicked(move |_| {
            let dialog = gtk::FileDialog::builder().title("Import settings").modal(true).build();
            let settings = settings.clone();
            let apply_theme = apply_theme.clone();
            dialog.open(Some(&win2), gtk::gio::Cancellable::NONE, move |res| {
                if let Ok(f) = res {
                    if let Some(p) = f.path() {
                        if let Ok(imported) = Settings::import_from(&p) {
                            *settings.borrow_mut() = imported;
                            settings.borrow().save();
                            apply_theme(&settings.borrow());
                        }
                    }
                }
            });
        });
    }
}

/// Standardized (non-experimental) ciphers offered as cascade defaults.
const CIPHER_LIST: &[(&str, u16)] = &[
    ("AES-256", 1),
    ("Serpent-256", 2),
    ("Twofish-256", 3),
    ("Camellia-256", 4),
    ("ChaCha20", 5),
    ("XChaCha20", 6),
];
