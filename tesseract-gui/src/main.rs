//! tesseract-gui — GTK4 + libadwaita front-end. Holds zero key material:
//! it renders agent state and collects intent, forwarding everything to the
//! memory-locked agent over the IPC socket. Cyberpunk-capable theme engine,
//! deep settings, file encryption, and YubiKey enrollment.

#![forbid(unsafe_code)]

mod agentlink;
mod applock;
mod archive;
mod fonts;
mod config;
mod dialogs;
mod filedialogs;
mod settings_ui;
mod theme;
mod widgets;

use std::cell::RefCell;
use std::rc::Rc;

use gtk::{gdk, gio, glib};
use libadwaita as adw;
use libadwaita::prelude::*;
use relm4::gtk;

use agentlink::{AgentMsg, Command};
use config::Settings;

const APP_ID: &str = "com.jegly.tesseract";

struct Ui {
    window: adw::ApplicationWindow,
    toasts: adw::ToastOverlay,
    volume_list: gtk::ListBox,
    empty_state: adw::StatusPage,
    status_scroll: gtk::ScrolledWindow,
    footer: gtk::Box,
    footer_label: gtk::Label,
    conn_dot: gtk::Label,
    settings: Rc<RefCell<Settings>>,
    agent_config: Rc<RefCell<tesseract_proto::AgentConfig>>,
    last_identity: Rc<RefCell<Option<(String, String)>>>,
    last_status: Rc<RefCell<Option<tesseract_proto::StatusInfo>>>,
    submit: Rc<dyn Fn(Command)>,
    /// When an open dialog wants inline status, it parks a callback here that
    /// the next Ok/Error result invokes (instead of a toast).
    pending_op: dialogs::OpSlot,
}

fn apply_theme(css: &gtk::CssProvider, settings: &Settings) {
    let palette = theme::find_theme(&settings.appearance.theme);
    let style = adw::StyleManager::default();
    if palette.follow_system {
        style.set_color_scheme(adw::ColorScheme::Default);
    } else if palette.dark {
        style.set_color_scheme(adw::ColorScheme::ForceDark);
    } else {
        style.set_color_scheme(adw::ColorScheme::ForceLight);
    }
    let css_text = theme::compile_css(
        &palette,
        &settings.appearance.accent,
        settings.appearance.glow_intensity,
        &settings.appearance.density,
        &settings.appearance.font,
    );
    css.load_from_string(&css_text);
}

fn build_volume_row(
    info: &tesseract_proto::VolumeInfo,
    settings: &Settings,
    submit: &Rc<dyn Fn(Command)>,
) -> gtk::ListBoxRow {
    let row = gtk::ListBoxRow::new();
    row.add_css_class("tsr-volume-row");
    let outer = gtk::Box::new(gtk::Orientation::Horizontal, 12);

    let icon = gtk::Image::from_icon_name(match info.state.as_str() {
        "ACTIVE_MOUNTED" => "drive-harddisk-symbolic",
        "UNLOCKING" | "UNMOUNTING" => "content-loading-symbolic",
        _ => "channel-secure-symbolic",
    });
    icon.set_pixel_size(28);
    outer.append(&icon);

    let textbox = gtk::Box::new(gtk::Orientation::Vertical, 2);
    textbox.set_hexpand(true);
    let title = gtk::Label::new(Some(if info.label.is_empty() {
        "Encrypted volume"
    } else {
        &info.label
    }));
    title.set_xalign(0.0);
    title.add_css_class("heading");
    textbox.append(&title);
    let detail = gtk::Label::new(Some(&format!(
        "{} · {}{}",
        info.cascade,
        info.profile,
        info.mount_point
            .as_ref()
            .map(|m| format!(" · {m}"))
            .unwrap_or_default()
    )));
    detail.set_xalign(0.0);
    detail.add_css_class("tsr-dim");
    detail.set_ellipsize(gtk::pango::EllipsizeMode::Middle);
    textbox.append(&detail);
    if settings.appearance.show_countdowns {
        if let Some(left) = info.idle_dismount_in {
            if left <= 120 {
                let cd = gtk::Label::new(Some(&format!("auto-dismount in {left}s")));
                cd.set_xalign(0.0);
                cd.add_css_class("tsr-dim");
                textbox.append(&cd);
            }
        }
    }
    if info.protection_triggered {
        let warn = gtk::Label::new(Some("⚠ hidden-volume protection triggered"));
        warn.set_xalign(0.0);
        warn.add_css_class("error");
        textbox.append(&warn);
    }
    outer.append(&textbox);

    let (chip_text, chip_class) = match info.state.as_str() {
        "ACTIVE_MOUNTED" => ("MOUNTED", "mounted"),
        "UNLOCKING" => ("UNLOCKING", "busy"),
        "UNMOUNTING" => ("UNMOUNTING", "busy"),
        "EMERGENCY_WIPING" => ("WIPING", "danger"),
        _ => ("LOCKED", "locked"),
    };
    outer.append(&widgets::status_chip(chip_text, chip_class));

    if info.state == "ACTIVE_MOUNTED" {
        let lock = gtk::Button::from_icon_name("changes-prevent-symbolic");
        lock.set_tooltip_text(Some("Lock & unmount"));
        lock.add_css_class("circular");
        lock.set_valign(gtk::Align::Center);
        let uuid = info.uuid.clone();
        let submit = submit.clone();
        lock.connect_clicked(move |_| {
            submit(Command::Lock {
                uuid: uuid.clone(),
                force: false,
            });
        });
        outer.append(&lock);
    }

    row.set_child(Some(&outer));
    row
}

fn refresh_volumes(ui: &Ui, status: &tesseract_proto::StatusInfo) {
    while let Some(child) = ui.volume_list.first_child() {
        ui.volume_list.remove(&child);
    }
    let settings = ui.settings.borrow();
    if status.volumes.is_empty() {
        ui.status_scroll.set_child(Some(&ui.empty_state));
    } else {
        for v in &status.volumes {
            ui.volume_list.append(&build_volume_row(v, &settings, &ui.submit));
        }
        ui.status_scroll.set_child(Some(&ui.volume_list));
    }
    ui.footer_label.set_text(&format!(
        "{} · {} KiB locked · entropy {} · {}",
        status.state_summary,
        status.locked_memory_kib,
        status.entropy_events,
        if status.sandbox.seccomp {
            "sandboxed"
        } else {
            "sandbox partial"
        }
    ));
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    // Make the bundled DotGothic16 font available before GTK initialises
    // fontconfig, so titles/headings/lock screen can use it immediately.
    fonts::install_bundled();
    let settings = Rc::new(RefCell::new(Settings::load()));

    let app = adw::Application::builder().application_id(APP_ID).build();

    app.connect_activate(move |app| {
        if let Some(win) = app.active_window() {
            win.present();
            return;
        }
        build_ui(app, settings.clone());
    });

    app.run();
}

fn build_ui(app: &adw::Application, settings: Rc<RefCell<Settings>>) {
    let css = gtk::CssProvider::new();
    if let Some(display) = gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &css,
            gtk::STYLE_PROVIDER_PRIORITY_USER,
        );
        // Make the bundled tesseract icon resolvable by name ("com.jegly.
        // tesseract") for the window and About dialog. Dev build points at
        // the source tree; installed builds find it in the system theme.
        let icon_theme = gtk::IconTheme::for_display(&display);
        icon_theme.add_search_path(concat!(env!("CARGO_MANIFEST_DIR"), "/../packaging/icons"));
    }
    gtk::Window::set_default_icon_name(APP_ID);
    apply_theme(&css, &settings.borrow());

    let (width, height) = {
        let s = settings.borrow();
        (s.appearance.window_width, s.appearance.window_height)
    };

    let window = adw::ApplicationWindow::builder()
        .application(app)
        .default_width(width)
        .default_height(height)
        .title("Tesseract")
        .build();

    let toasts = adw::ToastOverlay::new();
    let toolbar = adw::ToolbarView::new();

    let header = adw::HeaderBar::new();
    // No app name in the header bar (the window/taskbar title still says it).
    header.set_title_widget(Some(&adw::WindowTitle::new("", "")));

    let create_btn = gtk::Button::from_icon_name("list-add-symbolic");
    create_btn.set_tooltip_text(Some("Create volume"));
    header.pack_start(&create_btn);
    let mount_btn = gtk::Button::from_icon_name("folder-open-symbolic");
    mount_btn.set_tooltip_text(Some("Open & unlock a volume"));
    header.pack_start(&mount_btn);

    let menu_btn = gtk::MenuButton::new();
    menu_btn.set_icon_name("open-menu-symbolic");
    let menu = gio::Menu::new();
    let main_section = gio::Menu::new();
    main_section.append(Some("File encryption…"), Some("app.filemode"));
    main_section.append(Some("Volume keys & security keys…"), Some("app.volkeys"));
    main_section.append(Some("Identities…"), Some("app.identities"));
    main_section.append(Some("Benchmark…"), Some("app.benchmark"));
    menu.append_section(None, &main_section);
    let cfg_section = gio::Menu::new();
    cfg_section.append(Some("Preferences…"), Some("app.preferences"));
    cfg_section.append(Some("How to use…"), Some("app.guide"));
    cfg_section.append(Some("About Tesseract"), Some("app.about"));
    menu.append_section(None, &cfg_section);
    // Panic lives in its own section at the bottom of the menu (was a loud
    // header button; the keyboard shortcut Ctrl+Shift+P still works).
    let danger_section = gio::Menu::new();
    danger_section.append(Some("Panic — lock all & wipe keys"), Some("app.panic"));
    menu.append_section(None, &danger_section);
    menu_btn.set_menu_model(Some(&menu));
    header.pack_end(&menu_btn);

    let file_btn = gtk::Button::from_icon_name("mail-attachment-symbolic");
    file_btn.set_tooltip_text(Some("Encrypt / decrypt files"));
    header.pack_end(&file_btn);

    toolbar.add_top_bar(&header);

    let body = gtk::Box::new(gtk::Orientation::Vertical, 0);

    let status_scroll = gtk::ScrolledWindow::new();
    status_scroll.set_vexpand(true);
    let volume_list = gtk::ListBox::new();
    volume_list.add_css_class("boxed-list");
    volume_list.set_selection_mode(gtk::SelectionMode::None);
    volume_list.set_margin_top(14);
    volume_list.set_margin_bottom(14);
    volume_list.set_margin_start(16);
    volume_list.set_margin_end(16);
    volume_list.set_valign(gtk::Align::Start);

    let empty_state = adw::StatusPage::builder()
        .title("No volumes yet")
        .description("Create an encrypted volume or open an existing container to begin.")
        .build();
    let empty_create = gtk::Button::with_label("Create a volume");
    empty_create.add_css_class("suggested-action");
    empty_create.add_css_class("pill");
    empty_create.set_halign(gtk::Align::Center);
    empty_state.set_child(Some(&empty_create));
    status_scroll.set_child(Some(&empty_state));
    body.append(&status_scroll);

    let footer = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    footer.add_css_class("tsr-statusbar");
    let conn_dot = gtk::Label::new(Some("●"));
    conn_dot.add_css_class("tsr-dim");
    let footer_label = gtk::Label::new(Some("Connecting to agent…"));
    footer_label.set_xalign(0.0);
    footer_label.set_hexpand(true);
    footer_label.add_css_class("tsr-dim");
    footer.append(&conn_dot);
    footer.append(&footer_label);
    footer.set_visible(settings.borrow().appearance.show_status_bar);
    body.append(&footer);

    toolbar.set_content(Some(&body));
    toasts.set_child(Some(&toolbar));

    // App lock: optionally gate the whole UI behind a password. `lock_now`
    // swaps the window content to a clean lock screen (no padlock icon); the
    // real content is restored on the correct password.
    let lock_now: Rc<dyn Fn()> = {
        let window = window.clone();
        let real_content = toasts.clone();
        let settings = settings.clone();
        Rc::new(move || {
            let hash = settings.borrow().security.app_lock_hash.clone();
            if hash.is_empty() {
                window.set_content(Some(&real_content));
            } else {
                show_lock_screen(&window, &real_content, hash);
            }
        })
    };
    if settings.borrow().security.app_lock_enabled
        && !settings.borrow().security.app_lock_hash.is_empty()
    {
        lock_now();
    } else {
        window.set_content(Some(&toasts));
    }

    let (tx, rx) = relm4::channel::<AgentMsg>();
    let cmd_tx = agentlink::spawn(tx);
    let submit: Rc<dyn Fn(Command)> = {
        let cmd_tx = cmd_tx.clone();
        Rc::new(move |cmd| {
            cmd_tx.send(cmd).ok();
        })
    };

    let ui = Rc::new(Ui {
        window: window.clone(),
        toasts: toasts.clone(),
        volume_list,
        empty_state,
        status_scroll,
        footer: footer.clone(),
        footer_label,
        conn_dot,
        settings: settings.clone(),
        agent_config: Rc::new(RefCell::new(tesseract_proto::AgentConfig::default())),
        last_identity: Rc::new(RefCell::new(None)),
        last_status: Rc::new(RefCell::new(None)),
        submit: submit.clone(),
        pending_op: Rc::new(RefCell::new(None)),
    });

    let apply_theme_cb: settings_ui::ApplyTheme = {
        let css = css.clone();
        let ui = ui.clone();
        Rc::new(move |s: &Settings| {
            apply_theme(&css, s);
            ui.footer.set_visible(s.appearance.show_status_bar);
            if let Some(status) = ui.last_status.borrow().as_ref() {
                refresh_volumes(&ui, status);
            }
        })
    };

    register_actions(app, &ui, &apply_theme_cb);

    {
        let ui = ui.clone();
        let submit = submit.clone();
        create_btn.connect_clicked(move |_| {
            dialogs::create_wizard(&ui.window, &ui.settings.borrow(), submit.clone());
        });
    }
    {
        let ui = ui.clone();
        let submit = submit.clone();
        empty_create.connect_clicked(move |_| {
            dialogs::create_wizard(&ui.window, &ui.settings.borrow(), submit.clone());
        });
    }
    {
        let ui = ui.clone();
        let submit = submit.clone();
        mount_btn.connect_clicked(move |_| {
            dialogs::mount_dialog(&ui.window, &ui.settings.borrow(), None, submit.clone());
        });
    }
    {
        let ui = ui.clone();
        let submit = submit.clone();
        file_btn.connect_clicked(move |_| {
            filedialogs::file_mode(&ui.window, submit.clone(), ui.pending_op.clone());
        });
    }
    // panic action (menu item + Ctrl+Shift+P), with optional confirmation
    {
        let ui = ui.clone();
        let submit = submit.clone();
        let panic_action = gio::SimpleAction::new("panic", None);
        panic_action.connect_activate(move |_, _| {
            if ui.settings.borrow().security.panic_confirm {
                let dialog = adw::MessageDialog::builder()
                    .heading("Lock everything now?")
                    .body(
                        "This immediately unmounts every open volume and wipes all keys \
                         from memory.\n\nYour containers and files on disk are not deleted \
                         or harmed — you just re-enter your password to open them again.",
                    )
                    .transient_for(&ui.window)
                    .modal(true)
                    .build();
                dialog.add_responses(&[("cancel", "Cancel"), ("panic", "Lock & wipe")]);
                dialog.set_response_appearance("panic", adw::ResponseAppearance::Destructive);
                let submit = submit.clone();
                dialog.connect_response(None, move |_, resp| {
                    if resp == "panic" {
                        submit(Command::Panic);
                    }
                });
                dialog.present();
            } else {
                submit(Command::Panic);
            }
        });
        app.add_action(&panic_action);
        // The Ctrl+Shift+P hotkey is wired separately below so it can honor
        // the panic_hotkey setting (an app accelerator would always fire).
    }

    {
        let ui = ui.clone();
        let submit = submit.clone();
        let keyctl = gtk::EventControllerKey::new();
        keyctl.connect_key_pressed(move |_, key, _code, mods| {
            if ui.settings.borrow().security.panic_hotkey
                && mods.contains(gdk::ModifierType::CONTROL_MASK)
                && mods.contains(gdk::ModifierType::SHIFT_MASK)
                && key == gdk::Key::P
            {
                submit(Command::Panic);
                return glib::Propagation::Stop;
            }
            glib::Propagation::Proceed
        });
        window.add_controller(keyctl);
    }

    {
        let settings = settings.clone();
        let lock_now = lock_now.clone();
        window.connect_close_request(move |win| {
            {
                let mut s = settings.borrow_mut();
                if s.appearance.remember_window {
                    s.appearance.window_width = win.width();
                    s.appearance.window_height = win.height();
                }
            }
            settings.borrow().save();
            if settings.borrow().appearance.run_in_background {
                // re-lock before hiding so reopening requires the password
                let locked = settings.borrow().security.app_lock_enabled
                    && !settings.borrow().security.app_lock_hash.is_empty();
                if locked {
                    lock_now();
                }
                win.set_visible(false);
                return glib::Propagation::Stop;
            }
            glib::Propagation::Proceed
        });
    }

    {
        let ui = ui.clone();
        let submit = submit.clone();
        glib::spawn_future_local(async move {
            let rx = rx;
            while let Some(msg) = rx.recv().await {
                handle_agent_msg(&ui, &submit, msg);
            }
        });
    }

    submit(Command::GetConfig);
    submit(Command::Status);

    {
        let submit = submit.clone();
        glib::timeout_add_seconds_local(3, move || {
            submit(Command::Status);
            glib::ControlFlow::Continue
        });
    }

    if !settings.borrow().appearance.start_in_background {
        window.present();
    }
}

fn handle_agent_msg(ui: &Rc<Ui>, _submit: &Rc<dyn Fn(Command)>, msg: AgentMsg) {
    match msg {
        AgentMsg::Connected { hardened, version } => {
            ui.conn_dot.remove_css_class("tsr-dim");
            ui.conn_dot.remove_css_class("error");
            ui.conn_dot.add_css_class("success");
            ui.conn_dot.set_tooltip_text(Some(&format!(
                "agent {version} ({})",
                if hardened { "sandboxed" } else { "sandbox partial" }
            )));
        }
        AgentMsg::Disconnected(e) => {
            ui.conn_dot.remove_css_class("success");
            ui.conn_dot.add_css_class("error");
            ui.footer_label
                .set_text(&format!("agent unreachable: {e} — is tesseract-agent running?"));
        }
        AgentMsg::Status(status) => {
            refresh_volumes(ui, &status);
            *ui.last_status.borrow_mut() = Some(status);
        }
        AgentMsg::Config(cfg) => {
            *ui.agent_config.borrow_mut() = cfg;
        }
        AgentMsg::Bench(report) => {
            show_bench(ui, &report);
        }
        AgentMsg::Identity {
            public_b64,
            fingerprint,
            sealed,
        } => {
            *ui.last_identity.borrow_mut() = Some((public_b64.clone(), fingerprint.clone()));
            let toast = adw::Toast::builder()
                .title(format!(
                    "Identity ready ({}…)",
                    &fingerprint[..fingerprint.len().min(12)]
                ))
                .button_label("Copy recipient")
                .build();
            let pubk = public_b64.clone();
            let win = ui.window.clone();
            toast.connect_button_clicked(move |_| {
                win.clipboard().set_text(&pubk);
            });
            let _ = sealed;
            ui.toasts.add_toast(toast);
        }
        AgentMsg::Ok(message) => {
            // if a dialog is waiting for inline status, hand it the result;
            // otherwise fall back to a toast on the main window.
            let cb = ui.pending_op.borrow_mut().take();
            if let Some(cb) = cb {
                cb(Ok(message));
            } else {
                ui.toasts.add_toast(adw::Toast::new(&message));
            }
            (ui.submit)(Command::Status);
        }
        AgentMsg::Error(e) => {
            let cb = ui.pending_op.borrow_mut().take();
            if let Some(cb) = cb {
                cb(Err(e));
            } else {
                let toast = adw::Toast::builder().title(format!("Error: {e}")).timeout(6).build();
                ui.toasts.add_toast(toast);
            }
        }
        AgentMsg::Event(ev) => handle_event(ui, ev),
    }
}

fn handle_event(ui: &Rc<Ui>, ev: tesseract_proto::Event) {
    use tesseract_proto::Event;
    match ev {
        Event::VolumeState { state, trigger, .. } => {
            if let Some(t) = trigger {
                let toast = adw::Toast::builder()
                    .title(format!("Volume {state} ({t})"))
                    .timeout(4)
                    .build();
                ui.toasts.add_toast(toast);
            }
            (ui.submit)(Command::Status);
        }
        Event::PanicFired => {
            ui.toasts.add_toast(adw::Toast::new("Panic fired — all key material wiped"));
            (ui.submit)(Command::Status);
        }
        Event::ProtectionTriggered { .. } => {
            ui.toasts.add_toast(
                adw::Toast::builder()
                    .title("Hidden-volume protection triggered a write block")
                    .timeout(6)
                    .build(),
            );
            (ui.submit)(Command::Status);
        }
        Event::IdleCountdown { .. } | Event::Progress { .. } => {}
    }
}

/// Replace the window content with a clean password lock screen (no padlock
/// iconography). On the correct password, the real content is restored.
fn show_lock_screen(
    window: &adw::ApplicationWindow,
    real_content: &adw::ToastOverlay,
    hash: String,
) {
    let toolbar = adw::ToolbarView::new();
    let header = adw::HeaderBar::new();
    header.add_css_class("flat");
    header.set_show_title(false);
    toolbar.add_top_bar(&header);

    let center = gtk::Box::new(gtk::Orientation::Vertical, 14);
    center.set_valign(gtk::Align::Center);
    center.set_halign(gtk::Align::Center);
    center.set_margin_top(40);
    center.set_margin_bottom(40);
    center.set_width_request(360);

    let title = gtk::Label::new(Some("Tesseract"));
    title.add_css_class("tsr-hero");
    let subtitle = gtk::Label::new(Some("Enter your password to continue"));
    subtitle.add_css_class("tsr-dim");
    center.append(&title);
    center.append(&subtitle);

    let entry = gtk::PasswordEntry::builder()
        .show_peek_icon(true)
        .activates_default(true)
        .build();
    entry.set_property("placeholder-text", "Password");
    let list = gtk::ListBox::new();
    list.add_css_class("boxed-list");
    let row = gtk::ListBoxRow::new();
    row.set_child(Some(&entry));
    row.set_activatable(false);
    list.append(&row);
    center.append(&list);

    let error = gtk::Label::new(None);
    error.add_css_class("error");
    error.set_visible(false);
    center.append(&error);

    let unlock = gtk::Button::with_label("Unlock");
    unlock.add_css_class("suggested-action");
    unlock.add_css_class("pill");
    unlock.set_hexpand(true);
    center.append(&unlock);

    let clamp = adw::Clamp::builder().maximum_size(420).child(&center).build();
    toolbar.set_content(Some(&clamp));
    window.set_content(Some(&toolbar));
    entry.grab_focus();

    let try_unlock = {
        let window = window.clone();
        let real_content = real_content.clone();
        let entry = entry.clone();
        let error = error.clone();
        let hash = hash.clone();
        move || {
            if applock::verify_password(&entry.text(), &hash) {
                window.set_content(Some(&real_content));
            } else {
                error.set_text("Incorrect password");
                error.set_visible(true);
                entry.set_text("");
                entry.grab_focus();
            }
        }
    };
    {
        let try_unlock = try_unlock.clone();
        unlock.connect_clicked(move |_| try_unlock());
    }
    {
        let try_unlock = try_unlock.clone();
        entry.connect_activate(move |_| try_unlock());
    }
}

fn show_guide(parent: &adw::ApplicationWindow) {
    let win = adw::PreferencesWindow::builder()
        .title("How to use Tesseract")
        .modal(true)
        .search_enabled(false)
        .default_width(680)
        .default_height(640)
        .build();
    win.set_transient_for(Some(parent));

    // A small helper to build a guide page with a list of (title, body) rows.
    let page = |icon: &str, page_title: &str, group_title: &str, rows: &[(&str, &str)]| {
        let p = adw::PreferencesPage::builder()
            .title(page_title)
            .icon_name(icon)
            .build();
        let g = adw::PreferencesGroup::builder().title(group_title).build();
        for (t, body) in rows {
            let row = adw::ActionRow::builder()
                .title(*t)
                .subtitle(*body)
                .build();
            row.set_subtitle_lines(0);
            row.set_title_lines(0);
            g.add(&row);
        }
        p.add(&g);
        win.add(&p);
    };

    page(
        "dialog-information-symbolic",
        "Start here",
        "What this app is for",
        &[
            ("In one sentence",
             "Tesseract scrambles your files, folders, and drives so that only someone with the right password (or key) can read them — and it keeps working even against future quantum computers."),
            ("Two ways to use it",
             "1) Lock individual files or folders with a password. 2) Make an encrypted “vault” you can open and use like a USB drive, then close again. Most people only need the first one."),
            ("Don't worry about the jargon",
             "You can use everything here with just a password. Words like “keypair”, “recipient”, and “identity” are an OPTIONAL advanced mode for sending encrypted files to other people — skip them unless you need that."),
            ("Your data stays with you",
             "No account, no internet, no tracking. If you forget a password there is no “reset” — the whole point is that nobody, including us, can get in without it. Keep your passwords safe."),
        ],
    );

    page(
        "mail-attachment-symbolic",
        "Lock a file or folder",
        "The simple, everyday way",
        &[
            ("Step 1 — open it",
             "Click the paperclip icon at the top of the window. It opens on “Encrypt” with “Password” already selected — that's all you need."),
            ("Step 2 — choose what to lock",
             "Click “File…” for one file, or “Folder…” to lock a whole folder at once (it becomes a single locked file). Then pick where to save the locked copy — it ends in “.tsrf”."),
            ("Step 3 — set a password",
             "Type a password twice and click Encrypt. Done. The original is left as-is; the new “.tsrf” file is the locked copy. You can delete the original afterwards if you want."),
            ("To unlock later",
             "Open the paperclip again, go to the “Decrypt” tab, pick the “.tsrf” file, choose where to put the result, type the same password, and click Decrypt. A locked folder is unpacked back into a normal folder automatically."),
            ("Example — back up tax documents",
             "Click Folder…, pick your “Taxes” folder, save it as Taxes.tsrf with a strong password, and copy that one file to a USB stick or cloud. Even if the stick is lost, the files are unreadable."),
            ("Example — send a private document",
             "Lock a PDF with a password, email the .tsrf file, and tell the other person the password through a different channel (e.g. a phone call). They open it with Tesseract."),
            ("Which algorithm?",
             "Leave it on “ChaCha20-Poly1305 — fast, recommended”. The other choices are for people with specific preferences; they are all strong. The “Cascade” options encrypt twice for extra paranoia (slower)."),
        ],
    );

    page(
        "system-users-symbolic",
        "Sending to others",
        "Keypairs & recipients — the optional advanced bit",
        &[
            ("Think of a mailbox",
             "A “keypair” is like a mailbox. It has two parts: a SLOT that anyone can drop letters into (your “public key”, or “recipient” line), and a physical KEY that only you have to open the mailbox and read them (your “private key”, kept inside your “identity file”)."),
            ("Why use it instead of a password?",
             "So you never have to share a password. People drop files into your “mailbox” using your public recipient line; only your private identity file can open them. Great for receiving sensitive files regularly."),
            ("Make your mailbox",
             "Menu → Identities → Generate. This creates your identity FILE — guard it like a house key (optionally lock it with its own password). It also shows your “recipient” line, which is safe to share with anyone."),
            ("Receiving a file",
             "Give people your recipient line. They encrypt to it (Encrypt → Recipients → paste your line). You decrypt on the Decrypt tab using the “Identity” option and your identity file."),
            ("Sending to someone",
             "Ask them for THEIR recipient line, then Encrypt → Recipients → paste it → Encrypt. Only they can open the result — not even you can, afterwards."),
            ("Moving between computers",
             "A password-locked .tsrf opens on any computer with just the password. A recipient-locked .tsrf needs your identity file on that computer too — so copy your identity file across if you switch machines."),
        ],
    );

    page(
        "drive-harddisk-symbolic",
        "Encrypted vaults",
        "A drive that locks and unlocks",
        &[
            ("What it is",
             "A vault (a “volume”) is a single file that behaves like a secret USB drive. When you unlock it, it appears as a drive you can drag files in and out of. When you lock it, it's just an unreadable blob again."),
            ("Create one",
             "Click + at the top. Pick a size, set a password, and create. This makes the vault file."),
            ("Open and use it",
             "Click the folder icon, choose your vault file, enter the password. It mounts as a drive — use it like any folder. Everything written to it is encrypted instantly."),
            ("Close it",
             "Click the lock button on the vault in the list. It also closes itself automatically when you lock your screen, suspend, log out, or step away (you can tune this in Preferences → Auto-dismount)."),
            ("Example — a private work drive",
             "Make a 2 GB vault called work.tsr, keep client files in it, and it auto-locks the moment your screen locks — so a colleague who sits at your unlocked-then-locked laptop sees nothing."),
            ("Hidden vaults (advanced)",
             "When creating, you can hide a second vault inside the free space of the first. If someone forces you to reveal a password, you give the outer one; the hidden one stays mathematically invisible."),
        ],
    );

    page(
        "security-high-symbolic",
        "Safety & settings",
        "Locking the app, the panic button, and themes",
        &[
            ("Lock the app itself",
             "Preferences → Security → “Lock app with a password”. Set a password and the whole app asks for it on launch (and when you reopen it from the background). This is separate from your file passwords."),
            ("The Panic button",
             "Menu → “Panic” (or Ctrl+Shift+P) instantly closes every open vault and erases the keys from memory. IMPORTANT: it does NOT delete anything — your files and vaults are safe; you just re-enter your password to open them again. It asks for confirmation by default; you can turn that off in Preferences → Security."),
            ("Auto-locking",
             "Preferences → Auto-dismount lets you choose when vaults close themselves: on screen lock, suspend, logout, or after a few minutes of inactivity."),
            ("Themes",
             "Preferences → Appearance: Dracula, the four Catppuccin flavours, Vintage Light, a neon “cyberpunk” theme, or follow-system — with a colour picker. Changes apply instantly."),
            ("If you forget a password",
             "There is no recovery, by design. Use a password manager, or write important passwords down and store them somewhere physically safe."),
        ],
    );

    win.present();
}

fn show_bench(ui: &Rc<Ui>, report: &tesseract_proto::BenchReport) {
    let win = adw::Window::builder()
        .title("Benchmark")
        .modal(true)
        .default_width(520)
        .default_height(560)
        .build();
    win.set_transient_for(Some(&ui.window));
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&adw::HeaderBar::new());
    let scroll = gtk::ScrolledWindow::new();
    let list = gtk::ListBox::new();
    list.add_css_class("boxed-list");
    list.set_margin_top(14);
    list.set_margin_bottom(14);
    list.set_margin_start(16);
    list.set_margin_end(16);
    for e in &report.entries {
        let row = adw::ActionRow::builder().title(&e.name).build();
        let val = gtk::Label::new(Some(&format!("{:.2} {}", e.value, e.unit)));
        val.add_css_class("tsr-mono");
        val.set_valign(gtk::Align::Center);
        row.add_suffix(&val);
        list.append(&row);
    }
    scroll.set_child(Some(&list));
    toolbar.set_content(Some(&scroll));
    win.set_content(Some(&toolbar));
    win.present();
}

fn register_actions(app: &adw::Application, ui: &Rc<Ui>, apply_theme_cb: &settings_ui::ApplyTheme) {
    let prefs = gio::SimpleAction::new("preferences", None);
    {
        let ui = ui.clone();
        let apply_theme_cb = apply_theme_cb.clone();
        prefs.connect_activate(move |_, _| {
            settings_ui::open(
                &ui.window,
                ui.settings.clone(),
                ui.agent_config.clone(),
                apply_theme_cb.clone(),
                ui.submit.clone(),
            );
        });
    }
    app.add_action(&prefs);

    let filemode = gio::SimpleAction::new("filemode", None);
    {
        let ui = ui.clone();
        filemode.connect_activate(move |_, _| {
            filedialogs::file_mode(&ui.window, ui.submit.clone(), ui.pending_op.clone());
        });
    }
    app.add_action(&filemode);

    let identities = gio::SimpleAction::new("identities", None);
    {
        let ui = ui.clone();
        identities.connect_activate(move |_, _| {
            filedialogs::identity_manager(&ui.window, ui.last_identity.clone(), ui.submit.clone());
        });
    }
    app.add_action(&identities);

    let volkeys = gio::SimpleAction::new("volkeys", None);
    {
        let ui = ui.clone();
        volkeys.connect_activate(move |_, _| {
            filedialogs::manage_keys(&ui.window, ui.submit.clone(), ui.pending_op.clone());
        });
    }
    app.add_action(&volkeys);

    let guide = gio::SimpleAction::new("guide", None);
    {
        let ui = ui.clone();
        guide.connect_activate(move |_, _| {
            show_guide(&ui.window);
        });
    }
    app.add_action(&guide);

    let benchmark = gio::SimpleAction::new("benchmark", None);
    {
        let ui = ui.clone();
        benchmark.connect_activate(move |_, _| {
            ui.toasts.add_toast(adw::Toast::new("Benchmarking… (this can take a minute)"));
            (ui.submit)(Command::Benchmark {
                kind: "all".into(),
            });
        });
    }
    app.add_action(&benchmark);

    let about = gio::SimpleAction::new("about", None);
    {
        let ui = ui.clone();
        about.connect_activate(move |_, _| {
            let about = adw::AboutWindow::builder()
                .application_name("Tesseract")
                .application_icon(APP_ID)
                .version(env!("CARGO_PKG_VERSION"))
                .developer_name("jegly")
                .license_type(gtk::License::Gpl30)
                .comments(
                    "Post-quantum disk & file encryption.\n\
                     All key material lives in a memory-locked, sandboxed agent;\n\
                     this GUI never touches it.",
                )
                .website("https://github.com/jegly/tesseract")
                .build();
            about.set_transient_for(Some(&ui.window));
            about.present();
        });
    }
    app.add_action(&about);

    app.set_accels_for_action("app.preferences", &["<Ctrl>comma"]);
    app.set_accels_for_action("app.filemode", &["<Ctrl>e"]);
}
