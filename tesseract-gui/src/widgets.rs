//! Small reusable widget builders kept out of the big component files.

use gtk::prelude::*;
use relm4::gtk;

/// A rounded status chip ("MOUNTED", "LOCKED", ...).
pub fn status_chip(text: &str, class: &str) -> gtk::Label {
    let label = gtk::Label::new(Some(text));
    label.add_css_class("tsr-chip");
    label.add_css_class(class);
    label.set_valign(gtk::Align::Center);
    label
}

/// Section heading.
pub fn section_title(text: &str) -> gtk::Label {
    let l = gtk::Label::new(Some(text));
    l.add_css_class("tsr-section-title");
    l.set_xalign(0.0);
    l.set_margin_top(6);
    l.set_margin_bottom(2);
    l
}
