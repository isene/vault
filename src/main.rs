//! vault: the passwords of the Fe₂O₃ suite in the terminal.
//!
//! One encrypted file holds them all: the web logins gaze fills in, and
//! the rest (servers, doors, cards). Type to find an entry, Enter puts
//! its password on the clipboard for one paste without showing it, Tab
//! opens the entry to see and change everything.

mod clip;
mod hl;

use crust::{seq, style, Crust, Cursor, Input, Pane, Popup};
use std::io::Write;
use vault::{Login, Store};

const RUST_RGB: (u8, u8, u8) = (247, 76, 0);
const HEAD_RGB: (u8, u8, u8) = (247, 140, 60);
const TEXT_RGB: (u8, u8, u8) = (225, 225, 230);
const DIM_RGB: (u8, u8, u8) = (140, 140, 150);
const GOOD_RGB: (u8, u8, u8) = (120, 230, 140);
const BAR_BG: (u8, u8, u8) = (38, 38, 38);
const PICK_BG: (u8, u8, u8) = (52, 48, 60);

use vault::{OTHER, WEB};
/// With no key for this long the program ends, and the screen is cleared.
const IDLE_MS: u64 = 300_000;

struct App {
    store: Store,
    tab: usize,
    /// What was typed: the list is every entry that has it, in any tab.
    query: String,
    sel: usize,
    top: usize,
    note: String,
    /// The colour of a tag's tab, from ~/.vaultrc. Read once at the start.
    colours: Vec<(String, (u8, u8, u8))>,
    /// Where the cursor was in each tab left: its name, sel and top.
    places: Vec<(String, usize, usize)>,
    /// F2: the list is the possible doubles, with why beside each.
    doubles: bool,
    why: Vec<String>,
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    match arg.as_str() {
        "-v" | "--version" => { println!("vault {}", env!("CARGO_PKG_VERSION")); return; }
        "--clip" => { clip::serve(); return; }
        "-h" | "--help" => { usage(); return; }
        _ => {}
    }
    let path = std::env::var_os("VAULT_FILE").map(Into::into).unwrap_or_else(Store::default_path);
    let mut app = App { store: Store::new(path), tab: 0, query: String::new(), sel: 0, top: 0, note: String::new(), colours: read_colours(), places: Vec::new(), doubles: false, why: Vec::new() };
    term_on();
    Crust::set_app_identity("vault");
    let said = if arg == "--import-hl" {
        Some(import_hl(&mut app, &std::env::args().nth(2).unwrap_or_default()))
    } else if arg == "--clear-tags" {
        Some(if !app.open() { "Nothing changed.".into() } else {
            match app.store.clear_tags() {
                Ok((n, 0)) => format!("Entries that lost their tags: {n}."),
                Ok((n, k)) => format!("Entries that lost their tags: {n}. Kept theirs: {k}, since only the tag tells them from another entry."),
                Err(e) => format!("vault: {e}. Nothing changed."),
            }
        })
    } else {
        if app.open() { app.run(); }
        None
    };
    Crust::clear_screen();
    term_off();
    if let Some(said) = said { println!("{said}"); }
}

fn usage() {
    println!("vault — passwords in one encrypted file");
    println!();
    println!("  type           find: every entry that has the letters, in any tab");
    println!("  Enter          the password to the clipboard, for one paste");
    println!("  Ctrl+Enter     copy, quit, and paste into the window before (vault-pop)");
    println!("  Ctrl+U         the user name to the clipboard");
    println!("  →              open the entry: see and change everything");
    println!("  Ctrl+N         a new entry");
    println!("  Ctrl+D         delete the entry");
    println!("  Tab            the next tab");
    println!("  F2             possible doubles: entries that may be one thing twice");
    println!("  Ctrl+T         a colour for the tag of this tab (prism picks it)");
    println!("  Ctrl+P         a new master password");
    println!("  Esc            empty the search, or quit");
    println!("  F1             the keys");
    println!();
    println!("  vault --import-hl FILE   read an outline of passwords (title, then");
    println!("                           \"user / password\" indented under it)");
    println!("  vault --clear-tags       take the tags off every entry");
    println!();
    println!("The file is ~/.gaze/sync/passwords (VAULT_FILE names another), the");
    println!("one gaze fills web logins from. A copied password leaves the");
    println!("clipboard after the first paste, or after 30 seconds unused.");
}

/// Read an outline of passwords into the store. The answer is a count:
/// nothing of the file is ever printed.
fn import_hl(app: &mut App, file: &str) -> String {
    let Ok(text) = std::fs::read_to_string(file) else { return format!("vault: cannot read {file}") };
    let outline = if hl::sealed(&text) {
        Crust::clear_screen();
        let Some(pw) = ask(" Password of the file to import: ", "", true) else { return "Nothing imported.".into() };
        match hl::unseal(&text, &pw) {
            Ok(o) => o,
            Err(e) => return format!("vault: {e}. Nothing imported."),
        }
    } else {
        text
    };
    let (found, lost) = hl::entries(&outline);
    if !app.open() { return "Nothing imported.".into(); }
    let n = found.len();
    match app.store.import(found) {
        Ok(added) => format!("Imported {added} entries; {} were there already. {lost} lines fit no entry.\nCheck them in vault, then delete the old file yourself.", n - added),
        Err(e) => format!("vault: {e}. Nothing imported."),
    }
}

/// The bottom line as a prompt. None when Esc was pressed.
/// The terminal for the program. Ctrl+Enter is told from Enter only by
/// a terminal that is asked to (the kitty keyboard protocol); others
/// ignore the request.
fn term_on() {
    Crust::init();
    Crust::enable_modifier_keys();
}

fn term_off() {
    Crust::disable_modifier_keys();
    Crust::cleanup();
}

/// The file that tells vault-pop to paste: Ctrl+Enter was pressed.
fn paste_flag() -> std::path::PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir).join("vault-paste")
}

fn rc_path() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".vaultrc")
}

/// The lines `colour <tag> <#rrggbb>` of ~/.vaultrc.
fn read_colours() -> Vec<(String, (u8, u8, u8))> {
    let text = std::fs::read_to_string(rc_path()).unwrap_or_default();
    text.lines().filter_map(|l| {
        let mut w = l.split_whitespace();
        if w.next()? != "colour" { return None; }
        let tag = w.next()?.to_string();
        Some((tag, style::parse_hex_color(w.next()?)?))
    }).collect()
}

/// Write one tag's colour to ~/.vaultrc, in the place of its old line.
fn write_colour(tag: &str, hex: &str) {
    let text = std::fs::read_to_string(rc_path()).unwrap_or_default();
    let mut lines: Vec<String> = text.lines().filter(|l| {
        let mut w = l.split_whitespace();
        !(w.next() == Some("colour") && w.next() == Some(tag))
    }).map(String::from).collect();
    lines.push(format!("colour {tag} {hex}"));
    let _ = std::fs::write(rc_path(), lines.join("\n") + "\n");
}

fn ask(prompt: &str, initial: &str, secret: bool) -> Option<String> {
    let (cols, rows) = Crust::terminal_size();
    let mut p = Pane::new(1, rows, cols, 1, 255, 236);
    p.scroll = false;
    p.secret = secret;
    p.ask_or_cancel(prompt, initial)
}

impl App {
    /// Ask for the master password until the file opens. False on Esc.
    fn open(&mut self) -> bool {
        let (_, rows) = Crust::terminal_size();
        let mut said = if self.store.exists() { String::new() } else { "No password file yet: the master password you type now starts one.".to_string() };
        loop {
            Crust::clear_screen();
            print!("{}{}{}{}", Cursor::at(2, 2), style::rgb("vault", Some(RUST_RGB), None, "b"),
                Cursor::at(2, rows.saturating_sub(2).max(3)), style::rgb(&said, Some(HEAD_RGB), None, ""));
            std::io::stdout().flush().ok();
            let Some(master) = ask(" Master password: ", "", true) else { return false };
            if !self.store.exists() {
                match ask(" Once more: ", "", true) {
                    Some(again) if again == master => {}
                    Some(_) => { said = "Those two were not the same.".into(); continue; }
                    None => return false,
                }
            }
            print!("{}{}", Cursor::at(2, rows.saturating_sub(2).max(3)), seq::ERASE_EOL);
            std::io::stdout().flush().ok();
            match self.store.unlock(&master) {
                Ok(_) => { Crust::clear_screen(); return true; }
                Err(e) => said = format!("{e}."),
            }
        }
    }

    fn tabs(&self) -> Vec<String> { vault::tabs(self.store.logins()) }

    fn in_tab(l: &Login, tab: &str) -> bool { vault::in_tab(l, tab) }

    /// The entries in the list now, by name.
    fn rows(&mut self) -> Vec<Login> {
        if self.doubles {
            let found = vault::doubles(self.store.logins());
            self.why = found.iter().map(|(_, g, w)| format!("{g}: {w}")).collect();
            return found.into_iter().map(|(l, _, _)| l).collect();
        }
        let tab = self.tabs().get(self.tab).cloned().unwrap_or_default();
        vault::rows(self.store.logins(), &tab, &self.query)
    }

    /// A new master password. The current one is asked for first, so an
    /// open vault left alone cannot be given a password of someone else's.
    fn new_master(&mut self) {
        let Some(now) = ask(" Current master password: ", "", true) else { return };
        if !self.store.is_master(&now) { self.note = "That is not the master password. Nothing changed.".into(); return; }
        let Some(new) = ask(" New master password: ", "", true) else { return };
        if new.is_empty() { self.note = "An empty master password is no password. Nothing changed.".into(); return; }
        match ask(" Once more: ", "", true) {
            Some(again) if again == new => {}
            Some(_) => { self.note = "Those two were not the same. Nothing changed.".into(); return; }
            None => return,
        }
        self.note = match self.store.change_master(&new) {
            Ok(()) => "The master password is changed. gaze and the phone ask for the new one.".into(),
            Err(e) => format!("{e}. Nothing changed."),
        };
    }

    fn run(&mut self) {
        loop {
            self.store.refresh();
            if !self.store.unlocked() && !self.open() { return; }
            let rows = self.rows();
            if self.sel >= rows.len() { self.sel = rows.len().saturating_sub(1); }
            self.draw(&rows);
            // Nothing wakes this but a key. Left alone, the program ends.
            let Some(key) = Input::getchr_ms(IDLE_MS) else { return };
            let picked = rows.get(self.sel).cloned();
            let page = (Crust::terminal_size().1 as usize).saturating_sub(4).max(1);
            if key != "RESIZE" { self.note.clear(); }
            match key.as_str() {
                "C-Q" => return,
                "F2" => {
                    self.doubles = !self.doubles;
                    self.query.clear();
                    self.sel = 0;
                    self.top = 0;
                }
                "ESC" if self.doubles => { self.doubles = false; self.sel = 0; self.top = 0; }
                "ESC" => {
                    if self.query.is_empty() { return; }
                    self.query.clear();
                    self.sel = 0;
                }
                "DOWN" => self.sel += 1,
                "UP" => self.sel = self.sel.saturating_sub(1),
                "PgDOWN" => self.sel += page,
                "PgUP" => self.sel = self.sel.saturating_sub(page),
                "HOME" => self.sel = 0,
                "END" => self.sel = usize::MAX / 2,
                "TAB" | "S-TAB" => {
                    self.doubles = false;
                    let tabs = self.tabs();
                    let n = tabs.len();
                    // Each tab keeps its line. A search has no place to keep.
                    if self.query.is_empty() {
                        let here = tabs[self.tab].clone();
                        self.places.retain(|(t, _, _)| *t != here);
                        self.places.push((here, self.sel, self.top));
                    }
                    self.tab = if key == "S-TAB" { (self.tab + n - 1) % n } else { (self.tab + 1) % n };
                    self.query.clear();
                    let (sel, top) = self.places.iter().find(|(t, _, _)| *t == tabs[self.tab]).map(|(_, s, t)| (*s, *t)).unwrap_or((0, 0));
                    self.sel = sel;
                    self.top = top;
                }
                // Copy, leave, and have vault-pop paste into the window
                // that was in front before.
                "C-ENTER" => if let Some(l) = picked {
                    if l.password.is_empty() {
                        self.note = format!("{} has no password", l.name());
                    } else if clip::copy(&l.password) {
                        let _ = std::fs::write(paste_flag(), b"");
                        return;
                    } else {
                        self.note = "no X display here: Enter copies through the terminal".into();
                    }
                },
                "ENTER" => if let Some(l) = picked {
                    self.note = if l.password.is_empty() {
                        format!("{} has no password", l.name())
                    } else if clip::copy(&l.password) {
                        format!("password of {} copied: gone after one paste, or in 30 seconds", l.name())
                    } else {
                        // No X display (a console, ssh): the terminal's own
                        // clipboard, which nothing can empty afterwards.
                        crust::clipboard_copy(&l.password, "clipboard");
                        format!("password of {} copied; it stays on the clipboard here", l.name())
                    };
                },
                "C-U" => if let Some(l) = picked {
                    crust::clipboard_copy(&l.username, "clipboard");
                    self.note = format!("user name of {} copied", l.name());
                },
                "RIGHT" => if let Some(l) = picked { self.edit(Some(l)); },
                "C-N" | "INS" => self.edit(None),
                "C-D" | "DEL" => if let Some(l) = picked { self.delete(l); },
                "C-P" => { self.new_master(); Crust::clear_screen(); }
                "C-T" => self.colour_tab(),
                "F1" => { help(); Crust::clear_screen(); }
                "BACK" => { self.query.pop(); self.sel = 0; }
                k if k.chars().count() == 1 && !k.chars().next().is_some_and(char::is_control) => {
                    self.doubles = false;
                    self.query.push_str(k);
                    self.sel = 0;
                }
                _ => {}
            }
        }
    }

    /// A colour for the tag whose tab is open. prism picks it; the
    /// colour is a line in ~/.vaultrc.
    fn colour_tab(&mut self) {
        let tab = self.tabs().get(self.tab).cloned().unwrap_or_default();
        if tab == WEB || tab == OTHER {
            self.note = "Web and Other have no colour: go to a tag's tab first".into();
            return;
        }
        let out = std::env::temp_dir().join(format!("vault_pick_{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&out);
        let now = self.colour(&tab).map(|(r, g, b)| format!("#{r:02x}{g:02x}{b:02x}")).unwrap_or_else(|| "#f78c3c".into());
        term_off();
        let ran = std::process::Command::new("prism").arg("--pick").arg(format!("--out={}", out.display())).arg(&now).status();
        term_on();
        Crust::clear_screen();
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        let _ = std::fs::remove_file(&out);
        let hex = text.lines().find_map(|l| { let h = l.strip_prefix("fg=").unwrap_or(l).trim(); style::parse_hex_color(h).map(|_| h.to_string()) });
        self.note = match (ran, hex) {
            (Err(_), _) => "prism is not installed".into(),
            (_, None) => "no colour picked".into(),
            (_, Some(hex)) => {
                write_colour(&tab, &hex);
                self.colours = read_colours();
                format!("{tab} is {hex} now")
            }
        };
    }

    fn colour(&self, tag: &str) -> Option<(u8, u8, u8)> {
        self.colours.iter().find(|(t, _)| t == tag).map(|(_, c)| *c)
    }

    fn delete(&mut self, l: Login) {
        self.say(&format!("delete {}? y/n", l.name()));
        if Input::getchr_ms(60_000).as_deref() != Some("y") { self.note.clear(); return; }
        self.note = match self.store.delete(&l) {
            Ok(true) => format!("deleted {}", l.name()),
            Ok(false) => "it was gone already".into(),
            Err(e) => e,
        };
        self.tab = self.tab.min(self.tabs().len().saturating_sub(1));
    }

    fn say(&mut self, text: &str) {
        self.note = text.to_string();
        let rows = self.rows();
        self.draw(&rows);
    }

    fn draw(&mut self, list: &[Login]) {
        let (cols, rows) = Crust::terminal_size();
        let w = cols as usize;
        let mut out = String::new();

        // The bar across the top: the tabs, or what is searched for.
        let mut bar = format!("{}{}", style::rgb(" ", None, Some(BAR_BG), ""), style::rgb("vault", Some(RUST_RGB), Some(BAR_BG), "b"));
        let mut used = 6;
        if self.doubles {
            let groups = self.why.iter().filter_map(|w| w.split(':').next()).last().unwrap_or("0").to_string();
            let piece = format!("   possible doubles: {} entries in {} groups   (F2 or Esc: back)", list.len(), groups);
            used += crust::display_width(&piece);
            bar.push_str(&style::rgb(&piece, Some(GOOD_RGB), Some(BAR_BG), ""));
        } else if self.query.is_empty() {
            for (i, t) in self.tabs().iter().enumerate() {
                let piece = format!("   {t}");
                used += crust::display_width(&piece);
                // A tag with a colour of its own has it in both states;
                // the open tab is bold and underlined.
                let (fg, attr) = match (self.colour(t), i == self.tab) {
                    (Some(c), true) => (c, "bu"),
                    (Some(c), false) => (c, ""),
                    (None, true) => (HEAD_RGB, "b"),
                    (None, false) => (DIM_RGB, ""),
                };
                bar.push_str(&style::rgb("   ", None, Some(BAR_BG), ""));
                bar.push_str(&style::rgb(t, Some(fg), Some(BAR_BG), attr));
            }
        } else {
            let piece = format!("   find: {}▏  ({})", self.query, list.len());
            used += crust::display_width(&piece);
            bar.push_str(&style::rgb(&piece, Some(GOOD_RGB), Some(BAR_BG), ""));
        }
        bar.push_str(&style::rgb(&" ".repeat(w.saturating_sub(used)), None, Some(BAR_BG), ""));
        out.push_str(&format!("{}{}", Cursor::at(1, 1), bar));
        out.push_str(&format!("{}{}", Cursor::at(1, 2), seq::ERASE_EOL));

        // The list, scrolled so the cursor stays in view. No password in it.
        let room = (rows as usize).saturating_sub(3);
        if self.sel < self.top { self.top = self.sel; }
        if self.sel >= self.top + room { self.top = self.sel + 1 - room; }
        let name_w = (w / 3).clamp(16, 40);
        for r in 0..room {
            let body = match list.get(self.top + r) {
                Some(l) => {
                    let last = if self.doubles {
                        // Where it lives, its group, and what ties it to the group.
                        format!("{:<5} {}", if l.is_web() { WEB } else { OTHER }, self.why.get(self.top + r).cloned().unwrap_or_default())
                    } else if self.query.is_empty() {
                        if l.is_web() && !l.title.is_empty() { vault::site_key(&l.origin) } else { first_line(&l.note) }
                    } else {
                        // Where it lives, and its tags.
                        format!("{} {}", if l.is_web() { WEB } else { OTHER }, l.group).trim_end().to_string()
                    };
                    let line = format!(" {}  {}  {}",
                        // The name in the colour of the entry's first tag that has one.
                        style::rgb(&fit(&l.name(), name_w), Some(l.tags().find_map(|g| self.colour(g)).unwrap_or(TEXT_RGB)), None, ""),
                        style::rgb(&fit(&l.username, name_w), Some(HEAD_RGB), None, ""),
                        style::rgb(&take_cells(&last, w.saturating_sub(2 * name_w + 6)), Some(DIM_RGB), None, ""));
                    if self.top + r == self.sel { pick(&line, w) } else { line }
                }
                None if r == 0 && list.is_empty() => {
                    let why = if self.query.is_empty() { if self.doubles { "no possible doubles" } else { "nothing here yet; Ctrl+N makes an entry" } } else { "nothing has those letters" };
                    format!("   {}", style::rgb(why, Some(DIM_RGB), None, "i"))
                }
                None => String::new(),
            };
            out.push_str(&format!("{}{}{}", Cursor::at(1, 3 + r as u16), body, seq::ERASE_EOL));
        }
        out.push_str(&foot(&self.note, "type to find · Enter copy password · → open · Tab next tab · F1 all keys · Esc quit", w, rows));
        print!("{out}");
        std::io::stdout().flush().ok();
    }

    /// The entry on a screen of its own: every field in the clear, each
    /// one changed with Enter. `None` starts a new entry in this tab.
    fn edit(&mut self, old: Option<Login>) {
        let mut l = old.clone().unwrap_or_else(|| {
            let tab = self.tabs().get(self.tab).cloned().unwrap_or_default();
            Login { group: if tab == WEB || tab == OTHER { String::new() } else { tab }, ..Login::default() }
        });
        let start = l.clone();
        let mut at = 0usize;
        let mut note = String::new();
        const NAMES: [&str; 6] = ["Title", "Tags", "Site", "User", "Password", "Note"];
        Crust::clear_screen();
        loop {
            let (cols, rows) = Crust::terminal_size();
            let w = cols as usize;
            let mut out = format!("{}{}{}", Cursor::at(1, 1),
                style::rgb(" ", None, Some(BAR_BG), ""),
                style::rgb(&fit(&format!("vault   {}", if old.is_some() { l.name() } else { "new entry".into() }), w.saturating_sub(1)), Some(RUST_RGB), Some(BAR_BG), "b"));
            let values = [&l.title, &l.group, &l.origin, &l.username, &l.password, &l.note];
            let mut y = 3u16;
            for (i, name) in NAMES.iter().enumerate() {
                let shown: Vec<&str> = if i == 5 { values[i].lines().collect() } else { vec![values[i].as_str()] };
                let first = shown.first().copied().unwrap_or("");
                let line = format!("  {}  {}", style::rgb(&format!("{name:<9}"), Some(HEAD_RGB), None, "b"), style::rgb(&take_cells(first, w.saturating_sub(14)), Some(TEXT_RGB), None, ""));
                out.push_str(&format!("{}{}{}", Cursor::at(1, y), if i == at { pick(&line, w) } else { line }, seq::ERASE_EOL));
                y += 1;
                for more in shown.iter().skip(1) {
                    if y + 2 >= rows { break; }
                    out.push_str(&format!("{}{}{}{}", Cursor::at(1, y), " ".repeat(13), style::rgb(&take_cells(more, w.saturating_sub(14)), Some(TEXT_RGB), None, ""), seq::ERASE_EOL));
                    y += 1;
                }
            }
            for clear in y..rows { out.push_str(&format!("{}{}", Cursor::at(1, clear), seq::ERASE_EOL)); }
            out.push_str(&foot(&note, "↑ ↓ field · Enter change it · Ctrl+G make a password · Ctrl+Y copy the field · ← back", w, rows));
            print!("{out}");
            std::io::stdout().flush().ok();

            let Some(key) = Input::getchr_ms(IDLE_MS) else { break };
            note.clear();
            match key.as_str() {
                "UP" => at = at.saturating_sub(1),
                "DOWN" | "TAB" => at = (at + 1).min(5),
                "C-G" => { l.password = vault::new_password(24); at = 4; note = "a new password of 24 characters; Esc and y keeps it".into(); }
                "C-Y" => {
                    let v = [&l.title, &l.group, &l.origin, &l.username, &l.password, &l.note][at].clone();
                    if at == 4 && clip::copy(&v) { note = "password copied: gone after one paste, or in 30 seconds".into(); }
                    else { crust::clipboard_copy(&v, "clipboard"); note = format!("{} copied", NAMES[at].to_lowercase()); }
                }
                "ENTER" => {
                    let field = [&mut l.title, &mut l.group, &mut l.origin, &mut l.username, &mut l.password, &mut l.note];
                    let [title, group, origin, user, password, text] = field;
                    let target = match at { 0 => title, 1 => group, 2 => origin, 3 => user, 4 => password, _ => text };
                    if at == 5 && (target.contains('\n') || target.len() > 60) {
                        match in_editor(target) {
                            Ok(t) => *target = t,
                            Err(e) => note = e,
                        }
                        Crust::clear_screen();
                    } else if let Some(v) = ask(&format!(" {}: ", NAMES[at]), target, false) {
                        *target = v.trim().to_string();
                    }
                }
                "ESC" | "LEFT" | "C-Q" => break,
                _ => {}
            }
        }
        Crust::clear_screen();
        if l == start { return; }
        if l.title.is_empty() && !l.is_web() { self.note = "not kept: an entry needs a title or a site".into(); return; }
        self.say(&format!("keep the changes to {}? y/n", l.name()));
        if Input::getchr_ms(60_000).as_deref() != Some("y") { self.note = "changes dropped".into(); return; }
        let name = l.name();
        let done = match &old {
            Some(o) => self.store.replace(o, l.clone()),
            None => self.store.add(l.clone()),
        };
        self.note = match done { Ok(()) => format!("kept {name}"), Err(e) => e };
        // Stay on the entry: its tab, and the cursor on it.
        self.query.clear();
        let tabs = self.tabs();
        if !tabs.get(self.tab).is_some_and(|t| Self::in_tab(&l, t)) { self.tab = if l.is_web() { tabs.len().saturating_sub(1) } else { 0 }; }
        self.sel = self.rows().iter().position(|r| r.name() == name && r.username == l.username).unwrap_or(0);
    }
}

/// A long note in the editor. The text waits in a file only this user
/// can read, in memory (`$XDG_RUNTIME_DIR`), and the file goes after.
fn in_editor(text: &str) -> Result<String, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = std::env::var_os("XDG_RUNTIME_DIR").ok_or("no XDG_RUNTIME_DIR: a note is edited in a file that never touches the disk, and there is no such place here")?;
    let path = std::path::PathBuf::from(dir).join(format!("vault-note-{}", std::process::id()));
    let made = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path)
        .and_then(|mut f| f.write_all(text.as_bytes()));
    if let Err(e) = made { return Err(e.to_string()); }
    let editor = std::env::var("VISUAL").or_else(|_| std::env::var("EDITOR")).unwrap_or_else(|_| "scribe".into());
    term_off();
    let ran = std::process::Command::new(&editor).arg(&path).status();
    term_on();
    let out = std::fs::read_to_string(&path).map(|t| t.trim_end().to_string()).map_err(|e| e.to_string());
    let _ = std::fs::remove_file(&path);
    match ran { Ok(s) if s.success() => out, Ok(_) => Err(format!("{editor} ended badly; the note is as it was")), Err(e) => Err(format!("{editor}: {e}")) }
}

/// The bar along the bottom: what just happened, or the keys.
fn foot(note: &str, keys: &str, w: usize, rows: u16) -> String {
    let version = format!("v{} ", env!("CARGO_PKG_VERSION"));
    let text = if note.is_empty() { keys } else { note };
    let text = format!(" {}", take_cells(text, w.saturating_sub(version.len() + 3)));
    let pad = w.saturating_sub(crust::display_width(&text) + version.len());
    format!("{}{}{}", Cursor::at(1, rows),
        style::rgb(&format!("{text}{}", " ".repeat(pad)), Some((200, 200, 205)), Some(BAR_BG), ""),
        style::rgb(&version, Some(DIM_RGB), Some(BAR_BG), ""))
}

fn help() {
    let hdr = |s: &str| style::styled(s, Some(208), None, "b");
    let key = |s: &str| style::styled(&format!("  {:<10}", s), Some(46), None, "");
    let mut t = String::new();
    t.push_str(&format!(" {}\n", hdr("THE LIST")));
    t.push_str(&format!("{}find: every entry with the letters, in any tab\n", key("type")));
    t.push_str(&format!("{}the password to the clipboard, for one paste\n", key("Enter")));
    t.push_str(&format!("{}copy, quit, paste into the window before\n", key("Ctrl+Enter")));
    t.push_str(&format!("{}the user name to the clipboard\n", key("Ctrl+U")));
    t.push_str(&format!("{}open the entry: every field, the password too\n", key("→")));
    t.push_str(&format!("{}a new entry in this tab\n", key("Ctrl+N")));
    t.push_str(&format!("{}delete the entry\n", key("Ctrl+D")));
    t.push_str(&format!("{}the next tab; Shift+Tab the one before\n", key("Tab")));
    t.push_str(&format!("{}possible doubles, side by side\n", key("F2")));
    t.push_str(&format!("{}a colour for this tab's tag\n", key("Ctrl+T")));
    t.push_str(&format!("{}a new master password\n", key("Ctrl+P")));
    t.push_str(&format!("{}empty the search, or quit\n", key("Esc")));
    t.push_str(&format!(" {}\n", hdr("AN ENTRY")));
    t.push_str(&format!("{}change the field under the cursor\n", key("Enter")));
    t.push_str(&format!("{}make a new password\n", key("Ctrl+G")));
    t.push_str(&format!("{}copy the field\n", key("Ctrl+Y")));
    t.push_str(&format!("{}back; asks before it keeps a change\n", key("← Esc")));
    t.push_str(&format!(" {}\n", hdr("GOOD TO KNOW")));
    t.push_str("  An entry with a Site is a web login: gaze fills it.\n");
    t.push_str("  Tags are words, with spaces between. Each has a tab.\n");
    t.push_str("  Five minutes with no key, and vault ends.");
    Popup::centered(62, 26, 231, 236).view(&t);
}

fn first_line(s: &str) -> String { s.lines().next().unwrap_or("").to_string() }

/// A row with the cursor on it: the same text on a lifted background,
/// out to the edge.
fn pick(line: &str, w: usize) -> String {
    let pad = w.saturating_sub(crust::display_width(line));
    let body = format!("{line}{}", " ".repeat(pad));
    let arm = style::rgb("", None, Some(PICK_BG), "");
    let arm = arm.trim_end_matches(style::RESET).to_string();
    format!("{arm}{}{}", body.replace(style::RESET, &format!("{}{arm}", style::RESET)), style::RESET)
}

/// Exactly `w` cells: cut with a mark when too long, padded when short.
fn fit(s: &str, w: usize) -> String {
    if crust::display_width(s) <= w {
        return format!("{s}{}", " ".repeat(w - crust::display_width(s)));
    }
    let mut t = take_cells(s, w.saturating_sub(1));
    t.push('…');
    let pad = w.saturating_sub(crust::display_width(&t));
    format!("{t}{}", " ".repeat(pad))
}

/// The first `max` cells of `s`, never cutting a glyph in two.
fn take_cells(s: &str, max: usize) -> String {
    let mut walker = crust::WidthWalker::new();
    let mut out = String::new();
    let mut w = 0;
    for c in s.chars() {
        let add = walker.push(c);
        if w + add > max { break; }
        w += add;
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(name: &str) -> App {
        let dir = std::env::temp_dir().join(format!("vault-app-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = Store::new(dir.join("passwords"));
        store.unlock("m").unwrap();
        let other = |title: &str, group: &str| Login { title: title.into(), group: group.into(), password: "p".into(), ..Login::default() };
        store.add(other("office door", "Work")).unwrap();
        store.add(other("build server", "Servers")).unwrap();
        store.add(other("bike lock", "")).unwrap();
        store.add(Login { origin: "https://example.com".into(), username: "alice".into(), password: "p".into(), ..Login::default() }).unwrap();
        App { store, tab: 0, query: String::new(), sel: 0, top: 0, note: String::new(), colours: Vec::new(), places: Vec::new(), doubles: false, why: Vec::new() }
    }

    #[test]
    fn the_tabs_are_other_then_the_tags_then_web() {
        let mut a = app("tabs");
        a.store.add(Login { origin: "https://work.example".into(), group: "work, vpn".into(), password: "p".into(), ..Login::default() }).unwrap();
        assert_eq!(a.tabs(), ["Other", "Servers", "vpn", "Work", "Web"]);
        let names = |a: &mut App| a.rows().iter().map(Login::name).collect::<Vec<_>>();
        a.tab = 4;
        assert_eq!(names(&mut a), ["example.com", "work.example"]);
        a.tab = 0;
        assert_eq!(names(&mut a), ["bike lock", "build server", "office door"], "a tagged entry stays in Other");
        a.tab = 3;
        assert_eq!(names(&mut a), ["office door", "work.example"], "a tag gathers web and other entries");
        a.tab = 2;
        assert_eq!(names(&mut a), ["work.example"], "an entry with two tags is in both tabs");
    }

    #[test]
    fn the_master_password_is_checked_before_it_changes() {
        let mut a = app("master");
        assert!(a.store.is_master("m"));
        assert!(!a.store.is_master("x"));
        a.store.change_master("n").unwrap();
        assert!(a.store.is_master("n") && !a.store.is_master("m"));
        let dir = std::env::temp_dir().join(format!("vault-app-master-{}", std::process::id()));
        let mut again = Store::new(dir.join("passwords"));
        assert!(again.unlock("m").is_err());
        assert_eq!(again.unlock("n").unwrap(), 4);
    }

    #[test]
    fn typing_finds_in_every_tab() {
        let mut a = app("find");
        a.query = "o".into();
        assert_eq!(a.rows().iter().map(Login::name).collect::<Vec<_>>(), ["bike lock", "example.com", "office door"]);
        a.query = "ALICE".into();
        assert_eq!(a.rows().len(), 1);
        a.query = "zz".into();
        assert!(a.rows().is_empty());
    }

    #[test]
    fn a_name_is_always_its_column_wide() {
        assert_eq!(crust::display_width(&fit("home", 10)), 10);
        assert_eq!(crust::display_width(&fit("a very long entry name indeed", 10)), 10);
    }
}
