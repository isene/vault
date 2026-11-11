//! A password on the clipboard, for one paste.
//!
//! `vault --clip` reads the password on its standard input and owns the
//! CLIPBOARD and PRIMARY selections itself. The first program that pastes gets it;
//! a moment later this one ends, and the clipboard is empty again. With
//! no paste it ends after half a minute. It sleeps in the kernel between
//! those events, and it does not exist the rest of the day.
//!
//! The selection says it is a password (`x-kde-passwordManagerHint`), so
//! a clipboard history such as yank leaves it alone.

use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    AtomEnum, ConnectionExt as _, CreateWindowAux, EventMask, PropMode, SelectionNotifyEvent,
    WindowClass, SELECTION_NOTIFY_EVENT,
};
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;

/// How long an unused password stays.
const UNUSED: Duration = Duration::from_secs(30);
/// How long it stays after the first paste. Some programs ask twice for
/// one paste.
const AFTER_PASTE: Duration = Duration::from_secs(2);

/// Hand `secret` to a helper that keeps it for one paste. False when no
/// helper could be started (no X display).
pub fn copy(secret: &str) -> bool {
    use std::io::Write;
    if std::env::var_os("DISPLAY").is_none() { return false; }
    let Ok(me) = std::env::current_exe() else { return false };
    use std::os::unix::process::CommandExt;
    // setsid: the helper outlives this program and its terminal. A
    // process group of its own from the first instant: vault may quit
    // right after (Ctrl+Enter), and the closing terminal hangs up on its
    // foreground group before setsid has run.
    let Ok(mut child) = std::process::Command::new("setsid")
        .arg(me).arg("--clip")
        .process_group(0)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn() else { return false };
    let sent = child.stdin.take().map(|mut s| s.write_all(secret.as_bytes()).is_ok()).unwrap_or(false);
    std::thread::spawn(move || { let _ = child.wait(); });
    sent
}

/// The helper itself.
pub fn serve() {
    use std::io::Read;
    let mut secret = Vec::new();
    if std::io::stdin().read_to_end(&mut secret).is_err() || secret.is_empty() { return; }
    let Ok((conn, screen)) = RustConnection::connect(None) else { return };
    let root = conn.setup().roots[screen].root;
    let atom = |name: &[u8]| conn.intern_atom(false, name).ok().and_then(|c| c.reply().ok()).map(|r| r.atom);
    let (Some(clipboard), Some(utf8), Some(targets), Some(hint)) =
        (atom(b"CLIPBOARD"), atom(b"UTF8_STRING"), atom(b"TARGETS"), atom(b"x-kde-passwordManagerHint")) else { return };
    let string: u32 = AtomEnum::STRING.into();
    let Ok(win) = conn.generate_id() else { return };
    let made = conn.create_window(0, win, root, 0, 0, 1, 1, 0, WindowClass::INPUT_ONLY, 0,
        &CreateWindowAux::new().event_mask(EventMask::NO_EVENT));
    if made.is_err() { return; }
    let _ = conn.set_selection_owner(win, clipboard, x11rb::CURRENT_TIME);
    // The mouse selection too: a terminal pastes that one on Shift+Insert.
    let _ = conn.set_selection_owner(win, u32::from(AtomEnum::PRIMARY), x11rb::CURRENT_TIME);
    let _ = conn.flush();
    let owner = conn.get_selection_owner(clipboard).ok().and_then(|c| c.reply().ok()).map(|r| r.owner);
    if owner != Some(win) { return; }

    let mut until = Instant::now() + UNUSED;
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() { return; }
        // Sleep until the X server has something, or the time is up.
        let mut fd = libc::pollfd { fd: conn.stream().as_raw_fd(), events: libc::POLLIN, revents: 0 };
        let n = unsafe { libc::poll(&mut fd, 1, left.as_millis().min(60_000) as i32) };
        if n < 0 || fd.revents & (libc::POLLHUP | libc::POLLERR) != 0 { return; }
        loop {
            let ev = match conn.poll_for_event() {
                Ok(Some(ev)) => ev,
                Ok(None) => break,
                Err(_) => return,
            };
            match ev {
                // Something else was copied: the password is gone already.
                Event::SelectionClear(_) => return,
                Event::SelectionRequest(r) => {
                    let prop = if r.property == x11rb::NONE { r.target } else { r.property };
                    let ok = if r.target == targets {
                        conn.change_property32(PropMode::REPLACE, r.requestor, prop, AtomEnum::ATOM, &[targets, utf8, string, hint]).is_ok()
                    } else if r.target == utf8 || r.target == string {
                        until = until.min(Instant::now() + AFTER_PASTE);
                        conn.change_property8(PropMode::REPLACE, r.requestor, prop, r.target, &secret).is_ok()
                    } else if r.target == hint {
                        conn.change_property8(PropMode::REPLACE, r.requestor, prop, string, b"secret").is_ok()
                    } else {
                        false
                    };
                    let note = SelectionNotifyEvent {
                        response_type: SELECTION_NOTIFY_EVENT,
                        sequence: 0,
                        time: r.time,
                        requestor: r.requestor,
                        selection: r.selection,
                        target: r.target,
                        property: if ok { prop } else { x11rb::NONE },
                    };
                    let _ = conn.send_event(false, r.requestor, EventMask::NO_EVENT, note);
                    let _ = conn.flush();
                }
                _ => {}
            }
        }
    }
}
