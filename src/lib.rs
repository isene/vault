//! The password store of the Fe₂O₃ suite: one encrypted file.
//!
//! The file is the JSON list of entries, sealed with ChaCha20-Poly1305
//! under a key that Argon2id derives from the master password. The key
//! lives in memory only while the store is unlocked.
//!
//! gaze fills web logins from it, the `vault` program shows and edits
//! all of it, and the phone shares the file through Syncthing. So a
//! change reads the file again first when it changed on disk, and lands
//! on top of it. Two machines that both changed it while apart leave a
//! Syncthing conflict file; the next unlock takes the newer of each
//! entry from it.

use argon2::Argon2;
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// What a file starts with. `GAZE1` holds web logins only; a program that
/// knows only that one would drop titles, groups and notes. So a file
/// that has any says `GAZE2`, and the old program leaves it alone.
const MAGIC: &[u8] = b"GAZE2";
const MAGIC_OLD: &[u8] = b"GAZE1";
const MAGIC_LEN: usize = 5;
pub const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEAD: usize = MAGIC_LEN + SALT_LEN + NONCE_LEN;

/// One entry. A web login has an `origin`; a password for anything else
/// (a server, a door, a card) has a `title` and no origin.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct Login {
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub username: String,
    pub password: String,
    /// Seconds since the epoch of the last fill; the most recent fills first.
    #[serde(default)]
    pub used: u64,
    /// What the entry is called, when it is not a web login.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
    /// The tab it sits under in `vault`. Empty for a plain web login.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group: String,
    /// Free text: a PIN, an answer to a secret question, where the key is.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// Seconds since the epoch of the last change. When two machines
    /// changed the same entry while apart, the later one is kept.
    #[serde(default)]
    pub changed: u64,
}

impl Login {
    /// The tags of the entry: the words of its `group` field, split at
    /// commas and spaces.
    pub fn tags(&self) -> impl Iterator<Item = &str> {
        self.group.split(|c: char| c == ',' || c.is_whitespace()).filter(|t| !t.is_empty())
    }

    pub fn is_web(&self) -> bool { !self.origin.trim().is_empty() }

    /// What to call it in a list: its title, or the site without `https://`.
    pub fn name(&self) -> String {
        if !self.title.is_empty() { return self.title.clone(); }
        let site = site_key(&self.origin);
        site.split_once("://").map(|(_, host)| host.to_string()).unwrap_or(site)
    }

    /// Two entries with the same answer here are the same entry.
    fn id(&self) -> (String, String, String, String) {
        let site = if self.is_web() { site_key(&self.origin) } else { String::new() };
        (site, self.username.clone(), self.title.clone(), self.group.clone())
    }
}

#[derive(Debug, PartialEq)]
pub enum Change { New, Updated, Same }

/// The salt of a password file, or None when it is no such file.
pub fn salt_of(file: &[u8]) -> Option<[u8; SALT_LEN]> {
    if file.len() < HEAD || (&file[..MAGIC_LEN] != MAGIC && &file[..MAGIC_LEN] != MAGIC_OLD) { return None; }
    file[MAGIC_LEN..MAGIC_LEN + SALT_LEN].try_into().ok()
}

pub fn new_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// The key the master password gives with this salt. Slow on purpose.
pub fn derive(master: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Argon2::default().hash_password_into(master.as_bytes(), salt, &mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

/// The entries of a file, or None when the key does not open it.
pub fn open(file: &[u8], key: &[u8; 32]) -> Option<Vec<Login>> {
    salt_of(file)?;
    let plain = ChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(&file[MAGIC_LEN + SALT_LEN..HEAD]), &file[HEAD..]).ok()?;
    serde_json::from_slice(&plain).ok()
}

/// The file that holds these entries.
pub fn seal(logins: &[Login], key: &[u8; 32], salt: &[u8; SALT_LEN]) -> Result<Vec<u8>, String> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let plain = serde_json::to_vec(logins).map_err(|e| e.to_string())?;
    let sealed = ChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(Nonce::from_slice(&nonce), plain.as_ref())
        .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(HEAD + sealed.len());
    // Web logins alone are still a file the older programs read.
    let plain_web = logins.iter().all(|l| l.title.is_empty() && l.group.is_empty() && l.note.is_empty());
    out.extend_from_slice(if plain_web { MAGIC_OLD } else { MAGIC });
    out.extend_from_slice(salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Take from `theirs` what `mine` lacks, and the entries changed later
/// there. Returns how many entries that brought in.
pub fn merge(mine: &mut Vec<Login>, theirs: Vec<Login>) -> usize {
    let mut n = 0;
    for t in theirs {
        match mine.iter_mut().find(|m| m.id() == t.id()) {
            Some(m) => {
                if t.changed > m.changed { *m = t; n += 1; }
            }
            None => { mine.push(t); n += 1; }
        }
    }
    n
}

/// A password nobody could guess: `len` characters out of 64, each one
/// as likely as the next.
pub fn new_password(len: usize) -> String {
    const SET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| SET[(b & 63) as usize] as char).collect()
}

pub struct Store {
    path: PathBuf,
    key: Option<[u8; 32]>,
    salt: [u8; SALT_LEN],
    logins: Vec<Login>,
    /// When the file was last read or written by this store.
    seen: Option<std::time::SystemTime>,
}

impl Store {
    pub fn new(path: PathBuf) -> Store {
        Store { path, key: None, salt: [0; SALT_LEN], logins: Vec::new(), seen: None }
    }

    /// Where the suite keeps the file: beside gaze's other synced files,
    /// in the folder Syncthing already shares with the phone.
    pub fn default_path() -> PathBuf {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        home.join(".gaze/sync/passwords")
    }

    pub fn exists(&self) -> bool { self.path.exists() }
    pub fn unlocked(&self) -> bool { self.key.is_some() }
    pub fn logins(&self) -> &[Login] { &self.logins }

    /// Open the store with the master password, or start a new one when
    /// there is no file yet. Returns how many entries it holds.
    pub fn unlock(&mut self, master: &str) -> Result<usize, String> {
        let Ok(raw) = std::fs::read(&self.path) else {
            self.salt = new_salt();
            self.key = Some(derive(master, &self.salt)?);
            self.logins.clear();
            self.save()?;
            return Ok(0);
        };
        let Some(salt) = salt_of(&raw) else { return Err("not a password file".into()) };
        let key = derive(master, &salt)?;
        self.logins = open(&raw, &key).ok_or("wrong master password")?;
        self.salt = salt;
        self.key = Some(key);
        self.seen = self.modified();
        self.take_conflicts();
        Ok(self.logins.len())
    }

    fn modified(&self) -> Option<std::time::SystemTime> {
        std::fs::metadata(&self.path).and_then(|m| m.modified()).ok()
    }

    /// Syncthing keeps the losing file when two machines both changed it:
    /// `passwords.sync-conflict-<date>-<time>-<id>`. Take what it has that
    /// this one lacks, and remove it. A file this key does not open stays.
    fn take_conflicts(&mut self) {
        let (Some(key), Some(dir), Some(name)) = (self.key, self.path.parent(), self.path.file_name()) else { return };
        let prefix = format!("{}.sync-conflict-", name.to_string_lossy());
        let Ok(files) = std::fs::read_dir(dir) else { return };
        for f in files.flatten() {
            if !f.file_name().to_string_lossy().starts_with(&prefix) { continue; }
            let Some(theirs) = std::fs::read(f.path()).ok().and_then(|raw| open(&raw, &key)) else { continue };
            let before = self.logins.clone();
            merge(&mut self.logins, theirs);
            if self.save().is_ok() { let _ = std::fs::remove_file(f.path()); } else { self.logins = before; }
        }
    }

    /// Read the file again when it changed on disk since this store last
    /// saw it (the phone saved a login). A file sealed under another
    /// master password locks the store, so the next use asks again.
    pub fn refresh(&mut self) {
        let Some(key) = self.key else { return };
        let now = self.modified();
        if now.is_none() || now == self.seen { return; }
        let opened = std::fs::read(&self.path).ok().and_then(|raw| {
            if salt_of(&raw)? != self.salt { return None; }
            open(&raw, &key)
        });
        match opened {
            Some(logins) => { self.logins = logins; self.seen = now; }
            None => self.lock(),
        }
    }

    /// Ready to change: unlocked, and holding what the file holds now.
    fn fresh(&mut self) -> Result<(), String> {
        if self.key.is_none() { return Err("passwords are locked".into()); }
        self.refresh();
        if self.key.is_none() { return Err("the password file changed on another machine; unlock again".into()); }
        Ok(())
    }

    /// Is this the master password the open store was opened with?
    pub fn is_master(&self, master: &str) -> bool {
        match (self.key, derive(master, &self.salt)) {
            (Some(key), Ok(k)) => key == k,
            _ => false,
        }
    }

    /// Seal the store under a new master password, with a fresh salt.
    pub fn change_master(&mut self, master: &str) -> Result<(), String> {
        if self.key.is_none() { return Err("passwords are locked".into()); }
        let salt = new_salt();
        let key = derive(master, &salt)?;
        let (old_salt, old_key) = (self.salt, self.key);
        self.salt = salt;
        self.key = Some(key);
        if let Err(e) = self.save() {
            self.salt = old_salt;
            self.key = old_key;
            return Err(e);
        }
        Ok(())
    }

    pub fn lock(&mut self) {
        self.key = None;
        self.logins.clear();
    }

    /// The logins for the site of `uri`, the last used first.
    pub fn for_site(&self, uri: &str) -> Vec<&Login> {
        let site = site_key(uri);
        let mut out: Vec<&Login> = self.logins.iter().filter(|l| l.is_web() && site_key(&l.origin) == site).collect();
        out.sort_by(|a, b| b.used.cmp(&a.used).then(a.username.cmp(&b.username)));
        out
    }

    /// Keep a login the page just sent. A known username on the site gets
    /// its password replaced; the same password again changes nothing.
    pub fn remember(&mut self, login: Login) -> Result<Change, String> {
        self.fresh()?;
        let site = site_key(&login.origin);
        let change = match self.logins.iter_mut()
            .find(|l| l.is_web() && site_key(&l.origin) == site && l.username == login.username)
        {
            Some(l) if l.password == login.password => return Ok(Change::Same),
            Some(l) => { l.password = login.password; l.used = now(); l.changed = now(); Change::Updated }
            None => { self.logins.push(Login { used: now(), changed: now(), ..login }); Change::New }
        };
        self.save()?;
        Ok(change)
    }

    /// Note that a login was filled, so it comes first next time.
    pub fn touch(&mut self, origin: &str, username: &str) {
        if self.fresh().is_err() { return; }
        let site = site_key(origin);
        if let Some(l) = self.logins.iter_mut().find(|l| l.is_web() && site_key(&l.origin) == site && l.username == username) {
            l.used = now();
            let _ = self.save();
        }
    }

    pub fn remove(&mut self, uri: &str, username: &str) -> Result<bool, String> {
        self.fresh()?;
        let site = site_key(uri);
        let before = self.logins.len();
        self.logins.retain(|l| !(l.is_web() && site_key(&l.origin) == site && l.username == username));
        if self.logins.len() == before { return Ok(false); }
        self.save()?;
        Ok(true)
    }

    /// A new entry, written by hand. One just like it must not be there.
    pub fn add(&mut self, login: Login) -> Result<(), String> {
        self.fresh()?;
        if self.logins.iter().any(|l| l.id() == login.id()) { return Err("there is such an entry already".into()); }
        self.logins.push(Login { changed: now(), ..login });
        self.save()
    }

    /// Put `new` where `old` is. `old` is the entry as it was shown, so a
    /// change the phone made to it meanwhile is not written over blindly.
    pub fn replace(&mut self, old: &Login, new: Login) -> Result<(), String> {
        self.fresh()?;
        if new.id() != old.id() && self.logins.iter().any(|l| l.id() == new.id()) {
            return Err("there is such an entry already".into());
        }
        let Some(l) = self.logins.iter_mut().find(|l| *l == old) else {
            return Err("the entry changed on another machine; open it again".into());
        };
        *l = Login { changed: now(), ..new };
        self.save()
    }

    pub fn delete(&mut self, old: &Login) -> Result<bool, String> {
        self.fresh()?;
        let before = self.logins.len();
        self.logins.retain(|l| l != old);
        if self.logins.len() == before { return Ok(false); }
        self.save()?;
        Ok(true)
    }

    /// Import the CSV Firefox writes from about:logins → Export. Returns
    /// (added, updated).
    pub fn import_csv(&mut self, text: &str) -> Result<(usize, usize), String> {
        self.fresh()?;
        let rows = parse_csv(text);
        let Some(header) = rows.first() else { return Err("empty file".into()) };
        let col = |name: &str| header.iter().position(|h| h.trim().eq_ignore_ascii_case(name));
        let (Some(u), Some(us), Some(pw)) = (col("url"), col("username"), col("password")) else {
            return Err("no url, username and password columns; export from Firefox's about:logins".into());
        };
        let used = col("timeLastUsed");
        let (mut added, mut updated) = (0, 0);
        for row in &rows[1..] {
            let (Some(origin), Some(username), Some(password)) = (row.get(u), row.get(us), row.get(pw)) else { continue };
            if origin.is_empty() || password.is_empty() { continue; }
            let when = used.and_then(|i| row.get(i)).and_then(|s| s.parse::<u64>().ok()).map(|ms| ms / 1000).unwrap_or(0);
            let site = site_key(origin);
            match self.logins.iter_mut().find(|l| l.is_web() && site_key(&l.origin) == site && l.username == *username) {
                Some(l) => { if l.password != *password { l.password = password.clone(); l.changed = now(); updated += 1; } }
                None => {
                    self.logins.push(Login {
                        origin: origin.clone(), username: username.clone(), password: password.clone(),
                        used: when, changed: now(), ..Login::default()
                    });
                    added += 1;
                }
            }
        }
        self.save()?;
        Ok((added, updated))
    }

    /// Add entries read from somewhere else. One that is here already
    /// (same place, name and group) is left as it is. Returns how many
    /// were added.
    pub fn import(&mut self, entries: Vec<Login>) -> Result<usize, String> {
        self.fresh()?;
        let mut added = 0;
        for e in entries {
            if self.logins.iter().any(|l| l.id() == e.id()) { continue; }
            self.logins.push(Login { changed: now(), ..e });
            added += 1;
        }
        if added > 0 { self.save()?; }
        Ok(added)
    }

    fn save(&mut self) -> Result<(), String> {
        let Some(key) = self.key else { return Err("passwords are locked".into()) };
        let out = seal(&self.logins, &key, &self.salt)?;
        if let Some(dir) = self.path.parent() { std::fs::create_dir_all(dir).map_err(|e| e.to_string())?; }
        let tmp = self.path.with_extension("tmp");
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)
                .open(&tmp).map_err(|e| e.to_string())?;
            f.write_all(&out).map_err(|e| e.to_string())?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| e.to_string())?;
        self.seen = self.modified();
        Ok(())
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `scheme://host` of a URI, lower case, without a leading `www.`, so a
/// login saved on www.example.com fills on example.com too.
pub fn site_key(uri: &str) -> String {
    let (scheme, rest) = uri.trim().split_once("://").unwrap_or(("https", uri.trim()));
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    let host = host.strip_prefix("www.").unwrap_or(host);
    format!("{}://{}", scheme.to_ascii_lowercase(), host.to_ascii_lowercase())
}

/// A small CSV reader: commas, double quotes, doubled quotes inside a
/// quoted field, and newlines inside quotes.
pub fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') => {
                if chars.peek() == Some(&'"') { field.push('"'); chars.next(); } else { quoted = false; }
            }
            (true, _) => field.push(c),
            (false, '"') => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut field)),
            (false, '\r') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            (false, _) => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh(name: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("vault-test-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Store::new(dir.join("passwords"))
    }

    fn done(s: &Store) { let _ = std::fs::remove_dir_all(s.path.parent().unwrap()); }

    fn web(origin: &str, user: &str, pw: &str) -> Login {
        Login { origin: origin.into(), username: user.into(), password: pw.into(), ..Login::default() }
    }

    fn other(title: &str, group: &str, pw: &str) -> Login {
        Login { title: title.into(), group: group.into(), password: pw.into(), ..Login::default() }
    }

    #[test]
    fn a_login_survives_lock_and_unlock_and_refuses_the_wrong_master() {
        let mut s = fresh("roundtrip");
        assert_eq!(s.unlock("hunter2").unwrap(), 0);
        assert_eq!(s.remember(web("https://www.example.com", "alice", "pw")).unwrap(), Change::New);
        s.lock();
        assert!(!s.unlocked());
        assert_eq!(s.unlock("nope").unwrap_err(), "wrong master password");
        assert_eq!(s.unlock("hunter2").unwrap(), 1);
        let found = s.for_site("https://example.com/login?next=/");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].password, "pw");
        done(&s);
    }

    #[test]
    fn the_same_password_again_is_no_change_and_a_new_one_updates() {
        let mut s = fresh("update");
        s.unlock("").unwrap();
        assert_eq!(s.remember(web("https://a.no", "u", "one")).unwrap(), Change::New);
        assert_eq!(s.remember(web("https://a.no", "u", "one")).unwrap(), Change::Same);
        assert_eq!(s.remember(web("https://a.no", "u", "two")).unwrap(), Change::Updated);
        assert_eq!(s.logins().len(), 1);
        assert!(s.remove("https://a.no/x", "u").unwrap());
        assert!(s.logins().is_empty());
        done(&s);
    }

    #[test]
    fn firefox_csv_imports_and_the_last_used_comes_first() {
        let mut s = fresh("csv");
        s.unlock("m").unwrap();
        let csv = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
                   \"https://accounts.example.com\",\"old\",\"p1\",,\"https://accounts.example.com\",\"{1}\",\"1600000000000\",\"1600000000000\",\"1600000000000\"\n\
                   \"https://accounts.example.com\",\"new\",\"p,2\"\"q\",,\"https://accounts.example.com\",\"{2}\",\"1700000000000\",\"1700000000000\",\"1700000000000\"\n";
        assert_eq!(s.import_csv(csv).unwrap(), (2, 0));
        let found = s.for_site("https://accounts.example.com/signin");
        assert_eq!(found[0].username, "new");
        assert_eq!(found[0].password, "p,2\"q");
        assert_eq!(s.import_csv(csv).unwrap(), (0, 0));
        done(&s);
    }

    #[test]
    fn the_master_password_can_be_changed() {
        let mut s = fresh("master");
        s.unlock("old").unwrap();
        s.remember(web("https://a.no", "u", "p")).unwrap();
        s.change_master("new").unwrap();
        s.lock();
        assert!(s.unlock("old").is_err());
        assert_eq!(s.unlock("new").unwrap(), 1);
        done(&s);
    }

    #[test]
    fn a_login_saved_elsewhere_is_kept_when_this_store_saves() {
        let mut laptop = fresh("two");
        laptop.unlock("m").unwrap();
        laptop.remember(web("https://a.no", "u", "p")).unwrap();
        // The phone opens the same file and adds a login.
        let mut phone = Store::new(laptop.path.clone());
        phone.unlock("m").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        phone.remember(web("https://b.no", "v", "q")).unwrap();
        // The laptop saves next, and the phone's login survives.
        laptop.remember(web("https://c.no", "w", "r")).unwrap();
        assert_eq!(laptop.logins().len(), 3);
        let mut again = Store::new(laptop.path.clone());
        assert_eq!(again.unlock("m").unwrap(), 3);
        done(&laptop);
    }

    #[test]
    fn a_site_key_drops_www_port_and_path() {
        assert_eq!(site_key("https://www.Example.com:443/a?b#c"), "https://example.com");
        assert_eq!(site_key("http://user@host.no/"), "http://host.no");
        assert_eq!(site_key("example.org"), "https://example.org");
    }

    #[test]
    fn an_entry_without_a_site_is_kept_apart_from_the_web_logins() {
        let mut s = fresh("other");
        s.unlock("m").unwrap();
        s.add(other("office door", "Work", "4711")).unwrap();
        s.add(Login { note: "second floor".into(), username: "root".into(), ..other("build server", "Servers", "s3cret") }).unwrap();
        s.remember(web("https://a.no", "u", "p")).unwrap();
        assert_eq!(s.add(other("office door", "Work", "0000")).unwrap_err(), "there is such an entry already");
        // No page is filled from an entry that has no site.
        assert_eq!(s.for_site("https://").len(), 0);
        assert_eq!(s.for_site("https://a.no").len(), 1);
        s.lock();
        assert_eq!(s.unlock("m").unwrap(), 3);
        let server = s.logins().iter().find(|l| l.title == "build server").unwrap().clone();
        assert_eq!((server.group.as_str(), server.note.as_str(), server.username.as_str()), ("Servers", "second floor", "root"));
        assert_eq!(server.name(), "build server");
        assert_eq!(s.logins().iter().find(|l| l.is_web()).unwrap().name(), "a.no");
        done(&s);
    }

    #[test]
    fn an_entry_is_changed_and_deleted_as_it_was_shown() {
        let mut s = fresh("edit");
        s.unlock("m").unwrap();
        s.add(other("wifi", "Home", "old")).unwrap();
        let shown = s.logins()[0].clone();
        s.replace(&shown, Login { password: "new".into(), ..shown.clone() }).unwrap();
        assert_eq!(s.logins()[0].password, "new");
        // The entry as it was shown is gone, so a second change from the
        // old screen is refused instead of writing over the first.
        assert!(s.replace(&shown, Login { password: "x".into(), ..shown.clone() }).is_err());
        assert!(!s.delete(&shown).unwrap());
        let now = s.logins()[0].clone();
        assert!(s.delete(&now).unwrap());
        assert!(s.logins().is_empty());
        done(&s);
    }

    #[test]
    fn a_file_of_the_old_kind_opens_and_turns_new_with_the_first_entry_that_needs_it() {
        let mut s = fresh("old");
        let salt = new_salt();
        let key = derive("m", &salt).unwrap();
        let mut file = seal(&[web("https://a.no", "u", "p")], &key, &salt).unwrap();
        file[..MAGIC_LEN].copy_from_slice(MAGIC_OLD);
        std::fs::create_dir_all(s.path.parent().unwrap()).unwrap();
        std::fs::write(&s.path, &file).unwrap();
        assert_eq!(s.unlock("m").unwrap(), 1);
        s.remember(web("https://b.no", "v", "q")).unwrap();
        assert_eq!(&std::fs::read(&s.path).unwrap()[..MAGIC_LEN], MAGIC_OLD, "web logins alone stay readable by the old phone app");
        s.add(other("door", "", "1")).unwrap();
        assert_eq!(&std::fs::read(&s.path).unwrap()[..MAGIC_LEN], MAGIC);
        done(&s);
    }

    #[test]
    fn a_conflict_file_gives_its_newer_entries_and_goes() {
        let mut s = fresh("conflict");
        s.unlock("m").unwrap();
        s.add(other("door", "Work", "mine")).unwrap();
        s.add(other("safe", "Home", "kept")).unwrap();
        // The other machine changed the door later, and added a card.
        let mut theirs = s.logins().to_vec();
        theirs[0].password = "theirs".into();
        theirs[0].changed += 100;
        theirs[1].password = "older".into();
        theirs[1].changed -= 100;
        theirs.push(Login { changed: 5, ..other("card", "Home", "1234") });
        let lost = s.path.with_file_name("passwords.sync-conflict-20261111-101500-ABCDEFG");
        std::fs::write(&lost, seal(&theirs, &s.key.unwrap(), &s.salt).unwrap()).unwrap();
        s.lock();
        assert_eq!(s.unlock("m").unwrap(), 3);
        let pw = |t: &str| s.logins().iter().find(|l| l.title == t).unwrap().password.clone();
        assert_eq!((pw("door"), pw("safe"), pw("card")), ("theirs".into(), "kept".into(), "1234".into()));
        assert!(!lost.exists());
        done(&s);
    }
}
