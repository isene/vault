//! Passwords kept as an outline (a HyperList that scribe encrypts), read
//! into entries.
//!
//! The outline is a title with its login indented under it:
//!
//! ```text
//! Build server
//!     root / the-password
//! ```
//!
//! A title can have several logins. A line under it that is a web address
//! becomes the site, and any other line goes into the note. A heading
//! above the title becomes its tag.

use vault::Login;

/// Is this text sealed by scribe, so that it needs its password?
pub fn sealed(text: &str) -> bool {
    let t = text.trim_start();
    t.starts_with("ENC:") || t.starts_with("U2FsdGVk")
}

/// The plain outline of a file scribe sealed. Both of scribe's forms:
/// `ENC:` + base64(salt 16, iv 16, AES-256-CBC), and openssl's `Salted__`.
pub fn unseal(text: &str, password: &str) -> Result<String, String> {
    use aes::Aes256;
    use base64::Engine as _;
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use hmac::Hmac;
    use sha2::Sha256;
    type Dec = cbc::Decryptor<Aes256>;

    let stretch = |salt: &[u8], out: &mut [u8]| {
        pbkdf2::pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, 10000, out).map_err(|e| e.to_string())
    };
    let b64 = |s: &str| {
        let packed: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        base64::engine::general_purpose::STANDARD.decode(packed).map_err(|_| "the file is damaged".to_string())
    };
    let t = text.trim();
    let (key, iv, body) = if let Some(rest) = t.strip_prefix("ENC:") {
        let blob = b64(rest)?;
        if blob.len() < 32 { return Err("the file is too short".into()); }
        let mut key = [0u8; 32];
        stretch(&blob[..16], &mut key)?;
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&blob[16..32]);
        (key, iv, blob[32..].to_vec())
    } else {
        let blob = b64(t)?;
        if blob.len() < 16 || &blob[..8] != b"Salted__" { return Err("not a file scribe sealed".into()); }
        let mut both = [0u8; 48];
        stretch(&blob[8..16], &mut both)?;
        let (mut key, mut iv) = ([0u8; 32], [0u8; 16]);
        key.copy_from_slice(&both[..32]);
        iv.copy_from_slice(&both[32..]);
        (key, iv, blob[16..].to_vec())
    };
    let plain = Dec::new(&key.into(), &iv.into()).decrypt_padded_vec_mut::<Pkcs7>(&body).map_err(|_| "wrong password".to_string())?;
    String::from_utf8(plain).map_err(|_| "wrong password".to_string())
}

/// The entries of an outline, and how many lines fit no entry.
pub fn entries(outline: &str) -> (Vec<Login>, usize) {
    // (indent, text) of every line that says something.
    let lines: Vec<(usize, &str)> = outline.lines().filter(|l| !l.trim().is_empty())
        .map(|l| (l.chars().take_while(|c| c.is_whitespace()).map(|c| if c == '\t' { 4 } else { 1 }).sum(), l.trim()))
        .collect();
    let mut out: Vec<Login> = Vec::new();
    let mut lost = 0;
    // The headings above the line being read, outermost first.
    let mut above: Vec<(usize, &str)> = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let (indent, text) = lines[i];
        while above.last().is_some_and(|(d, _)| *d >= indent) { above.pop(); }
        let kids: Vec<&str> = lines[i + 1..].iter().take_while(|(d, _)| *d > indent).map(|(_, t)| *t).collect();
        let leaves_only = !kids.is_empty() && lines[i + 1..i + 1 + kids.len()].windows(2).all(|w| w[1].0 <= w[0].0);
        if !leaves_only {
            // A heading over other titles, or a line on its own.
            if kids.is_empty() { lost += 1; } else { above.push((indent, text)); }
            i += 1;
            continue;
        }
        // A title with its lines.
        let tag = above.last().map(|(_, t)| t.split_whitespace().collect::<Vec<_>>().join("-")).unwrap_or_default();
        let mut logins: Vec<(String, String)> = Vec::new();
        let mut origin = String::new();
        let mut rest: Vec<&str> = Vec::new();
        for k in &kids {
            if let Some((user, pw)) = k.split_once(" / ") {
                logins.push((user.trim().to_string(), pw.trim().to_string()));
            } else if origin.is_empty() && (k.starts_with("http://") || k.starts_with("https://")) && !k.contains(' ') {
                origin = k.to_string();
            } else {
                rest.push(k);
            }
        }
        // One bare word under a title is a password with no user: a door code.
        if logins.is_empty() && rest.len() == 1 && !rest[0].contains(' ') {
            logins.push((String::new(), rest.remove(0).to_string()));
        }
        if logins.is_empty() { logins.push((String::new(), String::new())); }
        let note = rest.join("\n");
        for (username, password) in logins {
            out.push(Login { title: text.to_string(), group: tag.clone(), origin: origin.clone(), username, password, note: note.clone(), ..Login::default() });
        }
        i += 1 + kids.len();
    }
    (out, lost)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUTLINE: &str = "Old servers\n\tBuild box\n\t\troot / pw one\n\t\tdeploy / pw-two\n\t\tsecond floor\nShop\n   https://shop.example/login\n   alice@example.com / s3 / x\nBike lock\n   4711\nA line alone\n";

    #[test]
    fn a_title_with_its_logins_becomes_entries() {
        let (got, lost) = entries(OUTLINE);
        assert_eq!(lost, 1, "the line with nothing under it");
        let brief: Vec<_> = got.iter().map(|l| (l.title.as_str(), l.group.as_str(), l.username.as_str(), l.password.as_str())).collect();
        assert_eq!(brief, [
            ("Build box", "Old-servers", "root", "pw one"),
            ("Build box", "Old-servers", "deploy", "pw-two"),
            ("Shop", "", "alice@example.com", "s3 / x"),
            ("Bike lock", "", "", "4711"),
        ]);
        assert_eq!(got[0].note, "second floor");
        assert_eq!(got[2].origin, "https://shop.example/login");
        assert!(got[2].is_web() && !got[3].is_web());
    }

    /// The two forms scribe writes, made here the way scribe makes them.
    #[test]
    fn both_of_scribes_forms_open() {
        use aes::Aes256;
        use base64::Engine as _;
        use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        use hmac::Hmac;
        use sha2::Sha256;
        let b64 = base64::engine::general_purpose::STANDARD;
        let seal = |key: &[u8; 32], iv: &[u8; 16]| cbc::Encryptor::<Aes256>::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(OUTLINE.as_bytes());

        let (salt, iv) = ([7u8; 16], [9u8; 16]);
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2::<Hmac<Sha256>>(b"pw", &salt, 10000, &mut key).unwrap();
        let enc = format!("ENC:{}", b64.encode([&salt[..], &iv[..], &seal(&key, &iv)].concat()));
        assert!(sealed(&enc));
        assert_eq!(unseal(&enc, "pw").unwrap(), OUTLINE);
        assert_eq!(unseal(&enc, "no").unwrap_err(), "wrong password");

        let salt = [3u8; 8];
        let mut both = [0u8; 48];
        pbkdf2::pbkdf2::<Hmac<Sha256>>(b"pw", &salt, 10000, &mut both).unwrap();
        let (key, iv): ([u8; 32], [u8; 16]) = (both[..32].try_into().unwrap(), both[32..].try_into().unwrap());
        let ssl = b64.encode([&b"Salted__"[..], &salt[..], &seal(&key, &iv)].concat());
        assert!(sealed(&ssl));
        assert_eq!(unseal(&ssl, "pw").unwrap(), OUTLINE);
        assert!(!sealed(OUTLINE));
    }
}
