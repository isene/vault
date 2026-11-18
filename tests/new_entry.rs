//! An entry made with + is kept when the question after the form is
//! answered with Enter. Before 0.5.3 only y kept it, and Enter threw the
//! whole entry away.
#![cfg(target_os = "linux")]

use std::time::Duration;

#[test]
fn enter_keeps_a_new_entry() {
    let home = std::env::temp_dir().join(format!("vault-new-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let file = home.join("passwords");
    let mut app = still::Run::new(env!("CARGO_BIN_EXE_vault"))
        .env("HOME", &home).env("VAULT_FILE", &file).start().unwrap();
    let wait = Duration::from_millis(400);
    app.settle(wait);
    for keys in ["test1\r", "test1\r", "+", "\r", "Bank\r", "\x1b", "\r", "\x1b"] {
        app.keys(keys).unwrap();
        app.settle(wait);
    }
    assert!(app.ended(Duration::from_secs(2)), "vault did not quit on Esc");

    let mut store = vault::Store::new(file);
    store.unlock("test1").unwrap();
    let names: Vec<String> = store.logins().iter().map(|l| l.title.clone()).collect();
    let _ = std::fs::remove_dir_all(&home);
    assert_eq!(names, ["Bank"]);
}
