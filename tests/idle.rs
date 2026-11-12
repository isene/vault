//! The password prompt costs nothing while it waits, and it ends when
//! its terminal goes away. A prompt that read on kept a core busy.
#![cfg(target_os = "linux")]

use std::time::Duration;

#[test]
fn the_password_prompt_waits_still_and_ends_with_its_terminal() {
    let home = std::env::temp_dir().join(format!("vault-test-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let mut app = still::Run::new(env!("CARGO_BIN_EXE_vault"))
        .env("HOME", &home).env("VAULT_FILE", home.join("passwords")).start().unwrap();
    app.settle(Duration::from_millis(500));

    let idle = app.idle(Duration::from_secs(2)).unwrap();
    assert!(idle.is_still(), "{idle:?}");

    app.hang_up();
    assert!(app.ended(Duration::from_secs(1)));
    let _ = std::fs::remove_dir_all(&home);
}
