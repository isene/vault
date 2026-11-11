# vault

<img src="img/vault.svg" align="right" width="150">

**Every password in one encrypted file, and one key press to paste one.**

![Rust](https://img.shields.io/badge/language-Rust-orange) ![Unlicense](https://img.shields.io/badge/license-Unlicense-green) ![Platform](https://img.shields.io/badge/platform-Linux-blue) ![Stay Amazing](https://img.shields.io/badge/Stay-Amazing-important)

The logins your browser fills, and the passwords it has no use for: a server, a door code. Part of the [Fe₂O₃ Rust terminal suite](https://github.com/isene/fe2o3).

vault reads the same file as the [gaze](https://github.com/isene/gaze) browser and its phone half. The phone has a [vault app](https://github.com/isene/nomad/tree/master/apps/vault) too. A login gaze saves shows up here, and one you change here is the one gaze fills.

## Using it

```bash
vault
```

It asks for the master password. The first time, it asks twice and makes the file.

Type a few letters and the list narrows to the entries that have them. Every field but the password is searched. The list never shows a password.

| Key | Does |
|---|---|
| letters | Find |
| `Enter` | Copy the password, for one paste |
| `Ctrl+Enter` | Copy, quit, and paste into the window you came from |
| `Ctrl+U` | Copy the user name |
| `→` | Open the entry: see and change everything, the password too |
| `+`, `Ctrl+N` or `Ins` | A new entry (`+` only while nothing is typed) |
| `Ctrl+D` or `Del` | Delete the entry, after a yes |
| `Tab` | The next tab; `Shift+Tab` the one before |
| `Ctrl+T` | A colour for the tag of this tab |
| `F2` | Possible doubles: entries that may be one thing twice |
| `Ctrl+P` | A new master password; asks for the current one first |
| `Esc` | Clear what you typed, then quit |
| `Ctrl+Q` | Quit |
| `F1` | This list, in a box |

Two tabs are always there: `Other` first, for entries with no site, and `Web` last, for those gaze fills. Give an entry tags, words with spaces between, and each tag gets a tab with every entry that has it.

On a tag's tab, `Ctrl+T` opens [prism](https://github.com/isene/prism) to pick the colour of its name. An entry's name in the list takes the colour of its first tag that has one. The colours are lines in `~/.vaultrc`: `colour work #78e68c`.

In an open entry, `↑` `↓` move, `Enter` changes the field, `Ctrl+G` makes a new password of 24 characters, and `Ctrl+Y` copies the field. `←` or `Esc` goes back, and asks whether to keep the changes. `Ctrl+E` opens the note in your editor, for a note of many lines; a long note opens there on `Enter` too.

`F2` lists the entries that may be one thing twice, each group together and numbered, web entries first. An entry is listed when it has the password of another one, or its name, such as `GitHub` beside github.com. Each line says why. Delete the one you do not need, or open it and give it a site.

After five minutes with no key, vault ends.

## Passwords from an outline

```bash
vault --import-hl passwords.hl
```

This reads passwords kept as an outline, such as a HyperList. A title, with the login indented under it:

```
Build server
    root / the-password
```

- A title can have several logins.
- A web address under the title becomes the site.
- Any other line goes into the note.
- No entry gets a tag: the tags are yours to give.

A file that [scribe](https://github.com/isene/scribe) sealed asks for its password first. vault prints how many entries it read, and nothing else.

`vault --clear-tags` takes the tags off every entry.

## One paste, then gone

`Enter` hands the password to a small helper that owns the clipboard. The first program that pastes gets it. Two seconds later the helper ends, and the clipboard is empty.

With no paste it ends after 30 seconds, or when you copy something else. In between it sleeps: it wakes only when a program asks for the clipboard. The rest of the day it does not exist.

The helper marks the clipboard as a password (`x-kde-passwordManagerHint`). A clipboard history that honours the mark, such as [yank](https://github.com/isene/yank) from 0.3.9, keeps no copy.

Outside X there is no helper. vault then copies through the terminal (OSC 52), and the password stays until you copy something else.

## One key from anywhere

`bin/vault-pop` opens vault in a [glass](https://github.com/isene/glass) terminal of its own. Bind it to a key in your window manager.

`Ctrl+Enter` on an entry then closes vault and pastes the password into the window you were in. The paste is one Shift+Insert, sent by [yank](https://github.com/isene/yank).

Started by hand in a terminal, `Ctrl+Enter` copies and quits, and the paste is yours to do.

## The file

`~/.gaze/sync/passwords`. `VAULT_FILE` names another one.

- The key is made from the master password with Argon2id.
- The list is sealed with ChaCha20-Poly1305, under a fresh nonce at every save.
- Nothing is written in the clear, and vault talks to no network.

Share the folder `~/.gaze/sync` with your phone through [Syncthing](https://syncthing.net), which encrypts the connection. The file is sealed before it leaves, so the connection carries nothing readable either way.

If both sides change the file at the same moment, Syncthing keeps both copies. vault and gaze merge them at the next start: for each entry, the copy changed last wins.

## Install

```bash
git clone https://github.com/isene/crust
git clone https://github.com/isene/vault
cd vault && cargo build --release
ln -s "$PWD/target/release/vault" ~/bin/vault
```

## For other programs

The crate is a library too. `default-features = false` leaves out the terminal program:

```toml
vault = { git = "https://github.com/isene/vault", default-features = false }
```

`Store` opens, changes and saves the file. gaze and the phone app are built on it, so the three cannot drift apart.

## License

[Unlicense](LICENSE): public domain.
