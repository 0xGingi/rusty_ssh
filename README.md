# rusty_ssh

 (WIP) CLI SSH Manager in Rust using argon2 and xchacha20
- Please Note: I did not add any specific way to use ssh keys as I have an alternative method I use alongside rusty_ssh and this is a personal project.

* Encrypted Vault via XChaCha20

* Add Logins and Connect to them via nicknames

* Uses System Native SSH Client

## Usage

* ./rusty_ssh - opens menu, add logins and connect from there

* ./rusty_ssh <server nickname> - connects to server without needing to use menu

## Build

```
git clone https://github.com/0xgingi/rusty_ssh.git
cargo build --release
```