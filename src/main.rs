extern crate argonautica;
extern crate chacha20poly1305;
extern crate rand;
extern crate serde_json;

use argonautica::Hasher;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, Key};
use rand::Rng;
use chacha20poly1305::aead::generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use std::io::{self};
use std::process::Command;
use std::fs;
use std::env;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
struct SshLogin {
    name: String,
    hostname: String,
    port: u16,
    username: String,
    password: String
}

#[derive(Serialize, Deserialize)]
struct Vault {
    ssh_logins: Vec<SshLogin>,
    master_password: Option<String>,
}

impl Vault {
    fn new() -> Self {
        Vault {
            ssh_logins: Vec::new(),
            master_password: None,
        }
    }

fn set_master_password(&mut self, master_password: String) {
    self.master_password = Some(master_password);
}

fn check_master_password(&self, master_password: &str) -> bool {
    match &self.master_password {
        Some(stored_password) => stored_password == master_password,
        None => false,
    }
}

fn save_to_file(&self, file_path: &str, master_password: &str) {
    let key = derive_key(master_password);
    let serialized_vault = serde_json::to_string(self).unwrap();
    let encrypted_vault = encrypt(&serialized_vault.as_bytes(), &key);
    fs::write(file_path, encrypted_vault).unwrap();
}

fn load_from_file(file_path: &str, master_password: &str) -> Self {
    let key = derive_key(master_password);
    let encrypted_vault = fs::read(file_path).unwrap();
    let decrypted_vault = decrypt(&encrypted_vault, &key);
    let serialized_vault = String::from_utf8(decrypted_vault).unwrap();
    serde_json::from_str(&serialized_vault).unwrap()
}

}

fn derive_key(master_password: &str) -> Key {
    let mut hasher = Hasher::default();
    let mut rng = rand::thread_rng();
    let secret_key: [u8; 32] = rng.gen();
    let salt: [u8; 32] = rng.gen();
    let hash = hasher
        .with_password(master_password)
        .with_secret_key(&secret_key[..])
        .with_salt(&salt[..])
        .hash()
        .unwrap();
    let hash_bytes = hash.as_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_bytes[0..32]);
    *Key::from_slice(&key)
}

fn encrypt(data: &[u8], key: &Key) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = GenericArray::from_slice(&[0u8; 24]);
    cipher.encrypt(nonce, data).unwrap()
}

fn decrypt(data: &[u8], key: &Key) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key);
    let nonce = GenericArray::from_slice(&[0u8; 24]);
    cipher.decrypt(nonce, data).unwrap()
}

fn find_vault_json() -> PathBuf {
    let exe_path = env::current_exe().expect("Failed to get the current executable path");
    let exe_dir = exe_path.parent().expect("Failed to get the executable's directory");
    let vault_path = exe_dir.join("vault.json");

    vault_path
}


fn main() {    
    let file_path_buf = find_vault_json();
    let file_path = match file_path_buf.to_str() {
        Some(path) => path,
        None => {
            println!("Failed to convert path to string");
            return;
        }
    };    
    let args: Vec<String> = env::args().collect();
    //let file_path = "vault.json";
    let master_password;
    let mut vault = Vault::new();

    if fs::metadata(file_path).is_ok() {
        master_password = rpassword::prompt_password("Enter your master password: ").unwrap();
        vault = Vault::load_from_file(file_path, master_password.trim());
        if !vault.check_master_password(master_password.trim()) {
            println!("Incorrect master password. Please try again.");
            return;
        }
    } else {
        master_password = rpassword::prompt_password("No master password set. Please create a new master password: ").unwrap();
        vault.set_master_password(master_password.trim().to_string());
    }

    if args.len() > 1 {
        let ssh_name = &args[1];
        connect_to_ssh_login_direct(&vault, ssh_name);
    } else {

    loop {
        display_menu();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Failed to read line");
        let choice: u32 = match choice.trim().parse() {
            Ok(num) => num,
            Err(_) => continue,
        };

        match choice {
            2 => add_ssh_login(&mut vault),
            3 => remove_ssh_login(&mut vault),
            4 => edit_ssh_login(&mut vault),
            1 => connect_to_ssh_login(&mut vault),
            5 => show_saved_hosts(&mut vault),
            6 => {
                vault.save_to_file(file_path, master_password.trim());
                println!("Exiting...");
                break;
            },
            _ => println!("Invalid option, please try again."),
        }
    }
}
}

fn display_menu() {
    println!("\nWhat would you like to do?");
    println!("1. Connect to an SSH login");
    println!("2. Add a new SSH login");
    println!("3. Remove an existing SSH login");
    println!("4. Edit an existing SSH login");
    println!("5. Saved Hosts");
    println!("6. Exit");
}

fn add_ssh_login(vault: &mut Vault) {
    println!("Enter the name for the new SSH login:");
    let mut name = String::new();
    io::stdin().read_line(&mut name).expect("Failed to read line");
    let name = name.trim().to_string();

    println!("Enter the hostname for the new SSH login:");
    let mut hostname = String::new();
    io::stdin().read_line(&mut hostname).expect("Failed to read line");
    let hostname = hostname.trim().to_string();

    println!("Enter the port for the new SSH login:");
    let mut port = String::new();
    io::stdin().read_line(&mut port).expect("Failed to read line");
    let port: u16 = port.trim().parse().expect("Please type a number!");

    println!("Enter the username for the new SSH login:");
    let mut username = String::new();
    io::stdin().read_line(&mut username).expect("Failed to read line");
    let username = username.trim().to_string();

    println!("Enter the password for the new SSH login:");
    let mut password = String::new();
    io::stdin().read_line(&mut password).expect("Failed to read line");
    let password = password.trim().to_string();

    let ssh_login = SshLogin {
        name,
        hostname,
        port,
        username,
        password,
    };

    vault.ssh_logins.push(ssh_login);
    println!("New SSH login added successfully!");
}

fn remove_ssh_login(vault: &mut Vault) {
    println!("Enter the name of the SSH login to remove:");
    let mut name = String::new();
    io::stdin().read_line(&mut name).expect("Failed to read line");
    let name = name.trim();

    let initial_len = vault.ssh_logins.len();
    vault.ssh_logins.retain(|login| login.name != name);

    if vault.ssh_logins.len() < initial_len {
        println!("SSH login removed successfully.");
    } else {
        println!("SSH login not found.");
    }
}

fn edit_ssh_login(vault: &mut Vault) {
    println!("Enter the name of the SSH login to edit:");
    let mut name = String::new();
    io::stdin().read_line(&mut name).expect("Failed to read line");
    let name = name.trim();

    if let Some(login) = vault.ssh_logins.iter_mut().find(|l| l.name == name) {
        println!("Editing SSH login for '{}'", name);

        println!("Enter new hostname (or press ENTER to keep current):");
        let mut hostname = String::new();
        io::stdin().read_line(&mut hostname).expect("Failed to read line");
        if !hostname.trim().is_empty() {
            login.hostname = hostname.trim().to_string();
        }

        println!("Enter new port (or press ENTER to keep current):");
        let mut port = String::new();
        io::stdin().read_line(&mut port).expect("Failed to read line");
        if let Ok(port) = port.trim().parse::<u16>() {
            login.port = port;
        }

        println!("Enter new username (or press ENTER to keep current):");
        let mut username = String::new();
        io::stdin().read_line(&mut username).expect("Failed to read line");
        if !username.trim().is_empty() {
            login.username = username.trim().to_string();
        }

        println!("Enter new password (or press ENTER to keep current):");
        let mut password = String::new();
        io::stdin().read_line(&mut password).expect("Failed to read line");
        if !password.trim().is_empty() {
            login.password = password.trim().to_string();
        }

        println!("SSH login '{}' updated successfully.", name);
    } else {
        println!("SSH login not found.");
    }
}

fn connect_to_ssh_login(vault: &Vault) {
    println!("Enter the name of the SSH login:");
    let mut login_name = String::new();
    io::stdin().read_line(&mut login_name).expect("Failed to read line");
    let login_name = login_name.trim();

    if let Some(login) = vault.ssh_logins.iter().find(|l| l.name == login_name) {
        let mut command = Command::new("ssh");
        command.arg(format!("{}@{}", login.username, login.hostname));
        command.arg("-p").arg(login.port.to_string());

        match command.spawn() {
            Ok(mut child) => {
                child.wait().expect("Failed to wait on child");
            },
            Err(e) => {
                println!("Failed to start ssh: {}", e);
            },
        }
    } else {
        println!("SSH login not found!");
    }
}

fn show_saved_hosts(vault: &Vault) {
    println!("Saved SSH logins:");
    for (index, login) in vault.ssh_logins.iter().enumerate() {
        println!("{}. {} - {}@{}:{}", index + 1, login.name, login.username, login.hostname, login.port);
    }
    if vault.ssh_logins.is_empty() {
        println!("No saved SSH logins.");
    }
}

fn connect_to_ssh_login_direct(vault: &Vault, login_name: &str) {
    if let Some(login) = vault.ssh_logins.iter().find(|l| l.name == login_name) {
        let mut command = Command::new("ssh");
        command.arg(format!("{}@{}", login.username, login.hostname));
        command.arg("-p").arg(login.port.to_string());

        match command.spawn() {
            Ok(mut child) => {
                child.wait().expect("Failed to wait on child");
            },
            Err(e) => {
                println!("Failed to start ssh: {}", e);
            },
        }
    } else {
        println!("SSH login not found!");
    }
}