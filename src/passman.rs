use crate::cryptman;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, usize};

use rand::{rngs::OsRng, RngCore};
use std::fs::{
    //self,
    File,
};
use std::io::{
    //Read,
    Write,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct Container {
    pub name: String,
    pub children: HashMap<String, Container>,
    pub entries: HashMap<String, Entry>,
    pub parent: String,
}
impl Container {
    /// add an entry to the list of entries, expects an entry.
    pub fn add_entry(&mut self, mut entry: Entry) {
        entry.parent = self.name.as_str().to_owned();
        self.entries.insert(entry.url.as_str().to_owned(), entry);
    }

    /// Add a child container, expects a container.
    pub fn add_child(&mut self, mut container: Container) {
        container.parent = self.name.as_str().to_owned();
        self.children
            .insert(container.name.as_str().to_owned(), container);
    }

    /// returns a JSON representation of the container as a string.
    pub fn to_json_string(&mut self) -> String {
        serde_json::to_string(self).unwrap()
    }

    /// populate a container from a &[u8] array,of a JSON serialisation of a container. returns a Result<(),serde_json::Error>
    pub fn from_json_arr(&mut self, arr: &[u8]) -> Result<(), serde_json::Error> {
        let from_json: Container = serde_json::from_slice(arr)?;
        *self = from_json;
        Ok(())
    }

    /// populate a container from a &str, of a  JSON serialisation of a container. returns a Result<(),serde_json::Error>
    pub fn from_json_string(&mut self, s: &str) -> Result<(), serde_json::Error> {
        let from_json_str: Container = serde_json::from_str(s)?;
        *self = from_json_str;
        Ok(())
    }

    // instantiate a new container, expects a name. Returns a container.
    pub fn new(name: &str) -> Self {
        let parent = "none";
        let children: HashMap<String, Container> = HashMap::new();
        let entries: HashMap<String, Entry> = HashMap::new();
        Container {
            name: name.to_owned(),
            parent: parent.to_owned(),
            children,
            entries,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    pub username: String,
    pub pass_vec: Vec<u8>,
    pub email: String,
    pub url: String,
    pub parent: String,
}

impl Entry {
    /// returns a JSON representation of the entry as a string.
    pub fn to_json_string(&mut self) -> String {
        serde_json::to_string(self).unwrap()
    }

    /// populate an entry from a &[u8] array,of a JSON serialisation of an entry. returns a Result<(),serde_json::Error>
    pub fn from_json_arr(&mut self, arr: &[u8]) -> Result<(), serde_json::Error> {
        let from_json: Entry = serde_json::from_slice(arr)?;
        *self = from_json;
        Ok(())
    }

    /// populate an entry from a &str, of a  JSON serialisation of an entry. returns a Result<(),serde_json::Error>
    pub fn from_json_string(&mut self, s: &str) -> Result<(), serde_json::Error> {
        #[derive(Clone, Serialize, Deserialize)]
        struct JsonEntry {
            pub username: String,
            pub password: String,
            pub email: String,
            pub url: String,
        }
        let json_in: JsonEntry = serde_json::from_str(s)?;
        self.username = json_in.username;
        self.pass_vec = json_in.password.as_bytes().to_vec();
        self.email = json_in.email;
        self.url = json_in.url;
        self.parent = String::from("");
        Ok(())
    }

    /// instantiate a new entry, expects a name,encrypted password, email and url. Returns an entry.
    pub fn new(username: &str, pass_vec: Vec<u8>, email: &str, url: &str) -> Self {
        Entry {
            username: username.to_owned(),
            pass_vec,
            email: email.to_owned(),
            url: url.to_owned(),
            parent: "".to_owned(),
        }
    }
    pub fn encrypt_password(
        &mut self,
        key: [u8; 32],
        nonce: [u8; 24],
        salt: [u8; 32],
    ) -> Result<(), anyhow::Error> {
        let binding =
            cryptman::encrypt_file_mem_with_salt(self.pass_vec.clone(), "", &key, &nonce, &salt)?;
        self.pass_vec = binding;
        Ok(())
    }

    pub fn decrypt_password(&mut self, password: &str) -> Result<(), anyhow::Error> {
        let binding = cryptman::decrypt_file_mem_gen_key(self.pass_vec.clone(), "", password)?;
        self.pass_vec = binding;
        Ok(())
    }
}

pub fn get_entries_by_field(
    container: &Container,
    field_name: &str,
    target_value: &str,
) -> Vec<Entry> {
    let mut result = Vec::new();
    // Check entries in the current container
    for entry in container.entries.values() {
        match field_name {
            "url" => {
                if entry.url == target_value {
                    result.push(entry.clone()); // Clone the Entry
                }
            }
            "email" => {
                if entry.email == target_value {
                    result.push(entry.clone()); // Clone the Entry
                }
            }
            "parent" => {
                if entry.parent == target_value {
                    result.push(entry.clone()); // Clone the Entry
                }
            }
            "username" => {
                if entry.username == target_value {
                    result.push(entry.clone());
                }
            }
            _ => {
                log::debug!("{field_name:?}");
            } // Handle other fields if needed
        }
    }

    // Recursively check subcontainers
    for child_container in container.children.values() {
        result.extend(get_entries_by_field(
            child_container,
            field_name,
            target_value,
        ));
    }

    result
}

pub fn get_all_entries(container: &Container) -> Vec<Entry> {
    let mut result = Vec::new();
    // Print entries in the current container
    for entry in container.entries.values() {
        result.push(entry.clone());
    }

    // Recursively check and print entries from subcontainers
    for child_container in container.children.values() {
        result.extend(get_all_entries(child_container)); // Recursively print entries in the child container
    }

    result
}

// Function to load and decrypt a container from an encrypted file
pub fn load_and_decrypt_container(
    container: &mut Container,
    password: &str,
    file_path: &str,
) -> Result<(), anyhow::Error> {
    let enc_data = match std::fs::read(file_path) {
        Ok(data) => data,
        Err(error) => {
            println!("Failed to read encrypted file: {error:?}");
            let e: anyhow::Error = error.into();
            return Err(e);
        }
    };

    let dec_res = match cryptman::decrypt_file_mem_gen_key(enc_data, "", password) {
        Ok(res) => res,
        Err(error) => {
            println!("Error decrypting data: {error:?}");
            let e: anyhow::Error = error.into();
            return Err(e);
        }
    };

    match container.from_json_arr(dec_res.as_slice()) {
        Ok(_) => Ok(()),
        Err(error) => {
            println!("Failed to deserialize container: {error:?}");
            let e: anyhow::Error = error.into();
            return Err(e);
        }
    }
}

// Function to encrypt and save a container to a file
pub fn encrypt_and_save_container(
    container: &mut Container,
    password: &str,
    file_path: &str,
) -> Result<(), anyhow::Error> {
    let json_data = container.to_json_string();
    let json_arr = json_data.as_bytes();

    let key_n_salt = match cryptman::pass_2_key(password, [0u8; 32]) {
        Ok(res) => res,
        Err(error) => {
            println!("Error generating key and salt: {error:?}");
            let e: anyhow::Error = error.into();
            return Err(e);
        }
    };

    let key = key_n_salt.0;
    let salt = key_n_salt.1;

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let enc_res =
        match cryptman::encrypt_file_mem_with_salt(json_arr.to_vec(), "", &key, &nonce, &salt) {
            Ok(res) => res,
            Err(error) => {
                println!("Error encrypting data: {error:?}");
                let e: anyhow::Error = error.into();
                return Err(e);
            }
        };

    match File::create(file_path) {
        Ok(mut file) => {
            if let Err(error) = file.write_all(&enc_res) {
                println!("Failed to write encrypted file: {error:?}");
                let e: anyhow::Error = error.into();
                return Err(e);
            }
        }
        Err(error) => {
            println!("Failed to create file: {error:?}");
            let e: anyhow::Error = error.into();
            return Err(e);
        }
    }

    println!("Container encrypted and saved successfully.");
    Ok(())
}
