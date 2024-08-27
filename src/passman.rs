use crate::cryptman;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::prelude::*;
use std::{collections::HashMap, usize};

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
        let from_json_str: Entry = serde_json::from_str(s)?;
        *self = from_json_str;
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
            _ => {} // Handle other fields if needed
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

pub fn flatten(parent: &Container) -> Result<HashMap<String, Entry>, anyhow::Error> {
    let mut entries: HashMap<String, Entry> = HashMap::new();

    // Add entries from the current container.
    for (key, value) in &parent.entries {
        entries.insert(key.to_owned(), value.clone());
    }

    // Recursively process nested containers.
    for (_, nested_container) in &parent.children {
        let nested_entries = flatten(nested_container)?;
        entries.extend(nested_entries);
    }

    Ok(entries)
}

pub fn open_store(path: String, pass: String) -> Result<Container, anyhow::Error> {
    let mut f = fs::File::open(path)?;
    let mut buffer = [0; 10];

    // read up to 10 bytes
    f.read(&mut buffer)?;

    let mut buffer = Vec::new();
    // read the whole file
    f.read_to_end(&mut buffer)?;

    // read into a String, so that you don't need to do the conversion.
    let mut buffer = String::new();
    f.read_to_string(&mut buffer)?;

    let mut passes: Container = Container::new("");
    let dec_res = cryptman::decrypt_file_mem_gen_key(buffer.as_bytes().to_vec(), "", &pass)?;
    passes.from_json_arr(dec_res.as_slice())?;
    Ok(passes)
}

pub fn write_store(
    path: String,
    mut container: Container,
    pass: String,
) -> Result<(), anyhow::Error> {
    let binding = container.to_json_string();
    let json_arr = binding.as_bytes();

    //generate a password and salt, keep them to be written to the encrypted file.
    let key_n_salt = match cryptman::pass_2_key(&pass, [0u8; 32]) {
        Ok(res) => res,
        Err(error) => return Err(anyhow::Error::msg(error)),
    };

    let key = key_n_salt.0;
    let salt = key_n_salt.1;

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    // encrypt the file
    let enc_res = cryptman::encrypt_file_mem_with_salt(json_arr.to_vec(), "", &key, &nonce, &salt)?;
    // ... later in code
    let mut file = fs::OpenOptions::new()
        // .create(true) // To create a new file
        .write(true)
        // either use the ? operator or unwrap since it returns a Result
        .open(path)?;

    // _ used to still break on error with ? operator
    let _ = file.write_all(&enc_res)?;
    Ok(())
}
