use crate::cryptman;
use serde::{Deserialize, Serialize};
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
    pub fn encrypt_password(&mut self,key:[u8;32],nonce:[u8;24],salt:[u8;32]) -> Result<(),anyhow::Error> {

        let binding = cryptman::encrypt_file_mem_with_salt(self.pass_vec.clone(), "", &key, &nonce, &salt)?;
        self.pass_vec = binding;
        Ok(())

    }
}
