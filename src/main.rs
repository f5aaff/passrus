use cryptman::hash_str;
use log::warn;
use rand::{rngs::OsRng, RngCore};
use std::{collections::HashMap, fs, process::exit};
mod cryptman;

mod passman {
    use serde::{Deserialize, Serialize};
    use std::{collections::HashMap, usize};

    #[derive(Clone, Serialize, Deserialize)]
    pub struct Container {
       pub  name: String,
       pub  children: HashMap<String, Container>,
       pub  entries: HashMap<String, Entry>,
       pub  parent: String,
    }
    impl Container {

        pub fn add_entry(&mut self, mut entry:Entry) {
            entry.parent = self.name.as_str().to_owned();
            self.entries.insert(entry.url.as_str().to_owned(), entry);
        }

        pub fn add_child(&mut self, mut container:Container) {
            container.parent = self.name.as_str().to_owned();
            self.children.insert(container.name.as_str().to_owned(), container);
        }
        pub fn to_json_string(&mut self) -> String {
            serde_json::to_string(self).unwrap()
        }

        pub fn from_json_arr(&mut self, arr: &[u8]) -> Result<(), serde_json::Error> {
            let from_json: Container = serde_json::from_slice(arr)?;
            *self = from_json;
            Ok(())
        }

        pub fn from_json_string(&mut self, s: &str) -> Result<(), serde_json::Error> {
            let from_json_str: Container = serde_json::from_str(s)?;
            *self = from_json_str;
            Ok(())
        }

        pub fn new(name:&str,parent:&str) -> Self {
            let children:HashMap<String,Container> = HashMap::new();
            let entries:HashMap<String,Entry> = HashMap::new();
            Container{name:name.to_owned(),parent:parent.to_owned(),children,entries}
        }
    }

    #[derive(Clone, Serialize, Deserialize)]
    pub struct Entry {
       pub  username: String,
       pub  pass_hash: String,
       pub  email: String,
       pub  url: String,
       pub  parent: String,
    }

    impl Entry {
        pub fn to_json_string(&mut self) -> String {
            serde_json::to_string(self).unwrap()
        }

        pub fn from_json_arr(&mut self, arr: &[u8]) -> Result<(), serde_json::Error> {
            let from_json: Entry = serde_json::from_slice(arr)?;
            *self = from_json;
            Ok(())
        }

        pub fn from_json_string(&mut self, s: &str) -> Result<(), serde_json::Error> {
            let from_json_str:Entry  = serde_json::from_str(s)?;
            *self = from_json_str;
            Ok(())
        }

        pub fn new(username:&str,pass_hash:&str,email:&str,url:&str) -> Self {
            Entry{username:username.to_owned(),pass_hash:pass_hash.to_owned(),email:email.to_owned(),url:url.to_owned(),parent:"".to_owned()}
        }
    }
}

fn main() {
    use crate::passman;
    // obligatory garbage password
    let pass = "password";

    //generate a password and salt, keep them to be written to the encrypted file.
    let key_n_salt = match cryptman::pass_2_key(pass, [0u8; 32]) {
        Ok(res) => res,

        Err(error) => {
            println! {"rip: {error:?}"}
            warn!(target:"main","error generating key and salt: {error:?}");
            exit(0);
        }
    };

    let key = key_n_salt.0;
    let salt = key_n_salt.1;

    let mut parent_container = passman::Container::new("parent_container","none");
    let mut sub_container = passman::Container::new("sub_container","none");

    //adding entries to a container that has been instantiated beforehand
    sub_container.add_entry(passman::Entry::new("user1",hash_str("this is a terrible password",key).as_str(),"user@email.com","test-site.com"));
    sub_container.add_entry(passman::Entry::new("user2",hash_str("this is also a terrible password",key).as_str(),"user2@email.com","test-site2.com"));

    //adding a new container as a child, then adding entries to it
    sub_container.add_child(passman::Container::new("sub_sub_container","none"));
    sub_container.children.get_mut("sub_sub_container").unwrap().add_entry(passman::Entry::new("user3",hash_str("this is also a terrible password",key).as_str(),"user3@email.com","test-site3.com"));

    //adding a container as a child after instantiating it and adding entries to it.
    parent_container.add_child(sub_container);


    let json_string = parent_container.to_json_string();
    println!("{}", json_string);

    //write the store to json, then to file.
    fs::write("pass_input.json", json_string).unwrap();
    // generate a nonce to use, fill with random bytes with OsRng.
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    // pick a file you own, don't care about, and can fit in memory.
    let filepath = "pass_input.json";

    // encrypt the file, generate encrypted content/write it to file.
    let plaintext = fs::read(filepath).unwrap();

    let _enc_res = match cryptman::encrypt_file_mem_with_salt(plaintext, "enc", &key, &nonce, &salt)
    {
        Ok(res) => {
            println!("encrypted with key,salt&nonce successfully");
            res
        }
        Err(error) => {
            println!("rip: {error:?}");
            exit(0);
        }
    };

    let enc = fs::read("enc").unwrap();

    // decrypt the content, reading it from file.
    let dec_res = match cryptman::decrypt_file_mem_gen_key(enc, "dec", pass) {
        Ok(res) => {
            println!("grabbed salt&nonce from file, decrypted successfully");
            res
        }

        Err(error) => {
            warn!(target:"main","error decrypting data: {error:?}");
            exit(0);
        }
    };
    let mut passes:passman::Container = passman::Container::new("","");
    passes.from_json_arr(dec_res.as_slice()).unwrap();
    let passes_json = passes.to_json_string();

    fs::write("deserialised", passes_json).unwrap();
}
