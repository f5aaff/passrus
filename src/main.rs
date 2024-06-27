use log::warn;
use rand::{rngs::OsRng, RngCore};
use std::{fs, process::exit};
mod cryptman;
mod passman;

fn main() {
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

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let mut parent_container = passman::Container::new("parent_container");
    let mut sub_container = passman::Container::new("sub_container");

    let user1_pass = String::from("this is a terrible password")
        .as_bytes()
        .to_vec();
    let user2_pass = String::from("this is also a terrible password")
        .as_bytes()
        .to_vec();
    let user3_pass = String::from("this is also a terrible password")
        .as_bytes()
        .to_vec();

    // adding entries to a container that has been instantiated beforehand
    sub_container.add_entry(passman::Entry::new(
        "user1",
        user1_pass,
        "user@email.com",
        "test-site.com",
    ));

    sub_container.add_entry(passman::Entry::new(
        "user2",
        user2_pass,
        "user2@email.com",
        "test-site2.com",
    ));

    let _ = sub_container
        .entries
        .get_mut("test-site.com")
        .unwrap()
        .encrypt_password(key, nonce, salt);
    let _ = sub_container
        .entries
        .get_mut("test-site2.com")
        .unwrap()
        .encrypt_password(key, nonce, salt);

    // adding a new container as a child, then adding entries to it
    sub_container.add_child(passman::Container::new("sub_sub_container"));
    sub_container
        .children
        .get_mut("sub_sub_container")
        .unwrap()
        .add_entry(passman::Entry::new(
            "user3",
            user3_pass,
            "user3@email.com",
            "test-site3.com",
        ));

    // encrypting a password of an entry already in a nested container
    let _ = sub_container
        .children
        .get_mut("sub_sub_container")
        .unwrap()
        .entries
        .get_mut("test-site3.com")
        .unwrap()
        .encrypt_password(key, nonce, salt);

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
    let mut passes: passman::Container = passman::Container::new("");
    passes.from_json_arr(dec_res.as_slice()).unwrap();
    let passes_json = passes.to_json_string();

    fs::write("deserialised", passes_json).unwrap();
}
