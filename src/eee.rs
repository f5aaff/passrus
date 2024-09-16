use crate::cryptman;
use crate::passman;
use log::warn;
use rand::rngs::OsRng;
use std::fs::File;
use std::io::Write;
use std::process::exit;
use std::path::Path;

// Function to load and decrypt a container from an encrypted file
fn load_and_decrypt_container(container: &mut passman::Container, password: &str, file_path: &str) {
    let enc_data = match std::fs::read(file_path) {
        Ok(data) => data,
        Err(error) => {
            println!("Failed to read encrypted file: {error:?}");
            exit(0);
        }
    };

    let key_n_salt = match cryptman::pass_2_key(password, [0u8; 32]) {
        Ok(res) => res,
        Err(error) => {
            println!("Error generating key and salt: {error:?}");
            exit(0);
        }
    };

    let key = key_n_salt.0;
    let salt = key_n_salt.1;

    let dec_res = match cryptman::decrypt_file_mem_gen_key(enc_data, "", password) {
        Ok(res) => res,
        Err(error) => {
            warn!(target:"main","Error decrypting data: {error:?}");
            exit(0);
        }
    };

    match container.from_json_arr(dec_res.as_slice()) {
        Ok(_) => println!("Container decrypted successfully."),
        Err(error) => {
            println!("Failed to deserialize container: {error:?}");
            exit(0);
        }
    }
}

// Function to encrypt and save a container to a file
fn encrypt_and_save_container(container: &passman::Container, password: &str, file_path: &str) {
    let json_data = container.to_json_string();
    let json_arr = json_data.as_bytes();

    let key_n_salt = match cryptman::pass_2_key(password, [0u8; 32]) {
        Ok(res) => res,
        Err(error) => {
            println!("Error generating key and salt: {error:?}");
            exit(0);
        }
    };

    let key = key_n_salt.0;
    let salt = key_n_salt.1;

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let enc_res = match cryptman::encrypt_file_mem_with_salt(json_arr.to_vec(), "", &key, &nonce, &salt) {
        Ok(res) => res,
        Err(error) => {
            println!("Error encrypting data: {error:?}");
            exit(0);
        }
    };

    match File::create(file_path) {
        Ok(mut file) => {
            if let Err(error) = file.write_all(&enc_res) {
                println!("Failed to write encrypted file: {error:?}");
                exit(0);
            }
        }
        Err(error) => {
            println!("Failed to create file: {error:?}");
            exit(0);
        }
    }

    println!("Container encrypted and saved successfully.");
}
