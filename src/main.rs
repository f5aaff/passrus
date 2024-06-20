use log::warn;
use rand::{rngs::OsRng, RngCore};
use std::{fs, process::exit};
mod cryptman;

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

    // generate a nonce to use, fill with random bytes with OsRng.
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    // pick a file you own, don't care about, and can fit in memory.
    let filepath = "input.txt";

    // encrypt the file, generate encrypted content/write it to file.
    let plaintext = fs::read(filepath).unwrap();

    let _enc_res =
        match cryptman::encrypt_file_mem_with_salt(plaintext, "w_salt_enc", &key, &nonce, &salt) {
            Ok(res) => {
                println!("encrypted with key,salt&nonce successfully");
                res
            }
            Err(error) => {
                println!("rip: {error:?}");
                exit(0);
            }
        };

    let enc = fs::read("w_salt_enc").unwrap();

    // decrypt the content, reading it from file.
    let _dec_res = match cryptman::decrypt_file_mem_gen_key(enc, "w_salt_dec", pass) {
        Ok(res) => {
            println!("grabbed salt&nonce from file, decrypted successfully");
            res
        }

        Err(error) => {
            warn!(target:"main","error decrypting data: {error:?}");
            exit(0);
        }
    };
}
