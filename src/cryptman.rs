use anyhow::anyhow;
use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, NewAead},
    XChaCha20Poly1305,
};
use log::{debug, info};
use rand::{rngs::OsRng, RngCore};
use hex_literal::hex;
use sha3::{Digest, Sha3_256};
use std::{
    fs,
    io::{prelude::*, BufReader, Write},
    str,
};

pub fn hash_str(input: &str,key:[u8;32])-> String{
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    let result = hasher.finalize();
    hex::encode(result).to_owned()
}

/**
expects clear text passphrase as str, and the salt for the key as [u8;32]. provide an empty array for salt to generate a new one.

**/
pub fn pass_2_key(input: &str, mut salt: [u8; 32]) -> Result<([u8; 32], [u8; 32]), argon2::Error> {
    info!(target:"pass_2_key", "attempting to generate key...");
    if salt.is_empty() {
        debug!(target:"pass_2_key", "empty salt provided, generating salt.");
        OsRng.fill_bytes(&mut salt);
    }

    let mut res = [0u8; 32];
    Argon2::default().hash_password_into(input.as_bytes(), salt.as_slice(), &mut res)?;
    info!(target:"pass_2_key", "successfully generated key from password & salt.");
    Ok((res, salt))
}

/**
encrypts data by loading it into memory wholly first. takes path,dest,key,nonce,and salt.
encrypted using XChaCha20Poly1305.
**/
pub fn encrypt_file_mem_with_salt(
    file_data: Vec<u8>,
    dist: &str,
    key: &[u8; 32],
    nonce: &[u8; 24],
    salt: &[u8; 32],
) -> Result<Vec<u8>, anyhow::Error> {
    info!(target:"encrypt_file_mem_with_salt", "attempting to encrypt data...");

    let cipher = XChaCha20Poly1305::new(key.into());
    debug!(target: "encrypt_file_mem_with_salt", "cipher generated from key successfully.");

    debug!(target: "encrypt_file_mem_with_salt", "target data read successfully.");

    let mut encrypted_file = cipher
        .encrypt(nonce.into(), file_data.as_ref())
        .map_err(|err| anyhow!("Encrypting small file: {}", err))?;
    debug!(target: "encrypt_file_mem_with_salt", "target data encrypted successfully.");

    if dist != "" {
        info!(target:"encrypt_file_mem_with_salt", "filepath provided: attempting to write encrypted content to file:{}...",dist);
        fs::write(&dist, encrypted_file.clone())?;
        let mut f = fs::OpenOptions::new().append(true).open(&dist)?;
        f.write(nonce)?;
        f.write(salt)?;
        info!(target:"encrypt_file_mem_with_salt", "encrypted content written to file written successfully");
    }
    encrypted_file.append(&mut nonce.to_vec());
    encrypted_file.append(&mut salt.to_vec());
    debug!(target:"encrypt_file_mem_with_salt", "nonce and salt appended to encrypted content successfully");
    Ok(encrypted_file)
}

fn read_n<R>(reader: R, bytes_to_read: u64) -> Vec<u8>
where
    R: Read,
{
    let mut buf = vec![];
    let mut chunk = reader.take(bytes_to_read);

    let n = chunk.read_to_end(&mut buf).expect("Didn't read enough");
    assert_eq!(bytes_to_read as usize, n);
    buf
}

/**
decrypt_file_mem_gen_key expects a path to the encrypted file,
the destination for the decrypted content,
and the password to decrypt it with.

the file is read in, then the salt and nonce are parsed
from the end of the file content.

these are used to then decrypt the remaining file content.

the file is loaded into memory, not streamed.

 **/
pub fn decrypt_file_mem_gen_key(
    file_data: Vec<u8>,
    dist: &str,
    pass: &str,
) -> Result<Vec<u8>, anyhow::Error> {
    let data_arr = file_data.as_slice();

    let data_len: usize = data_arr.len();

    let salt_len: usize = 32;
    let salt_start = data_len - salt_len;

    let nonce_len: usize = 24;
    let nonce_start = salt_start - nonce_len;

    debug!(target:"decrypt_file_mem_gen_key","retrieving salt and nonce from tail of file.");

    //pull salt & nonce from data bytes

    let salt: &mut [u8; 32] = &mut [0; 32];

    let nonce: &mut [u8; 24] = &mut [0; 24];

    let mut i: usize = 0;
    for byte in &data_arr[salt_start..] {
        salt[i] = *byte;
        i += 1;
    }
    debug!(target:"decrypt_file_mem_gen_key","salt retrieved.");

    let mut x: usize = 0;
    for byte in &data_arr[nonce_start..salt_start] {
        nonce[x] = *byte;
        x += 1;
    }
    debug!(target:"decrypt_file_mem_gen_key","nonce retrieved.");

    //generate a key based on the pass and salt pulled from file
    let key = pass_2_key(pass, salt.to_owned().into()).unwrap().0;
    debug!(target:"decrypt_file_mem_gen_key","generated key.");

    let cipher = XChaCha20Poly1305::new(&key.into());
    debug!(target:"decrypt_file_mem_gen_key","cipher generated from key.");


    let content_len: usize = data_len - (nonce_len + salt_len);

    let mut reader = BufReader::new(data_arr);

    let content = read_n(&mut reader, content_len as u64);
    debug!(target:"decrypt_file_mem_gen_key","read encrypted content from file.");

    //decrypt the content with the nonce pulled from file, and the generated key
    let decrypted_file = cipher
        .decrypt(&nonce.to_owned().into(), content.as_ref())
        .map_err(|err| anyhow!("Decrypting small file: {}", err))?;
    info!(target:"decrypt_file_mem_gen_key","decrypted content successfully.");

    //if a path is provided, write the decryted content to the given file.
    if dist != "" {
        info!(target:"decrypt_file_mem_gen_key","file path detected, writing decrypted content to destination file...");
        fs::write(&dist, decrypted_file.clone())?;
    }

    Ok(decrypted_file)
}
