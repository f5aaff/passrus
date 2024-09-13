use anyhow::anyhow;
use argon2::Argon2;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, NewAead},
    Key, XChaCha20Poly1305,
};
use rand::{rngs::OsRng, RngCore};
use std::{fs, io::Write, str};

///expects clear text passphrase as str, and the salt for the key as [u8;32]. provide an empty array for salt to generate a new one.
pub fn pass_2_key(input: &str, mut salt: [u8; 32]) -> Result<([u8; 32], [u8; 32]), anyhow::Error> {
    log::debug!("Attempting to generate key...");

    // Generate a salt if an empty one is provided
    if salt.iter().all(|&x| x == 0) {
        log::debug!("Empty salt provided, generating new salt.");
        OsRng.fill_bytes(&mut salt);
    } else {
        log::debug!("Using provided salt.");
    }

    let mut key = [0u8; 32]; // Buffer for the generated key

    // Hash the password with Argon2 to generate the key
    match Argon2::default().hash_password_into(input.as_bytes(), &salt, &mut key) {
        Ok(_) => {
            log::debug!("Successfully generated key.");
            Ok((key, salt))
        }
        Err(err) => {
            log::debug!("Error generating key: {:?}", err);
            Err(anyhow!("Key generation failed: {:?}", err))
        }
    }
}

/// encrypts data by loading it into memory wholly first. takes data as a Vec<u8> ,dest,key,nonce,and salt. encrypted using XChaCha20Poly1305.
pub fn encrypt_file_mem_with_salt(
    file_data: Vec<u8>,
    dist: &str,
    key: &[u8; 32],
    nonce: &[u8; 24],
    salt: &[u8; 32],
) -> Result<Vec<u8>, anyhow::Error> {
    log::debug!("Attempting to encrypt data...");

    // Create a cipher instance using the provided key
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    log::debug!("Cipher generated from key.");

    // Encrypt the file data
    let encrypted_file = match cipher.encrypt(GenericArray::from_slice(nonce), file_data.as_ref()) {
        Ok(encrypted_data) => {
            log::debug!("Data encrypted successfully.");
            encrypted_data
        }
        Err(err) => {
            log::debug!("Error encrypting data: {:?}", err);
            return Err(anyhow!("Encrypting small file: {:?}", err));
        }
    };

    // Optionally write the encrypted file along with nonce and salt to the disk
    if !dist.is_empty() {
        log::debug!(
            "File path provided: attempting to write encrypted content to {}",
            dist
        );

        // Write the encrypted content to the specified file
        fs::write(dist, &encrypted_file)?;

        // Append the nonce and salt to the file
        let mut f = fs::OpenOptions::new().append(true).open(dist)?;
        f.write_all(nonce)?;
        f.write_all(salt)?;

        log::debug!("Encrypted content written to file successfully.");
    }

    // Append nonce and salt to the in-memory encrypted file
    let mut final_file = encrypted_file.clone();
    final_file.extend_from_slice(nonce);
    final_file.extend_from_slice(salt);

    log::debug!("Nonce and salt appended to encrypted content in memory.");

    Ok(final_file)
}

/// decrypt_file_mem_gen_key expects a path to the encrypted file,
/// the destination for the decrypted content,
/// and the password to decrypt it with.
///
/// the file is read in, then the salt and nonce are parsed
/// from the end of the file content.
///
/// these are used to then decrypt the remaining file content.
///
/// the file is loaded into memory, not streamed.

pub fn decrypt_file_mem_gen_key(
    file_data: Vec<u8>,
    dist: &str,
    pass: &str,
) -> Result<Vec<u8>, anyhow::Error> {
    let data_arr = file_data.as_slice();
    let data_len = data_arr.len();

    // Define the lengths of the salt and nonce
    let salt_len = 32;
    let nonce_len = 24;

    // Ensure the file size is sufficient for salt, nonce, and encrypted content
    if data_len < (salt_len + nonce_len) {
        return Err(anyhow!(
            "Invalid file length. Not enough data for salt and nonce."
        ));
    }

    // Calculate where the salt and nonce start
    let salt_start = data_len - salt_len;
    let nonce_start = salt_start - nonce_len;

    // Extract the salt and nonce from the file data
    let salt: &[u8; 32] = &data_arr[salt_start..]
        .try_into()
        .expect("Invalid salt length");
    let nonce_bytes: &[u8; 24] = &data_arr[nonce_start..salt_start]
        .try_into()
        .expect("Invalid nonce length");

    // Convert nonce_bytes into a GenericArray<u8, U24> for the nonce
    let nonce = GenericArray::<u8, chacha20poly1305::aead::consts::U24>::from_slice(nonce_bytes);

    // Print debugging information to track the values of salt and nonce
    log::debug!("Salt: {:?}", String::from_utf8_lossy(salt));
    log::debug!("Nonce: {:?}", String::from_utf8_lossy(nonce_bytes));

    // Generate the key from the password and salt
    let key = match pass_2_key(pass, *salt) {
        Ok((generated_key, _)) => generated_key, // We only care about the key here
        Err(err) => {
            return Err(anyhow!("Error generating key: {:?}", err));
        }
    };

    // Print debugging information for the generated key
    let byte_slice: &[u8] = &key;
    log::debug!("Generated key: {:?}", String::from_utf8_lossy(byte_slice));

    // Create a cipher instance using the generated key
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    log::debug!("Cipher created.");

    // Extract the encrypted content (excluding nonce and salt)
    let encrypted_content = &data_arr[..nonce_start];

    // Print debugging information for the encrypted content
    log::debug!("Encrypted content: {:?}", String::from_utf8_lossy(encrypted_content));

    if encrypted_content.is_empty() {
        return Err(anyhow!("Encrypted content is empty"));
    }

    // Decrypt the content using the nonce and key
    let decrypted_file = match cipher.decrypt(nonce, encrypted_content) {
        Ok(decrypted_data) => decrypted_data,
        Err(err) => {
            // Print debugging information for the decryption error
            log::debug!("Decryption error: {:?}", err);
            return Err(anyhow!("Decrypting small file: {}", err));
        }
    };

    log::debug!("Decrypted content successfully.");
    log::debug!("decrypted Content: {:?}",String::from_utf8_lossy(decrypted_file.as_slice()));
    // If a path is provided, write the decrypted content to the destination file
    if !dist.is_empty() {
        log::debug!("File path detected, writing decrypted content to destination file...");
        fs::write(&dist, &decrypted_file)?;
    }

    Ok(decrypted_file)
}
