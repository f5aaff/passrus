use std::process::exit;
use rand::{rngs::OsRng, RngCore};
mod cryptman {
    use anyhow::anyhow;
    use argon2::Argon2;
    use chacha20poly1305::{
        aead::{Aead, NewAead},
        XChaCha20Poly1305,
    };
    use rand::{rngs::OsRng, RngCore};
    use std::{
        fs,
        io::{prelude::*, BufReader, Write},
        str,
    };

    /**
    expects clear text passphrase as str, and the salt for the key as [u8;32]. provide an empty array for salt to generate a new one.

    **/
    pub fn pass_2_key(
        input: &str,
        mut salt: [u8; 32],
    ) -> Result<([u8; 32], [u8; 32]), argon2::Error> {
        if salt.is_empty() {
            OsRng.fill_bytes(&mut salt);
        }

        let mut res = [0u8; 32];
        Argon2::default().hash_password_into(input.as_bytes(), salt.as_slice(), &mut res)?;
        Ok((res, salt))
    }

    /**
    encrypts a file by loading it into memory wholly first. takes path,dest,key,nonce,and salt.
    encrypted using XChaCha20Poly1305.
    **/
    pub fn encrypt_file_mem_with_salt(
        filepath: &str,
        dist: &str,
        key: &[u8; 32],
        nonce: &[u8; 24],
        salt: &[u8; 32],
    ) -> Result<Vec<u8>, anyhow::Error> {
        let cipher = XChaCha20Poly1305::new(key.into());

        let file_data = fs::read(filepath)?;

        let encrypted_file = cipher
            .encrypt(nonce.into(), file_data.as_ref())
            .map_err(|err| anyhow!("Encrypting small file: {}", err))?;

        fs::write(&dist, encrypted_file.clone())?;
        let mut f = fs::OpenOptions::new().append(true).open(&dist)?;
        f.write(nonce)?;
        f.write(salt)?;
        Ok(encrypted_file)
    }

    fn read_n<R>(reader: R, bytes_to_read: u64) -> Vec<u8>
    where
        R: Read,
    {
        let mut buf = vec![];
        let mut chunk = reader.take(bytes_to_read);
        // Do appropriate error handling for your situation
        // Maybe it's OK if you didn't read enough bytes?
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
        encrypted_file_path: &str,
        dist: &str,
        pass: &str,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let file_data = fs::read(encrypted_file_path)?;

        //get lengths of various components of encryption components
        let data_arr = file_data.as_slice();
        let data_len: usize = data_arr.len();
        let salt_len: usize = 32;
        let salt_start = data_len - salt_len;
        let nonce_len: usize = 24;
        let nonce_start = salt_start - nonce_len;

        //pull salt & nonce from data bytes
        let salt: &mut [u8; 32] = &mut [0; 32];
        let nonce: &mut [u8; 24] = &mut [0; 24];

        let mut i: usize = 0;
        for byte in &data_arr[salt_start..] {
            salt[i] = *byte;
            i += 1;
        }
        let mut x: usize = 0;
        for byte in &data_arr[nonce_start..salt_start] {
            nonce[x] = *byte;
            x += 1;
        }

        //generate a key based on the pass and salt pulled from file
        let key = pass_2_key(pass, salt.to_owned().into()).unwrap().0;
        let cipher = XChaCha20Poly1305::new(&key.into());

        //print lossy approximations of components, to compare initial and regenerated instances.
        //println!("salt:{}", String::from_utf8(salt.to_vec()).unwrap());
        //println!("nonce:{}", String::from_utf8_lossy(nonce));
        //println!("key:{}", String::from_utf8_lossy(&key));

        let content_len: usize = data_len - (nonce_len + salt_len);
        let mut reader = BufReader::new(data_arr);
        let content = read_n(&mut reader, content_len as u64);

        //decrypt the content with the nonce pulled from file, and the generated key
        let decrypted_file = cipher
            .decrypt(&nonce.to_owned().into(), content.as_ref())
            .map_err(|err| anyhow!("Decrypting small file: {}", err))?;

        fs::write(&dist, decrypted_file.clone())?;

        Ok(decrypted_file)
    }
}

fn main() {
    // obligatory garbage password
    let pass = "password";

    //generate a password and salt, keep them to be written to the encrypted file.
    let key_n_salt = match cryptman::pass_2_key(pass, [0u8; 32]) {
        Ok(res) => res,
        Err(error) => {
            println! {"rip: {error:?}"}
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

    //print lossy approximates of components, to compare initial and regenerated instances.

    //println!("salt before:{}", String::from_utf8_lossy(&salt));
    //println!("nonce before:{}", String::from_utf8_lossy(&nonce));
    //println!("key before:{}", String::from_utf8_lossy(&key));

    // encrypt the file, generate encrypted content/write it to file.
    let _enc_res = match cryptman::encrypt_file_mem_with_salt(filepath, "w_salt_enc", &key, &nonce, &salt) {
        Ok(res) => {
            println!("encrypted with key,salt&nonce successfully");
            res
        }
        Err(error) => {
            println!("rip: {error:?}");
            exit(0);
        }
    };

    // decrypt the content, reading it from file.
    let _dec_res = match cryptman::decrypt_file_mem_gen_key("w_salt_enc", "w_salt_dec", pass) {
        Ok(res) => {
            println!("grabbed salt&nonce from file, decrypted successfully");
            res
        }
        Err(error) => {
            println!("rip: {error:?}");
            exit(0);
        }
    };
}
