use log::warn;
use rand::{rngs::OsRng, RngCore};
use std::process::exit;
mod cryptman;
mod passman;
use anyhow::{anyhow, Result};
use std::fmt::Write as fmtWrite;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};

#[derive(Clone)]
struct State {
    pub store_path: String,
    pub current_container: passman::Container,
    pub last_pass: String,
}

fn handle_client(mut stream: UnixStream, state: &State) {
    let mut buffer = [0; 1024]; // Buffer to store incoming data

    match stream.read(&mut buffer) {
        Ok(n) if n > 0 => {
            let received_message = String::from_utf8_lossy(&buffer[..n]);
            println!("Received: {}", received_message);
            println!("toString: {}", received_message.to_string());
            // Generate response from the client input and state
            let response = match input_from_client(received_message.to_string(), state.clone()) {
                Ok(res) => res,
                Err(error) => {
                    format!("{error:?}")
                }
            };

            // Write the response string to the stream
            if let Err(e) = stream.write_all(response.as_bytes()) {
                eprintln!("Failed to send response: {}", e);
            }
        }
        Ok(_) => {
            // No data read (EOF or similar), you might want to handle this case
            eprintln!("No data read from the client");
        }
        Err(e) => {
            eprintln!("Failed to read from the client: {}", e);
        }
    }
}

fn main() -> std::io::Result<()> {
    let socket_path = "/tmp/rust_echo_service.sock";
    let store_path: &str = "/tmp/store";
    let state = State {
        store_path: store_path.to_owned(),
        current_container: passman::Container::new("new"),
        last_pass: String::new(),
    };
    // Remove any existing socket file
    if fs::metadata(socket_path).is_ok() {
        fs::remove_file(socket_path)?;
    }

    // Create a new Unix domain socket listener
    let listener = UnixListener::bind(socket_path)?;

    println!("Echo service is running on {}", socket_path);

    // Accept incoming connections in a loop
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle_client(stream, &state),
            Err(err) => eprintln!("Connection failed: {}", err),
        }
    }

    Ok(())
}

fn input_from_client(input: String, mut state: State) -> Result<String, anyhow::Error> {
    let input_str = &input;
    let mut args = input_str.split_whitespace();
    let response: String;

    let _ = args.next();

    let command = clean_arg(args.next().unwrap_or_default());

    let arg1 = clean_arg(args.next().unwrap_or_default());


    let arg2 = clean_arg(args.next().unwrap_or_default());

    match command {
        "open" => {
            println!("OPEN");
            match arg1 {
                "" => response = String::from("password required. Container is locked."),
                _ => {
                    state.current_container = match open_store(state.store_path, arg1) {
                        Ok(res) => {
                            response = String::from("Password accepted, pass store opened.");
                            res
                        }

                        Err(error) => {
                            response = format!("error opening store: {error:?}");
                            state.current_container
                        }
                    };
                }
            }
        }
        "close" => {
            match close_store(state.current_container, state.store_path, state.last_pass) {
                Ok(_) => {
                    response = String::from("store closed successfully.");
                }
                Err(error) => {
                    response = format!("error closing store: {error:?}");
                }
            };
        }

        "get" => match arg1 {
            "" => {
                response = String::from("provide a target field");
            }
            _ => {
                let target = arg1;
                match arg2 {
                    "" => {
                        response = String::from("provide a value to search by");
                    }
                    _ => {
                        let value = arg2;
                        let entries = match get_entries_by_field(
                            state.current_container,
                            target.to_owned(),
                            value.to_owned(),
                            state.last_pass,
                        ) {
                            Ok(res) => res,
                            Err(_) => Vec::new(),
                        };
                        response = format_structs_as_table(entries);
                    }
                }
            }
        },
        "" => {
            response = String::from("please provide an argument.");
        }
        _ => {
            println!("{} {} {}", command, arg1, arg2);
            let start = trim_start_pattern(command, "\"");
            let trimmed = trim_end_pattern(start, "\",");
            response = format!("{trimmed:?} not recognised.");
        }
    }
    Ok(response)
}
fn clean_arg<'a>(s: &'a str) -> &'a str {
   let start = trim_start_pattern(s, "\"");
   let end = trim_end_pattern(start, "\",");
   let end = trim_end_pattern(end,"\"]");
   end
}
fn trim_start_pattern<'a>(s: &'a str, pattern: &str) -> &'a str {
    let pattern_len = pattern.len();
    let mut start_index = 0;
    while s[start_index..].starts_with(pattern) {
        start_index += pattern_len;
        if start_index >= s.len() {
            return "";
        }
    }

    &s[start_index..]
}

fn trim_end_pattern<'a>(s: &'a str, pattern: &str) -> &'a str {
    let pattern_len = pattern.len();
    let mut end_index = s.len();
    while end_index > 0 && s[end_index - pattern_len..end_index] == *pattern {
        end_index -= pattern_len;
    }

    &s[..end_index]
}
fn format_structs_as_table(entries: Vec<passman::Entry>) -> String {
    // Create a buffer to hold the result
    let mut buffer = String::new();

    // Write table headers (the struct fields)
    writeln!(
        &mut buffer,
        "{:<20} | {:<5} | {:<15}| {:<20} | {:<20} ",
        "Username", "Email", "Url", "Parent", "Password"
    )
    .unwrap();
    writeln!(
        &mut buffer,
        "---------------------|-------|------------------"
    )
    .unwrap();

    // Iterate over each struct and write their values
    for entry in entries {
        writeln!(
            &mut buffer,
            "{:<20} | {:<5} | {:<15}| {:<20} | {:<20} ",
            entry.username,
            entry.email,
            entry.url,
            entry.parent,
            String::from_utf8_lossy(entry.pass_vec.as_slice()),
        )
        .unwrap();
    }

    // Return the formatted buffer as a string
    buffer
}
// given a string path to the store, and a string of the password, open a passman
// store. returns the decrypted and instantiated container struct.
fn open_store(store: String, pass: &str) -> Result<passman::Container, anyhow::Error> {
    let mut file = File::open(store)?;
    let mut buf = Vec::new();

    file.read_to_end(&mut buf)?;
    // decrypt the content, reading it from file.
    let dec_res = match cryptman::decrypt_file_mem_gen_key(buf, "", &pass) {
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
    passes.from_json_arr(dec_res.as_slice())?;
    Ok(passes)
}

// given a passman container, a destination string, and a password with which to encrypt it,
// encrypt and write to file the container to file.
fn close_store(
    mut store: passman::Container,
    dest: String,
    pass: String,
) -> Result<(), anyhow::Error> {
    let key_n_salt = cryptman::pass_2_key(&pass, [0u8; 32])
        .map_err(|e| anyhow!("error generating key and salt: {:?}", e))?;

    let key = key_n_salt.0;
    let salt = key_n_salt.1;

    let binding = store.to_json_string();
    let json_arr = binding.as_bytes();

    // generate a nonce to use, fill with random bytes with OsRng.
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    // encrypt the file
    let enc_res = cryptman::encrypt_file_mem_with_salt(json_arr.to_vec(), "", &key, &nonce, &salt)?;

    let mut file = File::create(dest)?;
    file.write_all(enc_res.as_slice())?;

    Ok(())
}

fn get_entries_by_field(
    store: passman::Container,
    target_field: String,
    target_value: String,
    password: String,
) -> Result<Vec<passman::Entry>, anyhow::Error> {
    let mut matching_entries = passman::get_entries_by_field(&store, &target_field, &target_value);
    for entry in &mut matching_entries {
        entry.pass_vec =
            cryptman::decrypt_file_mem_gen_key(entry.pass_vec.clone(), "", &password).unwrap();
    }
    Ok(matching_entries)
}

#[cfg(test)]
mod tests {

    use crate::cryptman;
    use crate::passman;
    use log::warn;
    use rand::{rngs::OsRng, RngCore};
    use std::process::exit;

    #[test]
    fn test() {
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

        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let _ = sub_container
            .entries
            .get_mut("test-site.com")
            .unwrap()
            .encrypt_password(key, nonce, salt);

        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

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

        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

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

        let binding = parent_container.to_json_string();
        let json_arr = binding.as_bytes();

        // generate a nonce to use, fill with random bytes with OsRng.
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        // encrypt the file
        let enc_res = match cryptman::encrypt_file_mem_with_salt(
            json_arr.to_vec(),
            "",
            &key,
            &nonce,
            &salt,
        ) {
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
        let dec_res = match cryptman::decrypt_file_mem_gen_key(enc_res, "", pass) {
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

        let target_field = "url"; // Change to "email" if needed
        let target_value = "test-site.com"; // Change to the desired value

        let matching_entries = passman::get_entries_by_field(&passes, target_field, target_value);
        for mut entry in matching_entries {
            let vec = &entry.pass_vec;
            let vec = &vec.clone();

            let lossy_encrypted = String::from_utf8_lossy(vec.as_slice());
            entry.pass_vec = cryptman::decrypt_file_mem_gen_key(entry.pass_vec, "", pass).unwrap();

            let password = String::from_utf8_lossy(entry.pass_vec.as_slice());
            println!(
                "Username: {}\t encrypted:{}\t pass:{}",
                entry.username, lossy_encrypted, password
            );
        }
    }
}
