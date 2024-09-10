use log::warn;
use rand::{rngs::OsRng, RngCore};
use std::process::exit;
mod cryptman;
mod passman;
use anyhow::{anyhow, Result};
use std::borrow::Cow;
use std::collections::HashMap;
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

// type def for command handler functions
type CommandHandler = fn(&mut State, &str, &str) -> Result<String, anyhow::Error>;

// struct def for overall command processor struct,
// contains Hashmap of CommandHandler functions
struct CommandProcessor {
    handlers: HashMap<String, CommandHandler>,
}

impl CommandProcessor {
    // on new CommandProcessor, generate a hashmap containing the command handler functions
    fn new() -> Self {
        let mut handlers = HashMap::new();
        handlers.insert("open".to_string(), handle_open as CommandHandler);
        handlers.insert("close".to_string(), handle_close as CommandHandler);
        handlers.insert("get".to_string(), handle_get as CommandHandler);
        handlers.insert("new".to_string(), handle_new as CommandHandler);
        Self { handlers }
    }

    // when process_command is called, retrieve execute the handler command
    fn process_command(&self, state: &mut State, command: &str, arg1: &str, arg2: &str) -> Result<String, anyhow::Error> {
        if let Some(handler) = self.handlers.get(command) {
            handler(state, arg1, arg2)
        } else {
            Ok(format!("{command:?} not recognised."))
        }
    }

}

// commandHandler for opening the password store
fn handle_open(state: &mut State, arg1: &str, _: &str) -> Result<String, anyhow::Error> {
    if arg1.is_empty() {
        return Ok("password required. Container is locked.".to_string());
    }

    let password = if state.last_pass.is_empty() {
        arg1.to_string()
    } else {
        state.last_pass.clone()
    };

    state.current_container = match open_store(state.store_path.clone(), &password) {
        Ok(container) => {
            state.last_pass = password;
            container
        }
        Err(error) => {
            state.last_pass.clear();
            return Ok(format!("error opening store: {:?}", error));
        }
    };

    Ok("Password accepted, pass store opened.".to_string())
}

// commandHandler for closing the password store
fn handle_close(state: &mut State, _: &str, _: &str) -> Result<String, anyhow::Error> {
    match close_store(state.current_container.clone(), state.store_path.clone(), state.last_pass.clone()) {
        Ok(_) => Ok("store closed successfully.".to_string()),
        Err(error) => Ok(format!("error closing store: {:?}", error)),
    }
}


// commandHandler for retrieving elements from the password store
fn handle_get(state: &mut State, arg1: &str, arg2: &str) -> Result<String, anyhow::Error> {
    if arg1.is_empty() {
        return Ok("provide a target field".to_string());
    }

    if arg2.is_empty() {
        return Ok("provide a value to search by".to_string());
    }

    let entries = match get_entries_by_field(
        state.current_container.clone(),
        arg1.to_string(),
        arg2.to_string(),
        state.last_pass.clone(),
    ) {
        Ok(entries) => entries,
        Err(_) => Vec::new(),
    };

    Ok(format_structs_as_table(entries))
}


// commandHandler for creating a password store
fn handle_new(state: &mut State, arg1: &str, arg2: &str) -> Result<String, anyhow::Error> {
    if arg1.is_empty() {
        return Ok("new requires an argument (e.g store,container,entry)".to_string());
    }

    match arg1 {
        "store" => {
            if arg2.is_empty() {
                return Ok("creating a store requires a password as the 2nd arg".to_string());
            }

            let path = Cow::Borrowed(&state.store_path);

            state.current_container = create_store(state.current_container.clone(), path.to_string(), arg2)?;
            Ok(format!("store created at: {}", path.to_string()))
        }
        _ => Ok(format!("{arg1:?} not recognised.")),
    }
}

// function to take the input from the socket message, process the arguments, then create the
// response.
fn input_from_client(input: String, mut state: State) -> Result<String, anyhow::Error> {
    let mut args = input.split_whitespace();

    let _ = args.next(); // Skip the first argument (command name)

    let command = clean_arg(args.next().unwrap_or_default());
    let arg1 = clean_arg(args.next().unwrap_or_default());
    let arg2 = clean_arg(args.next().unwrap_or_default());

    let processor = CommandProcessor::new();
    processor.process_command(&mut state, &command, &arg1, &arg2)
}

fn clean_arg<'a>(s: &'a str) -> &'a str {
    // Trim start pattern "\""
    let start_pattern = "\"";
    let pattern_len = start_pattern.len();
    let mut start_index = 0;
    while s[start_index..].starts_with(start_pattern) {
        start_index += pattern_len;
        if start_index >= s.len() {
            return "";
        }
    }

    // Slice the string after trimming the start
    let mut trimmed_str = &s[start_index..];

    // Trim end patterns "\",", "\"]"
    let end_patterns = [ "\",", "\"]" ];
    for end_pattern in &end_patterns {
        let pattern_len = end_pattern.len();
        let mut end_index = trimmed_str.len();
        while end_index >= pattern_len && &trimmed_str[end_index - pattern_len..end_index] == *end_pattern {
            end_index -= pattern_len;
        }
        trimmed_str = &trimmed_str[..end_index];
    }

    trimmed_str
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

fn create_store(
    current_store: passman::Container,
    store_path: String,
    pass: &str,
) -> Result<passman::Container> {
    let store = match current_store {
        current if current.entries.is_empty() && current.children.is_empty() => {
            let mut store = passman::Container::new("store");

            let key_n_salt = cryptman::pass_2_key(&pass, [0u8; 32])
                .map_err(|e| anyhow!("error generating key and salt: {:?}", e))?;

            let (key, salt) = key_n_salt;

            let binding = store.to_json_string();
            let json_arr = binding.as_bytes();

            // Generate a nonce to use, fill with random bytes with OsRng.
            let mut nonce = [0u8; 24];
            OsRng.fill_bytes(&mut nonce);

            // Encrypt the file
            let enc_res =
                cryptman::encrypt_file_mem_with_salt(json_arr.to_vec(), "", &key, &nonce, &salt)?;

            let mut file = File::create(&store_path)?;
            file.write_all(&enc_res)?;

            Ok(store)
        }
        _ => Ok(current_store),
    };

    store
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


// tests, not properly written yet, but it does exercise passman & cryptman.
#[cfg(test)]
mod tests;
