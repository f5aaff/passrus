use passman::get_all_entries;
use rand::{rngs::OsRng, RngCore};
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
            // No data read (EOF or similar)
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
type CommandHandler = fn(&mut State, &str, &str, &str) -> Result<String, anyhow::Error>;

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
    fn process_command(
        &self,
        state: &mut State,
        command: &str,
        arg1: &str,
        arg2: &str,
        arg3: &str,
    ) -> Result<String, anyhow::Error> {
        if let Some(handler) = self.handlers.get(command) {
            handler(state, arg1, arg2, arg3)
        } else {
            Ok(format!("{command:?} not recognised."))
        }
    }
}

// commandHandler for opening the password store
fn handle_open(state: &mut State, arg1: &str, _: &str, _: &str) -> Result<String, anyhow::Error> {
    if arg1.is_empty() {
        return Ok("password required. Container is locked.".to_string());
    }

    if state.last_pass.is_empty() {
        state.last_pass = arg1.to_string();
    };

    let path = Cow::Borrowed(&state.store_path);

    match open_store(
        &mut state.current_container,
        path.to_string(),
        &state.last_pass,
    ) {
        Ok(_) => Ok("Password accepted, pass store opened.".to_string()),
        Err(error) => {
            state.last_pass.clear();
            Ok(format!("error opening store: {:?}", error))
        }
    }
}

// commandHandler for closing the password store
fn handle_close(
    state: &mut State,
    pass_in: &str,
    _: &str,
    _: &str,
) -> Result<String, anyhow::Error> {
    let password: String;
    if pass_in.is_empty() {
        println!("password empty, using last password");
        password = state.last_pass.clone();
    } else {
        println!("password not empty");
        password = String::from(pass_in);
    }
    match close_store(
        &mut state.current_container,
        state.store_path.clone(),
        password,
    ) {
        Ok(_) => Ok("store closed successfully.".to_string()),
        Err(error) => Ok(format!("error closing store: {:?}", error)),
    }
}

// commandHandler for retrieving elements from the password store
fn handle_get(state: &mut State, _: &str, arg2: &str, arg3: &str) -> Result<String, anyhow::Error> {
    if arg2 == "all" || arg2 == "*" {
        let entries = match get_all(state.current_container.clone(), state.last_pass.clone()) {
            Ok(entries) => entries,
            Err(_) => Vec::new(),
        };
        return Ok(format_structs_as_table(entries));
    }
    if arg2.is_empty() {
        return Ok("provide a target field".to_string());
    }

    if arg3.is_empty() {
        return Ok("provide a value to search by".to_string());
    }

    let entries = match get_entries_by_field(
        state.current_container.clone(),
        arg2.to_string(),
        arg3.to_string(),
        state.last_pass.clone(),
    ) {
        Ok(entries) => entries,
        Err(_) => Vec::new(),
    };

    Ok(format_structs_as_table(entries))
}
// Command handler for creating a password store
fn handle_new(
    state: &mut State,
    arg1: &str,
    arg2: &str,
    arg3: &str,
) -> Result<String, anyhow::Error> {
    if arg1.is_empty() {
        return Ok("new requires an argument (e.g store, container, entry)".to_string());
    }

    // Match on the first argument and call the respective sub-command handler
    match arg1 {
        "store" => handle_new_store(state, arg2),
        "child" => handle_new_child(state, arg2),
        "entry" => handle_new_entry(state, arg2, arg3),
        _ => Ok(format!("{arg1:?} not recognised.")),
    }
}

// Handler for the 'new store' sub-command
fn handle_new_store(state: &mut State, password: &str) -> Result<String, anyhow::Error> {
    if password.is_empty() {
        return Ok("creating a store requires a password as the 2nd arg".to_string());
    }

    let path = Cow::Borrowed(&state.store_path);
    state.current_container =
        create_store(state.current_container.clone(), path.to_string(), password)?;

    Ok(format!("Store created at: {}", path.to_string()))
}

// Handler for the 'new child' sub-command
fn handle_new_child(state: &mut State, container_path: &str) -> Result<String, anyhow::Error> {
    if container_path.is_empty() {
        return Ok("creating a child-container requires a . separated path as the 2nd arg (e.g. 'subcontainer.subsubcontainer')".to_string());
    }

    match create_child(&mut state.current_container, container_path) {
        Ok(_) => Ok(format!("{container_path:?} created.")),
        Err(e) => Ok(format!(
            "Error creating child-container {container_path:?}: {e:?}"
        )),
    }
}

// Handler for the 'new entry' sub-command
fn handle_new_entry(
    state: &mut State,
    entry_path: &str,
    entry_json: &str,
) -> Result<String, anyhow::Error> {
    if entry_path.is_empty() {
        return Ok("Creating an entry requires a . separated path as the 2nd arg (e.g. 'subcontainer.subsubcontainer.entry')".to_string());
    }
    if entry_json.is_empty() {
        return Ok("Creating an entry requires a JSON string as the 3rd arg.".to_string());
    }

    let input = entry_json.replace(r#"\""#, r#"""#);
    println!("Entry JSON received: {}", input);

    let mut entry = passman::Entry::new("", Vec::new(), "", "");
    entry.from_json_string(&input)?;

    let key_n_salt = cryptman::pass_2_key(&state.last_pass, [0u8; 32])?;
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let (key, salt) = key_n_salt;

    entry.encrypt_password(key, nonce, salt)?;

    match add_entry_to_container(&mut state.current_container, entry_path, entry) {
        Ok(_) => {
            let entries = get_all_entries(&state.current_container);
            let table = format_structs_as_table(entries);
            println!("{table:?}");

            return Ok(format!("{entry_path:?} created."));
        },
        Err(e) => {
            println!("it done fucked up: {e:?}");
            let err:anyhow::Error = e.into();
            return Err(err);
        }
    };
}

// function to take the input from the socket message, process the arguments, then create the
// response.
fn input_from_client(input: String, mut state: State) -> Result<String, anyhow::Error> {
    let mut args = input.split_whitespace();

    let _ = args.next(); // Skip the first argument (command name)

    let command = clean_arg(args.next().unwrap_or_default());
    let arg1 = clean_arg(args.next().unwrap_or_default());
    let arg2 = clean_arg(args.next().unwrap_or_default());
    let arg3 = clean_arg(args.next().unwrap_or_default());
    let processor = CommandProcessor::new();
    processor.process_command(&mut state, &command, &arg1, &arg2, &arg3)
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

    let end_patterns = ["\",", "\"]"];
    for end_pattern in &end_patterns {
        let pattern_len = end_pattern.len();
        let mut end_index = trimmed_str.len();
        while end_index >= pattern_len
            && &trimmed_str[end_index - pattern_len..end_index] == *end_pattern
        {
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
        "        ----------------------|-------|----------------|----------------------|------------------"
    )
    .unwrap();

    // Iterate over each struct and write their values
    for entry in entries {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            entry.username,
            entry.email,
            entry.url,
            entry.parent,
            String::from_utf8_lossy(entry.pass_vec.as_slice())
        );
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

fn create_child<'a>(
    current_store: &'a mut passman::Container,
    name: &str,
) -> Result<&'a mut passman::Container, anyhow::Error> {
    let parts: Vec<&str> = name.split('.').collect();

    // Helper function to recursively traverse and create containers
    fn add_to_container<'a>(
        container: &'a mut passman::Container,
        parts: &[&str],
    ) -> Result<&'a mut passman::Container, anyhow::Error> {
        if parts.is_empty() {
            return Ok(container);
        }

        let part = parts[0];

        // Check if the current part exists in children
        if !container.children.contains_key(part) {
            // If it doesn't exist, create a new child container
            container.add_child(passman::Container::new(part));
        }

        // Recursively move to the next part of the path
        let child_container = container.children.get_mut(part).ok_or_else(|| {
            anyhow::anyhow!("Failed to get or create child container for part: {}", part)
        })?;

        add_to_container(child_container, &parts[1..])
    }

    // Start the recursive creation process
    add_to_container(current_store, &parts)
}

fn add_entry_to_container<'a>(
    current_store: &'a mut passman::Container,
    path: &str,
    entry: passman::Entry,
) -> Result<&'a mut passman::Container, anyhow::Error> {
    // Split the path by '.' to get the container hierarchy
    let parts: Vec<&str> = path.split('.').collect();

    // The path should have at least one part (for the container)
    if parts.is_empty() {
        return Err(anyhow::anyhow!(
            "Invalid path: must contain at least one part"
        ));
    }

    // Helper function to recursively traverse and create containers
    fn add_to_container<'a>(
        container: &'a mut passman::Container,
        parts: &[&str],
    ) -> Result<&'a mut passman::Container, anyhow::Error> {
        if parts.is_empty() {
            return Ok(container);
        }

        let part = parts[0];

        // Check if the current part exists in children, otherwise create a new container
        if !container.children.contains_key(part) {
            container.add_child(passman::Container::new(part));
        }

        // Recursively move to the next part of the path
        let child_container = container.children.get_mut(part).ok_or_else(|| {
            anyhow::anyhow!("Failed to get or create child container for part: {}", part)
        })?;

        add_to_container(child_container, &parts[1..])
    }

    // Traverse the path to the last container
    let target_container = add_to_container(current_store, &parts)?;

    // Add the entry to the last container
    target_container.add_entry(entry);

    Ok(target_container)
}

// given a string path to the store, and a string of the password, open a passman
// store. returns the decrypted and instantiated container struct.
fn open_store(
    store: &mut passman::Container,
    store_path: String,
    pass: &str,
) -> Result<(), anyhow::Error> {
    println!("opening store");
    match passman::load_and_decrypt_container(store, pass, &store_path) {
        Ok(_) => {
            return Ok(());
        }
        Err(e) => {
            let err: anyhow::Error = e.into();
            return Err(err);
        }
    };
}

// given a passman container, a destination string, and a password with which to encrypt it,
// encrypt and write to file the container to file.
fn close_store(
    store: &mut passman::Container,
    dest: String,
    pass: String,
) -> Result<(), anyhow::Error> {
    println!("encrypting and saving store");
    match passman::encrypt_and_save_container(store, &pass, &dest) {
        Ok(_) => {
            return Ok(());
        }
        Err(e) => {
            let err: anyhow::Error = e.into();
            return Err(err);
        }
    };
}

fn get_all(
    store: passman::Container,
    password: String,
) -> Result<Vec<passman::Entry>, anyhow::Error> {
    let mut entries = passman::get_all_entries(&store);
    for entry in &mut entries {
        println!("username: {}", entry.username);
        entry.decrypt_password(&password)?;
        let password = String::from_utf8_lossy(entry.pass_vec.as_slice());
        println!("Username: {}\tpassword:{}", entry.username, password);
    }
    Ok(entries)
}

fn get_entries_by_field(
    store: passman::Container,
    target_field: String,
    target_value: String,
    password: String,
) -> Result<Vec<passman::Entry>, anyhow::Error> {
    let mut matching_entries = passman::get_entries_by_field(&store, &target_field, &target_value);
    for entry in &mut matching_entries {
        entry.decrypt_password(&password)?;
        let password = String::from_utf8_lossy(entry.pass_vec.as_slice());
        println!("Username: {}\tpassword:{}", entry.username, password);
    }
    Ok(matching_entries)
}

// tests, not properly written yet, but it does exercise passman & cryptman.
#[cfg(test)]
mod tests;
