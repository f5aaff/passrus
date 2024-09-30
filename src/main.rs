use anyhow::Result;
use passman::{encrypt_and_save_container, load_and_decrypt_container, Container, Entry};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

mod cryptman;
mod passman;

#[derive(Debug, Serialize, Deserialize)]
enum Command {
    NewContainer {
        name: String,
        file_name: String,
        master_password: String,
    },
    CreateDbFile {
        file_name: String,
        master_password: String,
    },
    OpenDbFile {
        file_name: String,
        master_password: String,
    },
    AddEntry {
        container_name: String,
        username: String,
        email: String,
        url: String,
        password: String,
        master_password: String,
        file_path: String,
    },
    Decrypt {
        file_path: String,
        master_password: String,
    },
    GetEntries {
        container_name: String,
        master_password: String,
    },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum Message {
    Text(String),
    Anonymous(Value),
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    success: bool,
    message: Message,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Define the path to the Unix socket
    let socket_path = "/tmp/passman.sock";

    // Remove the socket file if it already exists
    if Path::new(socket_path).exists() {
        fs::remove_file(socket_path)?;
    }

    // Create a Unix socket listener
    let listener = UnixListener::bind(socket_path)?;

    // Create a thread-safe in-memory database of containers (Arc + Mutex for shared state)
    let container_db = Arc::new(Mutex::new(passman::Container {
        name: "".to_string(),
        children: HashMap::new(),
        entries: HashMap::new(),
        parent: "".to_string(),
    }));
    // Create a thread-safe in-memory database for decrypted containers
    let decrypted_container_db = Arc::new(Mutex::new(passman::Container {
        name: "".to_string(),
        children: HashMap::new(),
        entries: HashMap::new(),
        parent: "".to_string(),
    }));

    println!("Passman service running...");

    loop {
        // Accept incoming connections
        let (socket, _) = listener.accept().await?;

        // Clone the database references for each connection
        let db_clone = Arc::clone(&container_db);
        let decrypted_db_clone = Arc::clone(&decrypted_container_db);

        // Spawn a new task to handle the connection
        tokio::spawn(async move {
            if let Err(err) = handle_client(socket, db_clone, decrypted_db_clone).await {
                eprintln!("Error handling client: {}", err);
            }
        });
    }
}

/// Handles the client connection and processes commands
async fn handle_client(
    mut socket: UnixStream,
    container_db: Arc<Mutex<Container>>,
    decrypted_container_db: Arc<Mutex<Container>>,
) -> Result<()> {
    let (reader, mut writer) = socket.split();
    let mut buf_reader = BufReader::new(reader);
    let mut input = String::new();

    // Read command from client
    buf_reader.read_line(&mut input).await?;

    // Parse the incoming command
    let command: Command = serde_json::from_str(&input.trim())?;

    // Process the command and send a response
    let response = match command {
        Command::NewContainer {
            name,
            file_name,
            master_password,
        } => create_new_container(name, &container_db, file_name, master_password).await,
        Command::CreateDbFile {
            file_name,
            master_password,
        } => create_db_file(file_name, master_password, &container_db).await,
        Command::OpenDbFile {
            file_name,
            master_password,
        } => open_db_file(file_name, master_password, &container_db).await,
        Command::AddEntry {
            container_name,
            username,
            email,
            url,
            password,
            master_password,
            file_path,
        } => {
            add_entry_to_container(
                container_name,
                username,
                email,
                url,
                password,
                master_password,
                &container_db,
                file_path,
            )
            .await
        }
        Command::Decrypt {
            file_path,
            master_password,
        } => decrypt_container(file_path, master_password, &decrypted_container_db).await,
        Command::GetEntries {
            container_name,
            master_password,
        } => get_entries(container_name, master_password, &container_db).await,
    };

    // Send the response back to the client
    let response_json = serde_json::to_string(&response)?;
    writer.write_all(response_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;

    Ok(())
}

/// Create a new container and add it to the in-memory database
async fn create_new_container(
    name: String,
    container_db: &Arc<Mutex<Container>>,
    file_name: String,
    master_password: String,
) -> Response {
    // lock the thread, clone the child containers out
    let mut db = container_db.lock().unwrap();
    let mut new_children = db.children.clone();

    // match on some/none for getting the name from the child containers
    match new_children.get_mut(&name) {
        Some(_) => {
            return Response {
                success: false,
                message: Message::Text(format!("container already exists: {}", &name)),
            }
        }
        // if it doesn't exist yet, insert a new container into the child container hash map
        None => {
            new_children.insert(name.clone(), passman::Container::new(&name, Some(&db.name)));
        }
    };
    // reassign the original container children to the new hash map
    db.children = new_children;

    // clone out the db, so it can be encrypted and written to file.
    let to_file = db.clone();
    if let Err(e) = encrypt_and_save_container(to_file, &master_password, &file_name) {
        return Response {
            success: false,
            message: Message::Text(format!(
                "failed to save container {} due to error: {:#?} ",
                name, e
            )),
        };
    }
    return Response {
        success: true,
        message: Message::Text(format!("New container created: {}", name)),
    };
}

/// Create a new database file and initialize an in-memory container
async fn create_db_file(
    file_name: String,
    password: String,
    container_db: &Arc<Mutex<Container>>,
) -> Response {
    let new_container = Container::new(&file_name, None);
    let mut db = container_db.lock().unwrap();
    db.add_child(new_container.clone());

    // Save the initial empty container to the new file (as encrypted)
    if let Err(e) = encrypt_and_save_container(db.clone(), &password, &file_name) {
        return Response {
            success: false,
            message: Message::Text(format!("Failed to create database file: {}", e)),
        };
    }

    Response {
        success: true,
        message: Message::Text(format!("New database file created: {}", file_name)),
    }
}

async fn open_db_file(
    file_name: String,
    master_password: String,
    container_db: &Arc<Mutex<Container>>,
) -> Response {
    let new_container = Container::new(&file_name, None);
    let mut db = container_db.lock().unwrap();
    match load_and_decrypt_container(new_container, &master_password, &file_name) {
        Ok(container) => {
            *db = container;
            Response {
                success: true,
                message: Message::Text(format!(":db {} loaded successfully.", &file_name)),
            }
        }
        Err(e) => Response {
            success: false,
            message: Message::Text(format!("failed to load and decrypt database: {}", e)),
        },
    }
}

/// Add a new entry to a container
async fn add_entry_to_container(
    container_name: String,
    username: String,
    email: String,
    url: String,
    password: String,
    master_password: String,
    container_db: &Arc<Mutex<Container>>,
    file_path: String,
) -> Response {
    // lock mutex for db
    let mut db = container_db.lock().unwrap();

    // empty entry
    let new_entry = Entry::new(&username, password.as_bytes().to_vec(), &email, &url);

    // clone children out of container, to have as hash map proper, not mutex guard.
    let mut new_children = db.children.clone();
    // check if container name present in container children
    match new_children.get_mut(&container_name) {
        Some(container) => container.add_entry(new_entry),
        None => {
            return Response {
                success: false,
                message: Message::Text(format!("container not found: {}", container_name)),
            }
        }
    };
    // reassign db children to new_children
    db.children = new_children;

    // store to file
    let to_file = db.clone();
    if let Err(e) = encrypt_and_save_container(to_file, &master_password, &file_path) {
        return Response {
            success: false,
            message: Message::Text(format!("failed to encrypt and save db: {:?}", e)),
        };
    }

    return Response {
        success: true,
        message: Message::Text("Entry added successfully.".to_string()),
    };
}

/// Decrypt a container from a file and store it in memory
async fn decrypt_container(
    file_path: String,
    password: String,
    decrypted_container_db: &Arc<Mutex<Container>>,
) -> Response {
    let container = Container::new("decrypted_container", None);
    match passman::load_and_decrypt_container(container, &password, &file_path) {
        Ok(decrypted_container) => {
            // Store decrypted container in memory
            let mut db = decrypted_container_db.lock().unwrap();
            *db = decrypted_container.clone(); // Save the decrypted container in the shared state

            Response {
                success: true,
                message: Message::Text("Container decrypted and stored in memory.".to_string()),
            }
        }
        Err(e) => Response {
            success: false,
            message: Message::Text(format!("Failed to decrypt container: {}", e)),
        },
    }
}

fn decrypt_entry_vec(entries: Vec<passman::Entry>, master_password: String) -> Response {
    // template for a decrypted entry
    #[derive(Debug, Serialize, Deserialize)]
    struct DecryptedEntry {
        username: String,
        email: String,
        url: String,
        password: String,
    }
    // empty vec of decrypted entries
    let mut decrypted_entries: Vec<DecryptedEntry> = Vec::new();

    // clone the entries for ease of access/mutability
    let entry_clone = entries.clone();
    for mut entry in entry_clone {
        // create a decrypted entry from the current entry's vals
        let mut decrypted_entry = DecryptedEntry {
            username: entry.username.clone(),
            email: entry.email.clone(),
            url: entry.url.clone(),
            password: String::from(""),
        };

        println!("passvec:{}", String::from_utf8_lossy(&entry.pass_vec));
        // if the pass decrypts, convert to string
        match entry.decrypt_password(&master_password) {
            Ok(_) => {
                println!("passvec:{}", String::from_utf8_lossy(&entry.pass_vec));
                //decrypted_entry.password = format!("{}",String::from_utf8_lossy(&entry.pass_vec));
            }
            // fill with generic error message
            Err(_) => {
                decrypted_entry.password = format!("{}",String::from_utf8_lossy(&entry.pass_vec));
            }
        }
        decrypted_entries.push(decrypted_entry);
    }

    match serde_json::to_value(&decrypted_entries) {
        Ok(msg) => Response {
            success: true,
            message: Message::Anonymous(msg),
        },
        Err(e) => Response {
            success: false,
            message: Message::Text(format!("error formatting entries: {}", e)),
        },
    }
}

/// Get all entries from a container
async fn get_entries(
    container_name: String,
    master_password: String,
    container_db: &Arc<Mutex<Container>>,
) -> Response {
    let db = container_db.lock().unwrap();
    let opt_name: Option<&str> = Some(&container_name);
    // if the container_name is * or empty, get all entries in the whole db
    match opt_name {
        Some("*") | None => {
            let entries = passman::get_all_entries(&db.clone());
            return decrypt_entry_vec(entries, master_password);
        }
        Some(_) => {
            let mut new_children = db.children.clone();
            match new_children.get_mut(&container_name) {
                Some(container) => {
                    let entries = passman::get_all_entries(container);
                    return decrypt_entry_vec(entries, master_password);
                }
                None => {
                    return Response {
                        success: false,
                        message: Message::Text(format!("container {} not found", container_name)),
                    }
                }
            }
        }
    }
}
