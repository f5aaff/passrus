use anyhow::Result;
use passman::{Container, Entry};
use serde::{Deserialize, Serialize};
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
        master_password: String
    },
    CreateDbFile {
        file_name: String,
        master_password: String
    },
    AddEntry {
        container_name: String,
        username: String,
        email: String,
        url: String,
        password: String,
        master_password: String
    },
    Encrypt {
        container_name: String,
        master_password: String
    },
    Decrypt {
        file_path: String,
        master_password: String,
    },
    GetEntries {
        container_name: String,
        master_password: String
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    success: bool,
    message: String,
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
    let container_db = Arc::new(Mutex::new(vec![]));
    // Create a thread-safe in-memory database for decrypted containers
    let decrypted_container_db = Arc::new(Mutex::new(vec![]));

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
    container_db: Arc<Mutex<Vec<Container>>>,
    decrypted_container_db: Arc<Mutex<Vec<Container>>>,
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
        Command::NewContainer { name, master_password } => create_new_container(name, &container_db).await,
        Command::CreateDbFile { file_name, master_password } => create_db_file(file_name,master_password, &container_db).await,
        Command::AddEntry {
            container_name,
            username,
            email,
            url,
            password,
            master_password

        } => add_entry_to_container(container_name, username, email, url, password,master_password, &container_db).await,
        Command::Encrypt { container_name, master_password } => encrypt_container(container_name, master_password, &container_db).await,
        Command::Decrypt { file_path, master_password } => decrypt_container(file_path, master_password, &decrypted_container_db).await,
        Command::GetEntries { container_name, master_password } => get_entries(container_name, &container_db).await,
    };

    // Send the response back to the client
    let response_json = serde_json::to_string(&response)?;
    writer.write_all(response_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;

    Ok(())
}

/// Create a new container and add it to the in-memory database
async fn create_new_container(name: String, container_db: &Arc<Mutex<Vec<Container>>>) -> Response {
    let new_container = Container::new(&name, None);
    let mut db = container_db.lock().unwrap();
    db.push(new_container);

    Response {
        success: true,
        message: format!("New container created: {}", name),
    }
}

/// Create a new database file and initialize an in-memory container
async fn create_db_file(file_name: String, password:String, container_db: &Arc<Mutex<Vec<Container>>>) -> Response {
    let new_container = Container::new(&file_name, None);
    let mut db = container_db.lock().unwrap();
    db.push(new_container.clone());

    // Save the initial empty container to the new file (as encrypted)
    if let Err(e) = passman::encrypt_and_save_container(new_container.clone(), &password, &file_name) {
        return Response {
            success: false,
            message: format!("Failed to create database file: {}", e),
        };
    }

    Response {
        success: true,
        message: format!("New database file created: {}", file_name),
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
    container_db: &Arc<Mutex<Vec<Container>>>,
) -> Response {
    let mut db = container_db.lock().unwrap();
    if let Some(container) = db.iter_mut().find(|c| c.name == container_name) {
        let new_entry = Entry::new(&username, password.as_bytes().to_vec(), &email, &url);
        container.add_entry(new_entry);
        return Response {
            success: true,
            message: "Entry added successfully.".to_string(),
        };
    }

    Response {
        success: false,
        message: format!("Container not found: {}", container_name),
    }
}

/// Encrypt a container and save it
async fn encrypt_container(container_name: String, password: String, container_db: &Arc<Mutex<Vec<Container>>>) -> Response {
    let db = container_db.lock().unwrap();
    if let Some(container) = db.iter().find(|c| c.name == container_name) {
        match passman::encrypt_and_save_container(container.clone(), &password, &container_name) {
            Ok(_) => Response {
                success: true,
                message: "Container encrypted successfully.".to_string(),
            },
            Err(e) => Response {
                success: false,
                message: format!("Failed to encrypt container: {}", e),
            },
        }
    } else {
        Response {
            success: false,
            message: format!("Container not found: {}", container_name),
        }
    }
}

/// Decrypt a container from a file and store it in memory
async fn decrypt_container(file_path: String, password: String, decrypted_container_db: &Arc<Mutex<Vec<Container>>>) -> Response {
    let container = Container::new("decrypted_container", None);
    match passman::load_and_decrypt_container(container, &password, &file_path) {
        Ok(decrypted_container) => {
            // Store decrypted container in memory
            let mut db = decrypted_container_db.lock().unwrap();
            db.push(decrypted_container); // Save the decrypted container in the shared state

            Response {
                success: true,
                message: "Container decrypted and stored in memory.".to_string(),
            }
        }
        Err(e) => Response {
            success: false,
            message: format!("Failed to decrypt container: {}", e),
        },
    }
}

/// Get all entries from a container
async fn get_entries(container_name: String, container_db: &Arc<Mutex<Vec<Container>>>) -> Response {
    let db = container_db.lock().unwrap();
    if let Some(container) = db.iter().find(|c| c.name == container_name) {
        let entries = passman::get_all_entries(container);
        Response {
            success: true,
            message: format!("Entries: {:#?}", entries),
        }
    } else {
        Response {
            success: false,
            message: format!("Container not found: {}", container_name),
        }
    }
}
