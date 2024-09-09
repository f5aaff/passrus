use std::os::unix::net::UnixStream;
use std::io::{Write, Read};

fn main() -> std::io::Result<()> {
    let socket_path = "/tmp/rust_echo_service.sock";

    // Connect to the Unix socket where the service is listening
    let mut stream = UnixStream::connect(socket_path)?;

    // The message to send
    let message = b"Hello from the client!\n";

    // Send the message to the server
    stream.write_all(message)?;

    // Receive the echoed response
    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer)?;

    // Print the response from the server
    let echoed_message = String::from_utf8_lossy(&buffer[..n]);
    println!("Received echoed message: {}", echoed_message);

    Ok(())
}
