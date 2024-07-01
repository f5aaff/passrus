use cryptman::encrypt_file_mem_with_salt;
use log::warn;
use rand::{rngs::OsRng, RngCore};
use std::process::exit;
mod cryptman;
mod passman;
mod tui;

use std::{error::Error, io};

use ratatui::{
    backend::{Backend, CrosstermBackend},
    crossterm::{
        event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    },
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style, Stylize},
    terminal::{Frame, Terminal},
    text::{Line, Span, Text},
    widgets::{Block, List, ListItem, Paragraph},
};

enum InputMode {
    Normal,
    Editing,
}

/// App holds the state of the application
struct App {
    /// Current value of the input box
    input: String,
    /// Position of cursor in the editor area.
    character_index: usize,
    /// Current input mode
    input_mode: InputMode,
    /// History of recorded messages
    messages: Vec<String>,
}

impl App {
    const fn new() -> Self {
        Self {
            input: String::new(),
            input_mode: InputMode::Normal,
            messages: Vec::new(),
            character_index: 0,
        }
    }

    fn move_cursor_left(&mut self) {
        let cursor_moved_left = self.character_index.saturating_sub(1);
        self.character_index = self.clamp_cursor(cursor_moved_left);
    }

    fn move_cursor_right(&mut self) {
        let cursor_moved_right = self.character_index.saturating_add(1);
        self.character_index = self.clamp_cursor(cursor_moved_right);
    }

    fn enter_char(&mut self, new_char: char) {
        let index = self.byte_index();
        self.input.insert(index, new_char);
        self.move_cursor_right();
    }

    /// Returns the byte index based on the character position.
    ///
    /// Since each character in a string can be contain multiple bytes, it's necessary to calculate
    /// the byte index based on the index of the character.
    fn byte_index(&self) -> usize {
        self.input
            .char_indices()
            .map(|(i, _)| i)
            .nth(self.character_index)
            .unwrap_or(self.input.len())
    }

    fn delete_char(&mut self) {
        let is_not_cursor_leftmost = self.character_index != 0;
        if is_not_cursor_leftmost {
            // Method "remove" is not used on the saved text for deleting the selected char.
            // Reason: Using remove on String works on bytes instead of the chars.
            // Using remove would require special care because of char boundaries.

            let current_index = self.character_index;
            let from_left_to_current_index = current_index - 1;

            // Getting all characters before the selected character.
            let before_char_to_delete = self.input.chars().take(from_left_to_current_index);
            // Getting all characters after selected character.
            let after_char_to_delete = self.input.chars().skip(current_index);

            // Put all characters together except the selected one.
            // By leaving the selected one out, it is forgotten and therefore deleted.
            self.input = before_char_to_delete.chain(after_char_to_delete).collect();
            self.move_cursor_left();
        }
    }

    fn clamp_cursor(&self, new_cursor_pos: usize) -> usize {
        new_cursor_pos.clamp(0, self.input.chars().count())
    }

    fn reset_cursor(&mut self) {
        self.character_index = 0;
    }

    fn submit_message(&mut self) {
        let res = cryptman::pass_2_key(self.input.as_str(), [0u8;32]).unwrap();
        let enc_string = String::from_utf8_lossy(&res.0);
        self.messages.push(enc_string.into_owned());
        self.messages.push(self.input.clone());
        self.input.clear();
        self.reset_cursor();
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // create app and run it
    let app = App::new();
    let res = run_app(&mut terminal, app);

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{err:?}");
    }

    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, &app))?;

        if let Event::Key(key) = event::read()? {
            match app.input_mode {
                InputMode::Normal => match key.code {
                    KeyCode::Char('e') => {
                        app.input_mode = InputMode::Editing;
                    }
                    KeyCode::Char('q') => {
                        return Ok(());
                    }
                    _ => {}
                },
                InputMode::Editing if key.kind == KeyEventKind::Press => match key.code {
                    KeyCode::Enter => app.submit_message(),
                    KeyCode::Char(to_insert) => {
                        app.enter_char(to_insert);
                    }
                    KeyCode::Backspace => {
                        app.delete_char();
                    }
                    KeyCode::Left => {
                        app.move_cursor_left();
                    }
                    KeyCode::Right => {
                        app.move_cursor_right();
                    }
                    KeyCode::Esc => {
                        app.input_mode = InputMode::Normal;
                    }
                    _ => {}
                },
                InputMode::Editing => {}
            }
        }
    }
}

fn ui(f: &mut Frame, app: &App) {
    let vertical = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Min(1),
    ]);
    let [help_area, input_area, messages_area] = vertical.areas(f.size());

    let (msg, style) = match app.input_mode {
        InputMode::Normal => (
            vec![
                "Press ".into(),
                "q".bold(),
                " to exit, ".into(),
                "e".bold(),
                " to start editing.".bold(),
            ],
            Style::default().add_modifier(Modifier::RAPID_BLINK),
        ),
        InputMode::Editing => (
            vec![
                "Press ".into(),
                "Esc".bold(),
                " to stop editing, ".into(),
                "Enter".bold(),
                " to record the message".into(),
            ],
            Style::default(),
        ),
    };
    let text = Text::from(Line::from(msg)).patch_style(style);
    let help_message = Paragraph::new(text);
    f.render_widget(help_message, help_area);

    let input = Paragraph::new(app.input.as_str())
        .style(match app.input_mode {
            InputMode::Normal => Style::default(),
            InputMode::Editing => Style::default().fg(Color::Yellow),
        })
        .block(Block::bordered().title("Input"));
    f.render_widget(input, input_area);
    match app.input_mode {
        InputMode::Normal =>
            // Hide the cursor. `Frame` does this by default, so we don't need to do anything here
            {}

        InputMode::Editing => {
            // Make the cursor visible and ask ratatui to put it at the specified coordinates after
            // rendering
            #[allow(clippy::cast_possible_truncation)]
            f.set_cursor(
                // Draw the cursor at the current position in the input field.
                // This position is can be controlled via the left and right arrow key
                input_area.x + app.character_index as u16 + 1,
                // Move one line down, from the border to the input line
                input_area.y + 1,
            );
        }
    }

    let messages: Vec<ListItem> = app
        .messages
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let content = Line::from(Span::raw(format!("{i}: {m}")));
            ListItem::new(content)
        })
        .collect();
    let messages = List::new(messages).block(Block::bordered().title("Messages"));
    f.render_widget(messages, messages_area);
}



fn _test_passrus() {
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
    let enc_res =
        match cryptman::encrypt_file_mem_with_salt(json_arr.to_vec(), "", &key, &nonce, &salt) {
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
