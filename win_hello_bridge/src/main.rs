#![allow(bad_style)]

mod authenticator;
mod creator;

mod error;
pub(crate) use error::FailureReason;

const AUTHENTICATOR: &str = "authenticator";
const CREATOR: &str = "creator";
const MODES: [&str; 2] = [AUTHENTICATOR, CREATOR];

fn main() {
    use std::io::{Read, Write};

    let mut args = std::env::args();

    if args.len() < 2 || std::env::args().any(|arg| arg == "-h" || arg == "/?") {
        display_help();
        std::process::exit(1)
    }

    let mode = args.nth(1).unwrap();

    if !MODES.contains(&mode.as_str()) {
        display_help();
        std::process::exit(1);
    }

    let mut prompt_to_exit = false;
    let key_name = match args.next() {
        Some(name) => name,
        None => {
            prompt_to_exit = true;
            println!("Input the name of the key");
            print!("Name: ");
            std::io::stdout().flush().unwrap();
            let mut key_name = String::new();
            std::io::stdin().read_line(&mut key_name).unwrap();
            key_name
        }
    };
    let key_name = key_name.trim();

    let result = || -> Result<(), FailureReason> {
        match mode.as_str() {
            AUTHENTICATOR => {
                let data = {
                    let mut stdin = std::io::stdin();
                    let mut buffer = Vec::new();
                    stdin.read_to_end(&mut buffer).unwrap();
                    buffer
                };
                let signature = authenticator::verify_user(key_name, &data)?;
                let mut stdout = std::io::stdout();
                stdout.write_all(&signature).unwrap();
                Ok(())
            }
            CREATOR => {
                let pem_key = creator::create_public_key(key_name)?;
                let file_name = format!("./{}.pem", key_name);
                println!("file name: {}", file_name);
                std::fs::write(&file_name, &pem_key).unwrap();
                println!(
                    "Done. The public credential key is written in '{}'",
                    file_name
                );
                Ok(())
            }
            _ => {
                display_help();
                std::process::exit(1)
            }
        }
    };

    if let Err(e) = result() {
        println!("Error: {}", e);

        if prompt_to_exit {
            println!("Hit Enter key to terminate...");
            let mut buffer = String::new();
            std::io::stdin().read_line(&mut buffer).unwrap();
        }

        std::process::exit(e.to_code())
    }
}

fn display_help() {
    println!("usage: {}.exe <mode> key_name", env!("CARGO_BIN_NAME"));
    println!();

    println!("mode: ");
    print!("    authenticator: Authenticates the user with Windows Hello, ");
    println!("and outputs a signature of the input from stdin to stdout.");
    println!(
        "        The input will be signed by a private key that is associated with 'key_name'."
    );
    println!("        If key_name is not given, the prompt to ask the name will be shown.");

    println!();

    println!("    creator: Creates a KeyCredential with Windows Hello, and saves it to a file named 'key_name.pem'.");
    println!("        If key_name is not given, the prompt to ask the name will be shown.")
}
