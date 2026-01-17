use anyhow::Result;
use clap::Parser;
use htauth::{HashAlgorithm, Htpasswd};
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

/// A lightweight alternative to Apache's htpasswd tool.
#[derive(Parser)]
#[command(name = "htauth")]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Add a new user to the password file
    Add {
        /// Path to the password file
        file: PathBuf,
        /// Username to add
        username: String,
        /// Hash algorithm to use (bcrypt, sha256, sha512)
        #[arg(long, default_value = "bcrypt")]
        algorithm: String,
        /// Read password from stdin instead of prompting
        #[arg(long)]
        password: bool,
    },

    /// Update an existing user's password
    Update {
        /// Path to the password file
        file: PathBuf,
        /// Username to update
        username: String,
        /// Hash algorithm to use (bcrypt, sha256, sha512)
        #[arg(long, default_value = "bcrypt")]
        algorithm: String,
        /// Read password from stdin instead of prompting
        #[arg(long)]
        password: bool,
    },

    /// Verify a user's password
    Verify {
        /// Path to the password file
        file: PathBuf,
        /// Username to verify
        username: String,
        /// Read password from stdin instead of prompting
        #[arg(long)]
        password: bool,
    },

    /// List all users in the password file
    List {
        /// Path to the password file
        file: PathBuf,
    },

    /// Delete a user from the password file
    Delete {
        /// Path to the password file
        file: PathBuf,
        /// Username to delete
        username: String,
    },
}

fn read_password_from_stdin() -> Result<String> {
    let mut password = String::new();
    io::stdin().read_to_string(&mut password)?;
    Ok(password.trim_end().to_string())
}

fn prompt_password() -> Result<String> {
    Ok(rpassword::prompt_password("Enter password: ")?)
}

fn prompt_password_confirm() -> Result<String> {
    loop {
        let password = rpassword::prompt_password("New password: ")?;
        let confirm = rpassword::prompt_password("Re-type new password: ")?;

        if password == confirm {
            return Ok(password);
        }

        eprintln!("Password verification error:Passwords do not match");
        // Ask if they want to try again
        eprint!("Try again? [Y/n]: ");
        let mut response = String::new();
        io::stdin().read_line(&mut response)?;
        let response = response.trim().to_lowercase();

        if response == "n" || response == "no" {
            return Err(anyhow::anyhow!("Password confirmation failed"));
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Add {
            file,
            username,
            algorithm,
            password: from_stdin,
        } => {
            let password = if from_stdin {
                read_password_from_stdin()?
            } else {
                prompt_password_confirm()?
            };

            let algo: HashAlgorithm = algorithm.parse()?;
            let mut htpasswd = Htpasswd::open(&file)?;

            htpasswd.add_user(&username, &password, algo)?;
            htpasswd.save()?;

            println!("Adding password for user {}", username);
            Ok(ExitCode::SUCCESS)
        }

        Commands::Update {
            file,
            username,
            algorithm,
            password: from_stdin,
        } => {
            let password = if from_stdin {
                read_password_from_stdin()?
            } else {
                prompt_password_confirm()?
            };

            let algo: HashAlgorithm = algorithm.parse()?;
            let mut htpasswd = Htpasswd::open(&file)?;

            htpasswd.update_user(&username, &password, algo)?;
            htpasswd.save()?;

            println!("Updating password for user {}", username);
            Ok(ExitCode::SUCCESS)
        }

        Commands::Verify {
            file,
            username,
            password: from_stdin,
        } => {
            let password = if from_stdin {
                read_password_from_stdin()?
            } else {
                prompt_password()?
            };

            let htpasswd = Htpasswd::open(&file)?;

            match htpasswd.verify_user(&username, &password) {
                Ok(true) => {
                    println!("user {}: password correct", username);
                    Ok(ExitCode::SUCCESS)
                }
                Ok(false) => {
                    eprintln!("user {}: password incorrect", username);
                    Ok(ExitCode::FAILURE)
                }
                Err(e) => {
                    eprintln!("user {}: {}", username, e);
                    Ok(ExitCode::FAILURE)
                }
            }
        }

        Commands::List { file } => {
            let htpasswd = Htpasswd::open(&file)?;
            let users = htpasswd.list_users();

            for user in users {
                println!("{}", user);
            }

            Ok(ExitCode::SUCCESS)
        }

        Commands::Delete { file, username } => {
            let mut htpasswd = Htpasswd::open(&file)?;
            htpasswd.delete_user(&username)?;
            htpasswd.save()?;

            println!("Deleting user {}", username);
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}
