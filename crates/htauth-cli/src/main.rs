// use anyhow::Result;
use clap::Parser;
use htauth::{HashAlgorithm, Htpasswd};
use snafu::ResultExt;
use std::io::{self, Read};
use std::path::PathBuf;
use zeroize::Zeroizing;

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

type Result<T> = ::std::result::Result<T, snafu::Whatever>;

fn read_password_from_stdin() -> Result<Zeroizing<String>> {
    let mut password = String::new();
    io::stdin()
        .read_to_string(&mut password)
        .whatever_context("Can't read password from stdin")?;
    Ok(Zeroizing::new(password.trim_end().to_string()))
}

fn prompt_password() -> Result<Zeroizing<String>> {
    rpassword::prompt_password("Enter password: ")
        .whatever_context("Can't prompt for password")
        .map(Zeroizing::new)
}

fn prompt_password_confirm() -> Result<Zeroizing<String>> {
    loop {
        let password = Zeroizing::new(
            rpassword::prompt_password("New password: ")
                .whatever_context("Can't prompt for new password")?,
        );
        let confirm = Zeroizing::new(
            rpassword::prompt_password("Re-type new password: ")
                .whatever_context("Can't prompt for password re-type")?,
        );

        if *password == *confirm {
            return Ok(password);
        }

        eprintln!("Password verification error:Passwords do not match");
        // Ask if they want to try again
        eprint!("Try again? [Y/n]: ");
        let mut response = String::new();
        io::stdin()
            .read_line(&mut response)
            .whatever_context("Can't read line")?;
        let response = response.trim().to_lowercase();

        snafu::ensure_whatever!(
            response == "n" || response == "no",
            "Password confirmation failed"
        );
    }
}

fn run() -> Result<()> {
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

            let algo: HashAlgorithm = algorithm
                .parse()
                .whatever_context("Can't parse algorithm name")?;
            let mut htpasswd =
                Htpasswd::open(&file).whatever_context("Can't open password file")?;

            htpasswd
                .add_user(&username, &password, algo)
                .whatever_context("Can't add user")?;
            htpasswd
                .save()
                .whatever_context("Can't save password file")?;

            println!("Adding password for user {}", username);
            Ok(())
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

            let algo: HashAlgorithm = algorithm
                .parse()
                .whatever_context("Can't parse algorithm name")?;
            let mut htpasswd =
                Htpasswd::open(&file).whatever_context("Can't open password file")?;

            htpasswd
                .update_user(&username, &password, algo)
                .whatever_context("Can't update user")?;
            htpasswd
                .save()
                .whatever_context("Can't save password file")?;

            println!("Updating password for user {}", username);
            Ok(())
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

            let htpasswd = Htpasswd::open(&file).whatever_context("Can't open password file")?;

            match htpasswd.verify_user(&username, &password) {
                Ok(true) => {
                    println!("user {}: password correct", username);
                    Ok(())
                }
                Ok(false) => {
                    snafu::whatever!("user {}: password incorrect", username)
                }
                Err(e) => {
                    snafu::whatever!("user {}: {}", username, e)
                }
            }
        }

        Commands::List { file } => {
            let htpasswd = Htpasswd::open(&file).whatever_context("Can't open password file")?;
            let users = htpasswd.list_users();

            for user in users {
                println!("{}", user);
            }

            Ok(())
        }

        Commands::Delete { file, username } => {
            let mut htpasswd =
                Htpasswd::open(&file).whatever_context("Can't open password file")?;
            htpasswd
                .delete_user(&username)
                .whatever_context("Can't delete user")?;
            htpasswd
                .save()
                .whatever_context("Can't save password file")?;

            println!("Deleting user {}", username);
            Ok(())
        }
    }
}

#[snafu::report]
fn main() -> Result<()> {
    run()
}
