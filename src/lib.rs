//! A lightweight alternative to Apache's htpasswd tool.
//!
//! This library provides functionality to create, read, and modify htpasswd files
//! with support for bcrypt, SHA-256, SHA-512, and APR1-MD5 password hashing algorithms.
//!
//! # Example
//!
//! ```no_run
//! use htpasswd_rs::{Htpasswd, HashAlgorithm};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create or open an htpasswd file
//! let mut htpasswd = Htpasswd::open(".htpasswd")?;
//!
//! // Add a new user
//! htpasswd.add_user("alice", "password123", HashAlgorithm::Bcrypt)?;
//!
//! // Verify a user's password
//! if htpasswd.verify_user("alice", "password123")? {
//!     println!("Password correct!");
//! }
//!
//! // List all users
//! for user in htpasswd.list_users() {
//!     println!("{}", user);
//! }
//!
//! // Save changes
//! htpasswd.save()?;
//! # Ok(())
//! # }
//! ```

mod apr1_md5;
mod error;
mod hash;
mod htpasswd;

pub use error::{Error, Result};
pub use hash::{HashAlgorithm, detect_algorithm, hash_password, verify_password};
pub use htpasswd::Htpasswd;
