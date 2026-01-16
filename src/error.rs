use std::io;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("User '{0}' not found")]
    UserNotFound(String),

    #[error("User '{0}' already exists")]
    UserAlreadyExists(String),

    #[error("Invalid hash format: {0}")]
    InvalidHashFormat(String),

    #[error("Invalid username: '{0}'")]
    InvalidUsername(String),

    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("Bcrypt error: {0}")]
    BcryptError(#[from] bcrypt::BcryptError),

    #[error("Unknown hash algorithm: {0}")]
    UnknownAlgorithm(String),
}
