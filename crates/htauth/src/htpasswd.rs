use crate::hash::HashAlgorithm;
use crate::hash::{hash_password, verify_password};
use snafu::{OptionExt, ResultExt, Snafu};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Errors that can occur during htpasswd file operations.
#[derive(Debug, Snafu)]
pub enum Error {
    /// User was not found in the htpasswd file.
    #[snafu(display("User '{username}' not found"))]
    UserNotFound { username: String },

    /// User already exists in the htpasswd file.
    #[snafu(display("User '{username}' already exists"))]
    UserAlreadyExists { username: String },

    /// Username cannot be empty.
    #[snafu(display("Username cannot be empty"))]
    UsernameEmpty,

    /// Username contains invalid character.
    #[snafu(display("Username '{}' contains invalid character ':'", username))]
    UsernameInvalidCharacter { username: String },

    /// Failed to open htpasswd file.
    #[snafu(display("Failed to open htpasswd file '{}'", path.display()))]
    FileOpen {
        source: std::io::Error,
        path: PathBuf,
    },

    /// Failed to read from htpasswd file.
    #[snafu(display("Failed to read htpasswd file '{}'", path.display()))]
    FileRead {
        source: std::io::Error,
        path: PathBuf,
    },

    /// Failed to save htpasswd file.
    #[snafu(display("Failed to save htpasswd file '{}'", path.display()))]
    FileSave {
        source: std::io::Error,
        path: PathBuf,
    },

    /// Failed to create parent directory.
    #[snafu(display("Failed to create parent directory '{}'", path.display()))]
    CreateDir {
        source: std::io::Error,
        path: PathBuf,
    },

    /// Failed to hash password.
    #[snafu(display("Failed to hash password"))]
    Hash { source: crate::hash::Error },

    /// Failed to verify password.
    #[snafu(display("Failed to verify password"))]
    Verify { source: crate::hash::Error },
}

/// Represents an htpasswd file with user credentials.
pub struct Htpasswd {
    entries: HashMap<String, String>,
    comments: Vec<String>,
    path: PathBuf,
    file_existed: bool,
}

impl Htpasswd {
    /// Open an htpasswd file, creating it if it doesn't exist.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        let file_existed = path.exists();

        let mut entries = HashMap::new();
        let mut comments = Vec::new();

        if file_existed {
            let file = File::open(path).context(FileOpenSnafu {
                path: path.to_path_buf(),
            })?;
            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line = line.context(FileReadSnafu {
                    path: path.to_path_buf(),
                })?;
                let trimmed = line.trim();

                // Skip empty lines
                if trimmed.is_empty() {
                    continue;
                }

                // Store comment lines
                if trimmed.starts_with('#') {
                    comments.push(trimmed.to_string());
                    continue;
                }

                // Parse username:hash entries
                if let Some((username, hash)) = trimmed.split_once(':') {
                    snafu::ensure!(!username.is_empty(), UsernameEmptySnafu);
                    snafu::ensure!(
                        !username.contains(':'),
                        UsernameInvalidCharacterSnafu { username }
                    );
                    entries.insert(username.to_string(), hash.to_string());
                }
            }
        }

        Ok(Self {
            entries,
            comments,
            path: path.to_path_buf(),
            file_existed,
        })
    }

    /// Save the htpasswd file.
    pub fn save(&self) -> Result<(), Error> {
        // Create parent directories if needed
        if let Some(parent) = self.path.parent()
            && !parent.exists()
        {
            fs::create_dir_all(parent).context(CreateDirSnafu {
                path: parent.to_path_buf(),
            })?;
        }

        // Store reference to avoid repeated clones
        let path = self.path.as_path();

        // Set restrictive permissions when creating new file
        #[cfg(unix)]
        let mut file = if self.file_existed {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&self.path)
                .context(FileSaveSnafu { path })?
        } else {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&self.path)
                .context(FileSaveSnafu { path })?
        };

        #[cfg(not(unix))]
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .context(FileSaveSnafu { path })?;

        // Write comments first
        for comment in &self.comments {
            writeln!(file, "{}", comment).context(FileSaveSnafu { path })?;
        }

        // Write entries
        for (username, hash) in &self.entries {
            writeln!(file, "{}:{}", username, hash).context(FileSaveSnafu { path })?;
        }

        file.flush().context(FileSaveSnafu { path })?;
        Ok(())
    }

    /// Reload the htpasswd file from disk.
    pub fn reload(&mut self) -> Result<(), Error> {
        *self = Self::open(&self.path)?;
        Ok(())
    }

    /// Add a new user with the given password and hash algorithm.
    pub fn add_user(
        &mut self,
        username: &str,
        password: &str,
        algorithm: HashAlgorithm,
    ) -> Result<(), Error> {
        match self.entries.entry(username.to_string()) {
            Entry::Occupied(_) => UserAlreadyExistsSnafu { username }.fail(),
            Entry::Vacant(entry) => {
                let hash = hash_password(password, algorithm).context(HashSnafu)?;
                entry.insert(hash);
                Ok(())
            }
        }
    }

    /// Update an existing user's password with the specified algorithm.
    pub fn update_user(
        &mut self,
        username: &str,
        password: &str,
        algorithm: HashAlgorithm,
    ) -> Result<(), Error> {
        let entry = self
            .entries
            .get_mut(username)
            .context(UserNotFoundSnafu { username })?;
        *entry = hash_password(password, algorithm).context(HashSnafu)?;
        Ok(())
    }

    /// Delete a user from the htpasswd file.
    pub fn delete_user(&mut self, username: &str) -> Result<(), Error> {
        self.entries
            .remove(username)
            .context(UserNotFoundSnafu { username })?;
        Ok(())
    }

    /// Verify a user's password.
    pub fn verify_user(&self, username: &str, password: &str) -> Result<bool, Error> {
        let hash = self
            .entries
            .get(username)
            .context(UserNotFoundSnafu { username })?;

        verify_password(password, hash).context(VerifySnafu)
    }

    /// List all usernames in the htpasswd file.
    pub fn list_users(&self) -> Vec<String> {
        let mut users: Vec<String> = self.entries.keys().cloned().collect();
        users.sort();
        users
    }

    /// Check if a user exists in the htpasswd file.
    pub fn user_exists(&self, username: &str) -> bool {
        self.entries.contains_key(username)
    }

    /// Get the number of users in the htpasswd file.
    pub fn user_count(&self) -> usize {
        self.entries.len()
    }

    /// Get the file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_create_and_save() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.htpasswd");

        let mut htpasswd = Htpasswd::open(&file_path).unwrap();
        htpasswd
            .add_user("alice", "password123", HashAlgorithm::Bcrypt)
            .unwrap();
        htpasswd
            .add_user("bob", "password456", HashAlgorithm::Sha256)
            .unwrap();
        htpasswd.save().unwrap();

        // Verify file exists and has correct content
        assert!(file_path.exists());
        let content = fs::read_to_string(&file_path).unwrap();
        assert!(content.contains("alice:"));
        assert!(content.contains("bob:"));
        // SHA-256 hashes now use SHA-crypt format: $5$rounds=5000$salt$hash
        assert!(content.contains("$5$"));
    }

    #[test]
    fn test_add_duplicate_user() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.htpasswd");

        let mut htpasswd = Htpasswd::open(&file_path).unwrap();
        htpasswd
            .add_user("alice", "password123", HashAlgorithm::Bcrypt)
            .unwrap();
        let result = htpasswd.add_user("alice", "password456", HashAlgorithm::Bcrypt);
        assert!(matches!(result, Err(Error::UserAlreadyExists { .. })));
    }

    #[test]
    fn test_verify_user() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.htpasswd");

        let mut htpasswd = Htpasswd::open(&file_path).unwrap();
        htpasswd
            .add_user("alice", "password123", HashAlgorithm::Bcrypt)
            .unwrap();
        htpasswd.save().unwrap();

        // Reload and verify
        let htpasswd = Htpasswd::open(&file_path).unwrap();
        assert!(htpasswd.verify_user("alice", "password123").unwrap());
        assert!(!htpasswd.verify_user("alice", "wrongpassword").unwrap());
        assert!(htpasswd.verify_user("nonexistent", "password").is_err());
    }

    #[test]
    fn test_delete_user() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.htpasswd");

        let mut htpasswd = Htpasswd::open(&file_path).unwrap();
        htpasswd
            .add_user("alice", "password123", HashAlgorithm::Bcrypt)
            .unwrap();
        htpasswd.delete_user("alice").unwrap();
        htpasswd.save().unwrap();

        let htpasswd = Htpasswd::open(&file_path).unwrap();
        assert!(!htpasswd.user_exists("alice"));
    }

    #[test]
    fn test_delete_nonexistent_user() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.htpasswd");

        let mut htpasswd = Htpasswd::open(&file_path).unwrap();
        let result = htpasswd.delete_user("nonexistent");
        assert!(matches!(result, Err(Error::UserNotFound { .. })));
    }

    #[test]
    fn test_update_user() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.htpasswd");

        let mut htpasswd = Htpasswd::open(&file_path).unwrap();
        htpasswd
            .add_user("alice", "password123", HashAlgorithm::Bcrypt)
            .unwrap();
        htpasswd
            .update_user("alice", "newpassword", HashAlgorithm::Sha512)
            .unwrap();
        htpasswd.save().unwrap();

        let htpasswd = Htpasswd::open(&file_path).unwrap();
        assert!(!htpasswd.verify_user("alice", "password123").unwrap());
        assert!(htpasswd.verify_user("alice", "newpassword").unwrap());
    }

    #[test]
    fn test_list_users() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.htpasswd");

        let mut htpasswd = Htpasswd::open(&file_path).unwrap();
        htpasswd
            .add_user("charlie", "password123", HashAlgorithm::Bcrypt)
            .unwrap();
        htpasswd
            .add_user("alice", "password456", HashAlgorithm::Bcrypt)
            .unwrap();
        htpasswd
            .add_user("bob", "password789", HashAlgorithm::Bcrypt)
            .unwrap();

        let users = htpasswd.list_users();
        assert_eq!(users, vec!["alice", "bob", "charlie"]);
    }

    #[test]
    fn test_user_exists() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.htpasswd");

        let mut htpasswd = Htpasswd::open(&file_path).unwrap();
        assert!(!htpasswd.user_exists("alice"));

        htpasswd
            .add_user("alice", "password123", HashAlgorithm::Bcrypt)
            .unwrap();
        assert!(htpasswd.user_exists("alice"));
        assert!(!htpasswd.user_exists("bob"));
    }

    #[test]
    fn test_comment_preservation() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.htpasswd");

        // Create file with comments
        {
            let mut file = File::create(&file_path).unwrap();
            writeln!(file, "# This is a comment").unwrap();
            writeln!(file, "# Another comment").unwrap();
            writeln!(file, "alice:$2b$12$testhash").unwrap();
        }

        let mut htpasswd = Htpasswd::open(&file_path).unwrap();
        assert_eq!(htpasswd.comments.len(), 2);

        htpasswd
            .add_user("bob", "password456", HashAlgorithm::Bcrypt)
            .unwrap();
        htpasswd.save().unwrap();

        // Verify comments are preserved
        let content = fs::read_to_string(&file_path).unwrap();
        assert!(content.contains("# This is a comment"));
        assert!(content.contains("# Another comment"));
    }
}
