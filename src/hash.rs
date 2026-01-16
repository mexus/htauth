use crate::error::{Error, Result};
use bcrypt::{hash, verify};
use sha2::{Digest, Sha256, Sha512};
use std::str::FromStr;
use base64::Engine;

const BCRYPT_COST: u32 = 12;
const BCRYPT_PREFIX: &str = "$2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Bcrypt,
    Sha256,
    Sha512,
}

impl FromStr for HashAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "bcrypt" => Ok(HashAlgorithm::Bcrypt),
            "sha256" => Ok(HashAlgorithm::Sha256),
            "sha512" => Ok(HashAlgorithm::Sha512),
            _ => Err(Error::UnknownAlgorithm(s.to_string())),
        }
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgorithm::Bcrypt => write!(f, "bcrypt"),
            HashAlgorithm::Sha256 => write!(f, "sha256"),
            HashAlgorithm::Sha512 => write!(f, "sha512"),
        }
    }
}

/// Hash a password using the specified algorithm.
pub fn hash_password(password: &str, algorithm: HashAlgorithm) -> Result<String> {
    match algorithm {
        HashAlgorithm::Bcrypt => {
            // bcrypt produces its own prefix like $2b$12$...
            Ok(hash(password, BCRYPT_COST)?)
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            let hash = hasher.finalize();
            Ok(format!(
                "{{SHA256}}{}",
                base64::engine::general_purpose::STANDARD.encode(hash)
            ))
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(password.as_bytes());
            let hash = hasher.finalize();
            Ok(format!(
                "{{SHA512}}{}",
                base64::engine::general_purpose::STANDARD.encode(hash)
            ))
        }
    }
}

/// Verify a password against a hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let algorithm = detect_algorithm(hash).ok_or_else(|| {
        Error::InvalidHashFormat("Cannot determine hash algorithm".to_string())
    })?;

    match algorithm {
        HashAlgorithm::Bcrypt => {
            // All bcrypt variants ($2a$, $2b$, $2y$) are compatible for verification
            verify(password, hash).map_err(Error::from)
        }
        HashAlgorithm::Sha256 => {
            if let Some(encoded) = hash.strip_prefix("{SHA256}") {
                let mut hasher = Sha256::new();
                hasher.update(password.as_bytes());
                let computed = hasher.finalize();
                let expected =
                    base64::engine::general_purpose::STANDARD.decode(encoded.trim())?;
                Ok(computed.as_slice() == expected.as_slice())
            } else {
                Err(Error::InvalidHashFormat(
                    "Invalid SHA256 hash format".to_string(),
                ))
            }
        }
        HashAlgorithm::Sha512 => {
            if let Some(encoded) = hash.strip_prefix("{SHA512}") {
                let mut hasher = Sha512::new();
                hasher.update(password.as_bytes());
                let computed = hasher.finalize();
                let expected =
                    base64::engine::general_purpose::STANDARD.decode(encoded.trim())?;
                Ok(computed.as_slice() == expected.as_slice())
            } else {
                Err(Error::InvalidHashFormat(
                    "Invalid SHA512 hash format".to_string(),
                ))
            }
        }
    }
}

/// Detect the hash algorithm from a hash string.
pub fn detect_algorithm(hash: &str) -> Option<HashAlgorithm> {
    if hash.starts_with(BCRYPT_PREFIX) {
        Some(HashAlgorithm::Bcrypt)
    } else if hash.starts_with("{SHA256}") {
        Some(HashAlgorithm::Sha256)
    } else if hash.starts_with("{SHA512}") {
        Some(HashAlgorithm::Sha512)
    } else if hash.starts_with("{SHA}") {
        // SHA-1 is not supported but we can detect it
        None
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcrypt_hash_and_verify() {
        let password = "test_password_123";
        let hash = hash_password(password, HashAlgorithm::Bcrypt).unwrap();
        assert!(hash.starts_with("$2b$"));
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_sha256_hash_and_verify() {
        let password = "test_password_123";
        let hash = hash_password(password, HashAlgorithm::Sha256).unwrap();
        assert!(hash.starts_with("{SHA256}"));
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_sha512_hash_and_verify() {
        let password = "test_password_123";
        let hash = hash_password(password, HashAlgorithm::Sha512).unwrap();
        assert!(hash.starts_with("{SHA512}"));
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_detect_algorithm() {
        assert_eq!(
            detect_algorithm("$2b$12$abc"),
            Some(HashAlgorithm::Bcrypt)
        );
        assert_eq!(
            detect_algorithm("$2y$12$abc"),
            Some(HashAlgorithm::Bcrypt)
        );
        assert_eq!(
            detect_algorithm("$2a$12$abc"),
            Some(HashAlgorithm::Bcrypt)
        );
        assert_eq!(
            detect_algorithm("{SHA256}abc"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            detect_algorithm("{SHA512}abc"),
            Some(HashAlgorithm::Sha512)
        );
        assert_eq!(detect_algorithm("{SHA}abc"), None);
        assert_eq!(detect_algorithm("invalid"), None);
    }

    #[test]
    fn test_algorithm_from_str() {
        assert_eq!(
            HashAlgorithm::from_str("bcrypt").unwrap(),
            HashAlgorithm::Bcrypt
        );
        assert_eq!(
            HashAlgorithm::from_str("BCRYPT").unwrap(),
            HashAlgorithm::Bcrypt
        );
        assert_eq!(
            HashAlgorithm::from_str("sha256").unwrap(),
            HashAlgorithm::Sha256
        );
        assert_eq!(
            HashAlgorithm::from_str("sha512").unwrap(),
            HashAlgorithm::Sha512
        );
        assert!(HashAlgorithm::from_str("invalid").is_err());
    }
}
