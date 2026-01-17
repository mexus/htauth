use crate::error::{Error, Result};
use bcrypt::{hash, verify};
use sha_crypt::{Algorithm, Params, PasswordHasher, PasswordVerifier, ShaCrypt};
use std::str::FromStr;

const BCRYPT_COST: u32 = 12;
const BCRYPT_PREFIX: &str = "$2";
const SHA256_PREFIX: &str = "$5$";
const SHA512_PREFIX: &str = "$6$";
const APR1_PREFIX: &str = "$apr1$";
const DEFAULT_ROUNDS: u32 = 5000;

// Salt length in bytes for SHA-256/SHA-512
// Apache uses 16 characters of encoded salt (12 bytes → 16 chars when encoded with 6-bit chars)
const SALT_BYTE_LEN: usize = 12; // 12 bytes * 8 bits = 96 bits = 16 chars * 6 bits

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Bcrypt,
    Sha256,
    Sha512,
    Apr1Md5,
}

impl FromStr for HashAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "bcrypt" => Ok(HashAlgorithm::Bcrypt),
            "sha256" => Ok(HashAlgorithm::Sha256),
            "sha512" => Ok(HashAlgorithm::Sha512),
            "md5" | "apr1" | "apr1-md5" => Ok(HashAlgorithm::Apr1Md5),
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
            HashAlgorithm::Apr1Md5 => write!(f, "md5"),
        }
    }
}

/// Hash a password using the specified algorithm.
///
/// For SHA-256 and SHA-512, uses the SHA-crypt format compatible with Apache htpasswd.
/// The format is `$5$rounds=N$salt$hash` for SHA-256 and `$6$rounds=N$salt$hash` for SHA-512.
pub fn hash_password(password: &str, algorithm: HashAlgorithm) -> Result<String> {
    match algorithm {
        HashAlgorithm::Bcrypt => {
            // bcrypt produces its own prefix like $2b$12$...
            Ok(hash(password, BCRYPT_COST)?)
        }
        HashAlgorithm::Sha256 => {
            let params =
                Params::new(DEFAULT_ROUNDS).map_err(|e| Error::PasswordHashError(e.to_string()))?;
            let sha_crypt = ShaCrypt::new(Algorithm::Sha256Crypt, params);
            let mut salt_bytes = [0u8; SALT_BYTE_LEN];
            getrandom::fill(&mut salt_bytes)
                .map_err(|e| Error::PasswordHashError(e.to_string()))?;
            let hash = sha_crypt
                .hash_password_with_salt(password.as_bytes(), &salt_bytes)
                .map_err(|e| Error::PasswordHashError(e.to_string()))?;
            Ok(hash.to_string())
        }
        HashAlgorithm::Sha512 => {
            let params =
                Params::new(DEFAULT_ROUNDS).map_err(|e| Error::PasswordHashError(e.to_string()))?;
            let sha_crypt = ShaCrypt::new(Algorithm::Sha512Crypt, params);
            let mut salt_bytes = [0u8; SALT_BYTE_LEN];
            getrandom::fill(&mut salt_bytes)
                .map_err(|e| Error::PasswordHashError(e.to_string()))?;
            let hash = sha_crypt
                .hash_password_with_salt(password.as_bytes(), &salt_bytes)
                .map_err(|e| Error::PasswordHashError(e.to_string()))?;
            Ok(hash.to_string())
        }
        HashAlgorithm::Apr1Md5 => {
            // APR1-MD5 for compatibility with Apache htpasswd
            let salt = crate::apr1_md5::generate_salt()?;
            Ok(crate::apr1_md5::hash(password, &salt))
        }
    }
}

/// Verify a password against a hash.
pub fn verify_password(password: &str, hash_str: &str) -> Result<bool> {
    let algorithm = detect_algorithm(hash_str)
        .ok_or_else(|| Error::InvalidHashFormat("Cannot determine hash algorithm".to_string()))?;

    match algorithm {
        HashAlgorithm::Bcrypt => {
            // All bcrypt variants ($2a$, $2b$, $2y$) are compatible for verification
            verify(password, hash_str).map_err(Error::from)
        }
        HashAlgorithm::Sha256 | HashAlgorithm::Sha512 => {
            // sha-crypt handles both SHA-256 and SHA-512 verification
            // Returns Ok(true) if valid, Ok(false) if invalid (not Err)
            let sha_crypt = ShaCrypt::default();
            Ok(sha_crypt
                .verify_password(password.as_bytes(), hash_str)
                .is_ok())
        }
        HashAlgorithm::Apr1Md5 => {
            // APR1-MD5 verification
            Ok(crate::apr1_md5::verify(password, hash_str))
        }
    }
}

/// Detect the hash algorithm from a hash string.
pub fn detect_algorithm(hash: &str) -> Option<HashAlgorithm> {
    if hash.starts_with(BCRYPT_PREFIX) {
        Some(HashAlgorithm::Bcrypt)
    } else if hash.starts_with(SHA256_PREFIX) {
        Some(HashAlgorithm::Sha256)
    } else if hash.starts_with(SHA512_PREFIX) {
        Some(HashAlgorithm::Sha512)
    } else if hash.starts_with(APR1_PREFIX) {
        Some(HashAlgorithm::Apr1Md5)
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
        // SHA-crypt format: $5$rounds=5000$salt$hash
        assert!(hash.starts_with("$5$"));
        println!("Generated hash: {}", hash);

        // Try direct library verification
        use sha_crypt::{PasswordVerifier, ShaCrypt};
        let sha_crypt = ShaCrypt::default();
        match sha_crypt.verify_password(password.as_bytes(), hash.as_str()) {
            Ok(_) => println!("Direct verification SUCCESS"),
            Err(e) => println!("Direct verification FAILED: {:?}", e),
        }

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_sha512_hash_and_verify() {
        let password = "test_password_123";
        let hash = hash_password(password, HashAlgorithm::Sha512).unwrap();
        // SHA-crypt format: $6$rounds=5000$salt$hash
        assert!(hash.starts_with("$6$"));
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_detect_algorithm() {
        assert_eq!(detect_algorithm("$2b$12$abc"), Some(HashAlgorithm::Bcrypt));
        assert_eq!(detect_algorithm("$2y$12$abc"), Some(HashAlgorithm::Bcrypt));
        assert_eq!(detect_algorithm("$2a$12$abc"), Some(HashAlgorithm::Bcrypt));
        assert_eq!(
            detect_algorithm("$5$rounds=5000$salt$hash"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            detect_algorithm("$5$salt$hash"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            detect_algorithm("$6$rounds=5000$salt$hash"),
            Some(HashAlgorithm::Sha512)
        );
        assert_eq!(
            detect_algorithm("$6$salt$hash"),
            Some(HashAlgorithm::Sha512)
        );
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

    #[test]
    fn test_apache_sha256_format() {
        // Test that we can verify a hash generated by Apache htpasswd
        // This hash was generated with: htpasswd -nb2 testuser testpass123
        let apache_hash = "$5$6.O43dJ8bymsjcrp$QzfN4hZywImpvc6uE0O8TR.Xe87tgyvATwyV61rQbR5";
        assert!(detect_algorithm(apache_hash) == Some(HashAlgorithm::Sha256));

        // Debug: try direct library call
        use sha_crypt::{PasswordVerifier, ShaCrypt};
        let sha_crypt = ShaCrypt::default();
        match sha_crypt.verify_password(b"testpass123", apache_hash) {
            Ok(_) => println!("Direct Apache verification SUCCESS"),
            Err(e) => println!("Direct Apache verification FAILED: {:?}", e),
        }

        assert!(verify_password("testpass123", apache_hash).unwrap());
        assert!(!verify_password("wrongpass", apache_hash).unwrap());
    }

    #[test]
    fn test_apache_sha512_format() {
        // Test that we can verify a hash generated by Apache htpasswd
        // This hash was generated with: htpasswd -nb5 testuser testpass123
        let apache_hash = "$6$On58VpHvsS95KvxU$lbtz65RFxG2fcos.C3vi2wllW82efo8fDcO2PRVEnHwKpvS4tGE4OJ6He98QevZYUrenCYl9QiG0woAexDYkZ/";
        assert!(detect_algorithm(apache_hash) == Some(HashAlgorithm::Sha512));
        assert!(verify_password("testpass123", apache_hash).unwrap());
        assert!(!verify_password("wrongpass", apache_hash).unwrap());
    }
}
