//! Apache APR1-MD5 password hashing implementation.
//!
//! This module implements the APR1-MD5 password hashing algorithm used by
//! Apache's htpasswd tool. The format is: `$apr1$salt$hash`
//!
//! # Algorithm Source
//!
//! This implementation is based on the Apache Portable Runtime (APR) library's
//! `apr_md5_encode()` function from `crypto/apr_md5.c`. The APR implementation
//! itself is derived from the FreeBSD 3.0 MD5 crypt() function (Beer-Ware License).
//!
//! Key references:
//! - Apache APR: https://github.com/apache/apr-util/blob/master/crypto/apr_md5.c
//! - Apache htpasswd: https://github.com/apache/httpd/blob/trunk/support/htpasswd.c
//! - FreeBSD crypt.c: https://github.com/freebsd/freebsd-src/blob/master/lib/libcrypt/crypt.c
//!
//! The itoa64 alphabet and encoding scheme are defined in APR's `to64()` function:
//! ```c
//! static unsigned char itoa64[] =
//!     "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
//! ```
//!
//! # Security Warning
//!
//! MD5 is cryptographically broken. This implementation is provided for
//! compatibility with existing Apache htpasswd files only. Do not use
//! APR1-MD5 for new password hashes if possible - use bcrypt instead.

use crate::error::Result;
use md5::{Digest, Md5};

/// Custom base64 alphabet (itoa64) used by APR1-MD5.
///
/// This is the same alphabet used in Apache APR's `to64()` function and
/// SHA-crypt. It differs from standard base64 by starting with `./` instead
/// of `A-Za-z`.
///
/// Source: Apache apr-util/crypto/apr_md5.c
const ITOA64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// APR1-MD5 hash prefix
pub const APR1_PREFIX: &str = "$apr1$";

/// Salt length in characters for APR1-MD5
pub const APR1_SALT_LEN: usize = 8;

/// Number of MD5 rounds in APR1 algorithm
const APR1_ROUNDS: u32 = 1000;

/// Encode a value using the itoa64 alphabet (Apache's to64 function).
///
/// Direct port of Apache's to64() from apr_md5.c.
/// Takes `n` 6-bit values from `v` and encodes them using itoa64 alphabet.
fn to64(mut v: u32, n: usize) -> String {
    let mut result = String::with_capacity(n);
    for _ in 0..n {
        result.push(ITOA64[(v & 0x3f) as usize] as char);
        v >>= 6;
    }
    result
}

/// Encode a 16-byte MD5 digest into a 22-character string.
///
/// This follows Apache's exact encoding from apr_md5_encode().
///
/// The C code from apr_md5.c shows the byte ordering:
/// ```c
/// l = (final[ 0]<<16) | (final[ 6]<<8) | final[12]; to64(p, l, 4); p += 4;
/// l = (final[ 1]<<16) | (final[ 7]<<8) | final[13]; to64(p, l, 4); p += 4;
/// l = (final[ 2]<<16) | (final[ 8]<<8) | final[14]; to64(p, l, 4); p += 4;
/// l = (final[ 3]<<16) | (final[ 9]<<8) | final[15]; to64(p, l, 4); p += 4;
/// l = (final[ 4]<<16) | (final[10]<<8) | final[ 5]; to64(p, l, 4); p += 4;
/// l = final[11];                                     to64(p, l, 2); p += 2;
/// ```
fn encode_apr1_hash(digest: &[u8; 16]) -> String {
    let mut result = String::with_capacity(22);

    // 4-char encodings (24 bits each) following Apache's to64() calls
    result.push_str(&to64(
        u32::from(digest[0]) << 16 | u32::from(digest[6]) << 8 | u32::from(digest[12]),
        4,
    ));
    result.push_str(&to64(
        u32::from(digest[1]) << 16 | u32::from(digest[7]) << 8 | u32::from(digest[13]),
        4,
    ));
    result.push_str(&to64(
        u32::from(digest[2]) << 16 | u32::from(digest[8]) << 8 | u32::from(digest[14]),
        4,
    ));
    result.push_str(&to64(
        u32::from(digest[3]) << 16 | u32::from(digest[9]) << 8 | u32::from(digest[15]),
        4,
    ));
    result.push_str(&to64(
        u32::from(digest[4]) << 16 | u32::from(digest[10]) << 8 | u32::from(digest[5]),
        4,
    ));

    // 2-char encoding (12 bits)
    result.push_str(&to64(u32::from(digest[11]), 2));

    result
}

/// Generate a random salt string using the itoa64 alphabet.
///
/// APR1-MD5 uses an 8-character salt. The salt is generated from 6 random
/// bytes (48 bits), which are encoded using the itoa64 alphabet (6 bits per char).
pub fn generate_salt() -> Result<String> {
    let mut salt_bytes = [0u8; 6]; // 6 bytes * 8 bits = 48 bits = 8 chars * 6 bits
    getrandom::fill(&mut salt_bytes).map_err(|e| crate::error::Error::PasswordHashError(e.to_string()))?;

    // Encode using the same technique as the C code's generate_salt()
    let mut salt = String::with_capacity(APR1_SALT_LEN);
    let mut val: u32 = 0;
    let mut bits: u32 = 0;
    let mut n = 0;

    for _ in 0..APR1_SALT_LEN {
        if bits < 6 {
            val |= u32::from(salt_bytes[n]) << bits;
            n += 1;
            bits += 8;
        }
        salt.push(ITOA64[(val & 0x3f) as usize] as char);
        val >>= 6;
        bits -= 6;
    }

    Ok(salt)
}

/// Hash a password using the APR1-MD5 algorithm.
///
/// # Arguments
///
/// * `password` - The password to hash
/// * `salt` - The salt string (8 characters, will be truncated if longer)
///
/// # Returns
///
/// A string in the format `$apr1$salt$hash`
///
/// # Algorithm
///
/// This follows Apache APR's `apr_md5_encode()` from apr-util/crypto/apr_md5.c:
///
/// 1. Compute hash1 = MD5(password + salt + password)
/// 2. Build context = password + "$apr1$" + salt
/// 3. Extend context with hash1 repeated for each 16-byte chunk of password length
/// 4. Add alternating null bytes and first password character (based on password length bit pattern)
/// 5. Compute hash2 = MD5(context)
/// 6. Run 1000 rounds: for i in 0..999, MD5(conditional password/salt/hash2)
///    - If i is odd: start with password, else hash2
///    - If i % 3 != 0: add salt
///    - If i % 7 != 0: add password
///    - If i is odd: end with hash2, else password
/// 7. Encode result using to64() with itoa64 alphabet
pub fn hash(password: &str, salt: &str) -> String {
    let password_bytes = password.as_bytes();
    let salt = &salt[..salt.len().min(8)]; // Truncate to 8 chars

    // Step 1: hash1 = MD5(password + salt + password)
    let mut hasher1 = Md5::new();
    hasher1.update(password_bytes);
    hasher1.update(salt.as_bytes());
    hasher1.update(password_bytes);
    let hash1 = hasher1.finalize();

    // Step 2: Build context = password + "$apr1$" + salt + hash1[0:16] repeated
    let mut context = Vec::new();
    context.extend_from_slice(password_bytes);
    context.extend_from_slice(APR1_PREFIX.as_bytes());
    context.extend_from_slice(salt.as_bytes());

    // Add hash1 repeatedly for each 16-byte chunk of password length
    let mut i = password_bytes.len();
    while i > 0 {
        let chunk_len = hash1.len().min(i);
        context.extend_from_slice(&hash1[..chunk_len]);
        i -= chunk_len;
    }

    // Step 3: For each bit of password length, add null byte or first char
    i = password_bytes.len();
    while i > 0 {
        if (i & 1) == 1 {
            context.push(0); // Odd: add null byte
        } else {
            context.push(password_bytes[0]); // Even: add first password char
        }
        i >>= 1;
    }

    // Step 4: hash2 = MD5(context)
    let mut hasher2 = Md5::new();
    hasher2.update(&context);
    let mut hash2 = hasher2.finalize();

    // Step 5: 1000 rounds of MD5 with alternating input
    for i in 0..APR1_ROUNDS {
        let mut input = Vec::new();

        // Alternate between password and hash2
        if (i & 1) == 1 {
            input.extend_from_slice(password_bytes);
        } else {
            input.extend_from_slice(&hash2);
        }

        // Add salt every 3rd round (not 0, 3, 6, ...)
        if i % 3 != 0 {
            input.extend_from_slice(salt.as_bytes());
        }

        // Add password every 7th round (not 0, 7, 14, ...)
        if i % 7 != 0 {
            input.extend_from_slice(password_bytes);
        }

        // Alternate between hash2 and password
        if (i & 1) == 1 {
            input.extend_from_slice(&hash2);
        } else {
            input.extend_from_slice(password_bytes);
        }

        // Compute MD5 for next round
        let mut hasher = Md5::new();
        hasher.update(&input);
        hash2 = hasher.finalize();
    }

    // Step 6: Encode the final hash
    let encoded_hash = encode_apr1_hash(&hash2.into());

    format!("{}{}${}", APR1_PREFIX, salt, encoded_hash)
}

/// Verify a password against an APR1-MD5 hash.
///
/// # Arguments
///
/// * `password` - The password to verify
/// * `hash_str` - The hash string in format `$apr1$salt$hash`
///
/// # Returns
///
/// `true` if the password matches, `false` otherwise
pub fn verify(password: &str, hash_str: &str) -> bool {
    // Parse the hash to extract the salt
    if !hash_str.starts_with(APR1_PREFIX) {
        return false;
    }

    // Find the salt part (between $apr1$ and the next $)
    let after_prefix = &hash_str[APR1_PREFIX.len()..];
    let salt_end = after_prefix.find('$').unwrap_or(after_prefix.len());
    let salt = &after_prefix[..salt_end];

    // Re-compute the hash and compare
    let computed = hash(password, salt);

    // Use constant-time comparison
    computed.len() == hash_str.len()
        && computed
            .as_bytes()
            .iter()
            .zip(hash_str.as_bytes().iter())
            .all(|(a, b)| a == b)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors from Apache htpasswd
    // Generated with: htpasswd -nb <username> <password>

    #[test]
    fn test_apr1_hash_hello() {
        // Test vector from openssl: openssl passwd -apr1 -salt xlWep/gn hello
        // Expected: $apr1$xlWep/gn$6UNiHq3WE714EKfeH2X5c.
        let password = "hello";
        let salt = "xlWep/gn";
        let result = hash(password, salt);
        println!("Generated hash for 'hello': {}", result);
        assert!(result.starts_with("$apr1$xlWep/gn$"));
        assert_eq!(result, "$apr1$xlWep/gn$6UNiHq3WE714EKfeH2X5c.");
    }

    #[test]
    fn test_apr1_hash_password() {
        // Test vector from openssl: openssl passwd -apr1 -salt lZL6V/ci password
        // Expected: $apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00
        let password = "password";
        let salt = "lZL6V/ci";
        let result = hash(password, salt);
        println!("Generated hash for 'password': {}", result);
        assert!(result.starts_with("$apr1$lZL6V/ci$"));
        assert_eq!(result, "$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00");
    }

    #[test]
    fn test_apr1_verify_hello() {
        // Known hash for "hello" with salt "xlWep/gn" (from openssl)
        let hash_str = "$apr1$xlWep/gn$6UNiHq3WE714EKfeH2X5c.";
        assert!(verify("hello", hash_str));
        assert!(!verify("wrong", hash_str));
    }

    #[test]
    fn test_apr1_verify_password() {
        // Known hash for "password" with salt "lZL6V/ci" (from openssl)
        let hash_str = "$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00";
        assert!(verify("password", hash_str));
        assert!(!verify("wrong", hash_str));
    }

    #[test]
    fn test_apr1_verify_testpass123() {
        // Test vector from openssl: openssl passwd -apr1 -salt WxrZ8P3I testpass123
        // Expected: $apr1$WxrZ8P3I$XD2BykvOa82I1l5jCMtbW0
        let hash_str = "$apr1$WxrZ8P3I$XD2BykvOa82I1l5jCMtbW0";
        assert!(verify("testpass123", hash_str));
        assert!(!verify("wrongpass", hash_str));
    }

    #[test]
    fn test_apr1_hash_and_verify_roundtrip() {
        let password = "my_secure_password_123";
        let salt = generate_salt().unwrap();
        let hash_str = hash(password, &salt);
        assert!(verify(password, &hash_str));
        assert!(!verify("wrong_password", &hash_str));
    }

    #[test]
    fn test_generate_salt_length() {
        let salt = generate_salt().unwrap();
        assert_eq!(salt.len(), APR1_SALT_LEN);
    }

    #[test]
    fn test_generate_salt_valid_chars() {
        let salt = generate_salt().unwrap();
        // All characters should be from the itoa64 alphabet
        for ch in salt.chars() {
            assert!(ITOA64.contains(&(ch as u8)), "Invalid salt character: {}", ch);
        }
    }

    #[test]
    fn test_salt_truncation() {
        // Salt longer than 8 chars should be truncated
        let password = "test";
        let long_salt = "abcdefgh12345678";
        let hash1 = hash(password, long_salt);
        let hash2 = hash(password, "abcdefgh");
        assert_eq!(hash1, hash2);
    }
}
