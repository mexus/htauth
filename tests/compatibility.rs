//! Apache htpasswd compatibility tests
//!
//! These tests verify bidirectional compatibility with the Apache htpasswd tool.
//! Tests are only run when /usr/bin/htpasswd is available on the system.

use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

/// Check if Apache htpasswd is available
fn has_apache_htpasswd() -> bool {
    Path::new("/usr/bin/htpasswd").exists()
}

/// Get our htpasswd binary path
fn our_htpasswd_bin() -> String {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_htpasswd") {
        path
    } else {
        "./target/debug/htpasswd".to_string()
    }
}

/// Run our htpasswd with password from stdin
fn run_our_htpasswd_with_stdin(args: &[&str], password: &str) -> Result<bool, String> {
    let mut child = Command::new(our_htpasswd_bin())
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn: {}", e))?;

    // Write password to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(password.as_bytes())
            .map_err(|e| format!("Failed to write to stdin: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed to wait: {}", e))?;

    Ok(output.status.success())
}

/// Run Apache htpasswd with given arguments
fn run_apache_htpasswd(args: &[&str]) -> Result<ApacheResult, String> {
    let output = Command::new("/usr/bin/htpasswd")
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run htpasswd: {}", e))?;

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    Ok(ApacheResult {
        stderr,
        success: output.status.success(),
    })
}

struct ApacheResult {
    stderr: String,
    success: bool,
}

fn create_test_dir() -> TempDir {
    TempDir::new().expect("Failed to create temp dir")
}

//
// Test 1: Our tool can read Apache htpasswd files
//

#[test]
fn test_apache_bcrypt_read() {
    if !has_apache_htpasswd() {
        return;
    }

    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Create file with Apache htpasswd (bcrypt)
    let _ = run_apache_htpasswd(&["-cBb", file_path.to_str().unwrap(), "alice", "testpass123"]);
    let _ = run_apache_htpasswd(&["-Bb", file_path.to_str().unwrap(), "bob", "testpass456"]);

    // Read with our library
    let htpasswd = htpasswd_rs::Htpasswd::open(&file_path).unwrap();
    assert!(htpasswd.user_exists("alice"));
    assert!(htpasswd.user_exists("bob"));

    // Verify passwords work
    assert!(htpasswd.verify_user("alice", "testpass123").unwrap());
    assert!(htpasswd.verify_user("bob", "testpass456").unwrap());
    assert!(!htpasswd.verify_user("alice", "wrongpass").unwrap());
}

#[test]
fn test_apache_sha256_read() {
    if !has_apache_htpasswd() {
        return;
    }

    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Create file with Apache htpasswd (SHA-256)
    let _ = run_apache_htpasswd(&["-c2b", file_path.to_str().unwrap(), "alice", "testpass123"]);
    let _ = run_apache_htpasswd(&["-2b", file_path.to_str().unwrap(), "bob", "testpass456"]);

    // Read with our library
    let htpasswd = htpasswd_rs::Htpasswd::open(&file_path).unwrap();
    assert!(htpasswd.user_exists("alice"));
    assert!(htpasswd.user_exists("bob"));

    // Verify passwords work
    assert!(htpasswd.verify_user("alice", "testpass123").unwrap());
    assert!(htpasswd.verify_user("bob", "testpass456").unwrap());

    // Check hash format
    let content = std::fs::read_to_string(&file_path).unwrap();
    // Apache htpasswd uses SHA-crypt format: $5$salt$hash
    assert!(content.contains("$5$"));
}

#[test]
fn test_apache_sha512_read() {
    if !has_apache_htpasswd() {
        return;
    }

    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Create file with Apache htpasswd (SHA-512)
    let _ = run_apache_htpasswd(&["-c5b", file_path.to_str().unwrap(), "alice", "testpass123"]);
    let _ = run_apache_htpasswd(&["-5b", file_path.to_str().unwrap(), "bob", "testpass456"]);

    // Read with our library
    let htpasswd = htpasswd_rs::Htpasswd::open(&file_path).unwrap();
    assert!(htpasswd.user_exists("alice"));
    assert!(htpasswd.user_exists("bob"));

    // Verify passwords work
    assert!(htpasswd.verify_user("alice", "testpass123").unwrap());
    assert!(htpasswd.verify_user("bob", "testpass456").unwrap());

    // Check hash format
    let content = std::fs::read_to_string(&file_path).unwrap();
    // Apache htpasswd uses SHA-crypt format: $6$salt$hash
    assert!(content.contains("$6$"));
}

#[test]
fn test_apache_md5_read() {
    if !has_apache_htpasswd() {
        return;
    }

    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Create file with Apache htpasswd (APR1-MD5, default with -m flag)
    let _ = run_apache_htpasswd(&["-cmb", file_path.to_str().unwrap(), "alice", "testpass123"]);
    let _ = run_apache_htpasswd(&["-mb", file_path.to_str().unwrap(), "bob", "testpass456"]);

    // Read with our library
    let htpasswd = htpasswd_rs::Htpasswd::open(&file_path).unwrap();
    assert!(htpasswd.user_exists("alice"));
    assert!(htpasswd.user_exists("bob"));

    // Verify passwords work
    assert!(htpasswd.verify_user("alice", "testpass123").unwrap());
    assert!(htpasswd.verify_user("bob", "testpass456").unwrap());

    // Check hash format
    let content = std::fs::read_to_string(&file_path).unwrap();
    // Apache htpasswd uses APR1-MD5 format: $apr1$salt$hash
    assert!(content.contains("$apr1$"));
}

//
// Test 2: Apache htpasswd can read our files
//

#[test]
fn test_our_bcrypt_with_apache_verify() {
    if !has_apache_htpasswd() {
        return;
    }

    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Create file with our CLI (bcrypt)
    let success = run_our_htpasswd_with_stdin(
        &["add", file_path.to_str().unwrap(), "alice", "--password"],
        "testpass123",
    )
    .unwrap();
    assert!(success, "Our htpasswd failed to add user");

    // Verify with Apache htpasswd
    let result =
        run_apache_htpasswd(&["-vb", file_path.to_str().unwrap(), "alice", "testpass123"]).unwrap();
    assert!(
        result.success,
        "Apache verification failed: stderr={}",
        result.stderr
    );

    // Verify wrong password fails
    let result =
        run_apache_htpasswd(&["-vb", file_path.to_str().unwrap(), "alice", "wrongpass"]).unwrap();
    assert!(!result.success, "Apache should reject wrong password");
}

#[test]
fn test_our_sha256_with_apache_verify() {
    if !has_apache_htpasswd() {
        return;
    }

    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Create file with our CLI (SHA-256)
    let success = run_our_htpasswd_with_stdin(
        &[
            "add",
            file_path.to_str().unwrap(),
            "alice",
            "--algorithm",
            "sha256",
            "--password",
        ],
        "testpass123",
    )
    .unwrap();
    assert!(success, "Our htpasswd failed to add user");

    // Verify with Apache htpasswd (using -v2 for SHA-256)
    let result =
        run_apache_htpasswd(&["-v2b", file_path.to_str().unwrap(), "alice", "testpass123"])
            .unwrap();
    assert!(
        result.success,
        "Apache verification failed: stderr={}",
        result.stderr
    );
}

#[test]
fn test_our_sha512_with_apache_verify() {
    if !has_apache_htpasswd() {
        return;
    }

    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Create file with our CLI (SHA-512)
    let success = run_our_htpasswd_with_stdin(
        &[
            "add",
            file_path.to_str().unwrap(),
            "alice",
            "--algorithm",
            "sha512",
            "--password",
        ],
        "testpass123",
    )
    .unwrap();
    assert!(success, "Our htpasswd failed to add user");

    // Verify with Apache htpasswd (using -v5 for SHA-512)
    let result =
        run_apache_htpasswd(&["-v5b", file_path.to_str().unwrap(), "alice", "testpass123"])
            .unwrap();
    assert!(
        result.success,
        "Apache verification failed: stderr={}",
        result.stderr
    );
}

#[test]
fn test_our_md5_with_apache_verify() {
    if !has_apache_htpasswd() {
        return;
    }

    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Create file with our CLI (MD5/APR1)
    let success = run_our_htpasswd_with_stdin(
        &[
            "add",
            file_path.to_str().unwrap(),
            "alice",
            "--algorithm",
            "md5",
            "--password",
        ],
        "testpass123",
    )
    .unwrap();
    assert!(success, "Our htpasswd failed to add user");

    // Verify with Apache htpasswd (using -vm for APR1-MD5)
    let result =
        run_apache_htpasswd(&["-vmb", file_path.to_str().unwrap(), "alice", "testpass123"])
            .unwrap();
    assert!(
        result.success,
        "Apache verification failed: stderr={}",
        result.stderr
    );
}

//
// Test 3: Cross-compatibility - mixed files
//

#[test]
fn test_mixed_file_compatibility() {
    if !has_apache_htpasswd() {
        return;
    }

    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Create users with both tools
    // Apache - bcrypt
    run_apache_htpasswd(&[
        "-cBb",
        file_path.to_str().unwrap(),
        "apache_bcrypt",
        "pass1",
    ])
    .unwrap();

    // Our tool - SHA-256
    run_our_htpasswd_with_stdin(
        &[
            "add",
            file_path.to_str().unwrap(),
            "our_sha256",
            "--algorithm",
            "sha256",
            "--password",
        ],
        "pass2",
    )
    .unwrap();

    // Apache - SHA-512
    run_apache_htpasswd(&["-5b", file_path.to_str().unwrap(), "apache_sha512", "pass3"]).unwrap();

    // Our tool - bcrypt
    run_our_htpasswd_with_stdin(
        &[
            "add",
            file_path.to_str().unwrap(),
            "our_bcrypt",
            "--password",
        ],
        "pass4",
    )
    .unwrap();

    // Apache - MD5
    run_apache_htpasswd(&["-mb", file_path.to_str().unwrap(), "apache_md5", "pass5"]).unwrap();

    // Our tool - MD5
    run_our_htpasswd_with_stdin(
        &[
            "add",
            file_path.to_str().unwrap(),
            "our_md5",
            "--algorithm",
            "md5",
            "--password",
        ],
        "pass6",
    )
    .unwrap();

    // Verify with our library
    let htpasswd = htpasswd_rs::Htpasswd::open(&file_path).unwrap();
    assert_eq!(htpasswd.user_count(), 6);
    assert!(htpasswd.verify_user("apache_bcrypt", "pass1").unwrap());
    assert!(htpasswd.verify_user("our_sha256", "pass2").unwrap());
    assert!(htpasswd.verify_user("apache_sha512", "pass3").unwrap());
    assert!(htpasswd.verify_user("our_bcrypt", "pass4").unwrap());
    assert!(htpasswd.verify_user("apache_md5", "pass5").unwrap());
    assert!(htpasswd.verify_user("our_md5", "pass6").unwrap());

    // Verify with Apache htpasswd
    for (user, pass, flag) in &[
        ("apache_bcrypt", "pass1", "-vb"),
        ("apache_sha512", "pass3", "-v5b"),
        ("our_bcrypt", "pass4", "-vb"),
        ("apache_md5", "pass5", "-vmb"),
        ("our_md5", "pass6", "-vmb"),
    ] {
        let result = run_apache_htpasswd(&[flag, file_path.to_str().unwrap(), user, pass]).unwrap();
        assert!(
            result.success,
            "Apache failed to verify {} with {}: {}",
            user, flag, result.stderr
        );
    }
}
