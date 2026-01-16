//! CLI integration tests

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use tempfile::TempDir;

/// Helper function to get the htpasswd binary path
fn htpasswd_bin() -> PathBuf {
    // Use CARGO_BIN_EXE_htpasswd if available (set by cargo test)
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_htpasswd") {
        return PathBuf::from(path);
    }
    // Fallback to the built binary in target/debug
    PathBuf::from("./target/debug/htpasswd")
}

/// Helper to run the htpasswd CLI with optional stdin input
fn run_htpasswd(args: &[&str], stdin_input: Option<&str>) -> TestResult {
    let mut cmd = Command::new(&htpasswd_bin());
    cmd.args(args);

    let output = if let Some(input) = stdin_input {
        // Use spawn() to write to stdin
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("Failed to spawn htpasswd");

        // Write password to stdin
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input.as_bytes());
            let _ = stdin.flush();
        }

        child.wait_with_output().expect("Failed to read output")
    } else {
        cmd.output().expect("Failed to execute htpasswd")
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    TestResult {
        stdout,
        stderr,
        success: output.status.success(),
    }
}

struct TestResult {
    stdout: String,
    stderr: String,
    success: bool,
}

fn create_test_dir() -> TempDir {
    TempDir::new().expect("Failed to create temp dir")
}

#[test]
fn test_cli_add_user_bcrypt() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    let result = run_htpasswd(
        &[
            "add",
            file_path.to_str().unwrap(),
            "alice",
            "--algorithm",
            "bcrypt",
            "--password",
        ],
        Some("testpass123"),
    );

    assert!(result.success, "stderr: {}", result.stderr);
    assert!(result.stdout.contains("alice") || result.stderr.contains("alice"));

    // Verify the user was added
    let htpasswd = htpasswd_rs::Htpasswd::open(&file_path).unwrap();
    assert!(htpasswd.user_exists("alice"));
    assert!(htpasswd.verify_user("alice", "testpass123").unwrap());
}

#[test]
fn test_cli_add_user_sha256() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    let result = run_htpasswd(
        &[
            "add",
            file_path.to_str().unwrap(),
            "bob",
            "--algorithm",
            "sha256",
            "--password",
        ],
        Some("testpass456"),
    );

    assert!(result.success, "stderr: {}", result.stderr);

    // Verify the user was added with SHA256
    let htpasswd = htpasswd_rs::Htpasswd::open(&file_path).unwrap();
    assert!(htpasswd.user_exists("bob"));
    assert!(htpasswd.verify_user("bob", "testpass456").unwrap());

    // Check the hash format
    let content = std::fs::read_to_string(&file_path).unwrap();
    // SHA-256 now uses SHA-crypt format: $5$rounds=5000$salt$hash
    assert!(content.contains("$5$"));
}

#[test]
fn test_cli_add_user_sha512() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    let result = run_htpasswd(
        &[
            "add",
            file_path.to_str().unwrap(),
            "charlie",
            "--algorithm",
            "sha512",
            "--password",
        ],
        Some("testpass789"),
    );

    assert!(result.success, "stderr: {}", result.stderr);

    // Verify the user was added with SHA512
    let htpasswd = htpasswd_rs::Htpasswd::open(&file_path).unwrap();
    assert!(htpasswd.user_exists("charlie"));
    assert!(htpasswd.verify_user("charlie", "testpass789").unwrap());

    // Check the hash format
    let content = std::fs::read_to_string(&file_path).unwrap();
    // SHA-512 now uses SHA-crypt format: $6$rounds=5000$salt$hash
    assert!(content.contains("$6$"));
}

#[test]
fn test_cli_add_duplicate_user() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Add first user
    run_htpasswd(
        &["add", file_path.to_str().unwrap(), "alice", "--password"],
        Some("testpass123"),
    );

    // Try to add duplicate
    let result = run_htpasswd(
        &["add", file_path.to_str().unwrap(), "alice", "--password"],
        Some("testpass456"),
    );

    assert!(!result.success, "Should fail when adding duplicate user");
    assert!(result.stderr.contains("already exists") || result.stderr.contains("Error"));
}

#[test]
fn test_cli_list_users() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Add multiple users
    run_htpasswd(
        &["add", file_path.to_str().unwrap(), "alice", "--password"],
        Some("pass1"),
    );
    run_htpasswd(
        &["add", file_path.to_str().unwrap(), "bob", "--password"],
        Some("pass2"),
    );
    run_htpasswd(
        &["add", file_path.to_str().unwrap(), "charlie", "--password"],
        Some("pass3"),
    );

    // List users
    let result = run_htpasswd(&["list", file_path.to_str().unwrap()], None);

    assert!(result.success, "stderr: {}", result.stderr);
    assert!(result.stdout.contains("alice"));
    assert!(result.stdout.contains("bob"));
    assert!(result.stdout.contains("charlie"));
}

#[test]
fn test_cli_verify_correct_password() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    run_htpasswd(
        &["add", file_path.to_str().unwrap(), "alice", "--password"],
        Some("correctpass"),
    );

    let result = run_htpasswd(
        &["verify", file_path.to_str().unwrap(), "alice", "--password"],
        Some("correctpass"),
    );

    assert!(result.success);
    assert!(result.stdout.contains("correct") || result.stdout.contains("alice"));
}

#[test]
fn test_cli_verify_wrong_password() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    run_htpasswd(
        &["add", file_path.to_str().unwrap(), "alice", "--password"],
        Some("correctpass"),
    );

    let result = run_htpasswd(
        &["verify", file_path.to_str().unwrap(), "alice", "--password"],
        Some("wrongpass"),
    );

    assert!(!result.success);
    assert!(result.stderr.contains("incorrect") || result.stderr.contains("wrong"));
}

#[test]
fn test_cli_verify_nonexistent_user() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    run_htpasswd(
        &["add", file_path.to_str().unwrap(), "alice", "--password"],
        Some("pass"),
    );

    let result = run_htpasswd(
        &[
            "verify",
            file_path.to_str().unwrap(),
            "nonexistent",
            "--password",
        ],
        Some("pass"),
    );

    assert!(!result.success);
    assert!(result.stderr.contains("not found") || result.stderr.contains("Error"));
}

#[test]
fn test_cli_update_user() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Add user
    run_htpasswd(
        &["add", file_path.to_str().unwrap(), "alice", "--password"],
        Some("oldpass"),
    );

    // Verify old password works
    let htpasswd = htpasswd_rs::Htpasswd::open(&file_path).unwrap();
    assert!(htpasswd.verify_user("alice", "oldpass").unwrap());

    // Update password
    let result = run_htpasswd(
        &["update", file_path.to_str().unwrap(), "alice", "--password"],
        Some("newpass"),
    );
    assert!(result.success, "stderr: {}", result.stderr);

    // Verify new password works
    let htpasswd = htpasswd_rs::Htpasswd::open(&file_path).unwrap();
    assert!(htpasswd.verify_user("alice", "newpass").unwrap());
    assert!(!htpasswd.verify_user("alice", "oldpass").unwrap());
}

#[test]
fn test_cli_update_nonexistent_user() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    let result = run_htpasswd(
        &[
            "update",
            file_path.to_str().unwrap(),
            "nonexistent",
            "--password",
        ],
        Some("newpass"),
    );

    assert!(!result.success);
    assert!(result.stderr.contains("not found") || result.stderr.contains("Error"));
}

#[test]
fn test_cli_delete_user() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Add user
    run_htpasswd(
        &["add", file_path.to_str().unwrap(), "alice", "--password"],
        Some("pass"),
    );

    // Verify user exists
    let htpasswd = htpasswd_rs::Htpasswd::open(&file_path).unwrap();
    assert!(htpasswd.user_exists("alice"));

    // Delete user
    let result = run_htpasswd(&["delete", file_path.to_str().unwrap(), "alice"], None);
    assert!(result.success, "stderr: {}", result.stderr);

    // Verify user is gone
    let htpasswd = htpasswd_rs::Htpasswd::open(&file_path).unwrap();
    assert!(!htpasswd.user_exists("alice"));
}

#[test]
fn test_cli_delete_nonexistent_user() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    run_htpasswd(
        &["add", file_path.to_str().unwrap(), "alice", "--password"],
        Some("pass"),
    );

    let result = run_htpasswd(
        &["delete", file_path.to_str().unwrap(), "nonexistent"],
        None,
    );

    assert!(!result.success);
    assert!(result.stderr.contains("not found") || result.stderr.contains("Error"));
}

#[test]
fn test_cli_algorithm_variants() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Test all algorithm variants
    for (algo, user, pass) in &[
        ("bcrypt", "user_bcrypt", "pass123"),
        ("sha256", "user_sha256", "pass456"),
        ("sha512", "user_sha512", "pass789"),
    ] {
        let result = run_htpasswd(
            &[
                "add",
                file_path.to_str().unwrap(),
                user,
                "--algorithm",
                algo,
                "--password",
            ],
            Some(pass),
        );
        assert!(
            result.success,
            "Failed for algorithm {}: {}",
            algo, result.stderr
        );
    }

    // Verify all users exist
    let htpasswd = htpasswd_rs::Htpasswd::open(&file_path).unwrap();
    assert!(htpasswd.user_exists("user_bcrypt"));
    assert!(htpasswd.user_exists("user_sha256"));
    assert!(htpasswd.user_exists("user_sha512"));
    assert_eq!(htpasswd.user_count(), 3);
}

#[test]
fn test_cli_default_algorithm_is_bcrypt() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Add user without specifying algorithm
    let result = run_htpasswd(
        &["add", file_path.to_str().unwrap(), "alice", "--password"],
        Some("pass123"),
    );
    assert!(result.success);

    // Verify bcrypt was used (hash starts with $2b$)
    let content = std::fs::read_to_string(&file_path).unwrap();
    assert!(
        content.contains("$2b$"),
        "Expected bcrypt hash, got: {}",
        content
    );
}

#[test]
fn test_cli_comments_preserved() {
    let dir = create_test_dir();
    let file_path = dir.path().join("test.htpasswd");

    // Create file with comments
    {
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "# Comment line 1").unwrap();
        writeln!(file, "# Comment line 2").unwrap();
        writeln!(file, "alice:$2b$12$testhash").unwrap();
    }

    // Add another user
    run_htpasswd(
        &["add", file_path.to_str().unwrap(), "bob", "--password"],
        Some("pass456"),
    );

    // Verify comments are preserved
    let content = std::fs::read_to_string(&file_path).unwrap();
    assert!(content.contains("# Comment line 1"));
    assert!(content.contains("# Comment line 2"));
}
