#!/usr/bin/env bash
# Apache htpasswd compatibility test script
#
# Tests bidirectional compatibility between htauth and Apache htpasswd.
# Requires /usr/bin/htpasswd to be available.

set -euo pipefail

APACHE_HTPASSWD="/usr/bin/htpasswd"

# Colors for output
readonly GREEN='\033[0;32m'
readonly RED='\033[0;31m'
readonly YELLOW='\033[0;33m'
readonly NC='\033[0m' # No Color

PASSED=0
FAILED=0

# === Helper functions ===

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASSED++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAILED++))
}

# Check prerequisites
check_prerequisites() {
    if [[ ! -x "$APACHE_HTPASSWD" ]]; then
        log_info "Apache htpasswd not found at $APACHE_HTPASSWD, skipping tests"
        exit 3
    fi
    log_info "Found Apache htpasswd at $APACHE_HTPASSWD"
}

# Create temporary directory
TEST_DIR=$(mktemp -d)
trap "rm -rf '$TEST_DIR'" EXIT

# Run our htauth CLI with password from stdin
run_htauth() {
    local password="$1"
    shift
    echo "$password" | cargo run --quiet --bin htauth -- "$@"
}

# Run Apache htpasswd
run_apache() {
    "$APACHE_HTPASSWD" "$@" 2>&1
}

# Count users in htpasswd file using our CLI
count_users() {
    local file="$1"
    cargo run --quiet --bin htauth -- list "$file" 2>/dev/null | wc -l
}

# Check if hash prefix exists in file (using fixed string match)
has_hash_prefix() {
    local file="$1"
    local prefix="$2"
    grep -qF "$prefix" "$file"
}

# === Test 1: Our tool can read Apache htpasswd files ===

test_apache_bcrypt_read() {
    log_info "Testing: Read Apache-created bcrypt file"
    local file="$TEST_DIR/apache_bcrypt.htpasswd"

    run_apache -cBb "$file" alice testpass123 >/dev/null
    run_apache -Bb "$file" bob testpass456 >/dev/null

    # Verify users exist and passwords work using our CLI
    if run_htauth testpass123 verify "$file" alice --password >/dev/null 2>&1 && \
       run_htauth testpass456 verify "$file" bob --password >/dev/null 2>&1 && \
       ! run_htauth wrongpass verify "$file" alice --password >/dev/null 2>&1; then
        log_pass "Apache bcrypt file read correctly"
    else
        log_fail "Apache bcrypt file read failed"
        return 1
    fi
}

test_apache_sha256_read() {
    log_info "Testing: Read Apache-created SHA-256 file"
    local file="$TEST_DIR/apache_sha256.htpasswd"

    run_apache -c2b "$file" alice testpass123 >/dev/null
    run_apache -2b "$file" bob testpass456 >/dev/null

    # Verify users exist and passwords work
    if run_htauth testpass123 verify "$file" alice --password >/dev/null 2>&1 && \
       run_htauth testpass456 verify "$file" bob --password >/dev/null 2>&1 && \
       has_hash_prefix "$file" '$5$'; then
        log_pass "Apache SHA-256 file read correctly"
    else
        log_fail "Apache SHA-256 file read failed"
        return 1
    fi
}

test_apache_sha512_read() {
    log_info "Testing: Read Apache-created SHA-512 file"
    local file="$TEST_DIR/apache_sha512.htpasswd"

    run_apache -c5b "$file" alice testpass123 >/dev/null
    run_apache -5b "$file" bob testpass456 >/dev/null

    # Verify users exist and passwords work
    if run_htauth testpass123 verify "$file" alice --password >/dev/null 2>&1 && \
       run_htauth testpass456 verify "$file" bob --password >/dev/null 2>&1 && \
       has_hash_prefix "$file" '$6$'; then
        log_pass "Apache SHA-512 file read correctly"
    else
        log_fail "Apache SHA-512 file read failed"
        return 1
    fi
}

test_apache_md5_read() {
    log_info "Testing: Read Apache-created APR1-MD5 file"
    local file="$TEST_DIR/apache_md5.htpasswd"

    run_apache -cmb "$file" alice testpass123 >/dev/null
    run_apache -mb "$file" bob testpass456 >/dev/null

    # Verify users exist and passwords work
    if run_htauth testpass123 verify "$file" alice --password >/dev/null 2>&1 && \
       run_htauth testpass456 verify "$file" bob --password >/dev/null 2>&1 && \
       has_hash_prefix "$file" '$apr1$'; then
        log_pass "Apache APR1-MD5 file read correctly"
    else
        log_fail "Apache APR1-MD5 file read failed"
        return 1
    fi
}

# === Test 2: Apache htpasswd can read our files ===

test_our_bcrypt_with_apache_verify() {
    log_info "Testing: Apache can verify our bcrypt entry"
    local file="$TEST_DIR/our_bcrypt.htpasswd"

    run_htauth testpass123 add "$file" alice --password >/dev/null 2>&1

    # Verify with Apache htpasswd
    if run_apache -vb "$file" alice testpass123 >/dev/null 2>&1 && \
       ! run_apache -vb "$file" alice wrongpass >/dev/null 2>&1; then
        log_pass "Apache can verify our bcrypt entry"
    else
        log_fail "Apache bcrypt verification failed"
        return 1
    fi
}

test_our_sha256_with_apache_verify() {
    log_info "Testing: Apache can verify our SHA-256 entry"
    local file="$TEST_DIR/our_sha256.htpasswd"

    run_htauth testpass123 add "$file" alice --algorithm sha256 --password >/dev/null 2>&1

    # Verify with Apache htpasswd (using -v2 for SHA-256)
    if run_apache -v2b "$file" alice testpass123 >/dev/null 2>&1; then
        log_pass "Apache can verify our SHA-256 entry"
    else
        log_fail "Apache SHA-256 verification failed"
        return 1
    fi
}

test_our_sha512_with_apache_verify() {
    log_info "Testing: Apache can verify our SHA-512 entry"
    local file="$TEST_DIR/our_sha512.htpasswd"

    run_htauth testpass123 add "$file" alice --algorithm sha512 --password >/dev/null 2>&1

    # Verify with Apache htpasswd (using -v5 for SHA-512)
    if run_apache -v5b "$file" alice testpass123 >/dev/null 2>&1; then
        log_pass "Apache can verify our SHA-512 entry"
    else
        log_fail "Apache SHA-512 verification failed"
        return 1
    fi
}

test_our_md5_with_apache_verify() {
    log_info "Testing: Apache can verify our APR1-MD5 entry"
    local file="$TEST_DIR/our_md5.htpasswd"

    run_htauth testpass123 add "$file" alice --algorithm md5 --password >/dev/null 2>&1

    # Verify with Apache htpasswd (using -vm for APR1-MD5)
    if run_apache -vmb "$file" alice testpass123 >/dev/null 2>&1; then
        log_pass "Apache can verify our APR1-MD5 entry"
    else
        log_fail "Apache APR1-MD5 verification failed"
        return 1
    fi
}

# === Test 3: Mixed file compatibility ===

test_mixed_file_compatibility() {
    log_info "Testing: Mixed file with entries from both tools"
    local file="$TEST_DIR/mixed.htpasswd"

    # Apache - bcrypt
    run_apache -cBb "$file" apache_bcrypt pass1 >/dev/null 2>&1

    # Our tool - SHA-256
    run_htauth pass2 add "$file" our_sha256 --algorithm sha256 --password >/dev/null 2>&1

    # Apache - SHA-512
    run_apache -5b "$file" apache_sha512 pass3 >/dev/null 2>&1

    # Our tool - bcrypt
    run_htauth pass4 add "$file" our_bcrypt --password >/dev/null 2>&1

    # Apache - MD5
    run_apache -mb "$file" apache_md5 pass5 >/dev/null 2>&1

    # Our tool - MD5
    run_htauth pass6 add "$file" our_md5 --algorithm md5 --password >/dev/null 2>&1

    # Verify user count
    local count
    count=$(count_users "$file")
    if [[ $count -ne 6 ]]; then
        log_fail "Mixed file has wrong user count: $count (expected 6)"
        return 1
    fi

    # Verify all users with our CLI
    if ! run_htauth pass1 verify "$file" apache_bcrypt --password >/dev/null 2>&1 || \
       ! run_htauth pass2 verify "$file" our_sha256 --password >/dev/null 2>&1 || \
       ! run_htauth pass3 verify "$file" apache_sha512 --password >/dev/null 2>&1 || \
       ! run_htauth pass4 verify "$file" our_bcrypt --password >/dev/null 2>&1 || \
       ! run_htauth pass5 verify "$file" apache_md5 --password >/dev/null 2>&1 || \
       ! run_htauth pass6 verify "$file" our_md5 --password >/dev/null 2>&1; then
        log_fail "Mixed file verification with our CLI failed"
        return 1
    fi

    # Verify selected users with Apache htpasswd
    if ! run_apache -vb "$file" apache_bcrypt pass1 >/dev/null 2>&1 || \
       ! run_apache -v5b "$file" apache_sha512 pass3 >/dev/null 2>&1 || \
       ! run_apache -vb "$file" our_bcrypt pass4 >/dev/null 2>&1 || \
       ! run_apache -vmb "$file" apache_md5 pass5 >/dev/null 2>&1 || \
       ! run_apache -vmb "$file" our_md5 pass6 >/dev/null 2>&1; then
        log_fail "Mixed file verification with Apache htpasswd failed"
        return 1
    fi

    log_pass "Mixed file compatibility test passed"
}

# === Main test runner ===

main() {
    echo "=========================================="
    echo "Apache htpasswd Compatibility Tests"
    echo "=========================================="
    echo ""

    check_prerequisites
    echo ""

    # Run all tests
    test_apache_bcrypt_read || true
    test_apache_sha256_read || true
    test_apache_sha512_read || true
    test_apache_md5_read || true
    echo ""

    test_our_bcrypt_with_apache_verify || true
    test_our_sha256_with_apache_verify || true
    test_our_sha512_with_apache_verify || true
    test_our_md5_with_apache_verify || true
    echo ""

    test_mixed_file_compatibility || true
    echo ""

    # Print summary
    echo "=========================================="
    echo "Test Summary"
    echo "=========================================="
    echo -e "${GREEN}Passed:${NC} $PASSED"
    if [[ $FAILED -gt 0 ]]; then
        echo -e "${RED}Failed:${NC} $FAILED"
        exit 1
    else
        echo -e "${GREEN}Failed:${NC} $FAILED"
        echo ""
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

main
