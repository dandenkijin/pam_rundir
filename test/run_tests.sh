#!/bin/bash
# PAM Rundir Test Script
# Run with: sudo ./run_tests.sh

set -e

# Configuration
TEST_USER="pamtestuser"
TEST_PASS="pamtestpass123"
PAM_CONFIG="/etc/pam.d/sshd"
LOG_FILE="test_results_$(date +%Y%m%d_%H%M%S).log"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Test counter
TESTS_RUN=0
TESTS_PASSED=0

# Helper functions
log() {
    echo -e "$1"
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

run_test() {
    local test_name="$1"
    local test_cmd="$2"
    
    ((TESTS_RUN++))
    log "\n🧪 Running test: $test_name"
    
    if eval "$test_cmd" >> "$LOG_FILE" 2>&1; then
        log "✅ ${GREEN}PASSED: $test_name${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        log "❌ ${RED}FAILED: $test_name${NC}"
        log "💡 Check $LOG_FILE for details"
        return 1
    fi
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Create log file
echo "PAM Rundir Test Results - $(date)" > "$LOG_FILE"

# Check if SSH is running
check_ssh_running() {
    log "Checking if SSH daemon is running..."
    if pgrep -x "sshd" >/dev/null; then
        log "✅ SSH daemon is running"
        return 0
    else
        log "❌ SSH daemon is not running"
        log "   Please start it with: sudo service ssh start"
        return 1
    fi
}

# Function to run a command with error handling
run_command() {
    local cmd="$*"
    log "Running: $cmd"
    output=$($cmd 2>&1)
    local status=$?
    if [ $status -ne 0 ]; then
        log "Command failed with status $status"
        log "Output: $output"
        return $status
    else
        log "Command succeeded"
        log "Output: $output"
        return 0
    fi
}

# Main test function
run_tests() {
    log "🚀 Starting PAM Rundir tests..."
    
    # Check if SSH is running
    if ! check_ssh_running; then
        log "❌ SSH daemon is not running. Please start it before running tests."
        log "   On most systems, you can start it with: sudo service ssh start"
        return 1
    fi
    
    # Test 1: Create test user
    log "\n=== TEST 1: Create test user ==="
    if id -u "$TEST_USER" &>/dev/null; then
        log "Removing existing test user..."
        if ! userdel -r "$TEST_USER" 2>/dev/null; then
            log "❌ Failed to remove existing test user"
            return 1
        fi
    fi
    
    log "Creating test user: $TEST_USER"
    if ! useradd -m "$TEST_USER"; then
        log "❌ Failed to create test user"
        return 1
    fi
    
    if ! echo "$TEST_USER:$TEST_PASS" | chpasswd; then
        log "❌ Failed to set password for test user"
        return 1
    fi
    
    log "✅ Test user created successfully"
    id "$TEST_USER"
    
    # Test 2: Configure PAM
    log "\n=== TEST 2: Configure PAM ==="
    log "Backing up $PAM_CONFIG to ${PAM_CONFIG}.backup"
    if [ ! -f "${PAM_CONFIG}.backup" ]; then
        if ! cp "$PAM_CONFIG" "${PAM_CONFIG}.backup"; then
            log "❌ Failed to back up $PAM_CONFIG"
            return 1
        fi
    fi
    
    log "Configuring PAM to use pam_rundir"
    if ! grep -q 'pam_rundir.so' "$PAM_CONFIG"; then
        log "Adding pam_rundir to $PAM_CONFIG"
        if ! echo "session optional pam_rundir.so" >> "$PAM_CONFIG"; then
            log "❌ Failed to update $PAM_CONFIG"
            return 1
        fi
    else
        log "pam_rundir is already configured in $PAM_CONFIG"
    fi
    
    # Enable debug logging for PAM
    log "Enabling PAM debug logging..."
    echo "session optional pam_rundir.so debug" | sudo tee /etc/pam.d/sshd_rundir_test >/dev/null
    
    # Test 3: Test login and XDG_RUNTIME_DIR
    log "\n=== TEST 3: Test login and XDG_RUNTIME_DIR ==="
    log "Testing SSH login as $TEST_USER..."
    
    # Check if sshpass is installed
    if ! command -v sshpass >/dev/null; then
        log "❌ sshpass is required for testing. Install it with: sudo pacman -S --noconfirm sshpass"
        return 1
    fi
    
    # Get user's home directory
    USER_HOME=$(getent passwd "$TEST_USER" | cut -d: -f6)
    log "User home directory: $USER_HOME"
    
    # Check if PAM module is installed
    if [ ! -f "/lib/security/pam_rundir.so" ]; then
        log "❌ PAM module not found at /lib/security/pam_rundir.so"
        log "   Make sure to run 'sudo make install' in the project root"
        return 1
    fi
    
    # Test direct PAM authentication first
    log "\nTesting PAM authentication directly..."
    if ! echo "$TEST_PASS" | sudo pam_exec -v -d -- "$TEST_USER" 'echo "PAM authentication successful"'; then
        log "❌ PAM authentication failed"
        log "   Check /var/log/auth.log for details"
        return 1
    fi
    
    # Test SSH login and get XDG_RUNTIME_DIR
    log "\nTesting SSH connection..."
    RUNTIME_DIR=$(sshpass -p "$TEST_PASS" ssh -v -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$TEST_USER"@localhost 'echo $XDG_RUNTIME_DIR' 2>>"$LOG_FILE") || {
        log "❌ Failed to SSH as $TEST_USER"
        log "   Make sure password authentication is enabled in /etc/ssh/sshd_config"
        log "   and restart SSH: sudo systemctl restart sshd"
        log "   Debug output has been written to $LOG_FILE"
        return 1
    }
    
    if [ -z "$RUNTIME_DIR" ]; then
        log "❌ XDG_RUNTIME_DIR is not set"
        return 1
    fi
    
    log "✅ XDG_RUNTIME_DIR is set to: $RUNTIME_DIR"
    
    # Test 4: Verify directory exists
    log "\n=== TEST 4: Verify runtime directory exists ==="
    if [ ! -d "$RUNTIME_DIR" ]; then
        log "❌ Runtime directory does not exist: $RUNTIME_DIR"
        return 1
    fi
    log "✅ Runtime directory exists: $RUNTIME_DIR"
    
    # Test 5: Verify permissions
    log "\n=== TEST 5: Verify directory permissions ==="
    local perms=$(stat -c '%a' "$RUNTIME_DIR")
    if [ "$perms" != "700" ]; then
        log "❌ Incorrect permissions on $RUNTIME_DIR (expected 700, got $perms)"
        return 1
    fi
    log "✅ Directory has correct permissions (700)"
    
    # Test 6: Verify ownership
    log "\n=== TEST 6: Verify directory ownership ==="
    local owner=$(stat -c '%U' "$RUNTIME_DIR")
    if [ "$owner" != "$TEST_USER" ]; then
        log "❌ Incorrect ownership of $RUNTIME_DIR (expected $TEST_USER, got $owner)"
        return 1
    fi
    log "✅ Directory is owned by $TEST_USER"
    
    # Test 7: Test concurrent logins
    log "\n=== TEST 7: Test concurrent logins ==="
    log "Starting concurrent login test..."
    {
        sleep 1
        sshpass -p "$TEST_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$TEST_USER"@localhost 'echo "Concurrent login successful"' 2>>"$LOG_FILE"
    } &
    log "✅ Concurrent login test started in background"
    
    # Test 8: Test cleanup on logout
    log "\n=== TEST 8: Test cleanup on logout ==="
    log "Testing cleanup after logout..."
    if ! sshpass -p "$TEST_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$TEST_USER"@localhost 'exit' 2>>"$LOG_FILE"; then
        log "❌ Failed to log out cleanly"
        return 1
    fi
    
    # Give the system a moment to clean up
    sleep 1
    
    if [ -d "$RUNTIME_DIR" ]; then
        log "❌ Runtime directory was not cleaned up: $RUNTIME_DIR"
        return 1
    fi
    log "✅ Runtime directory was cleaned up successfully"
    
    # Test 9: Test error handling (read-only parent directory)
    log "\n=== TEST 9: Test error handling (read-only parent directory) ==="
    local PARENT_DIR="/run/users"
    log "Making $PARENT_DIR read-only..."
    if ! chmod 555 "$PARENT_DIR" 2>>"$LOG_FILE"; then
        log "⚠️  Failed to make $PARENT_DIR read-only (test will be skipped)"
    else
        log "Testing login with read-only parent directory..."
        if sshpass -p "$TEST_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$TEST_USER"@localhost 'echo $XDG_RUNTIME_DIR' 2>>"$LOG_FILE"; then
            log "❌ Login succeeded unexpectedly with read-only parent directory"
            chmod 755 "$PARENT_DIR"
            return 1
        fi
        log "✅ Login failed as expected with read-only parent directory"
        chmod 755 "$PARENT_DIR"
    fi
    
    log "\n✅ All tests completed successfully!"
    return 0
    
    # Cleanup
    log "\n🧹 Cleaning up..."
    
    # Kill any remaining SSH processes
    pkill -u "$TEST_USER" sshd 2>/dev/null || true
    
    # Remove test user
    if id "$TEST_USER" &>/dev/null; then
        userdel -r "$TEST_USER" 2>/dev/null || true
    fi
    
    # Restore PAM config
    if [ -f "${PAM_CONFIG}.backup" ]; then
        mv "${PAM_CONFIG}.backup" "$PAM_CONFIG"
    fi
    
    # Print summary
    log "\n📊 Test Summary:"
    log "Total tests run: $TESTS_RUN"
    log "Tests passed:    $TESTS_PASSED"
    log "Tests failed:    $((TESTS_RUN - TESTS_PASSED))"
    
    if [ "$TESTS_RUN" -eq "$TESTS_PASSED" ]; then
        log "\n🎉 ${GREEN}All tests passed!${NC}"
        exit 0
    else
        log "\n❌ ${RED}Some tests failed. Check $LOG_FILE for details.${NC}"
        exit 1
    fi
}

# Run tests
run_tests

exit 0
