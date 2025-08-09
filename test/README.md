# PAM Rundir Test Suite

This directory contains the test suite for the PAM Rundir module. The test suite verifies the functionality, security, and reliability of the PAM module.

## Prerequisites

- Linux system with PAM support
- Root/sudo access
- SSH server installed and running
- The following packages installed:
  ```bash
  sudo apt-get update
  sudo apt-get install -y build-essential libpam0g-dev sshpass
  ```

## Test Files

- `run_tests.sh`: Main test script that automates the testing process
- `test_results_*.log`: Log files generated during test execution

## Running Tests

1. **Build and install** the PAM module:
   ```bash
   cd ..
   ./configure
   make
   sudo make install
   ```

2. **Run the test suite** (as root):
   ```bash
   cd test
   chmod +x run_tests.sh
   sudo ./run_tests.sh
   ```

3. **View test results**:
   - The script will display colored output in the terminal
   - Detailed logs are saved to `test_results_*.log`

## Test Coverage

The test suite verifies:

1. **Basic Functionality**
   - User login and session creation
   - XDG_RUNTIME_DIR environment variable
   - Directory creation with correct permissions

2. **Security**
   - Proper file permissions (700)
   - Correct ownership
   - Protection against symlink attacks
   - Prevention of privilege escalation

3. **Error Handling**
   - Read-only parent directory
   - Full filesystem
   - Invalid configurations

4. **Concurrency**
   - Multiple simultaneous logins
   - Proper cleanup on logout

## Manual Testing

For additional verification, you can manually test the module:

1. Create a test user:
   ```bash
   sudo useradd -m testuser
   sudo passwd testuser
   ```

2. Configure PAM to use the module:
   ```bash
   echo "session optional pam_rundir.so" | sudo tee -a /etc/pam.d/sshd
   ```

3. Log in via SSH and verify:
   ```bash
   ssh testuser@localhost
   echo $XDG_RUNTIME_DIR
   ls -ld $XDG_RUNTIME_DIR
   ```

## Troubleshooting

1. If tests fail, check the log file for details:
   ```bash
   sudo cat test_results_*.log
   ```

2. Check system logs for PAM-related messages:
   ```bash
   sudo journalctl -u ssh -f
   ```

3. Verify PAM configuration:
   ```bash
   sudo pam-auth-update
   ```

## Cleanup

The test script automatically cleans up after itself. To manually clean up:

```bash
sudo userdel -r testuser 2>/dev/null || true
sudo rm -f /etc/pam.d/sshd.backup
```

## Security Note

- Always test in a controlled environment
- The test script creates a test user with a known password
- The script modifies PAM configuration - always review the changes before running
