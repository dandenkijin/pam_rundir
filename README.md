
# pam_rundir: Provide user runtime directory

pam_rundir is a PAM module that provides per-user runtime directories as specified in the XDG Base Directory Specification. It automatically creates a runtime directory for each user at login and removes it at logout, setting the `XDG_RUNTIME_DIR` environment variable accordingly.

## Features

- Creates user-specific runtime directories (typically under `/run/user/UID`)
- Sets `XDG_RUNTIME_DIR` environment variable
- Handles concurrent logins safely
- Configurable directory location and permissions
- Secure permissions (0700 by default)
- Automatic cleanup on logout

## Installation

### Prerequisites

- Linux system with PAM (Pluggable Authentication Modules)
- Standard C library development files
- PAM development files (typically `libpam0g-dev` on Debian/Ubuntu or `pam-devel` on RHEL/CentOS)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/jjk-jacky/pam_rundir.git
cd pam_rundir

# Configure the build
./configure

# Build the module
make

# Install (as root)
sudo make install
```

This will install:
- PAM module to `/lib/security/pam_rundir.so`
- Man page to `/usr/share/man/man8/pam_rundir.8.gz`

## Configuration

### PAM Configuration

Add the following line to the appropriate PAM configuration file (e.g., `/etc/pam.d/sshd` or `/etc/pam.d/login`):

```
session    required     pam_rundir.so
```

### Configuration Options

pam_rundir supports the following options:

- `debug` - Enable debug logging to syslog
- `umask=0XXX` - Set directory permissions (default: 0700)
- `dir=PATH` - Base directory for runtime directories (default: `/run/user`)
- `envvar=NAME` - Environment variable name (default: `XDG_RUNTIME_DIR`)

Example with custom options:
```
session    required     pam_rundir.so debug dir=/var/run/user umask=0077
```

## Usage

Once configured, the module will automatically create and manage the runtime directory. Users can access their runtime directory path via the `XDG_RUNTIME_DIR` environment variable:

```bash
echo $XDG_RUNTIME_DIR
# Output: /run/user/1000
```

### Verifying Installation

1. Check if the module is loaded in PAM stack:
   ```bash
   grep pam_rundir /etc/pam.d/*
   ```

2. Check system logs for any errors:
   ```bash
   journalctl -u ssh -f  # For SSH logins
   ```

3. Test the session by logging in and verifying the environment:
   ```bash
   ssh localhost env | grep XDG_RUNTIME_DIR
   ```

## Troubleshooting

- **Directory not created**: Check PAM logs and ensure the module is properly installed and configured
- **Permission denied**: Verify the parent directory is writable by root
- **Environment variable not set**: Check PAM configuration and ensure the module is called with `pam_env`

## Security Considerations

- The runtime directory is created with 0700 permissions by default
- Only the owner has access to their runtime directory
- The directory is automatically removed on logout
- Running with elevated privileges is required for directory creation

## Free Software

pam_rundir - Copyright (C) 2015-2025 Olivier Brunel <jjk@jjacky.com>

pam_rundir is free software: you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 2 of the License, or (at your option) any later
version.

pam_rundir is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
pam_rundir (COPYING). If not, see http://www.gnu.org/licenses/

## Documentation

For more detailed information, see the man page:

```bash
man 8 pam_rundir
```

## Resources

- [Official Site](http://jjacky.com/pam_rundir)
- [Source Code & Issue Tracker](https://github.com/jjk-jacky/pam_rundir)
- [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html)
