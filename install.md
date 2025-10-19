# WIRN Installation Guide

Complete installation instructions for WIRN - Enhanced Process Monitor.

## 📋 Prerequisites

### System Requirements

- **Operating System**: Linux (kernel 2.6.13+)
- **Go Version**: 1.21 or higher
- **Privileges**: Root access (sudo)
- **Disk Space**: ~50MB for build dependencies

### Required Tools

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y git make gcc

# CentOS/RHEL/Fedora
sudo dnf install -y git make gcc

# Arch Linux
sudo pacman -S git make gcc
```

## 🚀 Installation Methods

### Method 1: Quick Install (Recommended)

```bash
# Clone repository
git clone https://github.com/Lokidres/WIRN.git
cd WIRN

# One-command install
make deps && make build && sudo make install

# Verify installation
wirn --help
```

### Method 2: Manual Build

```bash
# Clone repository
git clone https://github.com/Lokidres/WIRN.git
cd WIRN

# Download dependencies
go mod download
go mod verify

# Build
go build -ldflags="-s -w" -o wirn .

# Install
sudo cp wirn /usr/local/bin/
sudo chmod +x /usr/local/bin/wirn

# Verify
wirn --help
```

### Method 3: Docker

```bash
# Build image
docker build -t wirn:latest .

# Or pull from registry (if published)
docker pull lokidres/wirn:latest

# Run
docker run --privileged --pid=host wirn:latest
```

### Method 4: Systemd Service

```bash
# Install binary first
make build
sudo make install

# Create log directory
sudo mkdir -p /var/log/wirn
sudo mkdir -p /var/lib/wirn

# Copy systemd service file
sudo cp wirn.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable and start service
sudo systemctl enable wirn
sudo systemctl start wirn

# Check status
sudo systemctl status wirn

# View logs
sudo journalctl -u wirn -f
```

## 🔧 Configuration

### Command Line Flags

Create an alias for your preferred configuration:

```bash
# Add to ~/.bashrc or ~/.zshrc
alias wirn-monitor='sudo wirn -proc -file -net -json -output /var/log/wirn/events.log'

# Reload shell
source ~/.bashrc
```

### Environment Variables

```bash
# Set log level
export WIRN_LOG_LEVEL=debug

# Custom watch directories
export WIRN_WATCH_DIRS="/tmp,/var/tmp,/home"
```

## 📦 Dependencies

WIRN requires the following Go packages:

```
github.com/fsnotify/fsnotify v1.7.0     # File system notifications
github.com/hashicorp/golang-lru/v2 v2.0.7  # LRU cache
github.com/sirupsen/logrus v1.9.3        # Structured logging
```

These are automatically installed by `make deps` or `go mod download`.

## 🔍 Verification

### Test Installation

```bash
# Run basic test
sudo wirn -max 10

# Test with all monitors
sudo wirn -proc -file -net -max 10

# Test JSON output
sudo wirn -json -max 5
```

### Check Version

```bash
wirn -version  # If version flag is implemented
# or
wirn --help | grep Version
```

## 🛠️ Troubleshooting

### Issue: "command not found"

```bash
# Check if installed
which wirn

# If not found, ensure /usr/local/bin is in PATH
echo $PATH

# Add to PATH if needed (add to ~/.bashrc)
export PATH="/usr/local/bin:$PATH"
```

### Issue: "permission denied"

```bash
# WIRN requires root privileges
sudo wirn

# Check binary permissions
ls -la /usr/local/bin/wirn
sudo chmod +x /usr/local/bin/wirn
```

### Issue: "module not found" during build

```bash
# Clean and reinstall dependencies
go clean -modcache
go mod download
go mod tidy

# Rebuild
make clean
make build
```

### Issue: High CPU usage

```bash
# Increase scan interval
sudo wirn -interval 2000

# Disable unnecessary monitors
sudo wirn -proc -net=false -file=false
```

### Issue: systemd service fails to start

```bash
# Check service logs
sudo journalctl -u wirn -n 50

# Check binary permissions
ls -la /usr/local/bin/wirn

# Check service file syntax
systemd-analyze verify wirn.service

# Test binary manually first
sudo /usr/local/bin/wirn -max 10
```

## 🔄 Updating

### Update to Latest Version

```bash
cd WIRN
git pull origin main
make clean
make deps
make build
sudo make install
```

### Restart Service After Update

```bash
sudo systemctl restart wirn
sudo systemctl status wirn
```

## 🗑️ Uninstallation

### Remove Binary

```bash
sudo make uninstall
# or
sudo rm /usr/local/bin/wirn
```

### Remove Systemd Service

```bash
sudo systemctl stop wirn
sudo systemctl disable wirn
sudo rm /etc/systemd/system/wirn.service
sudo systemctl daemon-reload
```

### Clean Build Artifacts

```bash
make clean
rm -rf build/
```

### Remove Logs

```bash
sudo rm -rf /var/log/wirn
sudo rm -rf /var/lib/wirn
```

## 🌐 Platform-Specific Notes

### Ubuntu/Debian

```bash
# Install dependencies
sudo apt-get install -y golang-1.21 git make gcc

# May need to link go
sudo ln -s /usr/lib/go-1.21/bin/go /usr/local/bin/go
```

### CentOS/RHEL 8+

```bash
# Enable Go module
sudo dnf install -y go-toolset git make gcc

# Build and install
make deps build
sudo make install
```

### Arch Linux

```bash
# Install from AUR (if package exists)
yay -S wirn-bin

# Or build manually
sudo pacman -S go git make gcc
make deps build
sudo make install
```

## 🔐 Security Considerations

### File Permissions

```bash
# Set appropriate permissions for log files
sudo chmod 640 /var/log/wirn/events.log
sudo chown root:root /var/log/wirn/events.log
```

### SELinux Considerations

```bash
# If SELinux is enabled
sudo chcon -t bin_t /usr/local/bin/wirn
sudo semanage fcontext -a -t var_log_t "/var/log/wirn(/.*)?"
sudo restorecon -R /var/log/wirn
```

### AppArmor Considerations

```bash
# May need to adjust AppArmor profile
sudo aa-complain /usr/local/bin/wirn
```

## 📚 Additional Resources

- **Documentation**: [README.md](README.md)
- **Issue Tracker**: [GitHub Issues](https://github.com/Lokidres/WIRN/issues)
- **Makefile Commands**: Run `make help` for all available commands

## ✅ Post-Installation Checklist

- [ ] Binary installed and executable
- [ ] Root/sudo access verified
- [ ] Test run completed successfully
- [ ] Logs being written (if configured)
- [ ] Systemd service running (if configured)
- [ ] Monitoring working as expected

## 🤝 Need Help?

If you encounter issues not covered here:

1. Check the [README.md](README.md) for usage examples
2. Run `make help` for build commands
3. Open an issue on [GitHub](https://github.com/Lokidres/WIRN/issues)
4. Include system info, error messages, and steps to reproduce

---

**Installation complete! Run `sudo wirn` to start monitoring.** 🎉
