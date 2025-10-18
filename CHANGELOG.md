# WIRN - Advanced Process Spy Tool

## Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of WIRN process spy tool
- Real-time process monitoring capabilities
- Stealth mode for detection avoidance
- Cross-platform support (Linux, Windows, macOS)
- Multiple output formats (JSON, colored text, plain text)
- File logging with rotation
- Process, user, and command filtering
- Docker support
- Build scripts for all platforms

### Security
- Process name spoofing (Linux)
- Memory footprint minimization
- Anti-analysis techniques
- Timing evasion patterns

## [1.0.0] - 2024-01-15

### Added
- Initial release
- Core process monitoring functionality
- Stealth mode implementation
- Basic filtering capabilities
- Logging system
- Cross-platform builds

### Technical Details
- Built with Go 1.21+
- Uses gopsutil v3 for process monitoring
- Cobra CLI framework for command-line interface
- Color output support with fatih/color
- Docker containerization support

### Performance
- Minimal CPU usage (~1-2%)
- Low memory footprint (~10-20MB)
- Efficient scanning algorithm
- Smart filtering system

### Security Features
- Stealth mode for detection avoidance
- Process name spoofing
- Memory hiding techniques
- Anti-debugging measures
- Resource limiting

### Documentation
- Comprehensive README.md
- Usage examples
- Configuration guide
- Docker deployment instructions
- Contributing guidelines
- License information
