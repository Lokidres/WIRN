# WIRN - Advanced Process Spy Tool

## Contributing Guidelines

Thank you for your interest in contributing to WIRN! Please read these guidelines before submitting any contributions.

### Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Follow professional communication standards
- Respect different viewpoints and experiences

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes**
4. **Add tests** for new functionality
5. **Update documentation** if needed
6. **Commit your changes** (`git commit -m 'Add amazing feature'`)
7. **Push to the branch** (`git push origin feature/amazing-feature`)
8. **Open a Pull Request**

### Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/wirn.git
cd wirn

# Add upstream remote
git remote add upstream https://github.com/original-owner/wirn.git

# Install dependencies
go mod tidy

# Run tests
go test -v ./...

# Build
go build -o wirn main.go
```

### Code Standards

- **Go formatting**: Use `go fmt`
- **Linting**: Follow `golangci-lint` rules
- **Testing**: Write unit tests for new features
- **Documentation**: Update README.md for new features
- **Commit messages**: Use clear, descriptive messages

### Pull Request Guidelines

- **Clear title**: Describe what the PR does
- **Detailed description**: Explain changes and motivation
- **Test coverage**: Include tests for new features
- **Documentation**: Update docs if needed
- **Breaking changes**: Clearly mark any breaking changes

### Issue Guidelines

When reporting issues:
- Use the issue templates
- Provide system information
- Include steps to reproduce
- Attach relevant logs
- Check existing issues first

### Security Issues

For security-related issues:
- **DO NOT** open public issues
- Email security concerns privately
- Include detailed reproduction steps
- Allow time for response before disclosure

### Release Process

- Version numbers follow semantic versioning
- Releases are tagged in git
- Binaries are built for all supported platforms
- Release notes are generated from commits

### Questions?

Feel free to open a discussion or contact the maintainers if you have questions about contributing.
