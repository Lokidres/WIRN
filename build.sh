#!/bin/bash

# WIRN Build Script
# Advanced Process Spy Tool - Build automation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Build configuration
BINARY_NAME="wirn"
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS="-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}"

# Build targets
TARGETS=(
    "linux/amd64"
    "linux/arm64"
    "windows/amd64"
    "darwin/amd64"
    "darwin/arm64"
)

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                              WIRN BUILD SCRIPT                            ║${NC}"
echo -e "${BLUE}║                        Advanced Process Spy Tool                          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Go is installed
check_go() {
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed or not in PATH"
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    print_status "Go version: $GO_VERSION"
}

# Clean previous builds
clean_builds() {
    print_status "Cleaning previous builds..."
    rm -rf dist/
    mkdir -p dist/
}

# Download dependencies
download_deps() {
    print_status "Downloading dependencies..."
    go mod download
    go mod tidy
}

# Run tests
run_tests() {
    print_status "Running tests..."
    if go test -v ./...; then
        print_status "All tests passed"
    else
        print_error "Tests failed"
        exit 1
    fi
}

# Build for specific target
build_target() {
    local os=$1
    local arch=$2
    local output_name="${BINARY_NAME}"
    
    if [ "$os" = "windows" ]; then
        output_name="${BINARY_NAME}.exe"
    fi
    
    local output_path="dist/${os}_${arch}/${output_name}"
    
    print_status "Building for ${os}/${arch}..."
    
    GOOS=$os GOARCH=$arch go build \
        -ldflags "${LDFLAGS}" \
        -o "$output_path" \
        main.go
    
    if [ $? -eq 0 ]; then
        print_status "✓ Built: $output_path"
        
        # Create checksum
        if command -v sha256sum &> /dev/null; then
            sha256sum "$output_path" > "${output_path}.sha256"
        elif command -v shasum &> /dev/null; then
            shasum -a 256 "$output_path" > "${output_path}.sha256"
        fi
    else
        print_error "✗ Failed to build: $output_path"
        return 1
    fi
}

# Build all targets
build_all() {
    print_status "Building for all targets..."
    
    for target in "${TARGETS[@]}"; do
        IFS='/' read -r os arch <<< "$target"
        build_target "$os" "$arch"
    done
}

# Build current platform only
build_current() {
    print_status "Building for current platform..."
    go build -ldflags "${LDFLAGS}" -o "${BINARY_NAME}" main.go
    print_status "✓ Built: ${BINARY_NAME}"
}

# Create release package
create_release() {
    print_status "Creating release package..."
    
    cd dist/
    
    for dir in */; do
        if [ -d "$dir" ]; then
            os_arch=$(basename "$dir")
            tar -czf "wirn_${VERSION}_${os_arch}.tar.gz" "$dir"
            print_status "✓ Created: wirn_${VERSION}_${os_arch}.tar.gz"
        fi
    done
    
    cd ..
}

# Security scan
security_scan() {
    print_status "Running security scan..."
    
    if command -v gosec &> /dev/null; then
        gosec ./...
    else
        print_warning "gosec not installed, skipping security scan"
        print_warning "Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"
    fi
}

# Lint code
lint_code() {
    print_status "Running linter..."
    
    if command -v golangci-lint &> /dev/null; then
        golangci-lint run
    else
        print_warning "golangci-lint not installed, skipping linting"
        print_warning "Install with: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"
    fi
}

# Format code
format_code() {
    print_status "Formatting code..."
    go fmt ./...
    print_status "Code formatted"
}

# Show help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  build       Build for current platform only"
    echo "  build-all   Build for all supported platforms"
    echo "  clean       Clean build artifacts"
    echo "  test        Run tests"
    echo "  lint        Run linter"
    echo "  format      Format code"
    echo "  security    Run security scan"
    echo "  release     Create release packages"
    echo "  help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 build"
    echo "  $0 build-all"
    echo "  $0 test && $0 build"
    echo "  $0 release"
}

# Main execution
main() {
    case "${1:-build}" in
        "build")
            check_go
            clean_builds
            download_deps
            run_tests
            build_current
            ;;
        "build-all")
            check_go
            clean_builds
            download_deps
            run_tests
            build_all
            ;;
        "clean")
            clean_builds
            ;;
        "test")
            check_go
            run_tests
            ;;
        "lint")
            check_go
            lint_code
            ;;
        "format")
            check_go
            format_code
            ;;
        "security")
            check_go
            security_scan
            ;;
        "release")
            check_go
            clean_builds
            download_deps
            run_tests
            build_all
            create_release
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
