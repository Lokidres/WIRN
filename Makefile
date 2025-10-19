BINARY_NAME=wirn
BUILD_DIR=build
INSTALL_DIR=/usr/local/bin

VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

.PHONY: all build clean install uninstall test run help

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) main.go
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

build-all:
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 main.go
	@GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 main.go
	@GOOS=linux GOARCH=arm go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-armv7 main.go
	@echo "Multi-platform build complete"

install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_DIR)..."
	@sudo cp $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/
	@sudo chmod +x $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Installation complete"

uninstall:
	@echo "Removing $(BINARY_NAME) from $(INSTALL_DIR)..."
	@sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Uninstallation complete"

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"

test:
	@echo "Running tests..."
	@go test -v ./...

run: build
	@$(BUILD_DIR)/$(BINARY_NAME)

run-suspicious: build
	@$(BUILD_DIR)/$(BINARY_NAME) -suspicious

run-all: build
	@$(BUILD_DIR)/$(BINARY_NAME) -file -net

help:
	@echo "WIRN - Makefile Commands"
	@echo ""
	@echo "  make build          - Build the binary"
	@echo "  make build-all      - Build for multiple platforms"
	@echo "  make install        - Install to $(INSTALL_DIR)"
	@echo "  make uninstall      - Remove from $(INSTALL_DIR)"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make test           - Run tests"
	@echo "  make run            - Build and run"
	@echo "  make run-suspicious - Run with suspicious mode"
	@echo "  make run-all        - Run with all features"
	@echo "  make help           - Show this help message"