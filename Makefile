# Makefile for Quorum Signer Plugin for HashiCorp Vault
# Improved version with better error handling and maintainability

# Shell configuration for better error handling
SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

# Variables (can be overridden)
GO ?= go
NAME ?= quorum-signer
VERSION ?= 0.2.2-SNAPSHOT
OUTPUT_DIR ?= build
DIST_DIR := $(OUTPUT_DIR)/dist
OS_ARCH := $(shell $(GO) env GOOS)-$(shell $(GO) env GOARCH)
BIN_PATH := $(DIST_DIR)/$(NAME)-$(VERSION)-$(OS_ARCH)
BUILD_LD_FLAGS ?= -s -w $(extraldflags)

# Phony targets
.PHONY: all deploy dev default clean clean-cache tools go-vulncheck go-sec go-vet check-fmt fixfmt test build package help

# Default target
default: deploy

# Main targets
all: deploy
deploy: clean tools go-vulncheck go-sec go-vet test build package
dev: clean clean-cache tools go-vulncheck go-sec go-vet check-fmt fixfmt test build package

# Clean build artifacts
clean:
	@echo "-------- Deleting build artifacts --------"
	@rm -rf $(OUTPUT_DIR)
	@echo "==> Cleaned $(OUTPUT_DIR)"

# Clean Go build and test caches
clean-cache:
	@echo "-------- Cleaning Go build and test caches --------"
	@$(GO) clean -cache -testcache
	@echo "==> Go build and test caches cleaned"

# Check Go formatting
check-fmt: tools
	@echo "-------- Checking Go formatting --------"
	@set -e; \
	GO_FMT_FILES="$$(goimports -l $$(find . -type f -name '*.go' 2>/dev/null || true))"; \
	if [ -n "$$GO_FMT_FILES" ]; then \
		echo "Please run 'make fixfmt' to format the following files:"; \
		echo "$$GO_FMT_FILES"; \
		exit 1; \
	fi
	@echo "==> All Go files are properly formatted"

# Fix Go formatting
fixfmt: tools
	@echo "-------- Fixing Go formatting --------"
	@find . -type f -name '*.go' -exec goimports -w {} + 2>/dev/null || true
	@echo "==> Go files have been formatted"

# Run tests
test:
	@echo "-------- Running tests --------"
	@GOFLAGS="-mod=readonly" $(GO) test ./...
	@echo "==> Tests completed successfully"

# Build binary
build:
	@echo "-------- Building binary(ies) --------"
	@mkdir -p $(DIST_DIR)
	@echo "==> Output to $(DIST_DIR)"
	@GOFLAGS="-mod=readonly" $(GO) build \
		-ldflags='$(BUILD_LD_FLAGS)' \
		-o $(BIN_PATH) \
		-race \
		.
	@echo "==> Built $(BIN_PATH)"

# Package binary and checksums
package: build
	@echo "-------- Packaging binary(ies) --------"
	@echo "==> Creating checksum files"
	@shasum -a 256 $(BIN_PATH) | awk '{print $$1}' > $(BIN_PATH).checksum
	@echo "==> Creating zip archive"
	@zip -j -FS -q $(BIN_PATH).zip $(DIST_DIR)/*
	@echo "==> Creating zip checksum file"
	@shasum -a 256 $(BIN_PATH).zip | awk '{print $$1}' > $(BIN_PATH).zip.checksum
	@echo "==> Packaged $(BIN_PATH).zip and checksum files"

# Ensure required tools are available
tools:
	@echo "-------- Ensuring required tools are installed --------"
	@command -v goimports >/dev/null 2>&1 || { \
		echo "goimports not installed. Installing..."; \
		$(GO) install golang.org/x/tools/cmd/goimports@latest; \
	}
	@echo "==> All required tools are installed"

# Run govulncheck (Go vulnerability scanner)
go-vulncheck: tools
	@echo "-------- Running govulncheck (Go vulnerability scanner) --------"
	@command -v govulncheck >/dev/null 2>&1 || { \
		echo "govulncheck not installed. Installing..."; \
		$(GO) install golang.org/x/vuln/cmd/govulncheck@latest; \
	}
	@govulncheck ./...
	@echo "==> govulncheck completed successfully"

# Run gosec (Go security scanner)
go-sec: tools
	@echo "-------- Running gosec (Go security scanner) --------"
	@command -v gosec >/dev/null 2>&1 || { \
		echo "gosec not installed. Installing..."; \
		$(GO) install github.com/securego/gosec/v2/cmd/gosec@latest; \
	}
	@gosec -quiet -fmt json -tests ./...
	@echo "==> gosec completed successfully"

# Run go vet
go-vet:
	@echo "-------- Running go vet --------"
	@$(GO) vet -c=25 ./...
	@echo "==> go vet completed successfully"

# Display help information
help:
	@echo "Available targets:"
	@echo "  all        - Same as deploy"
	@echo "  deploy     - Full build pipeline: clean, security checks, test, build, package"
	@echo "  dev        - Development pipeline: includes formatting checks and cache cleaning"
	@echo "  clean      - Remove build artifacts"
	@echo "  clean-cache- Clean Go build and test caches"
	@echo "  test       - Run tests"
	@echo "  build      - Build the binary"
	@echo "  package    - Package the binary with checksums"
	@echo "  check-fmt  - Check Go code formatting"
	@echo "  fixfmt     - Fix Go code formatting"
	@echo "  go-vet     - Run go vet"
	@echo "  go-sec     - Run gosec security scanner"
	@echo "  go-vulncheck - Run vulnerability scanner"
	@echo "  tools      - Install required tools"
	@echo "  help       - Show this help message"
