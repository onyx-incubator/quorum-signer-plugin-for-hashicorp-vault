# Refactored Makefile for better readability and maintainability

# Variables
CURDIR := $(CURDIR)
OUTPUT_DIR := $(CURDIR)/build
DIST_DIR := $(OUTPUT_DIR)/dist
NAME := quorum-signer
VERSION := 0.2.2-SNAPSHOT
OS_ARCH := $(shell go env GOOS)-$(shell go env GOARCH)
BIN_PATH := $(DIST_DIR)/$(NAME)-$(VERSION)-$(OS_ARCH)
BUILD_LD_FLAGS := -s -w $(extraldflags)

# Phony targets
.PHONY: all default clean check-fmt fixfmt test build package tools govulncheck

all: clean tools check-fmt fixfmt test build package govulncheck

default: all

# Clean build artifacts
clean:
	@echo -------- Deleting build artifacts --------
	@rm -rf $(OUTPUT_DIR)
    @echo ==\> Cleaned $(OUTPUT_DIR)

# Check Go formatting
check-fmt: tools
	@echo -------- Checking Go formatting --------
	@GO_FMT_FILES="$(shell goimports -l $(shell find . -type f -name '*.go'))"; \
	test -z "$$GO_FMT_FILES" || ( echo "Please run 'make fixfmt' to format the following files:\n$$GO_FMT_FILES"; exit 1 )
	@echo ==\> All Go files are properly formatted

# Fix Go formatting
fixfmt: tools
	@echo -------- Fixing Go formatting --------
	@goimports -w $(shell find . -type f -name '*.go')
	@echo ==\> Go files have been formatted

# Run tests
 test:
	@echo -------- Running tests --------
	GOFLAGS="-mod=readonly" go test ./...

# Build binary
build:
	@echo -------- Building binary\(ies\) --------
	@mkdir -p $(DIST_DIR)
	@echo ==\> Output to $(DIST_DIR)
	@GOFLAGS="-mod=readonly" go build \
		-ldflags='$(BUILD_LD_FLAGS)' \
		-o $(BIN_PATH) \
		.
	@echo ==\> Built $(BIN_PATH)

# Package binary and checksums
package: build
	@echo -------- Packaging binary\(ies\) --------
	@echo ==\> Creating checksum files
	@shasum -a 256 $(BIN_PATH) | awk '{print $$1}' > $(BIN_PATH).checksum
	@echo ==\> Creating zip archive
	@zip -j -FS -q $(BIN_PATH).zip $(DIST_DIR)/*
	@echo ==\> Creating zip checksum file
	@shasum -a 256 $(BIN_PATH).zip | awk '{print $$1}' > $(BIN_PATH).zip.checksum
	@echo ==\> Packaged $(BIN_PATH).zip and checksum files

# Ensure goimports is available
 tools:
	@echo -------- Ensuring required tools are installed --------
	@command -v goimports >/dev/null 2>&1 || { echo >&2 "goimports not installed. Installing..."; go install golang.org/x/tools/cmd/goimports@latest; }
	@echo ==\> All required tools are installed

# Run govulncheck (Go vulnerability scanner)
govulncheck: tools
	@echo -------- Running govulncheck \(golang vulnerability scanner\) --------
	@command -v govulncheck >/dev/null 2>&1 || { echo >&2 "govulncheck not installed. Installing..."; go install golang.org/x/vuln/cmd/govulncheck@latest; }
	@govulncheck ./...
	@echo ==\> govulncheck completed
