# SubLynx Makefile — build automation

SHELL := /usr/bin/env bash

# ────────────────────────────────────────────────────────────────
# Config
VERSION     ?= 1.0.0
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BINARY_NAME ?= sublynx
BUILD_DIR   ?= ./bin
DIST_DIR    ?= ./dist
GO          ?= go
CGO_ENABLED ?= 0

# ────────────────────────────────────────────────────────────────
# Flags
LDV      := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE) -s -w
LDFLAGS  := -ldflags "$(LDV)"
PKG_PATH := ./cmd/sublynx

# Default
all: build

# Build local platform
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(PKG_PATH)

# Install to /usr/local/bin (requires sudo)
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)

# Cross-builds (delegates to script)
build-all:
	@echo "Building for all platforms via scripts/build.sh..."
	./scripts/build.sh

# Tests
test:
	@echo "Running tests..."
	$(GO) test ./... -v -cover

test-cover:
	@echo "Running tests with coverage..."
	$(GO) test ./... -coverprofile=coverage.out
	$(GO) tool cover -html=coverage.out

# Hygiene
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR) $(DIST_DIR) coverage.out

fmt:
	@echo "Formatting..."
	$(GO) fmt ./...

vet:
	@echo "Vetting..."
	$(GO) vet ./...

mod-tidy:
	@echo "Tidying modules..."
	$(GO) mod tidy

# Lint (optional; requires golangci-lint)
lint:
	@echo "Linting..."
	golangci-lint run

# Security audit (optional; requires nancy)
audit:
	@echo "Running security audit..."
	$(GO) mod tidy
	$(GO) list -m all | nancy sleuth

# Docs (local godoc server)
docs:
	@echo "Starting godoc on :6060..."
	godoc -http=:6060

# Docker
docker:
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) -t $(BINARY_NAME):latest .

docker-run:
	@echo "Running Docker container..."
	docker run -it --rm -v $(PWD)/reports:/reports $(BINARY_NAME):latest

# Release
release: clean build-all test
	@echo "Preparing release $(VERSION)..."
	mkdir -p $(DIST_DIR)
	cp -r $(BUILD_DIR)/* $(DIST_DIR)/
	@if [ -f LICENSE ]; then cp LICENSE $(DIST_DIR)/; fi
	@if [ -f README.md ]; then cp README.md $(DIST_DIR)/; fi

# Dev tools
dev-tools:
	@echo "Installing dev tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/sonatype-nexus-community/nancy@latest
	go install golang.org/x/tools/cmd/godoc@latest

# Help
help:
	@echo "Targets:"
	@echo "  build        - Build the binary"
	@echo "  install      - Install to /usr/local/bin"
	@echo "  build-all    - Cross-build via scripts/build.sh"
	@echo "  test         - Run tests"
	@echo "  test-cover   - Run tests with coverage report"
	@echo "  clean        - Clean build artifacts"
	@echo "  fmt          - go fmt ./..."
	@echo "  vet          - go vet ./..."
	@echo "  mod-tidy     - go mod tidy"
	@echo "  lint         - golangci-lint run"
	@echo "  audit        - nancy audit"
	@echo "  docs         - local godoc server"
	@echo "  docker       - Build Docker image"
	@echo "  docker-run   - Run Docker container"
	@echo "  release      - Prepare release artifacts"
	@echo "  dev-tools    - Install dev tools"

.PHONY: all build install build-all test test-cover clean fmt vet lint audit docs docker docker-run release dev-tools help mod-tidy
