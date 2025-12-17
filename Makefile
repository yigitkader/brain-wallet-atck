# Makefile for Brainwallet Security Auditor
# Google/Microsoft Enterprise Standards

.PHONY: help build test clean run setup dictionaries docker

# Default target
help:
	@echo "╔═══════════════════════════════════════════════════════════╗"
	@echo "║  🎯 Brainwallet Security Auditor - Build System          ║"
	@echo "╚═══════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Available targets:"
	@echo "  make setup        - Install dependencies and setup environment"
	@echo "  make dictionaries - Download required dictionary files"
	@echo "  make build        - Build release binary"
	@echo "  make test         - Run all tests"
	@echo "  make bench        - Run benchmarks"
	@echo "  make run          - Run the auditor"
	@echo "  make clean        - Clean build artifacts"
	@echo "  make docker       - Build Docker image"
	@echo ""

# Setup development environment
setup:
	@echo "🔧 Setting up development environment..."
	@rustup update stable
	@rustup default stable
	@cargo install cargo-watch
	@cargo install cargo-audit
	@mkdir -p dictionaries output
	@echo "✅ Setup complete!"

# Download required dictionaries
dictionaries:
	@echo "📚 Downloading dictionaries..."
	@mkdir -p dictionaries

	# RockyOU password list (14M passwords)
	# Note: Dictionary will be auto-downloaded by the program with fallback URLs
	@echo "ℹ️  Note: rockyou.txt will be auto-downloaded on first run with fallback URLs"

	# BIP39 English wordlist
	@if [ ! -f dictionaries/bip39-english.txt ]; then \
		echo "Downloading BIP39 wordlist..."; \
		if command -v curl > /dev/null 2>&1; then \
			curl -L --max-time 30 --retry 3 --retry-delay 2 \
				https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt \
				-o dictionaries/bip39-english.txt || \
			(echo "❌ Error: Failed to download BIP39 wordlist"; exit 1); \
		elif command -v wget > /dev/null 2>&1; then \
			wget -q --show-progress --tries=3 --timeout=30 \
				https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt \
				-O dictionaries/bip39-english.txt || \
			(echo "❌ Error: Failed to download BIP39 wordlist"; exit 1); \
		else \
			echo "❌ Error: Neither curl nor wget found. Please install one of them."; \
			exit 1; \
		fi \
	fi

	# Verify downloaded files
	@if [ ! -s dictionaries/bip39-english.txt ]; then \
		echo "❌ Error: BIP39 wordlist is empty or missing"; \
		exit 1; \
	fi

	@echo "✅ Dictionaries ready!"
	@echo "ℹ️  Note: Other dictionaries will be auto-created on first run"

# Build release binary
build:
	@echo "🔨 Building release binary..."
	@cargo build --release
	@echo "✅ Binary: target/release/brainwallet-auditor"

# Build optimized binary
build-optimized:
	@echo "🚀 Building optimized binary..."
	@RUSTFLAGS="-C target-cpu=native" cargo build --release
	@strip target/release/brainwallet-auditor
	@echo "✅ Optimized binary ready!"

# Run tests
test:
	@echo "🧪 Running tests..."
	@cargo test --all
	@echo "✅ All tests passed!"

# Run tests with coverage
test-coverage:
	@echo "📊 Running tests with coverage..."
	@cargo tarpaulin --out Html --output-dir coverage
	@echo "✅ Coverage report: coverage/index.html"

# Run benchmarks
bench:
	@echo "⚡ Running benchmarks..."
	@cargo bench
	@echo "✅ Benchmarks complete!"

# Run the auditor
run:
	@echo "🎯 Starting Brainwallet Security Auditor..."
	@echo "ℹ️  Note: Config file will be auto-generated if missing"
	@cargo run --release

# Run with custom config
run-custom:
	@echo "🎯 Starting with custom config..."
	@if [ ! -f custom-config.toml ]; then \
		echo "❌ Error: custom-config.toml not found"; \
		exit 1; \
	fi
	@cargo run --release -- --config custom-config.toml


# Run in development mode (with auto-reload)
dev:
	@echo "👨‍💻 Starting development mode..."
	@cargo watch -x run

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@cargo clean
	@rm -rf output/*.json
	@echo "✅ Clean complete!"

# Format code
fmt:
	@echo "✨ Formatting code..."
	@cargo fmt --all
	@echo "✅ Code formatted!"

# Lint code
lint:
	@echo "🔍 Linting code..."
	@cargo clippy --all-targets --all-features -- -D warnings
	@echo "✅ Lint passed!"

# Security audit
audit:
	@echo "🔒 Running security audit..."
	@cargo audit
	@echo "✅ Security audit complete!"

# Generate documentation
docs:
	@echo "📖 Generating documentation..."
	@cargo doc --no-deps --open
	@echo "✅ Documentation ready!"

# Docker build
docker:
	@echo "🐳 Building Docker image..."
	@docker build -t brainwallet-auditor:latest .
	@echo "✅ Docker image ready!"

# Docker run
docker-run:
	@echo "🐳 Running Docker container..."
	@docker run --rm -it \
		-v $(PWD)/dictionaries:/app/dictionaries:ro \
		-v $(PWD)/output:/app/output \
		-v $(PWD)/config.toml:/app/config.toml:ro \
		brainwallet-auditor:latest

# Install binary to system
install:
	@echo "📦 Installing binary..."
	@cargo install --path .
	@echo "✅ Installed to ~/.cargo/bin/brainwallet-auditor"

# Create release package
package:
	@echo "📦 Creating release package..."
	@if [ ! -f target/release/brainwallet-auditor ]; then \
		echo "⚠️  Binary not found. Building first..."; \
		make build; \
	fi
	@mkdir -p releases
	@if [ -f LICENSE ]; then \
		tar czf releases/brainwallet-auditor-$(shell git describe --tags 2>/dev/null || echo "v1.0.0").tar.gz \
			target/release/brainwallet-auditor \
			config.toml \
			README.md \
			LICENSE; \
	else \
		tar czf releases/brainwallet-auditor-$(shell git describe --tags 2>/dev/null || echo "v1.0.0").tar.gz \
			target/release/brainwallet-auditor \
			config.toml \
			README.md; \
	fi
	@echo "✅ Package: releases/brainwallet-auditor-$(shell git describe --tags 2>/dev/null || echo "v1.0.0").tar.gz"

# CI/CD targets
ci: setup build test lint audit
	@echo "✅ CI pipeline passed!"


# Check for updates
update:
	@echo "🔄 Checking for updates..."
	@cargo update
	@echo "✅ Dependencies updated!"

# Performance profiling
profile:
	@echo "📊 Running profiler..."
	@cargo build --release
	@perf record -g ./target/release/brainwallet-auditor --max-patterns 1000
	@perf report
	@echo "✅ Profiling complete!"

# Memory check with valgrind
memcheck:
	@echo "🔍 Checking memory usage..."
	@cargo build
	@valgrind --leak-check=full ./target/debug/brainwallet-auditor --max-patterns 100
	@echo "✅ Memory check complete!"
