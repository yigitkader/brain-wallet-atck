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
	@if [ ! -f dictionaries/rockyou.txt ]; then \
		echo "Downloading rockyou.txt..."; \
		wget -q --show-progress https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt \
			-O dictionaries/rockyou.txt; \
	fi

	# BIP39 English wordlist
	@if [ ! -f dictionaries/bip39-english.txt ]; then \
		echo "Downloading BIP39 wordlist..."; \
		wget -q --show-progress https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt \
			-O dictionaries/bip39-english.txt; \
	fi

	# Create sample dictionaries
	@./scripts/generate_sample_dicts.sh

	@echo "✅ Dictionaries ready!"

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
	@cargo run --release

# Run with custom config
run-custom:
	@echo "🎯 Starting with custom config..."
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
	@mkdir -p releases
	@tar czf releases/brainwallet-auditor-$(shell git describe --tags).tar.gz \
		target/release/brainwallet-auditor \
		config.toml \
		README.md \
		LICENSE
	@echo "✅ Package: releases/brainwallet-auditor-$(shell git describe --tags).tar.gz"

# CI/CD targets
ci: setup build test lint audit
	@echo "✅ CI pipeline passed!"

# Generate sample config
config:
	@echo "⚙️ Generating default config..."
	@./target/release/brainwallet-auditor --generate-config > config.toml
	@echo "✅ Config saved to config.toml"

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
