# ===========================================================================
# Dockerfile
# ===========================================================================

FROM rust:1.75-slim as builder

WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy source
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build release
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary
COPY --from=builder /app/target/release/brainwallet-auditor /usr/local/bin/

# Create directories
RUN mkdir -p /app/dictionaries /app/output

# Set entrypoint
ENTRYPOINT ["brainwallet-auditor"]
CMD ["--help"]
