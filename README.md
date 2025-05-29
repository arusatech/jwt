# JWT Authentication Service

A high-performance JWT (JSON Web Token) authentication service built using Rust and WebAssembly (WASM), with a Python FastAPI interface.

## Features

- Secure JWT token generation and validation using industry-standard algorithms
- High-performance implementation with Rust compiled to WebAssembly
- Python FastAPI interface for easy integration
- Load-test ready with Vegeta support

## Prerequisites

- Rust toolchain with `wasm32-wasip1` target
- Python 3.7+
- Vegeta (for load testing)

## 1. Setup & Build

### Install Rust and WASM target
```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install wasm32-wasip1 target
rustup target add wasm32-wasip1

# Install dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y build-essential clang wabt
```

### Clone and build the project
```bash
# Clone repository
git clone https://github.com/arusatech/jwt.git
cd jwt

# Build WASM module
cargo build --target wasm32-wasip1 --release && mkdir -p libs/jwt/wasm && cp target/wasm32-wasip1/release/rust_wasi_jwt.wasm libs/jwt/wasm/

# Setup Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 2. Run the Service

```bash
# Start the FastAPI server
uvicorn api.main:app --reload

# Test with curl (in another terminal)
curl -X POST "http://localhost:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"username": "user123"}'
```

## 3. Load Testing

The service can be load tested using Vegeta. First, install Vegeta:

### Install Vegeta
```bash
# Ubuntu/Debian
sudo apt-get install vegeta

# macOS
brew install vegeta

# Or download binary from https://github.com/tsenart/vegeta/releases
```

### Run load test
```bash
# Create targets.txt file
cat > targets.txt << 'EOF'
POST http://localhost:8000/auth/login
Content-Type: application/json

{"username": "user1"}

POST http://localhost:8000/auth/login
Content-Type: application/json

{"username": "user2"}

POST http://localhost:8000/auth/login
Content-Type: application/json

{"username": "user3"}
EOF

# Run the load test
vegeta attack -targets=targets.txt -rate=10000 -duration=30s | vegeta report
```

## Project Structure

- `libs/jwt/src/` - Core Rust JWT implementation
- `api/` - Python FastAPI server implementation
- `libs/jwt/wasm/` - Compiled WebAssembly modules

## Implementation Details

The project uses the `jsonwebtoken` Rust library for secure token generation and validation. The Rust code is compiled to WebAssembly for high performance and seamless integration with Python.

## Configuration

The WASM module path can be configured via environment variable:

```bash
export WASM_PATH="/path/to/rust_wasi_jwt.wasm"
uvicorn api.main:app --reload
```

## License

[License details]

