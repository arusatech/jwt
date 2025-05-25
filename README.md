# jwt
## 1. Build
```bash
git clone https://github.com/arusatech/jwt.git
cd jwt
Install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
Install wasm32-wasip1 target
#Ubuntu
sudo apt-get update
sudo apt-get install -y build-essential clang
sudo apt install rustup
sudo apt install wabt
rustup target add wasm32-wasip1
cargo clean
cargo build --target wasm32-wasip1 --release
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


```

## 2. Run
```bash
Update the path of .wasm file in the main.py file
# Initialize JWT client
wasm_path = os.environ.get("WASM_PATH", "/home/ymohammad/rust-wasi-jwt/target/wasm32-wasip1/release/rust_wasi_jwt.wasm")
#Run
cd jwt
uvicorn api.main:app --reload
#in other teerminal send :
curl -X POST "http://localhost:8000/auth/login"   -H "Content-Type: application/json"   -d '{"username": "user123"}'
```

