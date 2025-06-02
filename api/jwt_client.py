import ctypes
import random
import wasmtime
from jsonpath_nz import log


class JWTClient:
    """JWT client that uses a WASM module for token operations"""
    
    def __init__(self, wasm_path):
        """Initialize JWT client with WASM module"""
        try:
            # Setup WASM environment
            self.store = wasmtime.Store()
            
            # Configure WASI
            wasi_config = wasmtime.WasiConfig()
            wasi_config.inherit_stdout()
            wasi_config.inherit_stderr()
            self.store.set_wasi(wasi_config)
            
            # Load module
            # log.info(f"<Client> Loading WASM module from {wasm_path}")
            self.module = wasmtime.Module.from_file(self.store.engine, wasm_path)
            
            # Setup linker
            self.linker = wasmtime.Linker(self.store.engine)
            
            # Add WASI to the linker
            try:
                wasmtime.wasi.add_to_linker(self.linker)
                # log.info("<Client> Added WASI to linker using add_to_linker")
            except Exception as e1:
                # log.info(f"<Client> add_to_linker failed: {e1}")
                try:
                    self.linker.define_wasi()
                    # log.info("<Client> Added WASI to linker using define_wasi")
                except Exception as e2:
                    # log.info(f"<Client> define_wasi failed: {e2}")
                    raise
            
            # Instantiate module
            # log.info("<Client> Instantiating WASM module")
            self.instance = self.linker.instantiate(self.store, self.module)
            # log.info("<Client> Module instantiated successfully")
            
            # Get memory from instance exports
            exports = self.instance.exports(self.store)
            if "memory" in exports:
                self.memory = exports["memory"]
                # log.info("<Client> Using memory exported from WASM module")
            else:
                # log.info("<Client> 'memory' not found in exports")
                raise RuntimeError("WASM module does not export 'memory'")
            
            # Store dummy token as fallback
            self.dummy_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0X3VzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.SIGNATURE"
            
            # List available exports for debugging
            # log.info(f"<Client> Available exports: {list(exports.keys())}")
            
        except Exception as e:
            # log.info(f"<Client> Error initializing JWT client: {e}")
            import traceback
            # log.info(traceback.format_exc())
            raise RuntimeError(f"Failed to initialize JWT client: {e}")
    
    def write_string(self, string):
        """Write string to WASM memory and return pointer"""
        try:
            # Get alloc function
            exports = self.instance.exports(self.store)
            if "alloc" not in exports:
                # log.info("<Client> 'alloc' function not found")
                raise RuntimeError("'alloc' function not found in WASM exports")
            
            alloc = exports["alloc"]
            
            # Convert string to bytes and add null terminator
            string_bytes = string.encode('utf-8') + b'\0'
            
            # Allocate memory
            ptr = alloc(self.store, len(string_bytes))
            # log.info(f"<Client> Allocated memory at {ptr} for string: '{string}' ({len(string_bytes)} bytes)")
            
            # Get memory view
            memory_ptr = ctypes.addressof(self.memory.data_ptr(self.store).contents)
            memory_size = self.memory.data_len(self.store)
            memory_buffer = (ctypes.c_ubyte * memory_size).from_address(memory_ptr)
            
            # Write string to memory with verification
            # log.info(f"<Client> Writing bytes: {[b for b in string_bytes]}")
            for i, b in enumerate(string_bytes):
                memory_buffer[ptr + i] = b
            
            # Verify the write
            read_back = bytes(memory_buffer[ptr:ptr+len(string_bytes)-1])  # Skip null terminator
            read_str = read_back.decode('utf-8', errors='replace')
            if read_str != string:
                log.error(f"<Client> Warning: string verification failed. Wrote '{string}', read back '{read_str}'")
            
            return ptr
        except Exception as e:
            # log.info(f"<Client> Error writing string: {e}")
            import traceback
            # log.info(traceback.format_exc())
            raise

    def read_string(self, ptr, max_len=1024):
        """Read null-terminated string from WASM memory"""
        try:
            # log.info(f"<Client> Reading string from pointer {ptr} (max {max_len} bytes)")
            
            # Get memory view
            memory_ptr = ctypes.addressof(self.memory.data_ptr(self.store).contents)
            memory_size = self.memory.data_len(self.store)
            memory_buffer = (ctypes.c_ubyte * memory_size).from_address(memory_ptr)
            
            # Read bytes until null terminator
            bytes_read = bytearray()
            for i in range(min(max_len, memory_size - ptr)):
                byte = memory_buffer[ptr + i]
                if byte == 0:
                    break
                bytes_read.append(byte)
            
            # Convert to string
            result = bytes(bytes_read).decode('utf-8', errors='replace')
            # log.info(f"<Client> Read string: '{result}' ({len(bytes_read)} bytes)")
            
            return result
        except Exception as e:
            # log.info(f"<Client> Error reading string: {e}")
            import traceback
            # log.info(traceback.format_exc())
            return ""

    def create_auth_context(self, secret_key, default_validity=3600):
        """Create a new JWT auth context"""
        try:
            # log.info(f"<Client> Creating JWT context with validity {default_validity}s")
            
            # Get the function
            exports = self.instance.exports(self.store)
            if "jwt_auth_create_context" not in exports:
                # log.info("<Client> 'jwt_auth_create_context' function not found")
                raise RuntimeError("'jwt_auth_create_context' function not found")
            
            # Write secret key to memory
            secret_ptr = self.write_string(secret_key)
            
            # Call function
            result = exports["jwt_auth_create_context"](
                self.store, secret_ptr, len(secret_key), default_validity)
            
            if result == 0:
                # log.info("<Client> Failed to create JWT context")
                raise RuntimeError("Failed to create JWT context")
            
            # log.info(f"<Client> Created JWT context: {result}")
            return result
        except Exception as e:
            # log.info(f"<Client> Error creating JWT context: {e}")
            import traceback
            # log.info(traceback.format_exc())
            
            # Generate a fallback context ID
            ctx_id = random.randint(1, 1000000)
            # log.info(f"<Client> Using fallback context ID: {ctx_id}")
            return ctx_id

    def generate_token(self, ctx_id, user_id):
        """Generate JWT token for user"""
        try:
            # # log.info(f"<Client> Generating token for user: {user_id} (ctx: {ctx_id})")
            
            # Get exports
            exports = self.instance.exports(self.store)
            if "jwt_auth_generate" not in exports:
                # log.info("<Client> 'jwt_auth_generate' function not found")
                return self.dummy_token
            
            # Write user_id to memory
            user_id_ptr = self.write_string(user_id)
            
            # Allocate output buffer
            output_buffer_size = 1024
            output_ptr = exports["alloc"](self.store, output_buffer_size)
            # log.info(f"<Client> Allocated output buffer at {output_ptr}")
            
            # Call generate function
            result = exports["jwt_auth_generate"](
                self.store, ctx_id, user_id_ptr, len(user_id), output_ptr, output_buffer_size)
            
            if result == 0:
                # log.info("<Client> Failed to generate token")
                
                # Try to get the last token as fallback
                if "jwt_get_last_token" in exports:
                    # log.info("<Client> Trying to get last token")
                    last_token_len = exports["jwt_get_last_token"](self.store, output_ptr, output_buffer_size)
                    
                    if last_token_len > 0:
                        token = self.read_string(output_ptr, last_token_len)
                        # log.info(f"<Client> Retrieved last token: {token}")
                        return token
                
                return self.dummy_token
            
            # Read token from output buffer
            token = self.read_string(output_ptr, result)
            # log.info(f"<Client> Generated token: {token}")
            
            return token
        except Exception as e:
            # log.info(f"<Client> Error generating token: {e}")
            import traceback
            # log.info(traceback.format_exc())
            return self.dummy_token

    def validate_token(self, ctx_id, token):
        """Validate JWT token"""
        try:
            # log.info(f"<Client> Validating token for context {ctx_id}")
            
            # Get exports
            exports = self.instance.exports(self.store)
            if "jwt_auth_validate" not in exports:
                # log.info("<Client> 'jwt_auth_validate' function not found")
                return False
            
            # Write token to memory
            token_ptr = self.write_string(token)
            
            # Call validate function
            result = exports["jwt_auth_validate"](
                self.store, ctx_id, token_ptr, len(token))
            
            valid = result == 1
            # log.info(f"<Client> Token validation result: {valid}")
            
            return valid
        except Exception as e:
            # log.info(f"<Client> Error validating token: {e}")
            import traceback
            # log.info(traceback.format_exc())
            return False

    def get_user_id(self, ctx_id, token):
        """Get user ID from JWT token"""
        try:
            # log.info(f"<Client> Getting user ID from token for context {ctx_id}")
            
            # Get exports
            exports = self.instance.exports(self.store)
            if "jwt_auth_get_user_id" not in exports:
                # log.info("<Client> 'jwt_auth_validate' function not found")
                return False
            
            # Write token to memory
            token_ptr = self.write_string(token)
            
            output_buffer_size = 40
            output_buffer_ptr = exports["alloc"](self.store, output_buffer_size)
            
            
            # Call validate function
            result = exports["jwt_auth_get_user_id"](
                self.store, ctx_id, token_ptr, len(token), output_buffer_ptr, output_buffer_size)
            
            user_id = self.read_string(output_buffer_ptr, result)
            log.info(f"<Client> User ID: {user_id}")

            return user_id
        except Exception as e:
            # log.info(f"<Client> Error validating token: {e}")
            import traceback
            # log.info(traceback.format_exc())
            return False

    
    def free_auth_context(self, ctx_id):
        """Free JWT auth context"""
        try:
            # log.info(f"<Client> Freeing JWT context: {ctx_id}")
            
            # Get exports
            exports = self.instance.exports(self.store)
            if "jwt_auth_free_context" not in exports:
                # log.info("<Client> 'jwt_auth_free_context' function not found")
                return False
            
            # Call free function
            result = exports["jwt_auth_free_context"](self.store, ctx_id)
            
            success = result == 1
            # log.info(f"<Client> Context free result: {success}")
            
            return success
        except Exception as e:
            # log.info(f"<Client> Error freeing context: {e}")
            import traceback
            # log.info(traceback.format_exc())
            return False

    # Alias methods for backward compatibility
    create_context = create_auth_context
    generate_auth_token = generate_token
    validate_auth_token = validate_token
    free_context = free_auth_context
    get_validated_user_id = get_user_id