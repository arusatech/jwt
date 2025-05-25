import unittest
import os
from jwt_client import JWTClient
from jsonpath_nz import log

class TestJWTClient(unittest.TestCase):
    def setUp(self):
        wasm_path = os.environ.get("WASM_PATH", "/home/ymohammad/rust-wasi-jwt/target/wasm32-wasip1/release/rust_wasi_jwt.wasm")
        self.jwt_client = JWTClient(wasm_path)
        self.secret = "test-secret-key"
        self.ctx_id = self.jwt_client.create_auth_context(self.secret, 3600)
    
    def tearDown(self):
        self.jwt_client.free_auth_context(self.ctx_id)
    
    def test_token_generation(self):
        # Generate token
        user_id = "testuser"
        token = self.jwt_client.generate_token(self.ctx_id, user_id)
        log.info(f"<Test> Generated token: {token}")
        # Token should be a non-empty string
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 0)
        
        # Token should have three parts separated by dots
        parts = token.split(".")
        self.assertEqual(len(parts), 3)
    
    def test_token_validation(self):
        # Generate token
        user_id = "testuser"
        log.info(f"<Test> Generating token for user: {user_id}")
        token = self.jwt_client.generate_token(self.ctx_id, user_id)
        log.info(f"<Test> Generated token: {token}")
        # Validate token
        validated_user_id = self.jwt_client.validate_token(self.ctx_id, token)
        
        # Validated user ID should match original
        self.assertEqual(validated_user_id, user_id)
    
    def test_invalid_token(self):
        # Invalid token
        token = "invalid.token.format"
        
        # Validation should fail
        with self.assertRaises(RuntimeError):
            self.jwt_client.validate_token(self.ctx_id, token)

    def test_basic_token(self):
        """Test basic token generation without user ID"""
        try:
            log.info("<Client> Running basic token test")
            
            # Get exports
            exports = self.jwt_client.instance.exports(self.jwt_client.store)
            
            # Call basic test function
            if hasattr(exports, "jwt_basic_test"):
                log.info("<Client> Calling jwt_basic_test")
                result = exports["jwt_basic_test"](self.jwt_client.store)
                log.info(f"<Client> jwt_basic_test result: {result}")
                
                # Allocate buffer for token
                buffer_size = 100
                buffer_ptr = exports["alloc"](self.jwt_client.store, buffer_size)
                log.info(f"<Client> Allocated buffer at {buffer_ptr}")
                
                # Get token from memory
                token_len = exports["jwt_basic_write_to_memory"](self.jwt_client.store, buffer_ptr, buffer_size)
                log.info(f"<Client> jwt_basic_write_to_memory result: {token_len}")
                
                if token_len > 0:
                    # Read token from memory
                    token = self.jwt_client.read_string(buffer_ptr, token_len)
                    log.info(f"<Client> Read token: '{token}'")
                    return token
                else:
                    log.error("<Client> Failed to write token to memory")
            else:
                log.error("<Client> jwt_basic_test function not found")
            
            return None
        except Exception as e:
            log.error(f"<Client> Error in basic token test: {e}")
            import traceback
            log.error(traceback.format_exc())
            return None

if __name__ == "__main__":
    unittest.main()
