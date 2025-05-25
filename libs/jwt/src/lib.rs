use std::sync::Mutex;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};

// Store the last generated token for debugging
static LAST_TOKEN: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));

// Memory management module
mod memory {
    // Copy data from Rust to WASM linear memory
    pub unsafe fn copy_to_mem(src_ptr: *const u8, len: usize, dest_ptr: usize) {
        let dest = dest_ptr as *mut u8;
        std::ptr::copy_nonoverlapping(src_ptr, dest, len);
    }

    // Copy data from WASM linear memory to Rust
    pub unsafe fn copy_from_mem(src_ptr: usize, len: usize) -> Vec<u8> {
        let src = src_ptr as *const u8;
        let mut result = vec![0u8; len];
        std::ptr::copy_nonoverlapping(src, result.as_mut_ptr(), len);
        result
    }
}

// Context management
struct JWTContext {
    id: usize,
    secret: String,
    validity: u64,
}

// Store active contexts
static CONTEXTS: Lazy<Mutex<Vec<JWTContext>>> = Lazy::new(|| Mutex::new(Vec::new()));

#[derive(Serialize, Deserialize)]
struct JWTClaims {
    sub: String,     // Subject (user ID)
    iat: u64,        // Issued at (timestamp)
    exp: u64,        // Expiration time (timestamp)
}

// Create a new JWT context
#[no_mangle]
pub extern "C" fn jwt_auth_create_context(
    secret_ptr: usize,
    secret_len: usize,
    validity: u64
) -> u32 {
    // Log parameters
    eprintln!("Creating JWT context with validity: {}", validity);
    
    // Read secret key
    let secret = unsafe {
        let bytes = memory::copy_from_mem(secret_ptr, secret_len);
        match std::str::from_utf8(&bytes) {
            Ok(s) => s.to_string(),
            Err(e) => {
                eprintln!("Error reading secret: {}", e);
                return 0; // Error
            }
        }
    };
    
    eprintln!("Read secret key: {}", secret);
    
    // Generate a context ID (simple incrementing ID)
    let ctx_id = {
        let contexts = CONTEXTS.lock().unwrap();
        contexts.len() + 1
    };
    
    // Store context
    {
        let mut contexts = CONTEXTS.lock().unwrap();
        contexts.push(JWTContext {
            id: ctx_id,
            secret,
            validity,
        });
    }
    
    eprintln!("Created JWT context: {}", ctx_id);
    
    // Return context ID
    ctx_id as u32
}

// Generate a JWT token for a user
#[no_mangle]
pub extern "C" fn jwt_auth_generate(
    ctx_id: u32,
    user_id_ptr: usize,
    user_id_len: usize,
    output_ptr: usize,
    output_max_len: usize,
) -> u32 {
    eprintln!("Generating token for context {}, user ID at {}, length {}", 
              ctx_id, user_id_ptr, user_id_len);
    
    // Read user ID
    let user_id = unsafe {
        let bytes = memory::copy_from_mem(user_id_ptr, user_id_len);
        eprintln!("Read user ID bytes: {:?}", bytes);
        
        match std::str::from_utf8(&bytes) {
            Ok(s) => {
                eprintln!("Parsed user ID: '{}'", s);
                s.to_string()
            },
            Err(e) => {
                eprintln!("Error parsing user ID: {}", e);
                return 0; // Error
            }
        }
    };
    
    // Get context
    let (secret, validity) = {
        let contexts = CONTEXTS.lock().unwrap();
        let ctx = match contexts.iter().find(|c| c.id == ctx_id as usize) {
            Some(c) => c,
            None => {
                eprintln!("Context {} not found", ctx_id);
                return 0; // Error
            }
        };
        (ctx.secret.clone(), ctx.validity)
    };
    
    // Get current time
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
        
    // Create claims
    let claims = JWTClaims {
        sub: user_id.clone(),
        iat: now,
        exp: now + validity,
    };
    
    // Generate JWT using jsonwebtoken crate
    let token = match encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes())
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error encoding JWT: {}", e);
            return 0; // Error
        }
    };
    
    eprintln!("Generated token: {}", token);
    
    // Store for debugging
    {
        let mut last_token = LAST_TOKEN.lock().unwrap();
        *last_token = token.clone();
    }
    
    // Write token to output buffer
    let token_bytes = token.as_bytes();
    if token_bytes.len() >= output_max_len {
        eprintln!("Output buffer too small");
        return 0; // Error
    }
    
    unsafe {
        memory::copy_to_mem(token_bytes.as_ptr(), token_bytes.len(), output_ptr);
        
        // Add null terminator
        let null_byte: u8 = 0;
        memory::copy_to_mem(&null_byte as *const u8, 1, output_ptr + token_bytes.len());
    }
    
    eprintln!("Token written to output buffer");
    
    // Return token length
    token_bytes.len() as u32
}

// Validate a JWT token
#[no_mangle]
pub extern "C" fn jwt_auth_validate(
    ctx_id: u32,
    token_ptr: usize,
    token_len: usize,
) -> u32 {
    eprintln!("Validating token for context {}, token at {}, length {}", 
              ctx_id, token_ptr, token_len);
    
    // Read token
    let token = unsafe {
        let bytes = memory::copy_from_mem(token_ptr, token_len);
        match std::str::from_utf8(&bytes) {
            Ok(s) => s.to_string(),
            Err(e) => {
                eprintln!("Error reading token: {}", e);
                return 0; // Invalid
            }
        }
    };
    
    eprintln!("Read token: {}", token);
    
    // Get context
    let secret = {
        let contexts = CONTEXTS.lock().unwrap();
        let ctx = match contexts.iter().find(|c| c.id == ctx_id as usize) {
            Some(c) => c,
            None => {
                eprintln!("Context {} not found", ctx_id);
                return 0; // Invalid
            }
        };
        ctx.secret.clone()
    };
    
    // Validate JWT using jsonwebtoken crate
    let validation = Validation::new(Algorithm::HS256);
    
    match decode::<JWTClaims>(
        &token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation
    ) {
        Ok(_) => {
            eprintln!("Token validated");
            1 // Valid
        },
        Err(e) => {
            eprintln!("Token validation failed: {}", e);
            0 // Invalid
        }
    }
}

// Free a JWT context
#[no_mangle]
pub extern "C" fn jwt_auth_free_context(ctx_id: u32) -> u32 {
    eprintln!("Freeing context {}", ctx_id);
    
    let mut contexts = CONTEXTS.lock().unwrap();
    let index = match contexts.iter().position(|c| c.id == ctx_id as usize) {
        Some(i) => i,
        None => {
            eprintln!("Context {} not found", ctx_id);
            return 0; // Error
        }
    };
    
    contexts.remove(index);
    eprintln!("Context {} removed", ctx_id);
    
    1 // Success
}

// Memory allocation
#[no_mangle]
pub extern "C" fn alloc(size: usize) -> usize {
    // Allocate memory and return pointer
    let mut buffer = Vec::with_capacity(size);
    let ptr = buffer.as_mut_ptr();
    
    // Convert pointer to usize using explicit casting steps
    let ptr_usize = ptr as *const u8 as usize;
    
    // Prevent buffer from being deallocated
    std::mem::forget(buffer);
    
    ptr_usize
}

// Memory deallocation
#[no_mangle]
pub extern "C" fn dealloc(ptr: usize, size: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr as *mut u8, 0, size);
        // Buffer is automatically deallocated when it goes out of scope
    }
}

// Debugging function to get the last generated token
#[no_mangle]
pub extern "C" fn jwt_get_last_token(output_ptr: usize, output_max_len: usize) -> u32 {
    let token = {
        let last_token = LAST_TOKEN.lock().unwrap();
        last_token.clone()
    };
    
    if token.is_empty() {
        eprintln!("No token available");
        return 0;
    }
    
    let token_bytes = token.as_bytes();
    if token_bytes.len() >= output_max_len {
        eprintln!("Output buffer too small");
        return 0;
    }
    
    unsafe {
        memory::copy_to_mem(token_bytes.as_ptr(), token_bytes.len(), output_ptr);
        
        // Add null terminator
        let null_byte: u8 = 0;
        memory::copy_to_mem(&null_byte as *const u8, 1, output_ptr + token_bytes.len());
    }
    
    token_bytes.len() as u32
}