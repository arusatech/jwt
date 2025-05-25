use std::sync::Mutex;
use once_cell::sync::Lazy;

// Memory management
static mut MEMORY: Vec<u8> = Vec::new();
static mut MEMORY_USED: usize = 0;
static MEMORY_MUTEX: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

// Initialize memory
#[no_mangle]
pub extern "C" fn memory_init(size: usize) -> usize {
    let _guard = MEMORY_MUTEX.lock().unwrap();
    unsafe {
        MEMORY = vec![0; size];
        MEMORY_USED = 0;
        MEMORY.len()
    }
}

// Get memory size
#[no_mangle]
pub extern "C" fn memory_size() -> usize {
    let _guard = MEMORY_MUTEX.lock().unwrap();
    unsafe { MEMORY.len() }
}

// Get memory used
#[no_mangle]
pub extern "C" fn memory_used() -> usize {
    let _guard = MEMORY_MUTEX.lock().unwrap();
    unsafe { MEMORY_USED }
}

// Grow memory
#[no_mangle]
pub extern "C" fn memory_grow(additional_size: usize) -> usize {
    let _guard = MEMORY_MUTEX.lock().unwrap();
    let old_size = unsafe { MEMORY.len() };
    unsafe {
        MEMORY.resize(old_size + additional_size, 0);
        MEMORY.len()
    }
}

// Allocate memory
#[no_mangle]
pub extern "C" fn alloc(size: usize) -> usize {
    let _guard = MEMORY_MUTEX.lock().unwrap();
    unsafe {
        // Check if we need to grow memory
        let total_memory = MEMORY.len();
        let needed_memory = MEMORY_USED + size;
        
        if needed_memory > total_memory {
            // Grow memory by at least 64KB or the size needed
            let grow_size = (needed_memory - total_memory + 65535) & !65535;
            MEMORY.resize(total_memory + grow_size, 0);
        }
        
        // Allocate from the start of free memory
        let ptr = MEMORY_USED;
        MEMORY_USED += size;
        
        // Return the allocated pointer
        ptr
    }
}

// Free memory (no-op for Phase 1)
#[no_mangle]
pub extern "C" fn mem_free(_ptr: usize) {
    // No-op in Phase 1
}

// Validate pointer
pub fn validate_ptr(ptr: usize, len: usize) -> bool {
    let _guard = MEMORY_MUTEX.lock().unwrap();
    unsafe {
        ptr < MEMORY.len() && ptr + len <= MEMORY.len()
    }
}

// Copy from host memory to WASM memory
pub unsafe fn copy_to_mem(src: *const u8, len: usize, dest: usize) {
    let _guard = MEMORY_MUTEX.lock().unwrap();
    if dest + len <= MEMORY.len() {
        std::ptr::copy_nonoverlapping(src, MEMORY.as_mut_ptr().add(dest), len);
    }
}

// Copy from WASM memory to host
pub unsafe fn copy_from_mem(src: usize, len: usize) -> Vec<u8> {
    let _guard = MEMORY_MUTEX.lock().unwrap();
    let mut result = vec![0; len];
    if src + len <= MEMORY.len() {
        std::ptr::copy_nonoverlapping(MEMORY.as_ptr().add(src), result.as_mut_ptr(), len);
    }
    result
}

pub unsafe fn refresh_memory_view() {
    // This is a no-op function that forces the Rust compiler
    // to refresh its view of memory. The actual implementation
    // depends on the memory model used.
    eprintln!("Refreshing memory view");
    
    // Force a memory barrier by accessing and modifying a shared value
    unsafe {
        // Access a volatile memory location to prevent optimization
        std::ptr::read_volatile(&0 as *const i32);
    }
}

// Simple function to write a single byte
pub unsafe fn write_byte(ptr: usize, value: u8) {
    let ptr = ptr as *mut u8;
    std::ptr::write_volatile(ptr, value);
}

// Simple function to read a single byte
pub unsafe fn read_byte(ptr: usize) -> u8 {
    let ptr = ptr as *const u8;
    std::ptr::read_volatile(ptr)
}