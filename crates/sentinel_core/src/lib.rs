#![allow(clippy::not_unsafe_ptr_arg_deref)]

//! Sentinel Core — Native C-ABI Shared Library for High-Performance Antivirus Operations.

pub mod hashing;
pub mod parallel_scanner;
pub mod pe_fast;

use hashing::{calculate_shannon_entropy, hash_file_dual, hash_file_sha256};
use parallel_scanner::{scan_directory_parallel, ScanFileCallback};
use pe_fast::{parse_pe_fast, PeFastTriageResult};
use std::ffi::CStr;
use std::os::raw::{c_char, c_void};
use std::ptr;
use std::slice;

static VERSION: &str = "2.2.0\0";

/// Return the version string of the native sentinel_core engine.
#[no_mangle]
pub extern "C" fn sentinel_core_version() -> *const c_char {
    VERSION.as_ptr() as *const c_char
}

/// Compute SHA-256 of a file using buffered streaming I/O.
/// Copies the 64-char lowercase hex string + null terminator into `out_buf`.
/// Returns 0 on success, -1 on I/O error, -2 on invalid UTF-8 path or insufficient buffer.
#[no_mangle]
pub extern "C" fn sentinel_hash_file_sha256(
    path: *const c_char,
    out_buf: *mut c_char,
    out_len: usize,
) -> i32 {
    if path.is_null() || out_buf.is_null() || out_len < 65 {
        return -2;
    }

    let c_str = unsafe { CStr::from_ptr(path) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    match hash_file_sha256(path_str) {
        Ok(hex_str) => {
            let bytes = hex_str.as_bytes();
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_buf, 64);
                *out_buf.add(64) = 0;
            }
            0
        }
        Err(_) => -1,
    }
}

/// Compute both SHA-256 and MD5 of a file in a single streaming pass.
/// `out_sha256` must be at least 65 bytes, `out_md5` must be at least 33 bytes.
/// Returns 0 on success, negative error code otherwise.
#[no_mangle]
pub extern "C" fn sentinel_hash_file_dual(
    path: *const c_char,
    out_sha256: *mut c_char,
    out_md5: *mut c_char,
) -> i32 {
    if path.is_null() || out_sha256.is_null() || out_md5.is_null() {
        return -2;
    }

    let c_str = unsafe { CStr::from_ptr(path) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    match hash_file_dual(path_str) {
        Ok((sha_hex, md5_hex)) => {
            let sha_bytes = sha_hex.as_bytes();
            let md5_bytes = md5_hex.as_bytes();
            unsafe {
                ptr::copy_nonoverlapping(sha_bytes.as_ptr() as *const c_char, out_sha256, 64);
                *out_sha256.add(64) = 0;

                ptr::copy_nonoverlapping(md5_bytes.as_ptr() as *const c_char, out_md5, 32);
                *out_md5.add(32) = 0;
            }
            0
        }
        Err(_) => -1,
    }
}

/// Calculate Shannon entropy of a memory buffer (0.0 to 8.0).
#[no_mangle]
pub extern "C" fn sentinel_shannon_entropy(data: *const u8, len: usize) -> f64 {
    if data.is_null() || len == 0 {
        return 0.0;
    }
    let slice = unsafe { slice::from_raw_parts(data, len) };
    calculate_shannon_entropy(slice)
}

/// Parse PE headers and evaluate fast heuristics.
/// Populates `out_result` with extracted metrics.
/// Returns 0 on success, -1 if invalid pointer.
#[no_mangle]
pub extern "C" fn sentinel_pe_fast_triage(
    data: *const u8,
    len: usize,
    out_result: *mut PeFastTriageResult,
) -> i32 {
    if data.is_null() || out_result.is_null() || len == 0 {
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(data, len) };
    let triage = parse_pe_fast(slice);
    unsafe {
        *out_result = triage;
    }
    0
}

/// Multi-threaded parallel recursive directory scanner.
/// Utilizes Rayon work-stealing across all CPU cores.
/// Invokes `callback` for each scanned file.
/// Returns total count of processed files.
#[no_mangle]
pub extern "C" fn sentinel_scan_directory_parallel(
    dir_path: *const c_char,
    callback: Option<ScanFileCallback>,
    user_data: *mut c_void,
) -> usize {
    if dir_path.is_null() {
        return 0;
    }
    let c_str = unsafe { CStr::from_ptr(dir_path) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    scan_directory_parallel(path_str, callback, user_data, None)
}
