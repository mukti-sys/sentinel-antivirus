use crate::hashing::hash_file_sha256;
use crate::pe_fast::parse_pe_fast;
use rayon::prelude::*;
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::raw::{c_char, c_void};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use walkdir::WalkDir;

/// C-ABI callback invoked per scanned file.
/// Return 0 to continue scanning, or non-zero to cancel.
pub type ScanFileCallback = extern "C" fn(
    path: *const c_char,
    sha256: *const c_char,
    file_size: u64,
    is_pe: i32,
    suspicious_packer: i32,
    user_data: *mut c_void,
) -> i32;

const IGNORE_DIRS: &[&str] = &[
    "$recycle.bin",
    "system volume information",
    "$windows.~bt",
    "$windows.~ws",
    "$winreagent",
    "recovery",
];

const IGNORE_FILES: &[&str] = &[
    "pagefile.sys",
    "swapfile.sys",
    "hiberfil.sys",
    "dumpstack.log.tmp",
];

fn should_ignore_entry(entry: &walkdir::DirEntry) -> bool {
    let name_lower = entry.file_name().to_string_lossy().to_lowercase();
    if entry.file_type().is_dir() {
        if name_lower.starts_with('.') {
            return true;
        }
        for &ign in IGNORE_DIRS {
            if name_lower == ign {
                return true;
            }
        }
    } else {
        for &ign in IGNORE_FILES {
            if name_lower == ign {
                return true;
            }
        }
    }
    false
}

/// Run parallel scan on a directory path.
pub fn scan_directory_parallel<P: AsRef<Path>>(
    root: P,
    callback: Option<ScanFileCallback>,
    user_data: *mut c_void,
    cancel_flag: Option<Arc<AtomicBool>>,
) -> usize {
    let root_path = root.as_ref();
    if !root_path.exists() {
        return 0;
    }

    // Fast-collect eligible files using walkdir
    let files: Vec<PathBuf> = WalkDir::new(root_path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !should_ignore_entry(e))
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.into_path())
        .collect();

    let total = files.len();
    let cancelled = cancel_flag.unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
    let user_data_addr = user_data as usize;

    // Process files in parallel across all CPU cores
    files.into_par_iter().for_each(|fpath| {
        if cancelled.load(Ordering::Relaxed) {
            return;
        }

        let metadata = match fpath.metadata() {
            Ok(m) => m,
            Err(_) => return,
        };

        let file_size = metadata.len();

        // Calculate SHA-256 via native streaming
        let sha256_str = match hash_file_sha256(&fpath) {
            Ok(s) => s,
            Err(_) => return,
        };

        // Quick PE header read (first 4KB is enough for header parsing)
        let mut is_pe = 0i32;
        let mut suspicious_packer = 0i32;

        if file_size >= 64 {
            let mut header_buf = [0u8; 4096];
            if let Ok(mut file) = File::open(&fpath) {
                if let Ok(n) = file.read(&mut header_buf) {
                    if n >= 64 && header_buf[0] == b'M' && header_buf[1] == b'Z' {
                        let triage = parse_pe_fast(&header_buf[..n]);
                        if triage.is_pe == 1 {
                            is_pe = 1;
                            if triage.suspicious_section_count > 0
                                || triage.max_section_entropy > 7.85
                            {
                                suspicious_packer = 1;
                            }
                        }
                    }
                }
            }
        }

        if let Some(cb) = callback {
            let path_str = fpath.to_string_lossy();
            if let (Ok(c_path), Ok(c_sha)) = (
                CString::new(path_str.as_ref()),
                CString::new(sha256_str.as_str()),
            ) {
                let status = cb(
                    c_path.as_ptr(),
                    c_sha.as_ptr(),
                    file_size,
                    is_pe,
                    suspicious_packer,
                    user_data_addr as *mut c_void,
                );
                if status != 0 {
                    cancelled.store(true, Ordering::Relaxed);
                }
            }
        }
    });

    total
}
