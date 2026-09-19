//! High-performance streaming hashing and Shannon entropy computation.

use md5::Md5;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

const CHUNK_SIZE: usize = 64 * 1024; // 64 KiB buffer

/// Calculate SHA-256 hex digest of a byte slice.
pub fn hash_bytes_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Calculate SHA-256 hex digest of a file using buffered streaming I/O.
/// Prevents large memory allocations and memory pressure for large files.
pub fn hash_file_sha256<P: AsRef<Path>>(path: P) -> Result<String, std::io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; CHUNK_SIZE];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

/// Calculate both SHA-256 and MD5 hex digests in a single I/O pass.
pub fn hash_file_dual<P: AsRef<Path>>(path: P) -> Result<(String, String), std::io::Error> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, file);
    let mut sha_hasher = Sha256::new();
    let mut md5_hasher = Md5::new();
    let mut buffer = [0u8; CHUNK_SIZE];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        sha_hasher.update(&buffer[..n]);
        md5_hasher.update(&buffer[..n]);
    }

    let sha256_hex = format!("{:x}", sha_hasher.finalize());
    let md5_hex = format!("{:x}", md5_hasher.finalize());
    Ok((sha256_hex, md5_hex))
}

/// Calculate Shannon entropy of a byte slice in bits/byte (0.0 to 8.0).
/// Uses an integer frequency lookup array and SIMD-friendly loop.
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len_f = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len_f;
            entropy -= p * p.log2();
        }
    }

    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bytes() {
        let h = hash_bytes_sha256(b"hello world");
        assert_eq!(
            h,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_entropy_zero_and_uniform() {
        assert_eq!(calculate_shannon_entropy(&[]), 0.0);
        assert_eq!(calculate_shannon_entropy(&[0u8; 100]), 0.0);

        // All 256 bytes present equally -> entropy should be exactly 8.0
        let mut full_range = Vec::with_capacity(256 * 4);
        for _ in 0..4 {
            for b in 0..=255u8 {
                full_range.push(b);
            }
        }
        let ent = calculate_shannon_entropy(&full_range);
        assert!((ent - 8.0).abs() < 1e-6);
    }
}
