//! Fast zero-allocation PE triage parser for Sentinel Antivirus.
//!
//! Parses DOS header, PE NT headers, and section tables in microseconds (<0.02ms)
//! without allocating memory or invoking Python bytecode.

use crate::hashing::calculate_shannon_entropy;

const KNOWN_PACKER_SECTIONS: &[&[u8]] = &[
    b"UPX0",
    b"UPX1",
    b"UPX2",
    b".aspack",
    b".adata",
    b".vmp",
    b"Themida",
    b"PEC2",
    b".petite",
    b"FSG!",
    b".neolite",
    b".enigma",
];

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PeFastTriageResult {
    pub is_pe: i32,
    pub is_64bit: i32,
    pub num_sections: u32,
    pub entry_point: u64,
    pub suspicious_section_count: u32,
    pub max_section_entropy: f64,
    pub avg_section_entropy: f64,
    pub min_section_raw_size: u64,
}

impl Default for PeFastTriageResult {
    fn default() -> Self {
        Self {
            is_pe: 0,
            is_64bit: 0,
            num_sections: 0,
            entry_point: 0,
            suspicious_section_count: 0,
            max_section_entropy: 0.0,
            avg_section_entropy: 0.0,
            min_section_raw_size: 0,
        }
    }
}

/// Fast in-memory PE parser.
pub fn parse_pe_fast(data: &[u8]) -> PeFastTriageResult {
    let mut res = PeFastTriageResult::default();

    // Check minimum DOS header size (64 bytes)
    if data.len() < 64 {
        return res;
    }

    // Check MZ signature (0x4D, 0x5A)
    if data[0] != b'M' || data[1] != b'Z' {
        return res;
    }

    // Read e_lfanew (offset to NT headers) at 0x3C (little-endian 32-bit int)
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;

    // Check PE signature offset bounds
    if e_lfanew + 4 > data.len() {
        return res;
    }

    // Check 'PE\0\0' signature (0x50, 0x45, 0x00, 0x00)
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return res;
    }

    res.is_pe = 1;

    let file_header_offset = e_lfanew + 4;
    if file_header_offset + 20 > data.len() {
        return res;
    }

    // Machine type at offset 0, NumberOfSections at offset 2, SizeOfOptionalHeader at offset 16
    let num_sections =
        u16::from_le_bytes([data[file_header_offset + 2], data[file_header_offset + 3]]) as usize;
    let size_of_opt_header =
        u16::from_le_bytes([data[file_header_offset + 16], data[file_header_offset + 17]]) as usize;

    res.num_sections = num_sections as u32;

    let opt_header_offset = file_header_offset + 20;
    if opt_header_offset + size_of_opt_header > data.len() || size_of_opt_header < 2 {
        return res;
    }

    let opt_magic = u16::from_le_bytes([data[opt_header_offset], data[opt_header_offset + 1]]);
    let is_pe32_plus = opt_magic == 0x20B;
    res.is_64bit = if is_pe32_plus { 1 } else { 0 };

    // Entry point offset is at +16 in OptionalHeader for both PE32 and PE32+
    if size_of_opt_header >= 20 {
        let entry_point = u32::from_le_bytes([
            data[opt_header_offset + 16],
            data[opt_header_offset + 17],
            data[opt_header_offset + 18],
            data[opt_header_offset + 19],
        ]);
        res.entry_point = entry_point as u64;
    }

    // Section headers immediately follow the optional header
    let section_headers_offset = opt_header_offset + size_of_opt_header;
    const SECTION_HEADER_SIZE: usize = 40;

    let mut suspicious_count = 0u32;
    let mut max_entropy = 0.0f64;
    let mut total_entropy = 0.0f64;
    let mut counted_sections = 0usize;
    let mut min_raw_size = u64::MAX;

    for i in 0..num_sections {
        let sh_offset = section_headers_offset + (i * SECTION_HEADER_SIZE);
        if sh_offset + SECTION_HEADER_SIZE > data.len() {
            break;
        }

        // Section Name (8 bytes)
        let name_bytes = &data[sh_offset..sh_offset + 8];
        let name_trimmed = match name_bytes.iter().position(|&b| b == 0) {
            Some(pos) => &name_bytes[..pos],
            None => name_bytes,
        };

        // Check suspicious packer section name
        for &packer in KNOWN_PACKER_SECTIONS {
            if name_trimmed.eq_ignore_ascii_case(packer) {
                suspicious_count += 1;
                break;
            }
        }

        // SizeOfRawData at offset +16, PointerToRawData at offset +20
        let size_of_raw = u32::from_le_bytes([
            data[sh_offset + 16],
            data[sh_offset + 17],
            data[sh_offset + 18],
            data[sh_offset + 19],
        ]) as usize;
        let ptr_to_raw = u32::from_le_bytes([
            data[sh_offset + 20],
            data[sh_offset + 21],
            data[sh_offset + 22],
            data[sh_offset + 23],
        ]) as usize;

        if (size_of_raw as u64) < min_raw_size {
            min_raw_size = size_of_raw as u64;
        }

        // Calculate entropy if section data exists within file buffer
        if size_of_raw > 0 && ptr_to_raw < data.len() {
            let end = (ptr_to_raw + size_of_raw).min(data.len());
            if end > ptr_to_raw {
                let sec_entropy = calculate_shannon_entropy(&data[ptr_to_raw..end]);
                if sec_entropy > max_entropy {
                    max_entropy = sec_entropy;
                }
                total_entropy += sec_entropy;
                counted_sections += 1;
            }
        }
    }

    res.suspicious_section_count = suspicious_count;
    res.max_section_entropy = max_entropy;
    res.avg_section_entropy = if counted_sections > 0 {
        total_entropy / (counted_sections as f64)
    } else {
        0.0
    };
    res.min_section_raw_size = if min_raw_size == u64::MAX {
        0
    } else {
        min_raw_size
    };

    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_pe() {
        let data = b"This is just a regular text file without MZ header.";
        let res = parse_pe_fast(data);
        assert_eq!(res.is_pe, 0);
    }

    #[test]
    fn test_synthetic_pe() {
        let mut buf = vec![0u8; 1024];
        // MZ header
        buf[0] = b'M';
        buf[1] = b'Z';
        // e_lfanew = 128 (0x80)
        buf[0x3C] = 0x80;

        // PE\0\0
        buf[0x80] = b'P';
        buf[0x81] = b'E';
        buf[0x82] = 0;
        buf[0x83] = 0;

        // NumberOfSections = 2 at 0x86
        buf[0x86] = 2;
        // SizeOfOptionalHeader = 0xE0 at 0x94
        buf[0x94] = 0xE0;

        // OptionalHeader magic = 0x20B (PE32+) at 0x84 + 20 = 0x98
        buf[0x98] = 0x0B;
        buf[0x99] = 0x02;

        let res = parse_pe_fast(&buf);
        assert_eq!(res.is_pe, 1);
        assert_eq!(res.is_64bit, 1);
        assert_eq!(res.num_sections, 2);
    }
}
