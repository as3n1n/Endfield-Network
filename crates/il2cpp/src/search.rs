//! Search algorithms for finding IL2CPP registration structures in binaries

use endfield_binary_parser::{BinaryFile, Section};
use endfield_core::Address;
use tracing::{debug, info, warn};

/// Result of searching for IL2CPP structures
#[derive(Debug)]
pub struct SearchResult {
    pub code_registration: Address,
    pub metadata_registration: Address,
}

/// Search strategy for finding IL2CPP structures
pub enum SearchStrategy {
    /// Search using known patterns
    Pattern,
    /// Search using metadata counts to validate
    PlusSearch,
    /// Use symbol table if available
    Symbol,
    /// Manual addresses provided by user
    Manual(Address, Address),
}

/// Search for IL2CPP registration structures in a binary
pub fn search_registrations(
    binary: &dyn BinaryFile,
    expected_types: usize,
    expected_methods: usize,
) -> Option<SearchResult> {
    // Try symbol search first (fastest if symbols are available)
    if let Some(result) = symbol_search(binary) {
        info!("Found registrations via symbol search");
        return Some(result);
    }

    // Try plus search (uses known counts from metadata)
    if let Some(result) = plus_search(binary, expected_types) {
        info!("Found registrations via plus search");
        return Some(result);
    }

    // Try pattern search as fallback
    if let Some(result) = pattern_search(binary) {
        info!("Found registrations via pattern search");
        return Some(result);
    }

    warn!("Could not find registration structures automatically");
    None
}

/// Search using symbol table
fn symbol_search(binary: &dyn BinaryFile) -> Option<SearchResult> {
    let mut code_reg = None;
    let mut meta_reg = None;

    for symbol in binary.symbols() {
        if symbol.name.contains("g_CodeRegistration") {
            code_reg = Some(symbol.address);
            debug!("Found g_CodeRegistration at {}", symbol.address);
        }
        if symbol.name.contains("g_MetadataRegistration") {
            meta_reg = Some(symbol.address);
            debug!("Found g_MetadataRegistration at {}", symbol.address);
        }
    }

    match (code_reg, meta_reg) {
        (Some(code), Some(meta)) => Some(SearchResult {
            code_registration: code,
            metadata_registration: meta,
        }),
        _ => None,
    }
}

/// Plus search: validate candidates using known counts
fn plus_search(binary: &dyn BinaryFile, expected_types: usize) -> Option<SearchResult> {
    let ptr_size = binary.architecture().pointer_size();
    let data_sections = binary.data_sections();

    for section in &data_sections {
        if let Some(result) = search_in_section(binary, section, expected_types, ptr_size) {
            return Some(result);
        }
    }

    None
}

fn search_in_section(
    binary: &dyn BinaryFile,
    section: &Section,
    expected_types: usize,
    ptr_size: usize,
) -> Option<SearchResult> {
    let section_data = binary.section_data(section)?;

    // Look for the expected types count in the data
    let expected_bytes = if ptr_size == 8 {
        (expected_types as u64).to_le_bytes().to_vec()
    } else {
        (expected_types as u32).to_le_bytes().to_vec()
    };

    for (offset, window) in section_data.windows(expected_bytes.len()).enumerate() {
        if window == expected_bytes.as_slice() {
            let candidate_addr = section.virtual_address.offset(offset as i64);

            // This could be types_count in MetadataRegistration
            // Try to validate by checking surrounding data
            if let Some(meta_reg) = validate_metadata_registration(binary, candidate_addr, ptr_size) {
                // Now search for CodeRegistration that points to this
                if let Some(code_reg) = find_code_registration(binary, ptr_size) {
                    return Some(SearchResult {
                        code_registration: code_reg,
                        metadata_registration: meta_reg,
                    });
                }
            }
        }
    }

    None
}

fn validate_metadata_registration(
    binary: &dyn BinaryFile,
    candidate: Address,
    ptr_size: usize,
) -> Option<Address> {
    // MetadataRegistration structure starts with:
    // - genericClassesCount (ptr)
    // - genericClasses (ptr)
    // - genericInstsCount (ptr)
    // ...

    // Try to find the start of the structure by going backwards
    // This is a heuristic and may need adjustment

    // For now, assume we found a valid count and return the candidate
    // In a real implementation, we'd validate more thoroughly
    Some(candidate)
}

fn find_code_registration(binary: &dyn BinaryFile, ptr_size: usize) -> Option<Address> {
    // CodeRegistration structure would contain pointers to method arrays
    // Look for patterns that indicate function pointer arrays

    // This is a placeholder - real implementation would search more thoroughly
    None
}

/// Pattern search using instruction patterns
fn pattern_search(binary: &dyn BinaryFile) -> Option<SearchResult> {
    use endfield_core::Architecture;

    match binary.architecture() {
        Architecture::X64 => x64_pattern_search(binary),
        Architecture::X86 => x86_pattern_search(binary),
        Architecture::Arm64 => arm64_pattern_search(binary),
        Architecture::Arm32 => arm32_pattern_search(binary),
        _ => None,
    }
}

fn x64_pattern_search(binary: &dyn BinaryFile) -> Option<SearchResult> {
    // Common x64 patterns for IL2CPP initialization:
    // lea rcx, [rip + offset]  ; CodeRegistration
    // lea rdx, [rip + offset]  ; MetadataRegistration

    // LEA with RIP-relative addressing: 48 8D 0D xx xx xx xx (lea rcx, [rip+disp32])
    // LEA with RIP-relative addressing: 48 8D 15 xx xx xx xx (lea rdx, [rip+disp32])

    let pattern_lea_rcx = [0x48, 0x8D, 0x0D];
    let pattern_lea_rdx = [0x48, 0x8D, 0x15];

    for section in binary.executable_sections() {
        if let Some(data) = binary.section_data(section) {
            // Search for lea rcx followed by lea rdx
            for i in 0..data.len().saturating_sub(20) {
                if data[i..].starts_with(&pattern_lea_rcx) {
                    // Check if lea rdx follows within reasonable distance
                    for j in (i + 7)..(i + 50).min(data.len() - 7) {
                        if data[j..].starts_with(&pattern_lea_rdx) {
                            // Found potential match
                            let code_offset = i32::from_le_bytes([
                                data[i + 3],
                                data[i + 4],
                                data[i + 5],
                                data[i + 6],
                            ]);
                            let meta_offset = i32::from_le_bytes([
                                data[j + 3],
                                data[j + 4],
                                data[j + 5],
                                data[j + 6],
                            ]);

                            let code_addr = section
                                .virtual_address
                                .offset((i as i64) + 7 + (code_offset as i64));
                            let meta_addr = section
                                .virtual_address
                                .offset((j as i64) + 7 + (meta_offset as i64));

                            debug!(
                                "Found potential x64 registration pattern at {}",
                                section.virtual_address.offset(i as i64)
                            );

                            return Some(SearchResult {
                                code_registration: code_addr,
                                metadata_registration: meta_addr,
                            });
                        }
                    }
                }
            }
        }
    }

    None
}

fn x86_pattern_search(binary: &dyn BinaryFile) -> Option<SearchResult> {
    // x86 uses direct addressing:
    // mov ecx, offset ; CodeRegistration
    // mov edx, offset ; MetadataRegistration

    // This is a placeholder - implement actual x86 pattern matching
    None
}

fn arm64_pattern_search(binary: &dyn BinaryFile) -> Option<SearchResult> {
    // ARM64 uses ADRP + ADD for address loading:
    // adrp x0, page
    // add x0, x0, offset

    // This is a placeholder - implement actual ARM64 pattern matching
    None
}

fn arm32_pattern_search(binary: &dyn BinaryFile) -> Option<SearchResult> {
    // ARM32 typically uses LDR with PC-relative addressing

    // This is a placeholder - implement actual ARM32 pattern matching
    None
}

/// Manually specify registration addresses
pub fn manual_search(code_registration: Address, metadata_registration: Address) -> SearchResult {
    SearchResult {
        code_registration,
        metadata_registration,
    }
}
