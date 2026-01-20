//! Common traits and types for binary parsing

use endfield_core::{Address, Architecture, BinaryFormat, Platform};
use crate::ParseResult;

/// Trait for parsed binary files
pub trait BinaryFile: Send + Sync {
    /// Get the binary format
    fn format(&self) -> BinaryFormat;

    /// Get the architecture
    fn architecture(&self) -> Architecture;

    /// Get the platform
    fn platform(&self) -> Platform;

    /// Check if 64-bit
    fn is_64bit(&self) -> bool {
        self.architecture().is_64bit()
    }

    /// Get the image base address
    fn image_base(&self) -> Address;

    /// Get the entry point address
    fn entry_point(&self) -> Address;

    /// Get all sections
    fn sections(&self) -> &[Section];

    /// Find a section by name
    fn find_section(&self, name: &str) -> Option<&Section> {
        self.sections().iter().find(|s| s.name == name)
    }

    /// Get all symbols (if available)
    fn symbols(&self) -> &[Symbol];

    /// Find a symbol by name
    fn find_symbol(&self, name: &str) -> Option<&Symbol> {
        self.symbols().iter().find(|s| s.name == name)
    }

    /// Convert virtual address to file offset
    fn va_to_offset(&self, va: Address) -> Option<u64>;

    /// Convert file offset to virtual address
    fn offset_to_va(&self, offset: u64) -> Option<Address>;

    /// Read bytes at a virtual address
    fn read_va(&self, va: Address, size: usize) -> ParseResult<&[u8]>;

    /// Read a null-terminated string at a virtual address
    fn read_string_va(&self, va: Address, max_len: usize) -> ParseResult<String>;

    /// Get the raw binary data
    fn data(&self) -> &[u8];

    /// Get executable sections
    fn executable_sections(&self) -> Vec<&Section> {
        self.sections()
            .iter()
            .filter(|s| s.characteristics.contains(SectionFlags::EXECUTE))
            .collect()
    }

    /// Get data sections
    fn data_sections(&self) -> Vec<&Section> {
        self.sections()
            .iter()
            .filter(|s| {
                !s.characteristics.contains(SectionFlags::EXECUTE)
                    && s.characteristics.contains(SectionFlags::READ)
            })
            .collect()
    }

    /// Search for a byte pattern in executable sections
    fn search_pattern(&self, pattern: &[u8]) -> Vec<Address> {
        let mut results = Vec::new();
        for section in self.executable_sections() {
            if let Some(data) = self.section_data(section) {
                for (offset, window) in data.windows(pattern.len()).enumerate() {
                    if window == pattern {
                        let va = section.virtual_address.offset(offset as i64);
                        results.push(va);
                    }
                }
            }
        }
        results
    }

    /// Search for a byte pattern with wildcards (0xFF = wildcard)
    fn search_pattern_masked(&self, pattern: &[u8], mask: &[u8]) -> Vec<Address> {
        assert_eq!(pattern.len(), mask.len());
        let mut results = Vec::new();

        for section in self.executable_sections() {
            if let Some(data) = self.section_data(section) {
                'outer: for (offset, window) in data.windows(pattern.len()).enumerate() {
                    for (i, &byte) in window.iter().enumerate() {
                        if mask[i] != 0 && byte != pattern[i] {
                            continue 'outer;
                        }
                    }
                    let va = section.virtual_address.offset(offset as i64);
                    results.push(va);
                }
            }
        }
        results
    }

    /// Get raw data for a section
    fn section_data(&self, section: &Section) -> Option<&[u8]> {
        let start = section.raw_offset as usize;
        let end = start + section.raw_size as usize;
        let data = self.data();
        if end <= data.len() {
            Some(&data[start..end])
        } else {
            None
        }
    }
}

/// Binary section information
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name
    pub name: String,
    /// Virtual address
    pub virtual_address: Address,
    /// Virtual size
    pub virtual_size: u64,
    /// Raw file offset
    pub raw_offset: u64,
    /// Raw file size
    pub raw_size: u64,
    /// Section characteristics/flags
    pub characteristics: SectionFlags,
}

bitflags::bitflags! {
    /// Section flags
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SectionFlags: u32 {
        const READ = 0x0001;
        const WRITE = 0x0002;
        const EXECUTE = 0x0004;
        const INITIALIZED = 0x0008;
        const UNINITIALIZED = 0x0010;
    }
}

/// Symbol information
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Symbol name
    pub name: String,
    /// Symbol address
    pub address: Address,
    /// Symbol size (if known)
    pub size: Option<u64>,
    /// Symbol type
    pub symbol_type: SymbolType,
}

/// Symbol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolType {
    Function,
    Object,
    Section,
    File,
    Unknown,
}

/// Helper to read primitives from byte slices
pub struct BinaryReader<'a> {
    data: &'a [u8],
    offset: usize,
    little_endian: bool,
}

impl<'a> BinaryReader<'a> {
    pub fn new(data: &'a [u8], little_endian: bool) -> Self {
        Self {
            data,
            offset: 0,
            little_endian,
        }
    }

    pub fn new_at(data: &'a [u8], offset: usize, little_endian: bool) -> Self {
        Self {
            data,
            offset,
            little_endian,
        }
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn set_offset(&mut self, offset: usize) {
        self.offset = offset;
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    pub fn read_u8(&mut self) -> ParseResult<u8> {
        if self.offset >= self.data.len() {
            return Err(crate::ParseError::truncated(1, 0));
        }
        let value = self.data[self.offset];
        self.offset += 1;
        Ok(value)
    }

    pub fn read_u16(&mut self) -> ParseResult<u16> {
        if self.offset + 2 > self.data.len() {
            return Err(crate::ParseError::truncated(2, self.remaining()));
        }
        let bytes = [self.data[self.offset], self.data[self.offset + 1]];
        self.offset += 2;
        Ok(if self.little_endian {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    }

    pub fn read_u32(&mut self) -> ParseResult<u32> {
        if self.offset + 4 > self.data.len() {
            return Err(crate::ParseError::truncated(4, self.remaining()));
        }
        let bytes = [
            self.data[self.offset],
            self.data[self.offset + 1],
            self.data[self.offset + 2],
            self.data[self.offset + 3],
        ];
        self.offset += 4;
        Ok(if self.little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }

    pub fn read_u64(&mut self) -> ParseResult<u64> {
        if self.offset + 8 > self.data.len() {
            return Err(crate::ParseError::truncated(8, self.remaining()));
        }
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.data[self.offset..self.offset + 8]);
        self.offset += 8;
        Ok(if self.little_endian {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        })
    }

    pub fn read_i32(&mut self) -> ParseResult<i32> {
        Ok(self.read_u32()? as i32)
    }

    pub fn read_i64(&mut self) -> ParseResult<i64> {
        Ok(self.read_u64()? as i64)
    }

    pub fn read_bytes(&mut self, count: usize) -> ParseResult<&'a [u8]> {
        if self.offset + count > self.data.len() {
            return Err(crate::ParseError::truncated(count, self.remaining()));
        }
        let bytes = &self.data[self.offset..self.offset + count];
        self.offset += count;
        Ok(bytes)
    }

    pub fn read_cstring(&mut self, max_len: usize) -> ParseResult<String> {
        let start = self.offset;
        let end = (start + max_len).min(self.data.len());

        for i in start..end {
            if self.data[i] == 0 {
                let s = String::from_utf8_lossy(&self.data[start..i]).to_string();
                self.offset = i + 1;
                return Ok(s);
            }
        }

        Err(crate::ParseError::parse("Unterminated string"))
    }

    pub fn skip(&mut self, count: usize) -> ParseResult<()> {
        if self.offset + count > self.data.len() {
            return Err(crate::ParseError::truncated(count, self.remaining()));
        }
        self.offset += count;
        Ok(())
    }

    pub fn peek_u32(&self) -> ParseResult<u32> {
        if self.offset + 4 > self.data.len() {
            return Err(crate::ParseError::truncated(4, self.remaining()));
        }
        let bytes = [
            self.data[self.offset],
            self.data[self.offset + 1],
            self.data[self.offset + 2],
            self.data[self.offset + 3],
        ];
        Ok(if self.little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }
}
