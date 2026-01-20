//! Binary format parsers for IL2CPP analysis
//!
//! Supports PE (Windows), ELF (Linux/Android), and Mach-O (macOS/iOS) formats.

pub mod pe;
pub mod elf;
pub mod macho;
pub mod common;
pub mod error;

pub use common::{BinaryFile, Section, Symbol};
pub use error::{ParseError, ParseResult};

use endfield_core::{Architecture, BinaryFormat, Platform};
use std::path::Path;

/// Detect binary format from magic bytes
pub fn detect_format(data: &[u8]) -> Option<BinaryFormat> {
    if data.len() < 4 {
        return None;
    }

    // PE: MZ header
    if data.len() >= 2 && &data[0..2] == b"MZ" {
        return Some(BinaryFormat::PE);
    }

    // ELF: 0x7F ELF
    if data.len() >= 4 && &data[0..4] == b"\x7FELF" {
        return Some(BinaryFormat::ELF);
    }

    // Mach-O: various magic numbers
    if data.len() >= 4 {
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        match magic {
            0xFEEDFACE | 0xFEEDFACF | 0xCAFEBABE | 0xBEBAFECA => {
                return Some(BinaryFormat::MachO);
            }
            _ => {}
        }
    }

    None
}

/// Load a binary file and parse it
pub fn load_binary(path: &Path) -> ParseResult<Box<dyn BinaryFile>> {
    let data = std::fs::read(path)?;
    parse_binary(&data)
}

/// Parse binary data
pub fn parse_binary(data: &[u8]) -> ParseResult<Box<dyn BinaryFile>> {
    let format = detect_format(data).ok_or_else(|| ParseError::UnknownFormat)?;

    match format {
        BinaryFormat::PE => {
            let pe = pe::PeFile::parse(data)?;
            Ok(Box::new(pe))
        }
        BinaryFormat::ELF => {
            let elf = elf::ElfFile::parse(data)?;
            Ok(Box::new(elf))
        }
        BinaryFormat::MachO => {
            let macho = macho::MachOFile::parse(data)?;
            Ok(Box::new(macho))
        }
        BinaryFormat::Unknown => Err(ParseError::UnknownFormat),
    }
}
