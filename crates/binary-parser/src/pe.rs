//! PE (Portable Executable) format parser for Windows binaries

use crate::common::{BinaryFile, BinaryReader, Section, SectionFlags, Symbol, SymbolType};
use crate::error::{ParseError, ParseResult};
use endfield_core::{Address, Architecture, BinaryFormat, Platform};

/// DOS header magic
const DOS_MAGIC: u16 = 0x5A4D; // "MZ"

/// PE signature
const PE_SIGNATURE: u32 = 0x00004550; // "PE\0\0"

/// PE machine types
const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_FILE_MACHINE_ARM: u16 = 0x01c0;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

/// PE optional header magic
const PE32_MAGIC: u16 = 0x10b;
const PE32PLUS_MAGIC: u16 = 0x20b;

/// Section characteristics
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;

/// Parsed PE file
pub struct PeFile {
    data: Vec<u8>,
    architecture: Architecture,
    image_base: Address,
    entry_point: Address,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    is_64bit: bool,
}

impl PeFile {
    /// Parse a PE file from raw bytes
    pub fn parse(data: &[u8]) -> ParseResult<Self> {
        let mut reader = BinaryReader::new(data, true);

        // Parse DOS header
        let dos_magic = reader.read_u16()?;
        if dos_magic != DOS_MAGIC {
            return Err(ParseError::InvalidMagic {
                expected: DOS_MAGIC as u32,
                actual: dos_magic as u32,
            });
        }

        // Skip to e_lfanew (offset to PE header) at offset 0x3C
        reader.set_offset(0x3C);
        let pe_offset = reader.read_u32()? as usize;

        // Parse PE signature
        reader.set_offset(pe_offset);
        let pe_sig = reader.read_u32()?;
        if pe_sig != PE_SIGNATURE {
            return Err(ParseError::InvalidMagic {
                expected: PE_SIGNATURE,
                actual: pe_sig,
            });
        }

        // Parse COFF header
        let machine = reader.read_u16()?;
        let number_of_sections = reader.read_u16()?;
        let _time_date_stamp = reader.read_u32()?;
        let _pointer_to_symbol_table = reader.read_u32()?;
        let _number_of_symbols = reader.read_u32()?;
        let size_of_optional_header = reader.read_u16()?;
        let _characteristics = reader.read_u16()?;

        let architecture = match machine {
            IMAGE_FILE_MACHINE_I386 => Architecture::X86,
            IMAGE_FILE_MACHINE_AMD64 => Architecture::X64,
            IMAGE_FILE_MACHINE_ARM => Architecture::Arm32,
            IMAGE_FILE_MACHINE_ARM64 => Architecture::Arm64,
            _ => Architecture::Unknown,
        };

        // Parse optional header
        let optional_header_offset = reader.offset();
        let optional_magic = reader.read_u16()?;
        let is_64bit = optional_magic == PE32PLUS_MAGIC;

        if optional_magic != PE32_MAGIC && optional_magic != PE32PLUS_MAGIC {
            return Err(ParseError::invalid_header(format!(
                "Invalid optional header magic: {:#x}",
                optional_magic
            )));
        }

        // Skip standard fields
        reader.skip(2)?; // MajorLinkerVersion, MinorLinkerVersion
        reader.skip(4)?; // SizeOfCode
        reader.skip(4)?; // SizeOfInitializedData
        reader.skip(4)?; // SizeOfUninitializedData

        let address_of_entry_point = reader.read_u32()?;

        reader.skip(4)?; // BaseOfCode
        if !is_64bit {
            reader.skip(4)?; // BaseOfData (PE32 only)
        }

        let image_base = if is_64bit {
            reader.read_u64()?
        } else {
            reader.read_u32()? as u64
        };

        // Skip to section headers
        let section_header_offset =
            optional_header_offset + size_of_optional_header as usize;
        reader.set_offset(section_header_offset);

        // Parse section headers
        let mut sections = Vec::with_capacity(number_of_sections as usize);
        for _ in 0..number_of_sections {
            let name_bytes = reader.read_bytes(8)?;
            let name = String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0')
                .to_string();

            let virtual_size = reader.read_u32()? as u64;
            let virtual_address = reader.read_u32()? as u64;
            let size_of_raw_data = reader.read_u32()? as u64;
            let pointer_to_raw_data = reader.read_u32()? as u64;
            reader.skip(4)?; // PointerToRelocations
            reader.skip(4)?; // PointerToLinenumbers
            reader.skip(2)?; // NumberOfRelocations
            reader.skip(2)?; // NumberOfLinenumbers
            let characteristics = reader.read_u32()?;

            let mut flags = SectionFlags::empty();
            if characteristics & IMAGE_SCN_MEM_READ != 0 {
                flags |= SectionFlags::READ;
            }
            if characteristics & IMAGE_SCN_MEM_WRITE != 0 {
                flags |= SectionFlags::WRITE;
            }
            if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
                flags |= SectionFlags::EXECUTE;
            }
            if characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
                flags |= SectionFlags::INITIALIZED;
            }
            if characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
                flags |= SectionFlags::UNINITIALIZED;
            }

            sections.push(Section {
                name,
                virtual_address: Address::new(image_base + virtual_address),
                virtual_size,
                raw_offset: pointer_to_raw_data,
                raw_size: size_of_raw_data,
                characteristics: flags,
            });
        }

        // TODO: Parse export table for symbols
        let symbols = Vec::new();

        Ok(Self {
            data: data.to_vec(),
            architecture,
            image_base: Address::new(image_base),
            entry_point: Address::new(image_base + address_of_entry_point as u64),
            sections,
            symbols,
            is_64bit,
        })
    }

    /// Get the data directory entry
    pub fn get_data_directory(&self, index: usize) -> Option<(u32, u32)> {
        // This would need to be implemented with proper parsing of the optional header
        None
    }
}

impl BinaryFile for PeFile {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::PE
    }

    fn architecture(&self) -> Architecture {
        self.architecture
    }

    fn platform(&self) -> Platform {
        Platform::Windows
    }

    fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    fn image_base(&self) -> Address {
        self.image_base
    }

    fn entry_point(&self) -> Address {
        self.entry_point
    }

    fn sections(&self) -> &[Section] {
        &self.sections
    }

    fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    fn va_to_offset(&self, va: Address) -> Option<u64> {
        for section in &self.sections {
            let section_va_start = section.virtual_address.as_u64();
            let section_va_end = section_va_start + section.virtual_size;

            if va.as_u64() >= section_va_start && va.as_u64() < section_va_end {
                let rva = va.as_u64() - section_va_start;
                return Some(section.raw_offset + rva);
            }
        }
        None
    }

    fn offset_to_va(&self, offset: u64) -> Option<Address> {
        for section in &self.sections {
            let raw_start = section.raw_offset;
            let raw_end = raw_start + section.raw_size;

            if offset >= raw_start && offset < raw_end {
                let section_offset = offset - raw_start;
                return Some(Address::new(
                    section.virtual_address.as_u64() + section_offset,
                ));
            }
        }
        None
    }

    fn read_va(&self, va: Address, size: usize) -> ParseResult<&[u8]> {
        let offset = self
            .va_to_offset(va)
            .ok_or_else(|| ParseError::AddressOutOfBounds(va.as_u64()))? as usize;

        if offset + size > self.data.len() {
            return Err(ParseError::AddressOutOfBounds(va.as_u64()));
        }

        Ok(&self.data[offset..offset + size])
    }

    fn read_string_va(&self, va: Address, max_len: usize) -> ParseResult<String> {
        let offset = self
            .va_to_offset(va)
            .ok_or_else(|| ParseError::AddressOutOfBounds(va.as_u64()))? as usize;

        let end = (offset + max_len).min(self.data.len());
        for i in offset..end {
            if self.data[i] == 0 {
                return Ok(String::from_utf8_lossy(&self.data[offset..i]).to_string());
            }
        }

        Ok(String::from_utf8_lossy(&self.data[offset..end]).to_string())
    }

    fn data(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dos_magic() {
        let data = b"MZ";
        let reader = BinaryReader::new(data, true);
        assert_eq!(reader.remaining(), 2);
    }
}
