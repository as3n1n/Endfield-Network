//! Mach-O format parser for macOS/iOS binaries

use crate::common::{BinaryFile, BinaryReader, Section, SectionFlags, Symbol, SymbolType};
use crate::error::{ParseError, ParseResult};
use endfield_core::{Address, Architecture, BinaryFormat, Platform};

/// Mach-O magic numbers
const MH_MAGIC: u32 = 0xFEEDFACE;      // 32-bit
const MH_MAGIC_64: u32 = 0xFEEDFACF;   // 64-bit
const MH_CIGAM: u32 = 0xCEFAEDFE;      // 32-bit big endian
const MH_CIGAM_64: u32 = 0xCFFAEDFE;   // 64-bit big endian
const FAT_MAGIC: u32 = 0xCAFEBABE;     // Universal binary

/// CPU types
const CPU_TYPE_I386: u32 = 7;
const CPU_TYPE_X86_64: u32 = 0x01000007;
const CPU_TYPE_ARM: u32 = 12;
const CPU_TYPE_ARM64: u32 = 0x0100000C;

/// Load commands
const LC_SEGMENT: u32 = 0x01;
const LC_SYMTAB: u32 = 0x02;
const LC_SEGMENT_64: u32 = 0x19;
const LC_MAIN: u32 = 0x80000028;

/// Segment flags
const VM_PROT_READ: u32 = 0x01;
const VM_PROT_WRITE: u32 = 0x02;
const VM_PROT_EXECUTE: u32 = 0x04;

/// Parsed Mach-O file
pub struct MachOFile {
    data: Vec<u8>,
    architecture: Architecture,
    is_64bit: bool,
    little_endian: bool,
    entry_point: Address,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
    text_base: Address,
}

impl MachOFile {
    /// Parse a Mach-O file from raw bytes
    pub fn parse(data: &[u8]) -> ParseResult<Self> {
        if data.len() < 4 {
            return Err(ParseError::truncated(4, data.len()));
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        let (is_64bit, little_endian, offset) = match magic {
            MH_MAGIC => (false, true, 0),
            MH_MAGIC_64 => (true, true, 0),
            MH_CIGAM => (false, false, 0),
            MH_CIGAM_64 => (true, false, 0),
            FAT_MAGIC => {
                // Universal binary - find the appropriate architecture
                return Self::parse_fat_binary(data);
            }
            _ => return Err(ParseError::InvalidMagic {
                expected: MH_MAGIC_64,
                actual: magic,
            }),
        };

        Self::parse_macho(data, offset, is_64bit, little_endian)
    }

    fn parse_fat_binary(data: &[u8]) -> ParseResult<Self> {
        let mut reader = BinaryReader::new(data, false); // FAT headers are big endian
        let _magic = reader.read_u32()?;
        let nfat_arch = reader.read_u32()?;

        // Try to find x86_64 or arm64 first
        let mut best_offset = None;
        let mut best_is_64 = false;

        for _ in 0..nfat_arch {
            let cputype = reader.read_u32()?;
            let _cpusubtype = reader.read_u32()?;
            let offset = reader.read_u32()?;
            let _size = reader.read_u32()?;
            let _align = reader.read_u32()?;

            match cputype {
                CPU_TYPE_X86_64 | CPU_TYPE_ARM64 => {
                    best_offset = Some(offset as usize);
                    best_is_64 = true;
                    break;
                }
                CPU_TYPE_I386 | CPU_TYPE_ARM => {
                    if best_offset.is_none() {
                        best_offset = Some(offset as usize);
                        best_is_64 = false;
                    }
                }
                _ => {}
            }
        }

        let offset = best_offset.ok_or_else(|| ParseError::invalid_header("No supported architecture in FAT binary"))?;

        // Re-check magic at offset
        let magic = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
        let little_endian = matches!(magic, MH_MAGIC | MH_MAGIC_64);

        Self::parse_macho(data, offset, best_is_64, little_endian)
    }

    fn parse_macho(data: &[u8], base_offset: usize, is_64bit: bool, little_endian: bool) -> ParseResult<Self> {
        let mut reader = BinaryReader::new(data, little_endian);
        reader.set_offset(base_offset);

        let _magic = reader.read_u32()?;
        let cputype = reader.read_u32()?;
        let _cpusubtype = reader.read_u32()?;
        let _filetype = reader.read_u32()?;
        let ncmds = reader.read_u32()?;
        let _sizeofcmds = reader.read_u32()?;
        let _flags = reader.read_u32()?;

        if is_64bit {
            let _reserved = reader.read_u32()?;
        }

        let architecture = match cputype {
            CPU_TYPE_I386 => Architecture::X86,
            CPU_TYPE_X86_64 => Architecture::X64,
            CPU_TYPE_ARM => Architecture::Arm32,
            CPU_TYPE_ARM64 => Architecture::Arm64,
            _ => Architecture::Unknown,
        };

        let mut sections = Vec::new();
        let mut symbols = Vec::new();
        let mut entry_point = Address::ZERO;
        let mut text_base = Address::ZERO;
        let mut symtab_offset = 0u32;
        let mut symtab_count = 0u32;
        let mut strtab_offset = 0u32;
        let mut strtab_size = 0u32;

        // Parse load commands
        for _ in 0..ncmds {
            let cmd_start = reader.offset();
            let cmd = reader.read_u32()?;
            let cmdsize = reader.read_u32()?;

            match cmd {
                LC_SEGMENT | LC_SEGMENT_64 => {
                    let (segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects) =
                        if cmd == LC_SEGMENT_64 {
                            let segname = reader.read_bytes(16)?;
                            let vmaddr = reader.read_u64()?;
                            let vmsize = reader.read_u64()?;
                            let fileoff = reader.read_u64()?;
                            let filesize = reader.read_u64()?;
                            let maxprot = reader.read_u32()?;
                            let initprot = reader.read_u32()?;
                            let nsects = reader.read_u32()?;
                            let _flags = reader.read_u32()?;
                            (segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects)
                        } else {
                            let segname = reader.read_bytes(16)?;
                            let vmaddr = reader.read_u32()? as u64;
                            let vmsize = reader.read_u32()? as u64;
                            let fileoff = reader.read_u32()? as u64;
                            let filesize = reader.read_u32()? as u64;
                            let maxprot = reader.read_u32()?;
                            let initprot = reader.read_u32()?;
                            let nsects = reader.read_u32()?;
                            let _flags = reader.read_u32()?;
                            (segname, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects)
                        };

                    let seg_name = String::from_utf8_lossy(segname)
                        .trim_end_matches('\0')
                        .to_string();

                    if seg_name == "__TEXT" {
                        text_base = Address::new(vmaddr);
                    }

                    // Parse sections within segment
                    for _ in 0..nsects {
                        let (sectname, segname_sect, addr, size, offset) = if cmd == LC_SEGMENT_64 {
                            let sectname = reader.read_bytes(16)?;
                            let segname = reader.read_bytes(16)?;
                            let addr = reader.read_u64()?;
                            let size = reader.read_u64()?;
                            let offset = reader.read_u32()?;
                            let _align = reader.read_u32()?;
                            let _reloff = reader.read_u32()?;
                            let _nreloc = reader.read_u32()?;
                            let _flags = reader.read_u32()?;
                            let _reserved1 = reader.read_u32()?;
                            let _reserved2 = reader.read_u32()?;
                            let _reserved3 = reader.read_u32()?;
                            (sectname, segname, addr, size, offset)
                        } else {
                            let sectname = reader.read_bytes(16)?;
                            let segname = reader.read_bytes(16)?;
                            let addr = reader.read_u32()? as u64;
                            let size = reader.read_u32()? as u64;
                            let offset = reader.read_u32()?;
                            let _align = reader.read_u32()?;
                            let _reloff = reader.read_u32()?;
                            let _nreloc = reader.read_u32()?;
                            let _flags = reader.read_u32()?;
                            let _reserved1 = reader.read_u32()?;
                            let _reserved2 = reader.read_u32()?;
                            (sectname, segname, addr, size, offset)
                        };

                        let section_name = String::from_utf8_lossy(sectname)
                            .trim_end_matches('\0')
                            .to_string();

                        let mut flags = SectionFlags::empty();
                        if initprot & VM_PROT_READ != 0 {
                            flags |= SectionFlags::READ;
                        }
                        if initprot & VM_PROT_WRITE != 0 {
                            flags |= SectionFlags::WRITE;
                        }
                        if initprot & VM_PROT_EXECUTE != 0 {
                            flags |= SectionFlags::EXECUTE;
                        }

                        sections.push(Section {
                            name: format!("{},{}", seg_name, section_name),
                            virtual_address: Address::new(addr),
                            virtual_size: size,
                            raw_offset: (base_offset as u64) + offset as u64,
                            raw_size: size,
                            characteristics: flags,
                        });
                    }
                }
                LC_MAIN => {
                    let entryoff = reader.read_u64()?;
                    let _stacksize = reader.read_u64()?;
                    entry_point = Address::new(entryoff);
                }
                LC_SYMTAB => {
                    symtab_offset = reader.read_u32()?;
                    symtab_count = reader.read_u32()?;
                    strtab_offset = reader.read_u32()?;
                    strtab_size = reader.read_u32()?;
                }
                _ => {}
            }

            reader.set_offset(cmd_start + cmdsize as usize);
        }

        // Adjust entry point to absolute address
        if entry_point.as_u64() > 0 && text_base.as_u64() > 0 {
            entry_point = Address::new(text_base.as_u64() + entry_point.as_u64());
        }

        // Parse symbols
        if symtab_count > 0 && symtab_offset > 0 && strtab_size > 0 {
            symbols = Self::parse_symbols(
                data,
                base_offset + symtab_offset as usize,
                symtab_count as usize,
                base_offset + strtab_offset as usize,
                strtab_size as usize,
                is_64bit,
                little_endian,
            )?;
        }

        Ok(Self {
            data: data.to_vec(),
            architecture,
            is_64bit,
            little_endian,
            entry_point,
            sections,
            symbols,
            text_base,
        })
    }

    fn parse_symbols(
        data: &[u8],
        symtab_offset: usize,
        symtab_count: usize,
        strtab_offset: usize,
        strtab_size: usize,
        is_64bit: bool,
        little_endian: bool,
    ) -> ParseResult<Vec<Symbol>> {
        let mut symbols = Vec::new();
        let sym_size = if is_64bit { 16 } else { 12 };
        let mut reader = BinaryReader::new(data, little_endian);

        for i in 0..symtab_count {
            let offset = symtab_offset + i * sym_size;
            if offset + sym_size > data.len() {
                break;
            }
            reader.set_offset(offset);

            let n_strx = reader.read_u32()?;
            let n_type = reader.read_u8()?;
            let _n_sect = reader.read_u8()?;
            let _n_desc = reader.read_u16()?;
            let n_value = if is_64bit {
                reader.read_u64()?
            } else {
                reader.read_u32()? as u64
            };

            if (n_strx as usize) >= strtab_size {
                continue;
            }

            let name_offset = strtab_offset + n_strx as usize;
            let mut end = name_offset;
            while end < data.len() && data[end] != 0 {
                end += 1;
            }
            let name = String::from_utf8_lossy(&data[name_offset..end]).to_string();

            if name.is_empty() {
                continue;
            }

            // Determine symbol type from n_type
            let symbol_type = if n_type & 0x0e == 0x0e {
                SymbolType::Function
            } else if n_type & 0x0e == 0x02 {
                SymbolType::Object
            } else {
                SymbolType::Unknown
            };

            symbols.push(Symbol {
                name,
                address: Address::new(n_value),
                size: None,
                symbol_type,
            });
        }

        Ok(symbols)
    }
}

impl BinaryFile for MachOFile {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::MachO
    }

    fn architecture(&self) -> Architecture {
        self.architecture
    }

    fn platform(&self) -> Platform {
        // Could be macOS or iOS - default to macOS
        Platform::MacOS
    }

    fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    fn image_base(&self) -> Address {
        self.text_base
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
                let offset_in_section = va.as_u64() - section_va_start;
                return Some(section.raw_offset + offset_in_section);
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
