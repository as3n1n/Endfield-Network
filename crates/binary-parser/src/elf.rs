//! ELF (Executable and Linkable Format) parser for Linux/Android binaries

use crate::common::{BinaryFile, BinaryReader, Section, SectionFlags, Symbol, SymbolType};
use crate::error::{ParseError, ParseResult};
use endfield_core::{Address, Architecture, BinaryFormat, Platform};

/// ELF magic
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF classes
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;

/// ELF endianness
const ELFDATA2LSB: u8 = 1; // Little endian
const ELFDATA2MSB: u8 = 2; // Big endian

/// ELF machine types
const EM_386: u16 = 3;
const EM_ARM: u16 = 40;
const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

/// ELF OS/ABI
const ELFOSABI_LINUX: u8 = 3;

/// Section flags
const SHF_WRITE: u64 = 0x1;
const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;

/// Section types
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_DYNSYM: u32 = 11;

/// Symbol types
const STT_NOTYPE: u8 = 0;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
const STT_FILE: u8 = 4;

/// Parsed ELF file
pub struct ElfFile {
    data: Vec<u8>,
    architecture: Architecture,
    is_64bit: bool,
    little_endian: bool,
    entry_point: Address,
    sections: Vec<Section>,
    symbols: Vec<Symbol>,
}

impl ElfFile {
    /// Parse an ELF file from raw bytes
    pub fn parse(data: &[u8]) -> ParseResult<Self> {
        if data.len() < 16 {
            return Err(ParseError::truncated(16, data.len()));
        }

        // Check magic
        if &data[0..4] != ELF_MAGIC {
            return Err(ParseError::InvalidMagic {
                expected: u32::from_le_bytes(ELF_MAGIC),
                actual: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            });
        }

        let elf_class = data[4];
        let is_64bit = match elf_class {
            ELFCLASS32 => false,
            ELFCLASS64 => true,
            _ => return Err(ParseError::invalid_header(format!("Invalid ELF class: {}", elf_class))),
        };

        let elf_data = data[5];
        let little_endian = match elf_data {
            ELFDATA2LSB => true,
            ELFDATA2MSB => false,
            _ => return Err(ParseError::invalid_header(format!("Invalid ELF data encoding: {}", elf_data))),
        };

        let mut reader = BinaryReader::new(data, little_endian);
        reader.set_offset(16); // Skip e_ident

        let _e_type = reader.read_u16()?;
        let e_machine = reader.read_u16()?;
        let _e_version = reader.read_u32()?;

        let architecture = match e_machine {
            EM_386 => Architecture::X86,
            EM_X86_64 => Architecture::X64,
            EM_ARM => Architecture::Arm32,
            EM_AARCH64 => Architecture::Arm64,
            _ => Architecture::Unknown,
        };

        let (entry_point, _ph_offset, sh_offset, _ph_entsize, _ph_num, sh_entsize, sh_num, sh_strndx) =
            if is_64bit {
                let e_entry = reader.read_u64()?;
                let e_phoff = reader.read_u64()?;
                let e_shoff = reader.read_u64()?;
                let _e_flags = reader.read_u32()?;
                let _e_ehsize = reader.read_u16()?;
                let e_phentsize = reader.read_u16()?;
                let e_phnum = reader.read_u16()?;
                let e_shentsize = reader.read_u16()?;
                let e_shnum = reader.read_u16()?;
                let e_shstrndx = reader.read_u16()?;
                (e_entry, e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx)
            } else {
                let e_entry = reader.read_u32()? as u64;
                let e_phoff = reader.read_u32()? as u64;
                let e_shoff = reader.read_u32()? as u64;
                let _e_flags = reader.read_u32()?;
                let _e_ehsize = reader.read_u16()?;
                let e_phentsize = reader.read_u16()?;
                let e_phnum = reader.read_u16()?;
                let e_shentsize = reader.read_u16()?;
                let e_shnum = reader.read_u16()?;
                let e_shstrndx = reader.read_u16()?;
                (e_entry, e_phoff, e_shoff, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx)
            };

        // Parse section headers
        let mut raw_sections = Vec::new();
        let mut strtab_offset = 0u64;
        let mut strtab_size = 0u64;

        if sh_num > 0 && sh_offset > 0 {
            for i in 0..sh_num as usize {
                let offset = sh_offset as usize + i * sh_entsize as usize;
                reader.set_offset(offset);

                let (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size) = if is_64bit {
                    let sh_name = reader.read_u32()?;
                    let sh_type = reader.read_u32()?;
                    let sh_flags = reader.read_u64()?;
                    let sh_addr = reader.read_u64()?;
                    let sh_offset = reader.read_u64()?;
                    let sh_size = reader.read_u64()?;
                    (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size)
                } else {
                    let sh_name = reader.read_u32()?;
                    let sh_type = reader.read_u32()?;
                    let sh_flags = reader.read_u32()? as u64;
                    let sh_addr = reader.read_u32()? as u64;
                    let sh_offset = reader.read_u32()? as u64;
                    let sh_size = reader.read_u32()? as u64;
                    (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size)
                };

                raw_sections.push((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size));

                // Find section header string table
                if i == sh_strndx as usize {
                    strtab_offset = sh_offset;
                    strtab_size = sh_size;
                }
            }
        }

        // Resolve section names
        let mut sections = Vec::with_capacity(raw_sections.len());
        for (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size) in raw_sections.iter() {
            let name = if strtab_size > 0 && (*sh_name as u64) < strtab_size {
                let name_offset = strtab_offset as usize + *sh_name as usize;
                let mut end = name_offset;
                while end < data.len() && data[end] != 0 {
                    end += 1;
                }
                String::from_utf8_lossy(&data[name_offset..end]).to_string()
            } else {
                String::new()
            };

            let mut flags = SectionFlags::empty();
            if sh_flags & SHF_ALLOC != 0 {
                flags |= SectionFlags::READ;
            }
            if sh_flags & SHF_WRITE != 0 {
                flags |= SectionFlags::WRITE;
            }
            if sh_flags & SHF_EXECINSTR != 0 {
                flags |= SectionFlags::EXECUTE;
            }

            sections.push(Section {
                name,
                virtual_address: Address::new(*sh_addr),
                virtual_size: *sh_size,
                raw_offset: *sh_offset,
                raw_size: *sh_size,
                characteristics: flags,
            });
        }

        // Parse symbols
        let symbols = Self::parse_symbols(data, &raw_sections, is_64bit, little_endian)?;

        Ok(Self {
            data: data.to_vec(),
            architecture,
            is_64bit,
            little_endian,
            entry_point: Address::new(entry_point),
            sections,
            symbols,
        })
    }

    fn parse_symbols(
        data: &[u8],
        raw_sections: &[(u32, u32, u64, u64, u64, u64)],
        is_64bit: bool,
        little_endian: bool,
    ) -> ParseResult<Vec<Symbol>> {
        let mut symbols = Vec::new();

        // Find symbol table and string table
        for (i, (_, sh_type, _, _, sh_offset, sh_size)) in raw_sections.iter().enumerate() {
            if *sh_type != SHT_SYMTAB && *sh_type != SHT_DYNSYM {
                continue;
            }

            // Find associated string table (usually sh_link, but we'll use a simple heuristic)
            let strtab_idx = i + 1;
            if strtab_idx >= raw_sections.len() {
                continue;
            }

            let (_, strtab_type, _, _, strtab_offset, strtab_size) = raw_sections[strtab_idx];
            if strtab_type != SHT_STRTAB {
                continue;
            }

            let sym_size = if is_64bit { 24 } else { 16 };
            let num_symbols = *sh_size as usize / sym_size;

            let mut reader = BinaryReader::new(data, little_endian);

            for j in 0..num_symbols {
                let offset = *sh_offset as usize + j * sym_size;
                reader.set_offset(offset);

                let (st_name, st_value, st_size, st_info) = if is_64bit {
                    let st_name = reader.read_u32()?;
                    let st_info = reader.read_u8()?;
                    let _st_other = reader.read_u8()?;
                    let _st_shndx = reader.read_u16()?;
                    let st_value = reader.read_u64()?;
                    let st_size = reader.read_u64()?;
                    (st_name, st_value, st_size, st_info)
                } else {
                    let st_name = reader.read_u32()?;
                    let st_value = reader.read_u32()? as u64;
                    let st_size = reader.read_u32()? as u64;
                    let st_info = reader.read_u8()?;
                    (st_name, st_value, st_size, st_info)
                };

                let name = if (st_name as u64) < strtab_size {
                    let name_offset = strtab_offset as usize + st_name as usize;
                    let mut end = name_offset;
                    while end < data.len() && data[end] != 0 {
                        end += 1;
                    }
                    String::from_utf8_lossy(&data[name_offset..end]).to_string()
                } else {
                    continue;
                };

                if name.is_empty() {
                    continue;
                }

                let sym_type = st_info & 0xf;
                let symbol_type = match sym_type {
                    STT_FUNC => SymbolType::Function,
                    STT_OBJECT => SymbolType::Object,
                    STT_SECTION => SymbolType::Section,
                    STT_FILE => SymbolType::File,
                    _ => SymbolType::Unknown,
                };

                symbols.push(Symbol {
                    name,
                    address: Address::new(st_value),
                    size: if st_size > 0 { Some(st_size) } else { None },
                    symbol_type,
                });
            }
        }

        Ok(symbols)
    }
}

impl BinaryFile for ElfFile {
    fn format(&self) -> BinaryFormat {
        BinaryFormat::ELF
    }

    fn architecture(&self) -> Architecture {
        self.architecture
    }

    fn platform(&self) -> Platform {
        // Could be Linux or Android - default to Linux
        Platform::Linux
    }

    fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    fn image_base(&self) -> Address {
        // ELF doesn't have a fixed image base like PE
        // Return the lowest section address
        self.sections
            .iter()
            .filter(|s| s.virtual_address.as_u64() > 0)
            .map(|s| s.virtual_address)
            .min()
            .unwrap_or(Address::ZERO)
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
