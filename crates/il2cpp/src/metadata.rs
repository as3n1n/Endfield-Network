//! IL2CPP global-metadata.dat parser

use crate::types::*;
use byteorder::{LittleEndian, ReadBytesExt};
use endfield_core::{Error, Result};
use std::io::Cursor;
use tracing::{debug, info, warn};

/// Parsed IL2CPP metadata
pub struct Metadata {
    /// Raw metadata bytes
    data: Vec<u8>,
    /// Metadata header
    pub header: Il2CppGlobalMetadataHeader,
    /// Metadata version
    pub version: u32,
    /// Type definitions
    pub type_definitions: Vec<Il2CppTypeDefinition>,
    /// Method definitions
    pub method_definitions: Vec<Il2CppMethodDefinition>,
    /// Field definitions
    pub field_definitions: Vec<Il2CppFieldDefinition>,
    /// Parameter definitions
    pub parameter_definitions: Vec<Il2CppParameterDefinition>,
    /// Property definitions
    pub property_definitions: Vec<Il2CppPropertyDefinition>,
    /// Event definitions
    pub event_definitions: Vec<Il2CppEventDefinition>,
    /// Image definitions
    pub image_definitions: Vec<Il2CppImageDefinition>,
    /// Assembly definitions
    pub assembly_definitions: Vec<Il2CppAssemblyDefinition>,
    /// Generic containers
    pub generic_containers: Vec<Il2CppGenericContainer>,
    /// Generic parameters
    pub generic_parameters: Vec<Il2CppGenericParameter>,
    /// String literals
    pub string_literals: Vec<Il2CppStringLiteral>,
    /// Interfaces
    pub interfaces: Vec<i32>,
    /// Nested types
    pub nested_types: Vec<i32>,
}

impl Metadata {
    /// Parse IL2CPP metadata from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(Error::parse("Metadata too small"));
        }

        let mut cursor = Cursor::new(data);

        // Read and verify magic
        let magic = cursor.read_u32::<LittleEndian>()?;
        if magic != METADATA_MAGIC {
            return Err(Error::InvalidMagic {
                expected: METADATA_MAGIC,
                actual: magic,
            });
        }

        // Read version
        let version = cursor.read_u32::<LittleEndian>()?;
        if version < MIN_METADATA_VERSION || version > MAX_METADATA_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }

        info!("Parsing IL2CPP metadata version {}", version);

        // Read header
        let header = Self::read_header(&mut cursor, version)?;
        debug!("Header parsed: {} type definitions", header.type_definitions_size / Self::type_def_size(version) as u32);

        // Parse arrays
        let type_definitions = Self::read_type_definitions(data, &header, version)?;
        let method_definitions = Self::read_method_definitions(data, &header, version)?;
        let field_definitions = Self::read_field_definitions(data, &header)?;
        let parameter_definitions = Self::read_parameter_definitions(data, &header)?;
        let property_definitions = Self::read_property_definitions(data, &header)?;
        let event_definitions = Self::read_event_definitions(data, &header)?;
        let image_definitions = Self::read_image_definitions(data, &header, version)?;
        let assembly_definitions = Self::read_assembly_definitions(data, &header, version)?;
        let generic_containers = Self::read_generic_containers(data, &header)?;
        let generic_parameters = Self::read_generic_parameters(data, &header)?;
        let string_literals = Self::read_string_literals(data, &header)?;
        let interfaces = Self::read_interfaces(data, &header)?;
        let nested_types = Self::read_nested_types(data, &header)?;

        info!(
            "Parsed {} types, {} methods, {} fields",
            type_definitions.len(),
            method_definitions.len(),
            field_definitions.len()
        );

        Ok(Self {
            data: data.to_vec(),
            header,
            version,
            type_definitions,
            method_definitions,
            field_definitions,
            parameter_definitions,
            property_definitions,
            event_definitions,
            image_definitions,
            assembly_definitions,
            generic_containers,
            generic_parameters,
            string_literals,
            interfaces,
            nested_types,
        })
    }

    fn read_header(cursor: &mut Cursor<&[u8]>, version: u32) -> Result<Il2CppGlobalMetadataHeader> {
        let mut header = Il2CppGlobalMetadataHeader::default();

        // Already read sanity and version
        header.sanity = METADATA_MAGIC;
        header.version = version;

        header.string_literal_offset = cursor.read_u32::<LittleEndian>()?;
        header.string_literal_size = cursor.read_u32::<LittleEndian>()?;
        header.string_literal_data_offset = cursor.read_u32::<LittleEndian>()?;
        header.string_literal_data_size = cursor.read_u32::<LittleEndian>()?;
        header.string_offset = cursor.read_u32::<LittleEndian>()?;
        header.string_size = cursor.read_u32::<LittleEndian>()?;
        header.events_offset = cursor.read_u32::<LittleEndian>()?;
        header.events_size = cursor.read_u32::<LittleEndian>()?;
        header.properties_offset = cursor.read_u32::<LittleEndian>()?;
        header.properties_size = cursor.read_u32::<LittleEndian>()?;
        header.methods_offset = cursor.read_u32::<LittleEndian>()?;
        header.methods_size = cursor.read_u32::<LittleEndian>()?;
        header.parameter_default_values_offset = cursor.read_u32::<LittleEndian>()?;
        header.parameter_default_values_size = cursor.read_u32::<LittleEndian>()?;
        header.field_default_values_offset = cursor.read_u32::<LittleEndian>()?;
        header.field_default_values_size = cursor.read_u32::<LittleEndian>()?;
        header.field_and_parameter_default_value_data_offset = cursor.read_u32::<LittleEndian>()?;
        header.field_and_parameter_default_value_data_size = cursor.read_u32::<LittleEndian>()?;
        header.field_marshaled_sizes_offset = cursor.read_u32::<LittleEndian>()?;
        header.field_marshaled_sizes_size = cursor.read_u32::<LittleEndian>()?;
        header.parameters_offset = cursor.read_u32::<LittleEndian>()?;
        header.parameters_size = cursor.read_u32::<LittleEndian>()?;
        header.fields_offset = cursor.read_u32::<LittleEndian>()?;
        header.fields_size = cursor.read_u32::<LittleEndian>()?;
        header.generic_parameters_offset = cursor.read_u32::<LittleEndian>()?;
        header.generic_parameters_size = cursor.read_u32::<LittleEndian>()?;
        header.generic_parameter_constraints_offset = cursor.read_u32::<LittleEndian>()?;
        header.generic_parameter_constraints_size = cursor.read_u32::<LittleEndian>()?;
        header.generic_containers_offset = cursor.read_u32::<LittleEndian>()?;
        header.generic_containers_size = cursor.read_u32::<LittleEndian>()?;
        header.nested_types_offset = cursor.read_u32::<LittleEndian>()?;
        header.nested_types_size = cursor.read_u32::<LittleEndian>()?;
        header.interfaces_offset = cursor.read_u32::<LittleEndian>()?;
        header.interfaces_size = cursor.read_u32::<LittleEndian>()?;
        header.vtable_methods_offset = cursor.read_u32::<LittleEndian>()?;
        header.vtable_methods_size = cursor.read_u32::<LittleEndian>()?;
        header.interface_offsets_offset = cursor.read_u32::<LittleEndian>()?;
        header.interface_offsets_size = cursor.read_u32::<LittleEndian>()?;
        header.type_definitions_offset = cursor.read_u32::<LittleEndian>()?;
        header.type_definitions_size = cursor.read_u32::<LittleEndian>()?;
        header.images_offset = cursor.read_u32::<LittleEndian>()?;
        header.images_size = cursor.read_u32::<LittleEndian>()?;
        header.assemblies_offset = cursor.read_u32::<LittleEndian>()?;
        header.assemblies_size = cursor.read_u32::<LittleEndian>()?;

        // Version-specific fields
        if version >= 19 {
            header.field_refs_offset = cursor.read_u32::<LittleEndian>()?;
            header.field_refs_size = cursor.read_u32::<LittleEndian>()?;
        }

        if version >= 20 {
            header.referenced_assemblies_offset = cursor.read_u32::<LittleEndian>()?;
            header.referenced_assemblies_size = cursor.read_u32::<LittleEndian>()?;
        }

        if version >= 21 {
            header.attribute_data_offset = cursor.read_u32::<LittleEndian>()?;
            header.attribute_data_size = cursor.read_u32::<LittleEndian>()?;
            header.attribute_data_range_offset = cursor.read_u32::<LittleEndian>()?;
            header.attribute_data_range_size = cursor.read_u32::<LittleEndian>()?;
        }

        if version >= 24 {
            header.unresolvedvirtual_call_parameter_types_offset = cursor.read_u32::<LittleEndian>()?;
            header.unresolvedvirtual_call_parameter_types_size = cursor.read_u32::<LittleEndian>()?;
            header.unresolvedvirtual_call_parameter_ranges_offset = cursor.read_u32::<LittleEndian>()?;
            header.unresolvedvirtual_call_parameter_ranges_size = cursor.read_u32::<LittleEndian>()?;
        }

        if version >= 24 && version <= 24 {
            header.windows_runtime_type_names_offset = cursor.read_u32::<LittleEndian>()?;
            header.windows_runtime_type_names_size = cursor.read_u32::<LittleEndian>()?;
            header.windows_runtime_strings_offset = cursor.read_u32::<LittleEndian>()?;
            header.windows_runtime_strings_size = cursor.read_u32::<LittleEndian>()?;
        }

        if version >= 24 {
            header.exported_type_definitions_offset = cursor.read_u32::<LittleEndian>()?;
            header.exported_type_definitions_size = cursor.read_u32::<LittleEndian>()?;
        }

        Ok(header)
    }

    fn type_def_size(version: u32) -> usize {
        if version >= 27 {
            88
        } else if version >= 24 {
            80
        } else {
            76
        }
    }

    fn read_type_definitions(data: &[u8], header: &Il2CppGlobalMetadataHeader, version: u32) -> Result<Vec<Il2CppTypeDefinition>> {
        let type_size = Self::type_def_size(version);
        let count = header.type_definitions_size as usize / type_size;
        let mut result = Vec::with_capacity(count);

        let offset = header.type_definitions_offset as usize;

        for i in 0..count {
            let pos = offset + i * type_size;
            if pos + type_size > data.len() {
                break;
            }

            let mut cursor = Cursor::new(&data[pos..]);
            let mut def = Il2CppTypeDefinition::default();

            def.name_index = cursor.read_u32::<LittleEndian>()?;
            def.namespace_index = cursor.read_u32::<LittleEndian>()?;
            def.byval_type_index = cursor.read_i32::<LittleEndian>()?;
            def.byref_type_index = cursor.read_i32::<LittleEndian>()?;
            def.declaring_type_index = cursor.read_i32::<LittleEndian>()?;
            def.parent_index = cursor.read_i32::<LittleEndian>()?;
            def.element_type_index = cursor.read_i32::<LittleEndian>()?;
            def.generic_container_index = cursor.read_i32::<LittleEndian>()?;
            def.flags = cursor.read_u32::<LittleEndian>()?;
            def.field_start = cursor.read_i32::<LittleEndian>()?;
            def.method_start = cursor.read_i32::<LittleEndian>()?;
            def.event_start = cursor.read_i32::<LittleEndian>()?;
            def.property_start = cursor.read_i32::<LittleEndian>()?;
            def.nested_types_start = cursor.read_i32::<LittleEndian>()?;
            def.interfaces_start = cursor.read_i32::<LittleEndian>()?;
            def.vtable_start = cursor.read_i32::<LittleEndian>()?;
            def.interface_offsets_start = cursor.read_i32::<LittleEndian>()?;
            def.method_count = cursor.read_u16::<LittleEndian>()?;
            def.property_count = cursor.read_u16::<LittleEndian>()?;
            def.field_count = cursor.read_u16::<LittleEndian>()?;
            def.event_count = cursor.read_u16::<LittleEndian>()?;
            def.nested_types_count = cursor.read_u16::<LittleEndian>()?;
            def.vtable_count = cursor.read_u16::<LittleEndian>()?;
            def.interfaces_count = cursor.read_u16::<LittleEndian>()?;
            def.interface_offsets_count = cursor.read_u16::<LittleEndian>()?;
            def.bitfield = cursor.read_u32::<LittleEndian>()?;
            def.token = cursor.read_u32::<LittleEndian>()?;

            result.push(def);
        }

        Ok(result)
    }

    fn read_method_definitions(data: &[u8], header: &Il2CppGlobalMetadataHeader, version: u32) -> Result<Vec<Il2CppMethodDefinition>> {
        let method_size = if version >= 24 { 24 } else { 20 };
        let count = header.methods_size as usize / method_size;
        let mut result = Vec::with_capacity(count);

        let offset = header.methods_offset as usize;

        for i in 0..count {
            let pos = offset + i * method_size;
            if pos + method_size > data.len() {
                break;
            }

            let mut cursor = Cursor::new(&data[pos..]);
            let mut def = Il2CppMethodDefinition::default();

            def.name_index = cursor.read_u32::<LittleEndian>()?;
            def.declaring_type = cursor.read_i32::<LittleEndian>()?;
            def.return_type = cursor.read_i32::<LittleEndian>()?;
            def.parameter_start = cursor.read_i32::<LittleEndian>()?;

            if version >= 24 {
                def.generic_container_index = cursor.read_i32::<LittleEndian>()?;
            }

            def.token = cursor.read_u32::<LittleEndian>()?;
            def.flags = cursor.read_u16::<LittleEndian>()?;
            def.iflags = cursor.read_u16::<LittleEndian>()?;
            def.slot = cursor.read_u16::<LittleEndian>()?;
            def.parameter_count = cursor.read_u16::<LittleEndian>()?;

            result.push(def);
        }

        Ok(result)
    }

    fn read_field_definitions(data: &[u8], header: &Il2CppGlobalMetadataHeader) -> Result<Vec<Il2CppFieldDefinition>> {
        let field_size = 12;
        let count = header.fields_size as usize / field_size;
        let mut result = Vec::with_capacity(count);

        let offset = header.fields_offset as usize;

        for i in 0..count {
            let pos = offset + i * field_size;
            if pos + field_size > data.len() {
                break;
            }

            let mut cursor = Cursor::new(&data[pos..]);
            let mut def = Il2CppFieldDefinition::default();

            def.name_index = cursor.read_u32::<LittleEndian>()?;
            def.type_index = cursor.read_i32::<LittleEndian>()?;
            def.token = cursor.read_u32::<LittleEndian>()?;

            result.push(def);
        }

        Ok(result)
    }

    fn read_parameter_definitions(data: &[u8], header: &Il2CppGlobalMetadataHeader) -> Result<Vec<Il2CppParameterDefinition>> {
        let param_size = 12;
        let count = header.parameters_size as usize / param_size;
        let mut result = Vec::with_capacity(count);

        let offset = header.parameters_offset as usize;

        for i in 0..count {
            let pos = offset + i * param_size;
            if pos + param_size > data.len() {
                break;
            }

            let mut cursor = Cursor::new(&data[pos..]);
            let mut def = Il2CppParameterDefinition::default();

            def.name_index = cursor.read_u32::<LittleEndian>()?;
            def.token = cursor.read_u32::<LittleEndian>()?;
            def.type_index = cursor.read_i32::<LittleEndian>()?;

            result.push(def);
        }

        Ok(result)
    }

    fn read_property_definitions(data: &[u8], header: &Il2CppGlobalMetadataHeader) -> Result<Vec<Il2CppPropertyDefinition>> {
        let prop_size = 20;
        let count = header.properties_size as usize / prop_size;
        let mut result = Vec::with_capacity(count);

        let offset = header.properties_offset as usize;

        for i in 0..count {
            let pos = offset + i * prop_size;
            if pos + prop_size > data.len() {
                break;
            }

            let mut cursor = Cursor::new(&data[pos..]);
            let mut def = Il2CppPropertyDefinition::default();

            def.name_index = cursor.read_u32::<LittleEndian>()?;
            def.get = cursor.read_i32::<LittleEndian>()?;
            def.set = cursor.read_i32::<LittleEndian>()?;
            def.attrs = cursor.read_u32::<LittleEndian>()?;
            def.token = cursor.read_u32::<LittleEndian>()?;

            result.push(def);
        }

        Ok(result)
    }

    fn read_event_definitions(data: &[u8], header: &Il2CppGlobalMetadataHeader) -> Result<Vec<Il2CppEventDefinition>> {
        let event_size = 24;
        let count = header.events_size as usize / event_size;
        let mut result = Vec::with_capacity(count);

        let offset = header.events_offset as usize;

        for i in 0..count {
            let pos = offset + i * event_size;
            if pos + event_size > data.len() {
                break;
            }

            let mut cursor = Cursor::new(&data[pos..]);
            let mut def = Il2CppEventDefinition::default();

            def.name_index = cursor.read_u32::<LittleEndian>()?;
            def.type_index = cursor.read_i32::<LittleEndian>()?;
            def.add = cursor.read_i32::<LittleEndian>()?;
            def.remove = cursor.read_i32::<LittleEndian>()?;
            def.raise = cursor.read_i32::<LittleEndian>()?;
            def.token = cursor.read_u32::<LittleEndian>()?;

            result.push(def);
        }

        Ok(result)
    }

    fn read_image_definitions(data: &[u8], header: &Il2CppGlobalMetadataHeader, version: u32) -> Result<Vec<Il2CppImageDefinition>> {
        let image_size = if version >= 24 { 40 } else { 24 };
        let count = header.images_size as usize / image_size;
        let mut result = Vec::with_capacity(count);

        let offset = header.images_offset as usize;

        for i in 0..count {
            let pos = offset + i * image_size;
            if pos + image_size > data.len() {
                break;
            }

            let mut cursor = Cursor::new(&data[pos..]);
            let mut def = Il2CppImageDefinition::default();

            def.name_index = cursor.read_u32::<LittleEndian>()?;
            def.assembly_index = cursor.read_i32::<LittleEndian>()?;
            def.type_start = cursor.read_i32::<LittleEndian>()?;
            def.type_count = cursor.read_u32::<LittleEndian>()?;

            if version >= 24 {
                def.exported_type_start = cursor.read_i32::<LittleEndian>()?;
                def.exported_type_count = cursor.read_u32::<LittleEndian>()?;
                def.entry_point_index = cursor.read_i32::<LittleEndian>()?;
                def.token = cursor.read_u32::<LittleEndian>()?;
                def.custom_attribute_start = cursor.read_i32::<LittleEndian>()?;
                def.custom_attribute_count = cursor.read_u32::<LittleEndian>()?;
            }

            result.push(def);
        }

        Ok(result)
    }

    fn read_assembly_definitions(data: &[u8], header: &Il2CppGlobalMetadataHeader, version: u32) -> Result<Vec<Il2CppAssemblyDefinition>> {
        let asm_size = if version >= 24 { 68 } else { 64 };
        let count = header.assemblies_size as usize / asm_size;
        let mut result = Vec::with_capacity(count);

        let offset = header.assemblies_offset as usize;

        for i in 0..count {
            let pos = offset + i * asm_size;
            if pos + asm_size > data.len() {
                break;
            }

            let mut cursor = Cursor::new(&data[pos..]);
            let mut def = Il2CppAssemblyDefinition::default();

            def.image_index = cursor.read_i32::<LittleEndian>()?;
            if version >= 24 {
                def.token = cursor.read_u32::<LittleEndian>()?;
            }
            def.referenced_assembly_start = cursor.read_i32::<LittleEndian>()?;
            def.referenced_assembly_count = cursor.read_i32::<LittleEndian>()?;

            // Assembly name
            def.aname.name_index = cursor.read_u32::<LittleEndian>()?;
            def.aname.culture_index = cursor.read_u32::<LittleEndian>()?;
            def.aname.public_key_index = cursor.read_u32::<LittleEndian>()?;
            def.aname.hash_value_index = cursor.read_u32::<LittleEndian>()?;
            cursor.read_exact(&mut def.aname.public_key_token)?;
            def.aname.hash_alg = cursor.read_u32::<LittleEndian>()?;
            def.aname.hash_len = cursor.read_i32::<LittleEndian>()?;
            def.aname.flags = cursor.read_u32::<LittleEndian>()?;
            def.aname.major = cursor.read_i32::<LittleEndian>()?;
            def.aname.minor = cursor.read_i32::<LittleEndian>()?;
            def.aname.build = cursor.read_i32::<LittleEndian>()?;
            def.aname.revision = cursor.read_i32::<LittleEndian>()?;

            result.push(def);
        }

        Ok(result)
    }

    fn read_generic_containers(data: &[u8], header: &Il2CppGlobalMetadataHeader) -> Result<Vec<Il2CppGenericContainer>> {
        let container_size = 16;
        let count = header.generic_containers_size as usize / container_size;
        let mut result = Vec::with_capacity(count);

        let offset = header.generic_containers_offset as usize;

        for i in 0..count {
            let pos = offset + i * container_size;
            if pos + container_size > data.len() {
                break;
            }

            let mut cursor = Cursor::new(&data[pos..]);
            let mut def = Il2CppGenericContainer::default();

            def.owner_index = cursor.read_i32::<LittleEndian>()?;
            def.type_argc = cursor.read_i32::<LittleEndian>()?;
            def.is_method = cursor.read_i32::<LittleEndian>()?;
            def.generic_parameter_start = cursor.read_i32::<LittleEndian>()?;

            result.push(def);
        }

        Ok(result)
    }

    fn read_generic_parameters(data: &[u8], header: &Il2CppGlobalMetadataHeader) -> Result<Vec<Il2CppGenericParameter>> {
        let param_size = 16;
        let count = header.generic_parameters_size as usize / param_size;
        let mut result = Vec::with_capacity(count);

        let offset = header.generic_parameters_offset as usize;

        for i in 0..count {
            let pos = offset + i * param_size;
            if pos + param_size > data.len() {
                break;
            }

            let mut cursor = Cursor::new(&data[pos..]);
            let mut def = Il2CppGenericParameter::default();

            def.owner_index = cursor.read_i32::<LittleEndian>()?;
            def.name_index = cursor.read_u32::<LittleEndian>()?;
            def.constraints_start = cursor.read_i16::<LittleEndian>()?;
            def.constraints_count = cursor.read_i16::<LittleEndian>()?;
            def.num = cursor.read_u16::<LittleEndian>()?;
            def.flags = cursor.read_u16::<LittleEndian>()?;

            result.push(def);
        }

        Ok(result)
    }

    fn read_string_literals(data: &[u8], header: &Il2CppGlobalMetadataHeader) -> Result<Vec<Il2CppStringLiteral>> {
        let literal_size = 8;
        let count = header.string_literal_size as usize / literal_size;
        let mut result = Vec::with_capacity(count);

        let offset = header.string_literal_offset as usize;

        for i in 0..count {
            let pos = offset + i * literal_size;
            if pos + literal_size > data.len() {
                break;
            }

            let mut cursor = Cursor::new(&data[pos..]);
            let mut def = Il2CppStringLiteral::default();

            def.length = cursor.read_u32::<LittleEndian>()?;
            def.data_index = cursor.read_u32::<LittleEndian>()?;

            result.push(def);
        }

        Ok(result)
    }

    fn read_interfaces(data: &[u8], header: &Il2CppGlobalMetadataHeader) -> Result<Vec<i32>> {
        let count = header.interfaces_size as usize / 4;
        let mut result = Vec::with_capacity(count);

        let offset = header.interfaces_offset as usize;

        for i in 0..count {
            let pos = offset + i * 4;
            if pos + 4 > data.len() {
                break;
            }

            let mut cursor = Cursor::new(&data[pos..]);
            result.push(cursor.read_i32::<LittleEndian>()?);
        }

        Ok(result)
    }

    fn read_nested_types(data: &[u8], header: &Il2CppGlobalMetadataHeader) -> Result<Vec<i32>> {
        let count = header.nested_types_size as usize / 4;
        let mut result = Vec::with_capacity(count);

        let offset = header.nested_types_offset as usize;

        for i in 0..count {
            let pos = offset + i * 4;
            if pos + 4 > data.len() {
                break;
            }

            let mut cursor = Cursor::new(&data[pos..]);
            result.push(cursor.read_i32::<LittleEndian>()?);
        }

        Ok(result)
    }

    /// Get a string from the string table
    pub fn get_string(&self, index: u32) -> Option<&str> {
        let offset = self.header.string_offset as usize + index as usize;
        if offset >= self.data.len() {
            return None;
        }

        let end = self.data[offset..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| offset + p)
            .unwrap_or(self.data.len());

        std::str::from_utf8(&self.data[offset..end]).ok()
    }

    /// Get a string literal
    pub fn get_string_literal(&self, index: usize) -> Option<String> {
        let literal = self.string_literals.get(index)?;
        let offset = self.header.string_literal_data_offset as usize + literal.data_index as usize;
        let end = offset + literal.length as usize * 2; // UTF-16

        if end > self.data.len() {
            return None;
        }

        let data = &self.data[offset..end];
        let utf16: Vec<u16> = data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        String::from_utf16(&utf16).ok()
    }
}
