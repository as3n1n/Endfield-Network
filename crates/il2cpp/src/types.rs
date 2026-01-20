//! IL2CPP structure definitions
//!
//! These structures mirror the IL2CPP runtime metadata format.

use serde::{Deserialize, Serialize};

/// IL2CPP metadata magic number
pub const METADATA_MAGIC: u32 = 0xFAB11BAF;

/// Supported metadata versions
pub const MIN_METADATA_VERSION: u32 = 16;
pub const MAX_METADATA_VERSION: u32 = 31;

/// Global metadata header
#[derive(Debug, Clone, Default)]
pub struct Il2CppGlobalMetadataHeader {
    pub sanity: u32,
    pub version: u32,
    pub string_literal_offset: u32,
    pub string_literal_size: u32,
    pub string_literal_data_offset: u32,
    pub string_literal_data_size: u32,
    pub string_offset: u32,
    pub string_size: u32,
    pub events_offset: u32,
    pub events_size: u32,
    pub properties_offset: u32,
    pub properties_size: u32,
    pub methods_offset: u32,
    pub methods_size: u32,
    pub parameter_default_values_offset: u32,
    pub parameter_default_values_size: u32,
    pub field_default_values_offset: u32,
    pub field_default_values_size: u32,
    pub field_and_parameter_default_value_data_offset: u32,
    pub field_and_parameter_default_value_data_size: u32,
    pub field_marshaled_sizes_offset: u32,
    pub field_marshaled_sizes_size: u32,
    pub parameters_offset: u32,
    pub parameters_size: u32,
    pub fields_offset: u32,
    pub fields_size: u32,
    pub generic_parameters_offset: u32,
    pub generic_parameters_size: u32,
    pub generic_parameter_constraints_offset: u32,
    pub generic_parameter_constraints_size: u32,
    pub generic_containers_offset: u32,
    pub generic_containers_size: u32,
    pub nested_types_offset: u32,
    pub nested_types_size: u32,
    pub interfaces_offset: u32,
    pub interfaces_size: u32,
    pub vtable_methods_offset: u32,
    pub vtable_methods_size: u32,
    pub interface_offsets_offset: u32,
    pub interface_offsets_size: u32,
    pub type_definitions_offset: u32,
    pub type_definitions_size: u32,
    pub images_offset: u32,
    pub images_size: u32,
    pub assemblies_offset: u32,
    pub assemblies_size: u32,
    pub field_refs_offset: u32,
    pub field_refs_size: u32,
    pub referenced_assemblies_offset: u32,
    pub referenced_assemblies_size: u32,
    pub attribute_data_offset: u32,
    pub attribute_data_size: u32,
    pub attribute_data_range_offset: u32,
    pub attribute_data_range_size: u32,
    pub unresolvedvirtual_call_parameter_types_offset: u32,
    pub unresolvedvirtual_call_parameter_types_size: u32,
    pub unresolvedvirtual_call_parameter_ranges_offset: u32,
    pub unresolvedvirtual_call_parameter_ranges_size: u32,
    pub windows_runtime_type_names_offset: u32,
    pub windows_runtime_type_names_size: u32,
    pub windows_runtime_strings_offset: u32,
    pub windows_runtime_strings_size: u32,
    pub exported_type_definitions_offset: u32,
    pub exported_type_definitions_size: u32,
}

/// Type definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Il2CppTypeDefinition {
    pub name_index: u32,
    pub namespace_index: u32,
    pub byval_type_index: i32,
    pub byref_type_index: i32,
    pub declaring_type_index: i32,
    pub parent_index: i32,
    pub element_type_index: i32,
    pub generic_container_index: i32,
    pub flags: u32,
    pub field_start: i32,
    pub method_start: i32,
    pub event_start: i32,
    pub property_start: i32,
    pub nested_types_start: i32,
    pub interfaces_start: i32,
    pub vtable_start: i32,
    pub interface_offsets_start: i32,
    pub method_count: u16,
    pub property_count: u16,
    pub field_count: u16,
    pub event_count: u16,
    pub nested_types_count: u16,
    pub vtable_count: u16,
    pub interfaces_count: u16,
    pub interface_offsets_count: u16,
    pub bitfield: u32,
    pub token: u32,
}

/// Method definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Il2CppMethodDefinition {
    pub name_index: u32,
    pub declaring_type: i32,
    pub return_type: i32,
    pub parameter_start: i32,
    pub generic_container_index: i32,
    pub token: u32,
    pub flags: u16,
    pub iflags: u16,
    pub slot: u16,
    pub parameter_count: u16,
}

/// Field definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Il2CppFieldDefinition {
    pub name_index: u32,
    pub type_index: i32,
    pub token: u32,
}

/// Parameter definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Il2CppParameterDefinition {
    pub name_index: u32,
    pub token: u32,
    pub type_index: i32,
}

/// Property definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Il2CppPropertyDefinition {
    pub name_index: u32,
    pub get: i32,
    pub set: i32,
    pub attrs: u32,
    pub token: u32,
}

/// Event definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Il2CppEventDefinition {
    pub name_index: u32,
    pub type_index: i32,
    pub add: i32,
    pub remove: i32,
    pub raise: i32,
    pub token: u32,
}

/// Image definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Il2CppImageDefinition {
    pub name_index: u32,
    pub assembly_index: i32,
    pub type_start: i32,
    pub type_count: u32,
    pub exported_type_start: i32,
    pub exported_type_count: u32,
    pub entry_point_index: i32,
    pub token: u32,
    pub custom_attribute_start: i32,
    pub custom_attribute_count: u32,
}

/// Assembly definition
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Il2CppAssemblyDefinition {
    pub image_index: i32,
    pub token: u32,
    pub referenced_assembly_start: i32,
    pub referenced_assembly_count: i32,
    pub aname: Il2CppAssemblyName,
}

/// Assembly name
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Il2CppAssemblyName {
    pub name_index: u32,
    pub culture_index: u32,
    pub public_key_index: u32,
    pub hash_value_index: u32,
    pub public_key_token: [u8; 8],
    pub hash_alg: u32,
    pub hash_len: i32,
    pub flags: u32,
    pub major: i32,
    pub minor: i32,
    pub build: i32,
    pub revision: i32,
}

/// Generic container
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Il2CppGenericContainer {
    pub owner_index: i32,
    pub type_argc: i32,
    pub is_method: i32,
    pub generic_parameter_start: i32,
}

/// Generic parameter
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Il2CppGenericParameter {
    pub owner_index: i32,
    pub name_index: u32,
    pub constraints_start: i16,
    pub constraints_count: i16,
    pub num: u16,
    pub flags: u16,
}

/// String literal
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Il2CppStringLiteral {
    pub length: u32,
    pub data_index: u32,
}

/// Field reference
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Il2CppFieldRef {
    pub type_index: i32,
    pub field_index: i32,
}

/// Code registration structure (found in binary)
#[derive(Debug, Clone, Default)]
pub struct Il2CppCodeRegistration {
    pub reverse_pinvoke_wrapper_count: u64,
    pub reverse_pinvoke_wrappers: u64,
    pub generic_method_pointers_count: u64,
    pub generic_method_pointers: u64,
    pub generic_adjustor_thunks: u64,
    pub invoker_pointers: u64,
    pub custom_attribute_count: u64,
    pub custom_attribute_generators: u64,
    pub unresolvedvirtual_call_count: u64,
    pub unresolvedvirtual_call_pointers: u64,
    pub interop_data_count: u64,
    pub interop_data: u64,
    pub windows_runtime_factory_count: u64,
    pub windows_runtime_factory_table: u64,
    pub code_gen_modules_count: u64,
    pub code_gen_modules: u64,
}

/// Metadata registration structure (found in binary)
#[derive(Debug, Clone, Default)]
pub struct Il2CppMetadataRegistration {
    pub generic_classes_count: i64,
    pub generic_classes: u64,
    pub generic_insts_count: i64,
    pub generic_insts: u64,
    pub generic_method_table_count: i64,
    pub generic_method_table: u64,
    pub types_count: i64,
    pub types: u64,
    pub method_specs_count: i64,
    pub method_specs: u64,
    pub field_offsets_count: i64,
    pub field_offsets: u64,
    pub type_definition_sizes_count: i64,
    pub type_definition_sizes: u64,
    pub metadata_usages_count: u64,
    pub metadata_usages: u64,
}

/// Type attribute flags
pub mod type_attributes {
    pub const VISIBILITY_MASK: u32 = 0x00000007;
    pub const NOT_PUBLIC: u32 = 0x00000000;
    pub const PUBLIC: u32 = 0x00000001;
    pub const NESTED_PUBLIC: u32 = 0x00000002;
    pub const NESTED_PRIVATE: u32 = 0x00000003;
    pub const NESTED_FAMILY: u32 = 0x00000004;
    pub const NESTED_ASSEMBLY: u32 = 0x00000005;
    pub const NESTED_FAM_AND_ASSEM: u32 = 0x00000006;
    pub const NESTED_FAM_OR_ASSEM: u32 = 0x00000007;

    pub const LAYOUT_MASK: u32 = 0x00000018;
    pub const AUTO_LAYOUT: u32 = 0x00000000;
    pub const SEQUENTIAL_LAYOUT: u32 = 0x00000008;
    pub const EXPLICIT_LAYOUT: u32 = 0x00000010;

    pub const CLASS_SEMANTIC_MASK: u32 = 0x00000020;
    pub const CLASS: u32 = 0x00000000;
    pub const INTERFACE: u32 = 0x00000020;

    pub const ABSTRACT: u32 = 0x00000080;
    pub const SEALED: u32 = 0x00000100;
    pub const SPECIAL_NAME: u32 = 0x00000400;
    pub const IMPORT: u32 = 0x00001000;
    pub const SERIALIZABLE: u32 = 0x00002000;

    pub const STRING_FORMAT_MASK: u32 = 0x00030000;
    pub const ANSI_CLASS: u32 = 0x00000000;
    pub const UNICODE_CLASS: u32 = 0x00010000;
    pub const AUTO_CLASS: u32 = 0x00020000;
    pub const CUSTOM_FORMAT_CLASS: u32 = 0x00030000;

    pub const BEFORE_FIELD_INIT: u32 = 0x00100000;
    pub const FORWARDER: u32 = 0x00200000;

    pub const RT_SPECIAL_NAME: u32 = 0x00000800;
    pub const HAS_SECURITY: u32 = 0x00040000;
}

/// Method attribute flags
pub mod method_attributes {
    pub const MEMBER_ACCESS_MASK: u16 = 0x0007;
    pub const COMPILER_CONTROLLED: u16 = 0x0000;
    pub const PRIVATE: u16 = 0x0001;
    pub const FAM_AND_ASSEM: u16 = 0x0002;
    pub const ASSEMBLY: u16 = 0x0003;
    pub const FAMILY: u16 = 0x0004;
    pub const FAM_OR_ASSEM: u16 = 0x0005;
    pub const PUBLIC: u16 = 0x0006;

    pub const STATIC: u16 = 0x0010;
    pub const FINAL: u16 = 0x0020;
    pub const VIRTUAL: u16 = 0x0040;
    pub const HIDE_BY_SIG: u16 = 0x0080;

    pub const VTABLE_LAYOUT_MASK: u16 = 0x0100;
    pub const REUSE_SLOT: u16 = 0x0000;
    pub const NEW_SLOT: u16 = 0x0100;

    pub const CHECK_ACCESS_ON_OVERRIDE: u16 = 0x0200;
    pub const ABSTRACT: u16 = 0x0400;
    pub const SPECIAL_NAME: u16 = 0x0800;

    pub const PINVOKE_IMPL: u16 = 0x2000;
    pub const UNMANAGED_EXPORT: u16 = 0x0008;

    pub const RT_SPECIAL_NAME: u16 = 0x1000;
    pub const HAS_SECURITY: u16 = 0x4000;
    pub const REQUIRE_SEC_OBJECT: u16 = 0x8000;
}
