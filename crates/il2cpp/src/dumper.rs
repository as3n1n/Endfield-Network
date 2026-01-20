//! IL2CPP dumper - extracts and organizes IL2CPP metadata

use crate::metadata::Metadata;
use crate::search;
use crate::types::*;
use endfield_binary_parser::{self, BinaryFile};
use endfield_core::{
    Address, DumpResults, DumpStatistics, DumpedField, DumpedMethod, DumpedProperty,
    DumpedType, MethodParameter, Result, StringLiteral,
};
use std::path::Path;
use tracing::{debug, info, warn};
use uuid::Uuid;
use chrono::Utc;

/// IL2CPP dumper
pub struct Il2CppDumper {
    binary: Box<dyn BinaryFile>,
    metadata: Metadata,
}

impl Il2CppDumper {
    /// Create a new dumper from binary and metadata files
    pub fn new(binary_path: &Path, metadata_path: &Path) -> Result<Self> {
        info!("Loading binary from {:?}", binary_path);
        let binary = endfield_binary_parser::load_binary(binary_path)
            .map_err(|e| endfield_core::Error::parse(e.to_string()))?;

        info!("Loading metadata from {:?}", metadata_path);
        let metadata = Metadata::parse(&std::fs::read(metadata_path)?)?;

        Ok(Self { binary, metadata })
    }

    /// Perform the dump
    pub fn dump(&self) -> Result<DumpResults> {
        info!("Starting IL2CPP dump");

        // Search for registration structures
        let _search_result = search::search_registrations(
            self.binary.as_ref(),
            self.metadata.type_definitions.len(),
            self.metadata.method_definitions.len(),
        );

        // Convert metadata to dumped types and methods
        let (types, methods) = self.process_types_and_methods();
        let string_literals = self.process_string_literals();

        let statistics = DumpStatistics {
            total_types: types.len(),
            total_methods: methods.len(),
            total_fields: types.iter().map(|t| t.fields.len()).sum(),
            total_strings: string_literals.len(),
            assemblies_count: self.metadata.assembly_definitions.len(),
        };

        info!(
            "Dump complete: {} types, {} methods, {} strings",
            statistics.total_types, statistics.total_methods, statistics.total_strings
        );

        Ok(DumpResults {
            timestamp: Utc::now(),
            unity_version: None, // Would need to parse from binary
            il2cpp_version: self.metadata.version,
            types,
            methods,
            string_literals,
            statistics,
        })
    }

    fn process_types_and_methods(&self) -> (Vec<DumpedType>, Vec<DumpedMethod>) {
        let mut types = Vec::with_capacity(self.metadata.type_definitions.len());
        let mut methods = Vec::with_capacity(self.metadata.method_definitions.len());
        let mut method_map = std::collections::HashMap::new();

        // Process all methods first
        for (idx, method_def) in self.metadata.method_definitions.iter().enumerate() {
            let method = self.process_method(idx, method_def);
            method_map.insert(idx, method.id);
            methods.push(method);
        }

        // Process all types
        for (idx, type_def) in self.metadata.type_definitions.iter().enumerate() {
            let dumped_type = self.process_type(idx, type_def, &method_map);
            types.push(dumped_type);
        }

        (types, methods)
    }

    fn process_type(
        &self,
        _idx: usize,
        type_def: &Il2CppTypeDefinition,
        method_map: &std::collections::HashMap<usize, Uuid>,
    ) -> DumpedType {
        let name = self
            .metadata
            .get_string(type_def.name_index)
            .unwrap_or("<unknown>")
            .to_string();

        let namespace = self
            .metadata
            .get_string(type_def.namespace_index)
            .unwrap_or("")
            .to_string();

        let full_name = if namespace.is_empty() {
            name.clone()
        } else {
            format!("{}.{}", namespace, name)
        };

        // Get parent type
        let parent_type = if type_def.parent_index >= 0 {
            self.get_type_name(type_def.parent_index as usize)
        } else {
            None
        };

        // Get interfaces
        let interfaces = self.get_interfaces(type_def);

        // Get fields
        let fields = self.get_fields(type_def);

        // Get methods
        let method_ids: Vec<Uuid> = if type_def.method_start >= 0 {
            (0..type_def.method_count as usize)
                .filter_map(|i| method_map.get(&(type_def.method_start as usize + i)).copied())
                .collect()
        } else {
            Vec::new()
        };

        // Get properties
        let properties = self.get_properties(type_def);

        let flags = type_def.flags;

        DumpedType {
            id: Uuid::new_v4(),
            name,
            namespace,
            full_name,
            parent_type,
            interfaces,
            fields,
            methods: method_ids,
            properties,
            is_enum: (type_def.bitfield & 0x1) != 0,
            is_interface: (flags & type_attributes::INTERFACE) != 0,
            is_abstract: (flags & type_attributes::ABSTRACT) != 0,
            is_sealed: (flags & type_attributes::SEALED) != 0,
            token: type_def.token,
        }
    }

    fn process_method(&self, _idx: usize, method_def: &Il2CppMethodDefinition) -> DumpedMethod {
        let name = self
            .metadata
            .get_string(method_def.name_index)
            .unwrap_or("<unknown>")
            .to_string();

        let class_name = if method_def.declaring_type >= 0 {
            let type_def = &self.metadata.type_definitions[method_def.declaring_type as usize];
            self.metadata
                .get_string(type_def.name_index)
                .unwrap_or("<unknown>")
                .to_string()
        } else {
            String::new()
        };

        let namespace = if method_def.declaring_type >= 0 {
            let type_def = &self.metadata.type_definitions[method_def.declaring_type as usize];
            self.metadata
                .get_string(type_def.namespace_index)
                .unwrap_or("")
                .to_string()
        } else {
            String::new()
        };

        let return_type = self.get_type_name_by_index(method_def.return_type);

        // Get parameters
        let parameters = self.get_parameters(method_def);

        let full_name = format!("{}$${}",
            if namespace.is_empty() {
                class_name.clone()
            } else {
                format!("{}.{}", namespace, class_name)
            },
            name
        );

        let flags = method_def.flags;

        DumpedMethod {
            id: Uuid::new_v4(),
            name,
            full_name,
            address: Address::ZERO, // Would be filled from binary analysis
            return_type,
            parameters,
            class_name,
            namespace,
            is_static: (flags & method_attributes::STATIC) != 0,
            is_virtual: (flags & method_attributes::VIRTUAL) != 0,
            is_abstract: (flags & method_attributes::ABSTRACT) != 0,
            token: method_def.token,
        }
    }

    fn get_type_name(&self, idx: usize) -> Option<String> {
        let type_def = self.metadata.type_definitions.get(idx)?;
        let name = self.metadata.get_string(type_def.name_index)?;
        let namespace = self.metadata.get_string(type_def.namespace_index).unwrap_or("");

        Some(if namespace.is_empty() {
            name.to_string()
        } else {
            format!("{}.{}", namespace, name)
        })
    }

    fn get_type_name_by_index(&self, type_index: i32) -> String {
        // In a full implementation, this would look up the Il2CppType
        // and resolve it properly. For now, return a placeholder.
        if type_index < 0 {
            "void".to_string()
        } else {
            format!("Type_{}", type_index)
        }
    }

    fn get_interfaces(&self, type_def: &Il2CppTypeDefinition) -> Vec<String> {
        if type_def.interfaces_start < 0 || type_def.interfaces_count == 0 {
            return Vec::new();
        }

        let start = type_def.interfaces_start as usize;
        let count = type_def.interfaces_count as usize;

        (0..count)
            .filter_map(|i| {
                let interface_idx = self.metadata.interfaces.get(start + i)?;
                if *interface_idx >= 0 {
                    self.get_type_name(*interface_idx as usize)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_fields(&self, type_def: &Il2CppTypeDefinition) -> Vec<DumpedField> {
        if type_def.field_start < 0 || type_def.field_count == 0 {
            return Vec::new();
        }

        let start = type_def.field_start as usize;
        let count = type_def.field_count as usize;

        (0..count)
            .filter_map(|i| {
                let field_def = self.metadata.field_definitions.get(start + i)?;
                let name = self
                    .metadata
                    .get_string(field_def.name_index)
                    .unwrap_or("<unknown>")
                    .to_string();
                let type_name = self.get_type_name_by_index(field_def.type_index);

                Some(DumpedField {
                    name,
                    type_name,
                    offset: 0, // Would be filled from field offsets in binary
                    is_static: false, // Would be determined from type flags
                    is_const: false,
                    default_value: None,
                })
            })
            .collect()
    }

    fn get_parameters(&self, method_def: &Il2CppMethodDefinition) -> Vec<MethodParameter> {
        if method_def.parameter_start < 0 || method_def.parameter_count == 0 {
            return Vec::new();
        }

        let start = method_def.parameter_start as usize;
        let count = method_def.parameter_count as usize;

        (0..count)
            .filter_map(|i| {
                let param_def = self.metadata.parameter_definitions.get(start + i)?;
                let name = self
                    .metadata
                    .get_string(param_def.name_index)
                    .unwrap_or(&format!("param{}", i))
                    .to_string();
                let type_name = self.get_type_name_by_index(param_def.type_index);

                Some(MethodParameter {
                    name,
                    type_name,
                    index: i as u32,
                })
            })
            .collect()
    }

    fn get_properties(&self, type_def: &Il2CppTypeDefinition) -> Vec<DumpedProperty> {
        if type_def.property_start < 0 || type_def.property_count == 0 {
            return Vec::new();
        }

        let start = type_def.property_start as usize;
        let count = type_def.property_count as usize;

        (0..count)
            .filter_map(|i| {
                let prop_def = self.metadata.property_definitions.get(start + i)?;
                let name = self
                    .metadata
                    .get_string(prop_def.name_index)
                    .unwrap_or("<unknown>")
                    .to_string();

                Some(DumpedProperty {
                    name,
                    type_name: String::new(), // Would need getter/setter return type
                    getter: None, // Would map to method UUID
                    setter: None,
                })
            })
            .collect()
    }

    fn process_string_literals(&self) -> Vec<StringLiteral> {
        self.metadata
            .string_literals
            .iter()
            .enumerate()
            .filter_map(|(idx, _)| {
                let value = self.metadata.get_string_literal(idx)?;
                Some(StringLiteral {
                    address: Address::ZERO, // Would be filled from binary
                    value,
                    index: idx as u32,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_name_generation() {
        let namespace = "Game.Core";
        let class_name = "Player";
        let method_name = "Update";

        let full_name = format!("{}.{}$${}", namespace, class_name, method_name);
        assert_eq!(full_name, "Game.Core.Player$$Update");
    }
}
