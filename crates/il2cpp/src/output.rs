//! Output generators for IL2CPP dump results

use endfield_core::{DumpResults, DumpedMethod, DumpedType, Result, StringLiteral};
use serde::Serialize;
use std::io::Write;
use std::path::Path;

/// JSON script output format (compatible with IDA/Ghidra scripts)
#[derive(Debug, Serialize)]
pub struct ScriptJson {
    #[serde(rename = "ScriptMethod")]
    pub methods: Vec<ScriptMethod>,
    #[serde(rename = "ScriptString")]
    pub strings: Vec<ScriptString>,
    #[serde(rename = "ScriptMetadata")]
    pub metadata: Vec<ScriptMetadata>,
    #[serde(rename = "ScriptMetadataMethod")]
    pub metadata_methods: Vec<ScriptMetadataMethod>,
    #[serde(rename = "Addresses")]
    pub addresses: Vec<u64>,
}

#[derive(Debug, Serialize)]
pub struct ScriptMethod {
    #[serde(rename = "Address")]
    pub address: u64,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Signature")]
    pub signature: String,
    #[serde(rename = "TypeSignature")]
    pub type_signature: String,
}

#[derive(Debug, Serialize)]
pub struct ScriptString {
    #[serde(rename = "Address")]
    pub address: u64,
    #[serde(rename = "Value")]
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct ScriptMetadata {
    #[serde(rename = "Address")]
    pub address: u64,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Signature")]
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct ScriptMetadataMethod {
    #[serde(rename = "Address")]
    pub address: u64,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "MethodAddress")]
    pub method_address: u64,
}

impl ScriptJson {
    /// Create from dump results
    pub fn from_results(results: &DumpResults) -> Self {
        let methods: Vec<ScriptMethod> = results
            .methods
            .iter()
            .map(|m| ScriptMethod {
                address: m.address.as_u64(),
                name: m.full_name.clone(),
                signature: Self::build_method_signature(m),
                type_signature: m.return_type.clone(),
            })
            .collect();

        let strings: Vec<ScriptString> = results
            .string_literals
            .iter()
            .map(|s| ScriptString {
                address: s.address.as_u64(),
                value: s.value.clone(),
            })
            .collect();

        Self {
            methods,
            strings,
            metadata: Vec::new(),
            metadata_methods: Vec::new(),
            addresses: Vec::new(),
        }
    }

    fn build_method_signature(method: &DumpedMethod) -> String {
        let params = method
            .parameters
            .iter()
            .map(|p| format!("{} {}", p.type_name, p.name))
            .collect::<Vec<_>>()
            .join(", ");

        format!("{} {}({})", method.return_type, method.name, params)
    }

    /// Write to JSON file
    pub fn write_to_file(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| endfield_core::Error::parse(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

/// C/C++ header output
pub struct HeaderGenerator;

impl HeaderGenerator {
    /// Generate C header from dump results
    pub fn generate(results: &DumpResults) -> String {
        let mut output = String::new();

        output.push_str("// Auto-generated IL2CPP header\n");
        output.push_str("// Do not edit manually\n\n");
        output.push_str("#pragma once\n\n");
        output.push_str("#include <stdint.h>\n\n");

        // Forward declarations
        output.push_str("// Forward declarations\n");
        for type_def in &results.types {
            if !type_def.is_interface {
                output.push_str(&format!("struct {};\n", Self::sanitize_name(&type_def.name)));
            }
        }
        output.push_str("\n");

        // Type definitions
        for type_def in &results.types {
            output.push_str(&Self::generate_type(type_def));
            output.push_str("\n");
        }

        output
    }

    fn generate_type(type_def: &DumpedType) -> String {
        let mut output = String::new();

        // Comment with full name
        output.push_str(&format!("// {}\n", type_def.full_name));

        if type_def.is_enum {
            output.push_str(&format!("enum {} {{\n", Self::sanitize_name(&type_def.name)));
            for field in &type_def.fields {
                if let Some(ref value) = field.default_value {
                    output.push_str(&format!("    {} = {},\n", Self::sanitize_name(&field.name), value));
                } else {
                    output.push_str(&format!("    {},\n", Self::sanitize_name(&field.name)));
                }
            }
            output.push_str("};\n");
        } else if type_def.is_interface {
            output.push_str(&format!("// Interface: {}\n", type_def.name));
        } else {
            output.push_str(&format!("struct {} {{\n", Self::sanitize_name(&type_def.name)));

            // IL2CPP object header
            output.push_str("    void* klass;  // Il2CppClass*\n");
            output.push_str("    void* monitor;  // MonitorData*\n");

            // Fields
            for field in &type_def.fields {
                if !field.is_static {
                    output.push_str(&format!(
                        "    {} {};  // Offset: 0x{:X}\n",
                        Self::type_to_c(&field.type_name),
                        Self::sanitize_name(&field.name),
                        field.offset
                    ));
                }
            }

            output.push_str("};\n");

            // Static fields
            let static_fields: Vec<_> = type_def.fields.iter().filter(|f| f.is_static).collect();
            if !static_fields.is_empty() {
                output.push_str(&format!("\n// Static fields for {}\n", type_def.name));
                for field in static_fields {
                    output.push_str(&format!(
                        "// static {} {};\n",
                        Self::type_to_c(&field.type_name),
                        Self::sanitize_name(&field.name)
                    ));
                }
            }
        }

        output
    }

    fn sanitize_name(name: &str) -> String {
        name.chars()
            .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
            .collect()
    }

    fn type_to_c(type_name: &str) -> &str {
        match type_name {
            "System.Void" | "void" => "void",
            "System.Boolean" | "bool" => "bool",
            "System.Byte" | "byte" => "uint8_t",
            "System.SByte" | "sbyte" => "int8_t",
            "System.Int16" | "short" => "int16_t",
            "System.UInt16" | "ushort" => "uint16_t",
            "System.Int32" | "int" => "int32_t",
            "System.UInt32" | "uint" => "uint32_t",
            "System.Int64" | "long" => "int64_t",
            "System.UInt64" | "ulong" => "uint64_t",
            "System.Single" | "float" => "float",
            "System.Double" | "double" => "double",
            "System.Char" | "char" => "uint16_t",
            "System.String" | "string" => "void*",  // Il2CppString*
            "System.Object" | "object" => "void*",  // Il2CppObject*
            _ => "void*",
        }
    }

    /// Write header to file
    pub fn write_to_file(results: &DumpResults, path: &Path) -> Result<()> {
        let content = Self::generate(results);
        std::fs::write(path, content)?;
        Ok(())
    }
}

/// C# dummy assembly generator
pub struct DummyAssemblyGenerator;

impl DummyAssemblyGenerator {
    /// Generate C# source code from dump results
    pub fn generate(results: &DumpResults) -> String {
        let mut output = String::new();

        output.push_str("// Auto-generated IL2CPP dummy assembly\n");
        output.push_str("// Do not edit manually\n\n");

        // Group types by namespace
        let mut namespaces: std::collections::HashMap<String, Vec<&DumpedType>> =
            std::collections::HashMap::new();

        for type_def in &results.types {
            namespaces
                .entry(type_def.namespace.clone())
                .or_default()
                .push(type_def);
        }

        // Generate by namespace
        for (namespace, types) in &namespaces {
            if !namespace.is_empty() {
                output.push_str(&format!("namespace {} {{\n\n", namespace));
            }

            for type_def in types {
                output.push_str(&Self::generate_type(type_def, results));
                output.push_str("\n");
            }

            if !namespace.is_empty() {
                output.push_str("}\n\n");
            }
        }

        output
    }

    fn generate_type(type_def: &DumpedType, results: &DumpResults) -> String {
        let mut output = String::new();

        // Attributes
        output.push_str(&format!("    // Token: 0x{:08X}\n", type_def.token));

        // Type declaration
        let modifiers = Self::get_type_modifiers(type_def);
        let kind = if type_def.is_enum {
            "enum"
        } else if type_def.is_interface {
            "interface"
        } else {
            "class"
        };

        output.push_str(&format!("    {} {} {}", modifiers, kind, type_def.name));

        // Inheritance
        let mut inheritance = Vec::new();
        if let Some(ref parent) = type_def.parent_type {
            if parent != "System.Object" && parent != "System.ValueType" && parent != "System.Enum" {
                inheritance.push(parent.clone());
            }
        }
        inheritance.extend(type_def.interfaces.clone());

        if !inheritance.is_empty() {
            output.push_str(&format!(" : {}", inheritance.join(", ")));
        }

        output.push_str(" {\n");

        // Fields
        for field in &type_def.fields {
            output.push_str(&format!(
                "        {} {} {};\n",
                if field.is_static { "static" } else { "public" },
                field.type_name,
                field.name
            ));
        }

        if !type_def.fields.is_empty() {
            output.push_str("\n");
        }

        // Methods
        for method_id in &type_def.methods {
            if let Some(method) = results.methods.iter().find(|m| &m.id == method_id) {
                output.push_str(&Self::generate_method(method));
            }
        }

        output.push_str("    }\n");

        output
    }

    fn generate_method(method: &DumpedMethod) -> String {
        let mut output = String::new();

        output.push_str(&format!("        // RVA: 0x{:X}\n", method.address.as_u64()));
        output.push_str(&format!("        // Token: 0x{:08X}\n", method.token));

        let modifiers = Self::get_method_modifiers(method);
        let params = method
            .parameters
            .iter()
            .map(|p| format!("{} {}", p.type_name, p.name))
            .collect::<Vec<_>>()
            .join(", ");

        output.push_str(&format!(
            "        {} {} {}({}) {{ }}\n\n",
            modifiers, method.return_type, method.name, params
        ));

        output
    }

    fn get_type_modifiers(type_def: &DumpedType) -> &'static str {
        if type_def.is_interface {
            "public"
        } else if type_def.is_abstract && type_def.is_sealed {
            "public static"
        } else if type_def.is_abstract {
            "public abstract"
        } else if type_def.is_sealed {
            "public sealed"
        } else {
            "public"
        }
    }

    fn get_method_modifiers(method: &DumpedMethod) -> &'static str {
        if method.is_static {
            "public static"
        } else if method.is_abstract {
            "public abstract"
        } else if method.is_virtual {
            "public virtual"
        } else {
            "public"
        }
    }

    /// Write to file
    pub fn write_to_file(results: &DumpResults, path: &Path) -> Result<()> {
        let content = Self::generate(results);
        std::fs::write(path, content)?;
        Ok(())
    }
}
