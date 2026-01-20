//! IL2CPP metadata parser and dumper
//!
//! This crate provides functionality to parse Unity IL2CPP metadata and extract
//! type definitions, method signatures, field offsets, and string literals.

pub mod metadata;
pub mod types;
pub mod dumper;
pub mod search;
pub mod output;

pub use metadata::Metadata;
pub use dumper::Il2CppDumper;
pub use types::*;

use endfield_core::{DumpResults, Result};
use std::path::Path;

/// Parse IL2CPP metadata from a file
pub fn parse_metadata(path: &Path) -> Result<Metadata> {
    let data = std::fs::read(path)?;
    Metadata::parse(&data)
}

/// Dump IL2CPP information from binary and metadata files
pub fn dump(binary_path: &Path, metadata_path: &Path) -> Result<DumpResults> {
    let dumper = Il2CppDumper::new(binary_path, metadata_path)?;
    dumper.dump()
}
