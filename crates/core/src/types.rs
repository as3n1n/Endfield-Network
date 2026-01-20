//! Common types used throughout the application

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Represents a memory address (supports both 32 and 64 bit)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub u64);

impl Address {
    pub const ZERO: Address = Address(0);

    pub fn new(addr: u64) -> Self {
        Self(addr)
    }

    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub fn as_u32(&self) -> u32 {
        self.0 as u32
    }

    pub fn offset(&self, offset: i64) -> Self {
        Self((self.0 as i64 + offset) as u64)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:X}", self.0)
    }
}

impl From<u64> for Address {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<u32> for Address {
    fn from(value: u32) -> Self {
        Self(value as u64)
    }
}

/// Architecture type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    X86,
    X64,
    Arm32,
    Arm64,
    Unknown,
}

impl Architecture {
    pub fn pointer_size(&self) -> usize {
        match self {
            Architecture::X86 | Architecture::Arm32 => 4,
            Architecture::X64 | Architecture::Arm64 => 8,
            Architecture::Unknown => 8,
        }
    }

    pub fn is_64bit(&self) -> bool {
        matches!(self, Architecture::X64 | Architecture::Arm64)
    }
}

/// Platform/OS type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    Windows,
    Linux,
    MacOS,
    Android,
    iOS,
    Unknown,
}

/// Binary format type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinaryFormat {
    PE,
    ELF,
    MachO,
    Unknown,
}

/// A dumped method with its metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpedMethod {
    pub id: Uuid,
    pub name: String,
    pub full_name: String,
    pub address: Address,
    pub return_type: String,
    pub parameters: Vec<MethodParameter>,
    pub class_name: String,
    pub namespace: String,
    pub is_static: bool,
    pub is_virtual: bool,
    pub is_abstract: bool,
    pub token: u32,
}

/// Method parameter information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodParameter {
    pub name: String,
    pub type_name: String,
    pub index: u32,
}

/// A dumped type/class with its metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpedType {
    pub id: Uuid,
    pub name: String,
    pub namespace: String,
    pub full_name: String,
    pub parent_type: Option<String>,
    pub interfaces: Vec<String>,
    pub fields: Vec<DumpedField>,
    pub methods: Vec<Uuid>,
    pub properties: Vec<DumpedProperty>,
    pub is_enum: bool,
    pub is_interface: bool,
    pub is_abstract: bool,
    pub is_sealed: bool,
    pub token: u32,
}

/// Field information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpedField {
    pub name: String,
    pub type_name: String,
    pub offset: u32,
    pub is_static: bool,
    pub is_const: bool,
    pub default_value: Option<String>,
}

/// Property information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpedProperty {
    pub name: String,
    pub type_name: String,
    pub getter: Option<Uuid>,
    pub setter: Option<Uuid>,
}

/// A captured network packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedPacket {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub direction: PacketDirection,
    pub protocol: Protocol,
    pub source_ip: String,
    pub source_port: u16,
    pub dest_ip: String,
    pub dest_port: u16,
    pub payload: Vec<u8>,
    pub decoded_data: Option<String>,
    pub packet_type: Option<String>,
}

/// Packet direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketDirection {
    Inbound,
    Outbound,
}

/// Network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
    HTTP,
    HTTPS,
    WebSocket,
    Custom(u16),
}

/// Project/session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectState {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub modified_at: DateTime<Utc>,
    pub binary_path: Option<String>,
    pub metadata_path: Option<String>,
    pub dump_results: Option<DumpResults>,
    pub capture_sessions: Vec<CaptureSession>,
}

impl ProjectState {
    pub fn new(name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            created_at: now,
            modified_at: now,
            binary_path: None,
            metadata_path: None,
            dump_results: None,
            capture_sessions: Vec::new(),
        }
    }
}

/// Results from IL2CPP dump
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpResults {
    pub timestamp: DateTime<Utc>,
    pub unity_version: Option<String>,
    pub il2cpp_version: u32,
    pub types: Vec<DumpedType>,
    pub methods: Vec<DumpedMethod>,
    pub string_literals: Vec<StringLiteral>,
    pub statistics: DumpStatistics,
}

/// String literal from the binary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringLiteral {
    pub address: Address,
    pub value: String,
    pub index: u32,
}

/// Statistics about the dump
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DumpStatistics {
    pub total_types: usize,
    pub total_methods: usize,
    pub total_fields: usize,
    pub total_strings: usize,
    pub assemblies_count: usize,
}

/// Network capture session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSession {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub packets: Vec<CapturedPacket>,
    pub filter: Option<String>,
}
