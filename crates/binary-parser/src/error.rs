//! Error types for binary parsing

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Unknown binary format")]
    UnknownFormat,

    #[error("Invalid magic number: expected {expected:#x}, got {actual:#x}")]
    InvalidMagic { expected: u32, actual: u32 },

    #[error("Invalid header: {0}")]
    InvalidHeader(String),

    #[error("Invalid section: {0}")]
    InvalidSection(String),

    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(String),

    #[error("Address out of bounds: {0:#x}")]
    AddressOutOfBounds(u64),

    #[error("Section not found: {0}")]
    SectionNotFound(String),

    #[error("Symbol not found: {0}")]
    SymbolNotFound(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Truncated data: expected {expected} bytes, got {actual}")]
    TruncatedData { expected: usize, actual: usize },
}

pub type ParseResult<T> = std::result::Result<T, ParseError>;

impl ParseError {
    pub fn invalid_header(msg: impl Into<String>) -> Self {
        Self::InvalidHeader(msg.into())
    }

    pub fn parse(msg: impl Into<String>) -> Self {
        Self::Parse(msg.into())
    }

    pub fn truncated(expected: usize, actual: usize) -> Self {
        Self::TruncatedData { expected, actual }
    }
}
