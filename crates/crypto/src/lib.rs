//! Cryptographic utilities and security features
//!
//! This crate provides encryption, hashing, and secure memory handling.

pub mod encryption;
pub mod hashing;
pub mod secure;
pub mod integrity;

pub use encryption::{Encryptor, EncryptionKey};
pub use hashing::{Hasher, HashAlgorithm};
pub use secure::SecureString;
pub use integrity::IntegrityChecker;
