//! File and data integrity checking

use crate::hashing::{HashAlgorithm, HashOutput, Hasher, IncrementalHasher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Integrity check errors
#[derive(Error, Debug)]
pub enum IntegrityError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Hash mismatch for {path}: expected {expected}, got {actual}")]
    HashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
}

pub type IntegrityResult<T> = std::result::Result<T, IntegrityError>;

/// File integrity record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityRecord {
    pub path: PathBuf,
    pub hash: String,
    pub algorithm: String,
    pub size: u64,
    pub modified: u64,
}

/// Integrity manifest for a set of files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityManifest {
    pub version: u32,
    pub created: u64,
    pub algorithm: String,
    pub files: HashMap<String, IntegrityRecord>,
}

impl Default for IntegrityManifest {
    fn default() -> Self {
        Self {
            version: 1,
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            algorithm: "blake3".to_string(),
            files: HashMap::new(),
        }
    }
}

impl IntegrityManifest {
    /// Create a new manifest
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm: match algorithm {
                HashAlgorithm::Sha256 => "sha256".to_string(),
                HashAlgorithm::Sha512 => "sha512".to_string(),
                HashAlgorithm::Sha3_256 => "sha3-256".to_string(),
                HashAlgorithm::Sha3_512 => "sha3-512".to_string(),
                HashAlgorithm::Blake3 => "blake3".to_string(),
            },
            ..Default::default()
        }
    }

    /// Add a file to the manifest
    pub fn add_file(&mut self, path: &Path, record: IntegrityRecord) {
        let key = path.to_string_lossy().to_string();
        self.files.insert(key, record);
    }

    /// Get a file record
    pub fn get_file(&self, path: &Path) -> Option<&IntegrityRecord> {
        let key = path.to_string_lossy().to_string();
        self.files.get(&key)
    }

    /// Save manifest to file
    pub fn save(&self, path: &Path) -> IntegrityResult<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| IntegrityError::VerificationFailed(e.to_string()))?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Load manifest from file
    pub fn load(path: &Path) -> IntegrityResult<Self> {
        let content = std::fs::read_to_string(path)?;
        serde_json::from_str(&content)
            .map_err(|e| IntegrityError::VerificationFailed(e.to_string()))
    }
}

/// Integrity checker for files and data
pub struct IntegrityChecker {
    algorithm: HashAlgorithm,
    hasher: Hasher,
}

impl IntegrityChecker {
    /// Create a new integrity checker
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            hasher: Hasher::new(algorithm),
        }
    }

    /// Create with default algorithm (Blake3)
    pub fn default_checker() -> Self {
        Self::new(HashAlgorithm::Blake3)
    }

    /// Compute hash for a file
    pub fn hash_file(&self, path: &Path) -> IntegrityResult<IntegrityRecord> {
        let metadata = std::fs::metadata(path)?;
        let hash = self.hasher.hash_file(path)?;

        Ok(IntegrityRecord {
            path: path.to_path_buf(),
            hash: hash.to_hex(),
            algorithm: self.algorithm_name(),
            size: metadata.len(),
            modified: metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0),
        })
    }

    /// Verify a file against an expected hash
    pub fn verify_file(&self, path: &Path, expected_hash: &str) -> IntegrityResult<bool> {
        let hash = self.hasher.hash_file(path)?;
        let actual = hash.to_hex();

        if actual != expected_hash {
            return Err(IntegrityError::HashMismatch {
                path: path.to_string_lossy().to_string(),
                expected: expected_hash.to_string(),
                actual,
            });
        }

        Ok(true)
    }

    /// Verify a file against a record
    pub fn verify_record(&self, record: &IntegrityRecord) -> IntegrityResult<bool> {
        if !record.path.exists() {
            return Err(IntegrityError::FileNotFound(
                record.path.to_string_lossy().to_string(),
            ));
        }

        self.verify_file(&record.path, &record.hash)
    }

    /// Verify all files in a manifest
    pub fn verify_manifest(&self, manifest: &IntegrityManifest) -> IntegrityResult<Vec<String>> {
        let mut failures = Vec::new();

        for (path, record) in &manifest.files {
            match self.verify_record(record) {
                Ok(_) => {}
                Err(e) => {
                    failures.push(format!("{}: {}", path, e));
                }
            }
        }

        Ok(failures)
    }

    /// Create a manifest for a directory
    pub fn create_manifest(&self, dir: &Path) -> IntegrityResult<IntegrityManifest> {
        let mut manifest = IntegrityManifest::new(self.algorithm);

        self.scan_directory(dir, dir, &mut manifest)?;

        Ok(manifest)
    }

    fn scan_directory(
        &self,
        base: &Path,
        dir: &Path,
        manifest: &mut IntegrityManifest,
    ) -> IntegrityResult<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                self.scan_directory(base, &path, manifest)?;
            } else if path.is_file() {
                let record = self.hash_file(&path)?;
                let relative = path.strip_prefix(base).unwrap_or(&path);
                manifest.add_file(relative, record);
            }
        }

        Ok(())
    }

    /// Hash data in memory
    pub fn hash_data(&self, data: &[u8]) -> HashOutput {
        self.hasher.hash(data)
    }

    /// Verify data against expected hash
    pub fn verify_data(&self, data: &[u8], expected_hash: &str) -> bool {
        let hash = self.hasher.hash(data);
        hash.to_hex() == expected_hash
    }

    fn algorithm_name(&self) -> String {
        match self.algorithm {
            HashAlgorithm::Sha256 => "sha256".to_string(),
            HashAlgorithm::Sha512 => "sha512".to_string(),
            HashAlgorithm::Sha3_256 => "sha3-256".to_string(),
            HashAlgorithm::Sha3_512 => "sha3-512".to_string(),
            HashAlgorithm::Blake3 => "blake3".to_string(),
        }
    }
}

/// Quick integrity check functions
pub fn verify_file_sha256(path: &Path, expected: &str) -> IntegrityResult<bool> {
    IntegrityChecker::new(HashAlgorithm::Sha256).verify_file(path, expected)
}

pub fn verify_file_blake3(path: &Path, expected: &str) -> IntegrityResult<bool> {
    IntegrityChecker::new(HashAlgorithm::Blake3).verify_file(path, expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_hash_and_verify_data() {
        let checker = IntegrityChecker::default_checker();
        let data = b"test data for integrity check";

        let hash = checker.hash_data(data);
        let hex = hash.to_hex();

        assert!(checker.verify_data(data, &hex));
        assert!(!checker.verify_data(b"different data", &hex));
    }
}
