//! Cryptographic hashing utilities

use sha2::{Sha256, Sha512, Digest as Sha2Digest};
use sha3::{Sha3_256, Sha3_512};
use blake3::Hasher as Blake3Hasher;
use hmac::{Hmac, Mac};

/// Hash algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Sha3_256,
    Sha3_512,
    Blake3,
}

/// Hash output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashOutput {
    pub bytes: Vec<u8>,
    pub algorithm: HashAlgorithm,
}

impl HashOutput {
    /// Convert to hexadecimal string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Convert to base64 string
    pub fn to_base64(&self) -> String {
        base64::encode(&self.bytes)
    }

    /// Verify against another hash in constant time
    pub fn verify(&self, other: &HashOutput) -> bool {
        if self.algorithm != other.algorithm || self.bytes.len() != other.bytes.len() {
            return false;
        }
        constant_time_eq::constant_time_eq(&self.bytes, &other.bytes)
    }
}

/// Hasher for computing cryptographic hashes
pub struct Hasher {
    algorithm: HashAlgorithm,
}

impl Hasher {
    /// Create a new hasher with the specified algorithm
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Hash data
    pub fn hash(&self, data: &[u8]) -> HashOutput {
        let bytes = match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha3_256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha3_512 => {
                let mut hasher = Sha3_512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Blake3 => {
                let mut hasher = Blake3Hasher::new();
                hasher.update(data);
                hasher.finalize().as_bytes().to_vec()
            }
        };

        HashOutput {
            bytes,
            algorithm: self.algorithm,
        }
    }

    /// Hash a file
    pub fn hash_file(&self, path: &std::path::Path) -> std::io::Result<HashOutput> {
        let data = std::fs::read(path)?;
        Ok(self.hash(&data))
    }

    /// Incremental hasher for large data
    pub fn incremental(algorithm: HashAlgorithm) -> IncrementalHasher {
        IncrementalHasher::new(algorithm)
    }
}

/// Incremental hasher for streaming data
pub enum IncrementalHasher {
    Sha256(Sha256),
    Sha512(Sha512),
    Sha3_256(Sha3_256),
    Sha3_512(Sha3_512),
    Blake3(Blake3Hasher),
}

impl IncrementalHasher {
    /// Create a new incremental hasher
    pub fn new(algorithm: HashAlgorithm) -> Self {
        match algorithm {
            HashAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
            HashAlgorithm::Sha512 => Self::Sha512(Sha512::new()),
            HashAlgorithm::Sha3_256 => Self::Sha3_256(Sha3_256::new()),
            HashAlgorithm::Sha3_512 => Self::Sha3_512(Sha3_512::new()),
            HashAlgorithm::Blake3 => Self::Blake3(Blake3Hasher::new()),
        }
    }

    /// Update the hasher with more data
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
            Self::Sha3_256(h) => h.update(data),
            Self::Sha3_512(h) => h.update(data),
            Self::Blake3(h) => { h.update(data); }
        }
    }

    /// Finalize and return the hash
    pub fn finalize(self) -> HashOutput {
        match self {
            Self::Sha256(h) => HashOutput {
                bytes: h.finalize().to_vec(),
                algorithm: HashAlgorithm::Sha256,
            },
            Self::Sha512(h) => HashOutput {
                bytes: h.finalize().to_vec(),
                algorithm: HashAlgorithm::Sha512,
            },
            Self::Sha3_256(h) => HashOutput {
                bytes: h.finalize().to_vec(),
                algorithm: HashAlgorithm::Sha3_256,
            },
            Self::Sha3_512(h) => HashOutput {
                bytes: h.finalize().to_vec(),
                algorithm: HashAlgorithm::Sha3_512,
            },
            Self::Blake3(h) => HashOutput {
                bytes: h.finalize().as_bytes().to_vec(),
                algorithm: HashAlgorithm::Blake3,
            },
        }
    }
}

/// HMAC computation
pub struct HmacComputer;

impl HmacComputer {
    /// Compute HMAC-SHA256
    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Compute HMAC-SHA512
    pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha512>::new_from_slice(key)
            .expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    /// Verify HMAC-SHA256 in constant time
    pub fn verify_hmac_sha256(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
        let computed = Self::hmac_sha256(key, data);
        constant_time_eq::constant_time_eq(&computed, expected)
    }

    /// Verify HMAC-SHA512 in constant time
    pub fn verify_hmac_sha512(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
        let computed = Self::hmac_sha512(key, data);
        constant_time_eq::constant_time_eq(&computed, expected)
    }
}

/// Quick hash functions
pub fn sha256(data: &[u8]) -> HashOutput {
    Hasher::new(HashAlgorithm::Sha256).hash(data)
}

pub fn sha512(data: &[u8]) -> HashOutput {
    Hasher::new(HashAlgorithm::Sha512).hash(data)
}

pub fn blake3(data: &[u8]) -> HashOutput {
    Hasher::new(HashAlgorithm::Blake3).hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"test");
        assert_eq!(hash.bytes.len(), 32);
        assert_eq!(
            hash.to_hex(),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_blake3() {
        let hash = blake3(b"test");
        assert_eq!(hash.bytes.len(), 32);
    }

    #[test]
    fn test_incremental() {
        let mut hasher = IncrementalHasher::new(HashAlgorithm::Sha256);
        hasher.update(b"te");
        hasher.update(b"st");
        let hash = hasher.finalize();

        let direct = sha256(b"test");
        assert!(hash.verify(&direct));
    }

    #[test]
    fn test_hmac() {
        let key = b"secret_key";
        let data = b"test data";
        let mac = HmacComputer::hmac_sha256(key, data);
        assert!(HmacComputer::verify_hmac_sha256(key, data, &mac));
    }
}
