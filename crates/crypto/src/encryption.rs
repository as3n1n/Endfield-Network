//! Encryption utilities using AES-GCM and ChaCha20-Poly1305

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use zeroize::Zeroizing;
use thiserror::Error;

/// Encryption errors
#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Invalid nonce length")]
    InvalidNonceLength,
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
}

pub type EncryptionResult<T> = std::result::Result<T, EncryptionError>;

/// Encryption algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Encryption key with secure memory handling
pub struct EncryptionKey {
    key: Zeroizing<Vec<u8>>,
    algorithm: EncryptionAlgorithm,
}

impl EncryptionKey {
    /// Generate a new random key
    pub fn generate(algorithm: EncryptionAlgorithm) -> Self {
        let key_len = match algorithm {
            EncryptionAlgorithm::Aes256Gcm => 32,
            EncryptionAlgorithm::ChaCha20Poly1305 => 32,
        };

        let mut key = vec![0u8; key_len];
        OsRng.fill_bytes(&mut key);

        Self {
            key: Zeroizing::new(key),
            algorithm,
        }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8], algorithm: EncryptionAlgorithm) -> EncryptionResult<Self> {
        let expected_len = match algorithm {
            EncryptionAlgorithm::Aes256Gcm => 32,
            EncryptionAlgorithm::ChaCha20Poly1305 => 32,
        };

        if bytes.len() != expected_len {
            return Err(EncryptionError::InvalidKeyLength {
                expected: expected_len,
                actual: bytes.len(),
            });
        }

        Ok(Self {
            key: Zeroizing::new(bytes.to_vec()),
            algorithm,
        })
    }

    /// Derive a key from a password using Argon2
    pub fn derive_from_password(
        password: &str,
        salt: &[u8],
        algorithm: EncryptionAlgorithm,
    ) -> EncryptionResult<Self> {
        use argon2::{
            password_hash::{PasswordHasher, SaltString},
            Argon2, Params,
        };

        let key_len = match algorithm {
            EncryptionAlgorithm::Aes256Gcm => 32,
            EncryptionAlgorithm::ChaCha20Poly1305 => 32,
        };

        // Configure Argon2 with secure parameters
        let params = Params::new(
            65536,  // m_cost: 64 MiB
            3,      // t_cost: 3 iterations
            4,      // p_cost: 4 parallel lanes
            Some(key_len),
        )
        .map_err(|e| EncryptionError::KeyDerivationFailed(e.to_string()))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| EncryptionError::KeyDerivationFailed(e.to_string()))?;

        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| EncryptionError::KeyDerivationFailed(e.to_string()))?;

        let hash = password_hash.hash.ok_or_else(|| {
            EncryptionError::KeyDerivationFailed("No hash output".to_string())
        })?;

        let key_bytes = hash.as_bytes();
        if key_bytes.len() < key_len {
            return Err(EncryptionError::InvalidKeyLength {
                expected: key_len,
                actual: key_bytes.len(),
            });
        }

        Ok(Self {
            key: Zeroizing::new(key_bytes[..key_len].to_vec()),
            algorithm,
        })
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> EncryptionAlgorithm {
        self.algorithm
    }

    /// Export the key bytes (use with caution)
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

/// Encryptor for data encryption/decryption
pub struct Encryptor {
    key: EncryptionKey,
}

impl Encryptor {
    /// Create a new encryptor with the given key
    pub fn new(key: EncryptionKey) -> Self {
        Self { key }
    }

    /// Generate a random nonce
    pub fn generate_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Encrypt data
    pub fn encrypt(&self, plaintext: &[u8]) -> EncryptionResult<Vec<u8>> {
        let nonce = Self::generate_nonce();
        let ciphertext = self.encrypt_with_nonce(plaintext, &nonce)?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Encrypt data with a specific nonce
    pub fn encrypt_with_nonce(&self, plaintext: &[u8], nonce: &[u8; 12]) -> EncryptionResult<Vec<u8>> {
        match self.key.algorithm {
            EncryptionAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(self.key.as_bytes())
                    .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

                let nonce = Nonce::from_slice(nonce);
                cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))
            }
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_bytes())
                    .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

                let nonce = chacha20poly1305::Nonce::from_slice(nonce);
                cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))
            }
        }
    }

    /// Decrypt data (expects nonce prepended)
    pub fn decrypt(&self, ciphertext: &[u8]) -> EncryptionResult<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(EncryptionError::InvalidNonceLength);
        }

        let (nonce, ciphertext) = ciphertext.split_at(12);
        let nonce: [u8; 12] = nonce.try_into().unwrap();

        self.decrypt_with_nonce(ciphertext, &nonce)
    }

    /// Decrypt data with a specific nonce
    pub fn decrypt_with_nonce(&self, ciphertext: &[u8], nonce: &[u8; 12]) -> EncryptionResult<Vec<u8>> {
        match self.key.algorithm {
            EncryptionAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new_from_slice(self.key.as_bytes())
                    .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

                let nonce = Nonce::from_slice(nonce);
                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
            }
            EncryptionAlgorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(self.key.as_bytes())
                    .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

                let nonce = chacha20poly1305::Nonce::from_slice(nonce);
                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
            }
        }
    }
}

/// Generate a random salt for key derivation
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_aes() {
        let key = EncryptionKey::generate(EncryptionAlgorithm::Aes256Gcm);
        let encryptor = Encryptor::new(key);

        let plaintext = b"Hello, World!";
        let ciphertext = encryptor.encrypt(plaintext).unwrap();
        let decrypted = encryptor.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_chacha() {
        let key = EncryptionKey::generate(EncryptionAlgorithm::ChaCha20Poly1305);
        let encryptor = Encryptor::new(key);

        let plaintext = b"Hello, World!";
        let ciphertext = encryptor.encrypt(plaintext).unwrap();
        let decrypted = encryptor.decrypt(&ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_key_derivation() {
        let password = "test_password";
        let salt = generate_salt();

        let key = EncryptionKey::derive_from_password(
            password,
            &salt,
            EncryptionAlgorithm::Aes256Gcm,
        ).unwrap();

        assert_eq!(key.as_bytes().len(), 32);
    }
}
