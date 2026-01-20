//! Secure memory handling

use zeroize::{Zeroize, Zeroizing};
use std::ops::Deref;

/// A string that is securely erased from memory when dropped
#[derive(Clone)]
pub struct SecureString {
    inner: Zeroizing<String>,
}

impl SecureString {
    /// Create a new secure string
    pub fn new(s: impl Into<String>) -> Self {
        Self {
            inner: Zeroizing::new(s.into()),
        }
    }

    /// Create an empty secure string
    pub fn empty() -> Self {
        Self::new(String::new())
    }

    /// Get the length
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl Deref for SecureString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::fmt::Debug for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureString([REDACTED])")
    }
}

impl std::fmt::Display for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

/// A byte buffer that is securely erased from memory when dropped
pub struct SecureBytes {
    inner: Zeroizing<Vec<u8>>,
}

impl SecureBytes {
    /// Create from bytes
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: Zeroizing::new(data.into()),
        }
    }

    /// Create with specific capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Zeroizing::new(Vec::with_capacity(capacity)),
        }
    }

    /// Get the length
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Push a byte
    pub fn push(&mut self, byte: u8) {
        self.inner.push(byte);
    }

    /// Extend from slice
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.inner.extend_from_slice(slice);
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.inner.zeroize();
        self.inner.clear();
    }
}

impl Deref for SecureBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBytes([{} bytes REDACTED])", self.len())
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for SecureBytes {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

/// Trait for types that can be securely cleared
pub trait SecureClear {
    fn secure_clear(&mut self);
}

impl SecureClear for String {
    fn secure_clear(&mut self) {
        // Fill with zeros before clearing
        unsafe {
            let bytes = self.as_bytes_mut();
            bytes.zeroize();
        }
        self.clear();
    }
}

impl SecureClear for Vec<u8> {
    fn secure_clear(&mut self) {
        self.zeroize();
        self.clear();
    }
}

/// Guard that ensures data is cleared when dropped
pub struct ClearOnDrop<T: SecureClear> {
    inner: T,
}

impl<T: SecureClear> ClearOnDrop<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    pub fn into_inner(mut self) -> T {
        // Take the inner value and replace with default
        std::mem::take(&mut self.inner)
    }
}

impl<T: SecureClear + Default> Default for ClearOnDrop<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: SecureClear> Deref for ClearOnDrop<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: SecureClear> std::ops::DerefMut for ClearOnDrop<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: SecureClear> Drop for ClearOnDrop<T> {
    fn drop(&mut self) {
        self.inner.secure_clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string() {
        let s = SecureString::new("secret password");
        assert_eq!(s.len(), 15);
        assert_eq!(s.as_bytes(), b"secret password");

        // Debug output should be redacted
        let debug = format!("{:?}", s);
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn test_secure_bytes() {
        let mut bytes = SecureBytes::new(vec![1, 2, 3, 4]);
        assert_eq!(bytes.len(), 4);
        assert_eq!(&*bytes, &[1, 2, 3, 4]);

        bytes.extend_from_slice(&[5, 6]);
        assert_eq!(bytes.len(), 6);
    }
}
