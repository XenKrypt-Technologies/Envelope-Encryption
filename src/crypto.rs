//! Cryptographic primitives for envelope encryption
//! 
//! This module provides AES-256-GCM encryption/decryption and HKDF key derivation.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{EnvelopeError, Result};

/// AES-256 key size in bytes (256 bits)
pub const AES_256_KEY_SIZE: usize = 32;

/// AES-GCM nonce size in bytes (96 bits)
pub const NONCE_SIZE: usize = 12;

/// AES-GCM authentication tag size in bytes (128 bits)
pub const TAG_SIZE: usize = 16;

/// A secure key wrapper that zeroizes memory on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    bytes: Vec<u8>,
}

impl SecureKey {
    /// Create a new SecureKey from raw bytes
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Generate a new random AES-256 key
    pub fn generate() -> Self {
        let mut key = vec![0u8; AES_256_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self { bytes: key }
    }

    /// Get the key bytes (use with caution)
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the key length
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the key is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureKey([REDACTED])")
    }
}

/// Encrypted data container with nonce and ciphertext
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedData {
    /// The nonce used for encryption (12 bytes for AES-GCM)
    pub nonce: Vec<u8>,
    /// The ciphertext including authentication tag
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    /// Create a new EncryptedData container
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// Encode to base64 for storage
    pub fn to_base64(&self) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let combined = [self.nonce.as_slice(), self.ciphertext.as_slice()].concat();
        STANDARD.encode(combined)
    }

    /// Decode from base64
    pub fn from_base64(encoded: &str) -> Result<Self> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|e| EnvelopeError::Crypto(format!("Base64 decode error: {}", e)))?;
        
        if decoded.len() < NONCE_SIZE + TAG_SIZE {
            return Err(EnvelopeError::Crypto("Invalid encrypted data length".into()));
        }

        let (nonce, ciphertext) = decoded.split_at(NONCE_SIZE);
        Ok(Self {
            nonce: nonce.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// AES-256-GCM cipher wrapper
pub struct AesGcmCipher;

impl AesGcmCipher {
    /// Encrypt plaintext using AES-256-GCM
    /// 
    /// # Arguments
    /// * `key` - The 256-bit encryption key
    /// * `plaintext` - The data to encrypt
    /// * `aad` - Additional authenticated data (optional context)
    /// 
    /// # Returns
    /// Encrypted data containing nonce and ciphertext with auth tag
    pub fn encrypt(key: &SecureKey, plaintext: &[u8], aad: Option<&[u8]>) -> Result<EncryptedData> {
        if key.len() != AES_256_KEY_SIZE {
            return Err(EnvelopeError::Crypto(format!(
                "Invalid key size: expected {}, got {}",
                AES_256_KEY_SIZE,
                key.len()
            )));
        }

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| EnvelopeError::Crypto(format!("Cipher init error: {}", e)))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt with optional AAD
        let ciphertext = match aad {
            Some(aad_data) => {
                use aes_gcm::aead::Payload;
                cipher
                    .encrypt(nonce, Payload { msg: plaintext, aad: aad_data })
                    .map_err(|e| EnvelopeError::Crypto(format!("Encryption error: {}", e)))?
            }
            None => cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| EnvelopeError::Crypto(format!("Encryption error: {}", e)))?,
        };

        Ok(EncryptedData::new(nonce_bytes.to_vec(), ciphertext))
    }

    /// Decrypt ciphertext using AES-256-GCM
    /// 
    /// # Arguments
    /// * `key` - The 256-bit decryption key
    /// * `encrypted` - The encrypted data (nonce + ciphertext)
    /// * `aad` - Additional authenticated data (must match encryption)
    /// 
    /// # Returns
    /// The decrypted plaintext
    pub fn decrypt(key: &SecureKey, encrypted: &EncryptedData, aad: Option<&[u8]>) -> Result<Vec<u8>> {
        if key.len() != AES_256_KEY_SIZE {
            return Err(EnvelopeError::Crypto(format!(
                "Invalid key size: expected {}, got {}",
                AES_256_KEY_SIZE,
                key.len()
            )));
        }

        if encrypted.nonce.len() != NONCE_SIZE {
            return Err(EnvelopeError::Crypto(format!(
                "Invalid nonce size: expected {}, got {}",
                NONCE_SIZE,
                encrypted.nonce.len()
            )));
        }

        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| EnvelopeError::Crypto(format!("Cipher init error: {}", e)))?;

        let nonce = Nonce::from_slice(&encrypted.nonce);

        // Decrypt with optional AAD
        let plaintext = match aad {
            Some(aad_data) => {
                use aes_gcm::aead::Payload;
                cipher
                    .decrypt(
                        nonce,
                        Payload {
                            msg: &encrypted.ciphertext,
                            aad: aad_data,
                        },
                    )
                    .map_err(|_| EnvelopeError::Crypto("Decryption failed: authentication error".into()))?
            }
            None => cipher
                .decrypt(nonce, encrypted.ciphertext.as_slice())
                .map_err(|_| EnvelopeError::Crypto("Decryption failed: authentication error".into()))?,
        };

        Ok(plaintext)
    }
}

/// HKDF-SHA256 based key derivation
pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive a key using HKDF-SHA256
    /// 
    /// This is an upgrade from simple HMAC-SHA256 derivation,
    /// providing proper extract-and-expand key derivation.
    /// 
    /// # Arguments
    /// * `master_key` - The input keying material (IKM)
    /// * `salt` - Optional salt value (can be derived from context)
    /// * `info` - Context-specific info string (e.g., "KEK" or data_id)
    /// * `output_len` - Desired output key length
    pub fn derive_key(
        master_key: &SecureKey,
        salt: Option<&[u8]>,
        info: &[u8],
        output_len: usize,
    ) -> Result<SecureKey> {
        let hkdf = Hkdf::<Sha256>::new(salt, master_key.as_bytes());
        
        let mut output = vec![0u8; output_len];
        hkdf.expand(info, &mut output)
            .map_err(|e| EnvelopeError::Crypto(format!("Key derivation error: {}", e)))?;

        Ok(SecureKey::new(output))
    }

    /// Derive a key specifically for a data ID (UUID-based context)
    /// 
    /// This provides backward compatibility concept while using HKDF
    /// instead of raw HMAC-SHA256.
    pub fn derive_key_for_data_id(
        master_key: &SecureKey,
        data_id: &uuid::Uuid,
        purpose: &str,
    ) -> Result<SecureKey> {
        let info = format!("envelope-encryption:{}:{}", purpose, data_id);
        Self::derive_key(master_key, None, info.as_bytes(), AES_256_KEY_SIZE)
    }
}

/// Generate cryptographically secure random bytes
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = SecureKey::generate();
        let plaintext = b"Hello, Envelope Encryption!";
        
        let encrypted = AesGcmCipher::encrypt(&key, plaintext, None).unwrap();
        let decrypted = AesGcmCipher::decrypt(&key, &encrypted, None).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = SecureKey::generate();
        let plaintext = b"Secret data";
        let aad = b"additional context";
        
        let encrypted = AesGcmCipher::encrypt(&key, plaintext, Some(aad)).unwrap();
        let decrypted = AesGcmCipher::decrypt(&key, &encrypted, Some(aad)).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
        
        // Should fail with wrong AAD
        let result = AesGcmCipher::decrypt(&key, &encrypted, Some(b"wrong aad"));
        assert!(result.is_err());
    }

    #[test]
    fn test_key_derivation() {
        let master = SecureKey::generate();
        let data_id = uuid::Uuid::new_v4();
        
        let derived1 = KeyDerivation::derive_key_for_data_id(&master, &data_id, "DEK").unwrap();
        let derived2 = KeyDerivation::derive_key_for_data_id(&master, &data_id, "DEK").unwrap();
        
        // Same inputs should produce same output
        assert_eq!(derived1.as_bytes(), derived2.as_bytes());
        
        // Different purpose should produce different key
        let derived3 = KeyDerivation::derive_key_for_data_id(&master, &data_id, "KEK").unwrap();
        assert_ne!(derived1.as_bytes(), derived3.as_bytes());
    }

    #[test]
    fn test_encrypted_data_base64() {
        let key = SecureKey::generate();
        let plaintext = b"Test data for base64";
        
        let encrypted = AesGcmCipher::encrypt(&key, plaintext, None).unwrap();
        let encoded = encrypted.to_base64();
        let decoded = EncryptedData::from_base64(&encoded).unwrap();
        
        assert_eq!(encrypted.nonce, decoded.nonce);
        assert_eq!(encrypted.ciphertext, decoded.ciphertext);
    }
}


