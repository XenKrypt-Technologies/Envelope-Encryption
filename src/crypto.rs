use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{EnvelopeError, Result};

pub const AES_256_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureKey {
    bytes: Vec<u8>,
}

impl SecureKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn generate() -> Self {
        let mut key = vec![0u8; AES_256_KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        Self { bytes: key }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for SecureKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureKey([REDACTED])")
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EncryptedData {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// Convert to industry-standard AEAD blob format: nonce || ciphertext || tag
    /// For AES-256-GCM: 12 bytes nonce + ciphertext + 16 bytes tag
    pub fn to_aead_blob(&self) -> Vec<u8> {
        [self.nonce.as_slice(), self.ciphertext.as_slice()].concat()
    }

    /// Parse from AEAD blob format: nonce || ciphertext || tag
    /// For AES-256-GCM encrypting 32-byte key: total 60 bytes
    pub fn from_aead_blob(blob: &[u8]) -> Result<Self> {
        if blob.len() < NONCE_SIZE + TAG_SIZE {
            return Err(EnvelopeError::Crypto(format!(
                "AEAD blob too small: expected at least {} bytes, got {}",
                NONCE_SIZE + TAG_SIZE,
                blob.len()
            )));
        }

        let (nonce, ciphertext) = blob.split_at(NONCE_SIZE);
        Ok(Self {
            nonce: nonce.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
    }

    pub fn to_base64(&self) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let combined = [self.nonce.as_slice(), self.ciphertext.as_slice()].concat();
        STANDARD.encode(combined)
    }

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

pub struct AesGcmCipher;

impl AesGcmCipher {
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

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

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

        let plaintext = match aad {
            Some(aad_data) => {
                use aes_gcm::aead::Payload;
                cipher
                    .decrypt(nonce, Payload { msg: &encrypted.ciphertext, aad: aad_data })
                    .map_err(|_| EnvelopeError::Crypto("Decryption failed".into()))?
            }
            None => cipher
                .decrypt(nonce, encrypted.ciphertext.as_slice())
                .map_err(|_| EnvelopeError::Crypto("Decryption failed".into()))?,
        };

        Ok(plaintext)
    }
}

pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

