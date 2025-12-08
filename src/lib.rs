//! # Envelope Encryption Library
//! 
//! A Rust implementation of HSM-like envelope encryption with a hierarchical key structure.
//! 
//! ## Overview
//! 
//! Envelope encryption is a data protection strategy where data is encrypted with a
//! Data Encryption Key (DEK), and the DEK is then encrypted (wrapped) with a Key
//! Encryption Key (KEK). This creates layers of protection and enables key rotation
//! without re-encrypting all data.
//! 
//! ## Key Hierarchy
//! 
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    Master Key (MK)                      │
//! │         Root of trust, protects all KEKs               │
//! └─────────────────────────┬───────────────────────────────┘
//!                           │
//!               ┌───────────┴───────────┐
//!               │                       │
//!               ▼                       ▼
//! ┌─────────────────────┐   ┌─────────────────────┐
//! │   KEK-1 (wrapped)   │   │   KEK-2 (wrapped)   │
//! │  Key Encryption Key │   │  Key Encryption Key │
//! └──────────┬──────────┘   └──────────┬──────────┘
//!            │                         │
//!     ┌──────┴──────┐          ┌───────┴───────┐
//!     │             │          │               │
//!     ▼             ▼          ▼               ▼
//! ┌───────┐    ┌───────┐  ┌───────┐      ┌───────┐
//! │ DEK-1 │    │ DEK-2 │  │ DEK-3 │      │ DEK-4 │
//! │(wrap) │    │(wrap) │  │(wrap) │      │(wrap) │
//! └───┬───┘    └───┬───┘  └───┬───┘      └───┬───┘
//!     │            │          │              │
//!     ▼            ▼          ▼              ▼
//! ┌───────┐    ┌───────┐  ┌───────┐      ┌───────┐
//! │ Data  │    │ Data  │  │ Data  │      │ Data  │
//! │  A    │    │  B    │  │  C    │      │  D    │
//! └───────┘    └───────┘  └───────┘      └───────┘
//! ```
//! 
//! ## Features
//! 
//! - **AES-256-GCM**: Industry-standard authenticated encryption
//! - **HKDF-SHA256**: Modern key derivation (upgrade from simple HMAC)
//! - **Key Rotation**: Rotate Master Keys, KEKs, or DEKs independently
//! - **Pluggable Storage**: In-memory (included), PostgreSQL (planned)
//! - **Zero-copy Security**: Keys are zeroized from memory when dropped
//! 
//! ## Quick Start
//! 
//! ```rust
//! use envelope_encryption::{EnvelopeEncryption, InMemoryStorage};
//! use std::sync::Arc;
//! 
//! // Create storage and encryption service
//! let storage = Arc::new(InMemoryStorage::new());
//! let mut service = EnvelopeEncryption::new(storage).unwrap();
//! service.initialize().unwrap();
//! 
//! // Encrypt data
//! let plaintext = b"Secret message";
//! let envelope = service.encrypt(plaintext, None, None).unwrap();
//! 
//! // Decrypt data
//! let decrypted = service.decrypt(&envelope).unwrap();
//! assert_eq!(plaintext.to_vec(), decrypted);
//! ```
//! 
//! ## Key Rotation
//! 
//! ```rust
//! use envelope_encryption::{EnvelopeEncryption, InMemoryStorage};
//! use std::sync::Arc;
//! 
//! let storage = Arc::new(InMemoryStorage::new());
//! let mut service = EnvelopeEncryption::new(storage).unwrap();
//! service.initialize().unwrap();
//! 
//! // Rotate master key (re-wraps all KEKs automatically)
//! let result = service.rotate_master_key().unwrap();
//! println!("Rotated: {} -> {}", result.old_version, result.new_version);
//! ```

pub mod crypto;
pub mod error;
pub mod storage;
pub mod key_manager;
pub mod envelope;

// Re-export commonly used types
pub use crypto::{
    AesGcmCipher,
    EncryptedData,
    SecureKey,
    KeyDerivation,
    AES_256_KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
};

pub use error::{EnvelopeError, Result};

pub use storage::{
    KeyStorage,
    InMemoryStorage,
    KeyMetadata,
    KeyType,
    StoredKey,
    EncryptedRecord,
};

pub use key_manager::{
    KeyManager,
    DekInfo,
    RotationResult,
    KeyStats,
};

pub use envelope::{
    EnvelopeEncryption,
    EnvelopeEncryptionBuilder,
    EncryptedEnvelope,
};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        EnvelopeEncryption,
        EnvelopeEncryptionBuilder,
        EncryptedEnvelope,
        InMemoryStorage,
        KeyStorage,
        KeyType,
        Result,
        EnvelopeError,
        SecureKey,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_full_workflow() {
        // Setup
        let storage = Arc::new(InMemoryStorage::new());
        let mut service = EnvelopeEncryption::new(storage).unwrap();
        service.initialize().unwrap();

        // Encrypt multiple pieces of data
        let data1 = b"First secret document";
        let data2 = b"Second secret document";
        let data3 = b"Third secret document";

        let env1 = service.encrypt(data1, None, None).unwrap();
        let env2 = service.encrypt(data2, None, None).unwrap();
        let env3 = service.encrypt(data3, None, None).unwrap();

        // Verify all can be decrypted
        assert_eq!(data1.to_vec(), service.decrypt(&env1).unwrap());
        assert_eq!(data2.to_vec(), service.decrypt(&env2).unwrap());
        assert_eq!(data3.to_vec(), service.decrypt(&env3).unwrap());

        // Rotate master key
        let rotation = service.rotate_master_key().unwrap();
        assert_eq!(rotation.new_version, 2);

        // Verify data still accessible after rotation
        assert_eq!(data1.to_vec(), service.decrypt(&env1).unwrap());
        assert_eq!(data2.to_vec(), service.decrypt(&env2).unwrap());
        assert_eq!(data3.to_vec(), service.decrypt(&env3).unwrap());

        // Check stats
        let stats = service.get_stats().unwrap();
        assert!(stats.active_keks >= 1);
        assert!(stats.active_deks >= 3);
    }

    #[test]
    fn test_stateless_mode() {
        let storage = Arc::new(InMemoryStorage::new());
        let service = EnvelopeEncryption::new(storage).unwrap();

        let data_id = uuid::Uuid::new_v4();
        let plaintext = b"Stateless encryption test data";

        // Encrypt without storing keys
        let encrypted = service.encrypt_stateless(plaintext, &data_id).unwrap();
        
        // Decrypt using same data_id
        let decrypted = service.decrypt_stateless(&encrypted, &data_id).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_multiple_keks() {
        let storage = Arc::new(InMemoryStorage::new());
        let mut service = EnvelopeEncryption::new(storage).unwrap();
        service.initialize().unwrap();

        // Generate additional KEK
        let kek2 = service.generate_kek().unwrap();

        let data1 = b"Data under default KEK";
        let data2 = b"Data under KEK2";

        let env1 = service.encrypt(data1, None, None).unwrap();
        let env2 = service.encrypt_with_kek(data2, &kek2, None, None).unwrap();

        // Different KEKs
        assert_ne!(env1.kek_id, env2.kek_id);

        // Both decrypt correctly
        assert_eq!(data1.to_vec(), service.decrypt(&env1).unwrap());
        assert_eq!(data2.to_vec(), service.decrypt(&env2).unwrap());
    }
}


